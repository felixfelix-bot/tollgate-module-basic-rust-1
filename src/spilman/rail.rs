//! The live payee-side rail: the `PaymentRail` implementation that is built from
//! [`SpilmanConfig`](crate::config::schema::SpilmanConfig) — and only when the
//! config says so.
//!
//! # Why the constructor returns `Option`
//!
//! [`SpilmanRail::from_config`] returns `Ok(None)` for a disabled config. The
//! caller therefore stores `Option<Arc<SpilmanRail>>` and there is *no rail object
//! at all* when Spilman is off — not an inert one whose every method must be
//! trusted to abstain. Absence is a stronger guarantee than good behaviour, and it
//! is what makes "`enabled: false` changes nothing" a property of the types rather
//! than of the code paths we remembered to check.
//!
//! # Credit accounting
//!
//! Credit is derived from the durable ledger, never from anything the caller
//! passes in: `authorize_bytes` reads the stored balance, converts it to millisats
//! in the channel's unit, and asks the *shared* billing arithmetic
//! ([`SessionPricing::amount_due_millisats`]) whether the cumulative bytes are
//! covered. Reusing that one function is deliberate — a second, "obviously
//! equivalent" comparison here is how a payee ends up serving a byte the payer's
//! signature does not cover.
//!
//! # Authenticity, and why it is not the ledger's job
//!
//! `record_payment` **verifies before it writes**, using upstream's own
//! `SpilmanBridge::validate_payment` against the channel's persisted funding record
//! (see [`super::payee_host`]). The ledger's compare-and-swap answers a different
//! question — "is this newly accepted funds, or a replay?" — and monotonicity is
//! not authenticity: a *higher* balance from anyone used to be accepted for any
//! channel id (`CRITICAL-UNVERIFIED-PAYMENT.md`). Both checks are required, in that
//! order.
//!
//! Fail-closed everywhere: an unknown channel, an unreadable ledger, an
//! unsupported unit, or a signature that does not verify all `Deny` or refuse.
//! None of them may be read as "no charge".

use std::path::Path;

use async_trait::async_trait;
use cdk_spilman::SpilmanBridge;

use crate::config::schema::SpilmanConfig;
use crate::spilman::ledger::{ChannelLedger, LedgerOutcome};
use crate::spilman::payee_host::LedgerPayeeHost;
use crate::spilman::payment_units::raw_units_to_msats;
use crate::spilman::pricing::SessionPricing;
use crate::spilman::{PaymentRail, RailDecision, SpilmanError};

/// Channel unit used for the wholesale rail's raw balance.
///
/// `sat` because the funding proofs are sat-denominated on every TollGate mint in
/// the field; `payment_units` handles the msat round-up.
pub const RAIL_UNIT: &str = "sat";

/// The payee-side Spilman rail, backed by the durable channel ledger.
#[derive(Debug)]
pub struct SpilmanRail {
    ledger: ChannelLedger,
    pricing: SessionPricing,
    mint_url: Option<String>,
    receiver_key: Option<cashu::nuts::SecretKey>,
}

impl SpilmanRail {
    /// Build the rail from config, or `Ok(None)` when the rail is disabled.
    ///
    /// Errors (rather than defaulting) when enabled without a ledger path: see
    /// [`SpilmanConfig`] on why a forgotten ledger is a money bug, not a nuisance.
    pub fn from_config(config: &SpilmanConfig) -> Result<Option<Self>, SpilmanError> {
        if !config.enabled {
            return Ok(None);
        }
        let path = config.channel_db_path.as_deref().ok_or_else(|| {
            SpilmanError::Config(
                "spilman.enabled is true but spilman.channel_db_path is unset: the channel \
                 balance ledger must be durable, or a restart loses balances and lets a payer \
                 re-spend the channel"
                    .to_string(),
            )
        })?;
        Self::open(
            Path::new(path),
            config.in_bytes_per_millisat,
            config.mint_url.clone(),
        )
        .map(Some)
    }

    /// Open the rail at an explicit path (used by tests and the config path above).
    pub fn open(
        path: &Path,
        in_bytes_per_millisat: u64,
        mint_url: Option<String>,
    ) -> Result<Self, SpilmanError> {
        // Symmetric rates: TollGate bills the same bytes-per-millisat in both
        // directions, so a single configured rate is the honest shape here.
        let pricing = SessionPricing::try_new(in_bytes_per_millisat, in_bytes_per_millisat)?;
        Ok(Self {
            ledger: ChannelLedger::open(path)?,
            pricing,
            mint_url,
            receiver_key: None,
        })
    }

    /// The mint this payee accepts channel funding from, if one was configured.
    pub fn mint_url(&self) -> Option<&str> {
        self.mint_url.as_deref()
    }

    /// The receiver (payee) public key this rail signs channel closes with, if it holds
    /// one. `None` means this rail cannot settle a channel at all, and must not
    /// advertise a key it cannot sign with.
    pub fn receiver_pubkey(&self) -> Option<cashu::nuts::PublicKey> {
        self.receiver_key.as_ref().map(|key| key.public_key())
    }

    /// Bytes of access a given **raw channel balance** buys at this rail's rate.
    ///
    /// The access path needs the inverse of `authorize_bytes`: it holds a verified
    /// balance and must turn it into an `allotment`. Floored to whole steps by
    /// `allotment_bytes_for`, which is the same rule the retail path uses — what
    /// cannot pay for a full step buys nothing, rather than buying a fraction of one.
    ///
    /// Returns `Err` when the raw balance cannot be converted (wrong unit), so a
    /// caller cannot silently treat an unconvertible balance as zero credit.
    pub fn bytes_for_raw_balance(&self, raw_balance: u64) -> Result<u64, SpilmanError> {
        let millisats = raw_units_to_msats(RAIL_UNIT, raw_balance)?;
        Ok(self.pricing.bytes_for_millisats(millisats))
    }

    /// Bytes per millisat in use (both directions).
    pub fn in_bytes_per_millisat(&self) -> u64 {
        self.pricing.in_bytes_per_millisat
    }

    /// Register an opened channel: persist the funding record this payee will
    /// verify future payments against.
    ///
    /// # Why this lives on the rail, not in the handler
    ///
    /// Same rule as every other `/spilman` decision: the handler translates, the
    /// rail decides. Registration is where "which bytes may this payee be asked to
    /// verify against" is settled — a policy question, not a parsing one — so the
    /// handler passes the request through and reports what came back.
    ///
    /// # The security property, stated once
    ///
    /// Registration **grants no credit**. It cannot: credit is issued only by
    /// [`SpilmanRail::record_payment`], which re-derives the channel from this
    /// record and verifies a BIP-340 signature over `(channel_id, balance)` with
    /// upstream's own validator before the durable write. So a forged registration
    /// (a record for a channel the poster does not hold the key for) does not
    /// inflate a balance — it produces a channel that **refuses every payment**,
    /// including the forger's. Wrong or unverified input fails closed here by
    /// construction; there is no path from "registered" to "credited" that skips
    /// the signature check.
    ///
    /// What registration *does* decide is which channel this payee will bother
    /// looking at, so a garbage record is still worth refusing at the door: a stored
    /// row that can never verify is a durable denial-of-service on that id.
    pub fn register_channel(
        &self,
        req: &crate::spilman::registration::ChannelRegistrationRequest,
    ) -> Result<crate::spilman::FundingRegistration, SpilmanError> {
        // Validate against upstream's own channel reconstruction, then store
        // compare-and-swap. Validation failure means nothing is written.
        let record = crate::spilman::registration::validate_registration(req)?;
        self.enforce_receiver_binding(&record)?;
        self.ledger.register_channel_funding(&record)
    }

    /// Refuse a channel addressed to a receiver key this payee does not hold.
    ///
    /// # Why registration must consult this
    ///
    /// A channel names its `receiver_pubkey` in the params, and every close signature
    /// this payee produces is made with **its own** receiver key
    /// (`LedgerPayeeHost::sign_with_tweaked_key`). A channel addressed to any other
    /// key therefore funds at the mint and then can never settle: the payer's money
    /// sits in a channel the payee cannot close, and every `POST /spilman/close` is a
    /// 409. That is the gap this refuses at the door instead of discovering at
    /// settlement time.
    ///
    /// # The `None` case — a keyless rail REFUSES
    ///
    /// A rail with no receiver key cannot settle anything, so accepting a registration
    /// would take the payer's funded channel and strand it: the money is already in the
    /// channel at the mint by the time this body arrives, and only *this* payee can
    /// ever release it. There is no honest answer to "is this key yours?" without a
    /// key, so the answer is a refusal, not a silent acceptance. (This used to be a
    /// documented carve-out that accepted keyless registrations; that was wrong for
    /// exactly the reason above.)
    ///
    /// Verification-only hosts still exist — `LedgerPayeeHost::new` answers `false` to
    /// `receiver_key_is_acceptable` — but they are not allowed to *accept a channel*.
    fn enforce_receiver_binding(
        &self,
        record: &crate::spilman::ChannelFundingRecord,
    ) -> Result<(), SpilmanError> {
        let refused = |detail: String| SpilmanError::InvalidRegistration {
            channel_id: record.channel_id.clone(),
            detail,
        };
        let Some(ours) = self.receiver_key.as_ref() else {
            return Err(refused(
                "this payee holds no receiver key and cannot settle a channel; \
                 refusing the registration rather than stranding the funding"
                    .to_string(),
            ));
        };
        let params: serde_json::Value =
            serde_json::from_str(&record.params_json).map_err(|e| refused(e.to_string()))?;
        let offered = params["receiver_pubkey"]
            .as_str()
            .ok_or_else(|| refused("channel params carry no receiver_pubkey".to_string()))?;
        let offered = cashu::nuts::PublicKey::from_hex(offered)
            .map_err(|e| refused(format!("receiver_pubkey is not a public key: {e}")))?;
        let host = LedgerPayeeHost::with_receiver(&self.ledger, ours);
        if !cdk_spilman::SpilmanHost::receiver_key_is_acceptable(&host, &offered) {
            return Err(refused(format!(
                "channel receiver_pubkey {offered} is not this payee's ({}); \
                 a channel for another key can never be settled here",
                ours.public_key()
            )));
        }
        self.enforce_mint_binding(&params, record, refused)
    }

    /// Refuse a channel funded at a mint this payee is not configured for.
    ///
    /// # What is honestly checkable here, and what is not
    ///
    /// The **mint URL** is trusted: it comes from the operator's `config.json`
    /// (`spilman.mint_url`), not from the payer. Comparing the channel's `mint` against
    /// it is a real check, and it is the one that matters — the close swap is issued to
    /// `self.mint_url`, so a channel funded elsewhere can never be redeemed here.
    ///
    /// The **keyset id** is *not* independently trusted at registration time: the only
    /// keyset bytes in a registration body are supplied by the payer
    /// (`keyset_info_json`). Comparing `params.keyset_id` against it proves the body is
    /// self-consistent, which `validate_registration` already establishes, and nothing
    /// more. The keyset becomes trusted only at close, where it is fetched from the
    /// configured mint — that is where `mint_and_keyset_is_acceptable` does real work
    /// (see `prepare_close` / `execute_close_with_network`, both of which build the host
    /// with `for_close`).
    ///
    /// So this delegates to the host's own `mint_and_keyset_is_acceptable` with the
    /// trusted mint and the body's keyset, and reports the two failures distinctly:
    /// a mint mismatch is a policy refusal, a keyset inconsistency is a malformed body.
    fn enforce_mint_binding<E>(
        &self,
        params: &serde_json::Value,
        record: &crate::spilman::ChannelFundingRecord,
        refused: E,
    ) -> Result<(), SpilmanError>
    where
        E: Fn(String) -> SpilmanError,
    {
        let Some(configured) = self.mint_url.as_deref() else {
            // No configured mint means this rail cannot redeem anything, and it cannot
            // vouch for the channel's mint either. Same reasoning as the keyless case.
            return Err(refused(
                "no mint is configured for this payee; it cannot redeem a channel and \
                 must not accept one"
                    .to_string(),
            ));
        };
        let claimed = params["mint"].as_str().ok_or_else(|| {
            refused("channel params carry no mint URL".to_string())
        })?;
        let keyset_id = params["keyset_id"]
            .as_str()
            .ok_or_else(|| refused("channel params carry no keyset_id".to_string()))?;
        let keyset_id = keyset_id
            .parse::<cashu::nuts::Id>()
            .map_err(|e| refused(format!("keyset_id is not a keyset id: {e}")))?;
        let key = self
            .receiver_key
            .as_ref()
            .ok_or_else(|| refused("receiver key unavailable".to_string()))?;
        let host = LedgerPayeeHost::for_close(
            &self.ledger,
            key,
            configured,
            &record.keyset_info_json,
        );
        if !cdk_spilman::SpilmanHost::mint_and_keyset_is_acceptable(&host, claimed, &keyset_id) {
            if claimed != configured {
                return Err(refused(format!(
                    "channel was funded at {claimed} but this payee is configured for \
                     {configured}; it could never redeem the channel"
                )));
            }
            return Err(refused(
                "channel keyset_id disagrees with the keyset info in the same body"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// The funding record this payee holds for a channel, if any.
    ///
    /// Used by the tests to assert "the stored record is still the original,
    /// byte-identical" after a refused overwrite, and by the driver to confirm
    /// registration landed.
    pub fn channel_funding(
        &self,
        channel_id: &str,
    ) -> Result<Option<crate::spilman::ChannelFundingRecord>, SpilmanError> {
        self.ledger.get_channel_funding(channel_id)
    }

    /// Whether this payee knows the channel at all — i.e. holds a funding record.
    ///
    /// Distinct from "has credit", and the distinction matters: a channel that was
    /// just registered has no balance row yet, and reading that absence as "unknown"
    /// would tell a payer its registration failed when it did not.
    pub fn is_known_channel(&self, channel_id: &str) -> Result<bool, SpilmanError> {
        Ok(self.ledger.get_channel_funding(channel_id)?.is_some())
    }

    /// The durable raw-unit balance for a channel, or `None` when it has none.
    ///
    /// `None` (registered, never paid) is deliberately distinct from `Some(0)`.
    pub fn channel_balance(&self, channel_id: &str) -> Result<Option<u64>, SpilmanError> {
        self.ledger.get_balance(channel_id)
    }

    /// TEST-ONLY escape hatch past signature verification.
    ///
    /// `record_payment` refuses every payment for a channel with no funding record
    /// (see `CRITICAL-UNVERIFIED-PAYMENT.md` and
    /// [`SpilmanRail::record_payment`]). That refusal is correct, but it also means
    /// the *credit arithmetic* — "1 sat of balance buys exactly 22,021,000 bytes" —
    /// would become untestable through the public path, and untested arithmetic is
    /// how a payee serves a byte nobody paid for.
    ///
    /// This exposes the ledger's own operation so the arithmetic can still be
    /// exercised, WITHOUT weakening the production refusal: it is behind the
    /// `test-support` feature, which is NOT in the default feature set, so a shipped
    /// binary does not contain it. Any production caller that wants to record a
    /// balance must go through `record_payment` and earn its signature check.
    ///
    /// (It cannot be `#[cfg(test)]`: integration tests in `tests/` are a separate
    /// crate and cannot see test-cfg items of the library.)
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn record_payment_for_tests(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
    ) -> Result<LedgerOutcome, SpilmanError> {
        self.ledger.record_payment_unverified(channel_id, balance, signature)
    }
}

/// Public close status. Never includes the secret-bearing preparation or payout proofs.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SellerCloseStatus {
    pub channel_id: String,
    pub state: String,
    pub receiver_sum: Option<u64>,
}

fn close_error(e: impl std::fmt::Debug) -> SpilmanError {
    SpilmanError::Ledger(format!("{e:?}"))
}

impl SpilmanRail {
    pub fn with_receiver_key(mut self, key: cashu::nuts::SecretKey) -> Self {
        self.receiver_key = Some(key);
        self
    }

    /// Authenticate before any mint I/O; return only the sender's durable receipt.
    /// `None` means authorized, but completion has not yet been persisted.
    pub fn authenticated_close_receipt(
        &self, payment: &cdk_spilman::Payment,
    ) -> Result<Option<cdk_spilman::CloseSuccess>, SpilmanError> {
        let id = &payment.channel_id;
        let funding = self.ledger.get_channel_funding(id)?
            .ok_or_else(|| close_error("unknown channel"))?;
        let params: serde_json::Value = serde_json::from_str(&funding.params_json).map_err(close_error)?;
        if params["mint"].as_str() != self.mint_url.as_deref() {
            return Err(close_error("channel mint does not match configured mint"));
        }
        let secret: [u8; 32] = hex::decode(&funding.channel_secret_hex)
            .map_err(close_error)?.try_into().map_err(close_error)?;
        let parameters = cdk_spilman::ChannelParameters::from_json_with_channel_secret(
            &funding.params_json,
            cdk_spilman::parse_keyset_info_from_json(&funding.keyset_info_json).map_err(close_error)?,
            secret).map_err(close_error)?;
        let channel = cdk_spilman::EstablishedChannel::new(parameters,
            serde_json::from_str(&funding.funding_proofs_json).map_err(close_error)?)
            .map_err(close_error)?;
        cdk_spilman::BalanceUpdateMessage {
            channel_id: id.clone(), amount: payment.balance,
            signature: payment.signature.parse().map_err(close_error)?,
        }.verify_sender_signature(&channel).map_err(close_error)?;
        let latest = self.ledger.get_latest_payment(id)?
            .ok_or_else(|| close_error("missing accepted payment"))?;
        if latest.balance != payment.balance || latest.signature != payment.signature {
            return Err(close_error("close authorization does not match accepted payment"));
        }
        let Some((_, state, completed)) = self.ledger.close_journal(id)? else { return Ok(None); };
        if state != "closed" { return Ok(None); }
        let completed: cdk_spilman::CompletedClose = serde_json::from_str(
            &completed.ok_or_else(|| close_error("closed journal missing completion"))?
        ).map_err(close_error)?;
        if completed.channel_id != *id || completed.balance != payment.balance {
            return Err(close_error("completion binding mismatch"));
        }
        Ok(Some(cdk_spilman::CloseSuccess {
            channel_id: id.clone(),
            total_value: completed.receiver_sum.checked_add(completed.sender_sum)
                .ok_or_else(|| close_error("completion value overflow"))?,
            receiver_sum: completed.receiver_sum,
            sender_sum: completed.sender_sum,
            sender_proofs: completed.sender_proofs_json,
            already_closed: true,
        }))
    }

    pub fn close_status(&self, id: &str) -> Result<SellerCloseStatus, SpilmanError> {
        let (_, state, completed) = self
            .ledger
            .close_journal(id)?
            .ok_or_else(|| close_error("no close journal"))?;
        let completed: Option<cdk_spilman::CompletedClose> = completed
            .map(|s| serde_json::from_str(&s))
            .transpose()
            .map_err(close_error)?;
        Ok(SellerCloseStatus {
            channel_id: id.into(),
            state,
            receiver_sum: completed.map(|c| c.receiver_sum),
        })
    }

    /// The output keyset must be fetched from the configured mint by the caller, not supplied by a remote payer.
    pub fn prepare_close(
        &self,
        id: &str,
        balance: u64,
        signature: &str,
        output_keyset_json: &str,
    ) -> Result<SellerCloseStatus, SpilmanError> {
        let key = self
            .receiver_key
            .as_ref()
            .ok_or_else(|| close_error("receiver signing key unavailable"))?;
        let funding = self
            .ledger
            .get_channel_funding(id)?
            .ok_or_else(|| close_error("unknown channel"))?;
        let params: serde_json::Value =
            serde_json::from_str(&funding.params_json).map_err(close_error)?;
        let mint = params["mint"]
            .as_str()
            .ok_or_else(|| close_error("missing mint"))?;
        if self.mint_url.as_deref() != Some(mint) {
            return Err(close_error("channel mint does not match configured mint"));
        }
        if let Some((saved, _, _)) = self.ledger.close_journal(id)? {
            let saved: cdk_spilman::PreparedCloseTransition =
                serde_json::from_str(&saved).map_err(close_error)?;
            if saved.payment.balance != balance || saved.payment.signature != signature {
                return Err(close_error("close authorization mismatch"));
            }
            return self.close_status(id);
        }
        let bridge = SpilmanBridge::new(LedgerPayeeHost::for_close(
            &self.ledger,
            key,
            mint,
            output_keyset_json,
        ));
        let transition = bridge
            .prepare_cooperative_close_transition(
                &serde_json::json!({"channel_id":id,"balance":balance,"signature":signature})
                    .to_string(),
            )
            .map_err(close_error)?;
        let stored = serde_json::to_string(&transition).map_err(close_error)?;
        self.ledger.freeze_close(id, balance, signature, &stored)?;
        self.close_status(id)
    }

    /// Execute at most once. An uncertain operation is recovered only by exact NUT-09 restore.
    /// Empty restore is NOT permission to replay: retain uncertainty for operator recovery.
    pub fn execute_close_with_network<N: cdk_spilman::SpilmanClientNetworking>(
        &self,
        id: &str,
        network: &N,
    ) -> Result<SellerCloseStatus, SpilmanError> {
        use cdk_spilman::SpilmanHost;
        let (saved, state, _) = self
            .ledger
            .close_journal(id)?
            .ok_or_else(|| close_error("no close journal"))?;
        if state == "closed" {
            return self.close_status(id);
        }
        let transition: cdk_spilman::PreparedCloseTransition =
            serde_json::from_str(&saved).map_err(close_error)?;
        let prepared = &transition.prepared_close;
        let key = self
            .receiver_key
            .as_ref()
            .ok_or_else(|| close_error("receiver signing key unavailable"))?;
        let keyset_json = prepared.output_keyset_info.to_string();
        let host = LedgerPayeeHost::for_close(&self.ledger, key, &prepared.mint_url, &keyset_json);
        let funding = host
            .get_funding(id)
            .ok_or_else(|| close_error("missing funding"))?;
        let latest = self
            .ledger
            .get_latest_payment(id)?
            .ok_or_else(|| close_error("missing payment"))?;
        if latest.balance != transition.payment.balance
            || latest.signature != transition.payment.signature
            || prepared.channel_id != id
            || self.mint_url.as_deref() != Some(&prepared.mint_url)
        {
            return Err(close_error("journal binding mismatch"));
        }
        let bridge = SpilmanBridge::new(host);
        bridge
            .verify_prepared_close(prepared, &funding, &transition.payment, &key.public_key())
            .map_err(close_error)?;
        let claimed = self
            .ledger
            .advance_close(id, &saved, "prepared", "uncertain", None)?;
        let completed = if claimed {
            let response = network
                .call_mint_swap(&prepared.mint_url, &prepared.swap_request.to_string())
                .map_err(close_error)?;
            bridge
                .complete_prepared_close(&response, prepared)
                .map_err(close_error)?
        } else {
            let response = network
                .call_mint_restore(
                    &prepared.mint_url,
                    &serde_json::json!({"outputs":prepared.swap_request["outputs"]}).to_string(),
                )
                .map_err(close_error)?;
            bridge
                .complete_prepared_close_restore(&response, prepared)
                .map_err(close_error)?
                .ok_or_else(|| {
                    close_error(
                        "close remains uncertain: no exact restore; swap will not be repeated",
                    )
                })?
        };
        let json = serde_json::to_string(&completed).map_err(close_error)?;
        if !self
            .ledger
            .advance_close(id, &saved, "uncertain", "closed", Some(&json))?
        {
            let status = self.close_status(id)?;
            if status.state != "closed" {
                return Err(close_error("close completion CAS refused"));
            }
        }
        self.close_status(id)
    }
}

#[async_trait]
impl PaymentRail for SpilmanRail {
    fn name(&self) -> &'static str {
        "spilman"
    }

    async fn authorize_bytes(
        &self,
        channel_id: &str,
        bytes_in: u64,
        bytes_out: u64,
    ) -> RailDecision {
        // An unreadable ledger must never be read as "no balance" *or* as "some
        // balance": deny, and leave the reason in the log.
        let stored = match self.ledger.get_balance(channel_id) {
            Ok(Some(balance)) => balance,
            Ok(None) => return RailDecision::Deny,
            Err(e) => {
                tracing::error!(channel_id, error = %e, "spilman ledger read failed; denying");
                return RailDecision::Deny;
            }
        };
        let budget_millisats = match raw_units_to_msats(RAIL_UNIT, stored) {
            Ok(m) => m,
            Err(e) => {
                tracing::error!(channel_id, error = %e, "spilman unit conversion failed; denying");
                return RailDecision::Deny;
            }
        };
        match self
            .pricing
            .amount_due_millisats(bytes_in, bytes_out)
            .ok()
            .and_then(|due| u64::try_from(due).ok())
        {
            Some(due) if due <= budget_millisats => RailDecision::Allow,
            Some(_) => RailDecision::Deny,
            None => {
                tracing::error!(channel_id, "spilman amount-due overflow; denying");
                RailDecision::Deny
            }
        }
    }

    async fn record_payment(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
    ) -> Result<LedgerOutcome, SpilmanError> {
        // ORDERING (the rule this rail lives by): AUTHENTICATE, then persist.
        //
        // 1. Load the channel's funding record. Absent -> UnknownChannel, the same
        //    fail-closed refusal this arm returned while the record did not exist at
        //    all. An unknown channel has nothing to verify against, and "no record"
        //    must never be read as "no capacity".
        if self.ledger.get_channel_funding(channel_id)?.is_none() {
            return Err(SpilmanError::UnknownChannel {
                channel_id: channel_id.to_string(),
            });
        }

        // 2. Verify with UPSTREAM'S OWN validator — not a re-implementation.
        //
        //    `SpilmanBridge::validate_payment` (bridge.rs:1312) re-derives the
        //    channel from the persisted params, funding proofs, channel secret and
        //    keyset info, refuses a balance above capacity, and verifies the sender's
        //    Schnorr signature over `(channel_id, balance)`. The host it runs against
        //    is `LedgerPayeeHost`, i.e. this same durable ledger.
        //
        //    Refusing on ANY error is the whole fix: before it, the ledger checked
        //    monotonicity only, so `{"channel_id":"deadbeef","balance":5,
        //    "signature":"00"}` minted credit for anyone (CRITICAL-UNVERIFIED-PAYMENT.md).
        let host = LedgerPayeeHost::new(&self.ledger);
        let bridge = SpilmanBridge::new(host);
        // The context is `String` (this rail's host is `SpilmanHost<String>`); the
        // payee's own byte accounting is driven by `authorize_bytes`, not here.
        let context = String::new();
        bridge
            .validate_payment(channel_id, balance, signature, &context)
            .map_err(|e| {
                tracing::warn!(
                    channel_id,
                    balance,
                    error = %e,
                    "spilman payment failed verification; refusing to credit it"
                );
                SpilmanError::PaymentNotVerified {
                    channel_id: channel_id.to_string(),
                    balance,
                    detail: e.to_string(),
                }
            })?;

        // 3. Only now the durable write — and it stays CAS (exact previous balance),
        //    because authenticity and "not a replay" are different questions: a
        //    re-sent valid signature verifies perfectly and must still not be credited
        //    twice.
        self.ledger.record_payment_unverified(channel_id, balance, signature)
    }
}
