//! The payee-side `SpilmanHost` — the bridge between the durable ledger and
//! cdk-spilman's own signature validator.
//!
//! # Why this exists
//!
//! `CRITICAL-UNVERIFIED-PAYMENT.md`: the rail accepted any balance for any channel
//! id because the ledger checks *monotonicity*, never *authenticity*. Upstream
//! already ships the authenticity check — `SpilmanBridge::validate_payment`
//! (bridge.rs:1312) — but it can only run against a host that serves the channel's
//! funding record. This is that host.
//!
//! The shape is MONAD's (`monad-relay/src/payments.rs:961`,
//! `impl SpilmanHost<PaymentContext> for MonadHost`): implement the host trait
//! directly over the durable store, rather than building the ~20-method
//! `SpilmanStorage` backend `configurable_host` needs. One host, one store, no
//! second copy of the balances.
//!
//! # The three methods that decide whether a payment is accepted
//!
//! `validate_payment` reads exactly three host values, so these three are the ones
//! that must be real:
//!
//! | hook | what upstream does with it | what a wrong answer would cost |
//! |---|---|---|
//! | `get_channel_state` | must be `Open`, else `UnknownChannel` | `Some(Open)` for an unfunded channel would verify nothing and credit a forgery |
//! | `get_funding` | the five values `verify_signature` runs on | a lossy or substituted record verifies the *wrong* bytes |
//! | `get_amount_due` | `balance < amount_due` is refused | a low answer would let a payment that does not cover usage through |
//!
//! All three are plain reads of the durable ledger, and all three fail **closed**:
//! an unreadable ledger yields `None`/`0`/`Err`, every one of which upstream turns
//! into a refusal.
//!
//! # What is deliberately not implemented
//!
//! The remaining hooks belong to channel *funding* and channel *close*, which this
//! rail does not do: funding records are written explicitly by the payee when a
//! channel is opened (`ChannelLedger::save_channel_funding`), and the close
//! lifecycle (`mark_channel_closing` / `mark_channel_closed` /
//! `get_closing_data`) has no home in the balance ledger. Each of those is
//! implemented as an explicit refusal or an empty answer — never as a plausible
//! value — because a hook that lies about a channel's state is how a payee ends up
//! settling a channel it never verified. They are marked `NOT ON THE
//! VERIFICATION PATH` below with the reason.

use std::time::{SystemTime, UNIX_EPOCH};

use cashu::nuts::{CurrencyUnit, Id, PublicKey};
use cdk_spilman::{
    ChannelFunding, ChannelPolicy, ChannelState, ClosingData, PaymentProof, SpilmanHost,
};

use crate::spilman::ledger::{ChannelFundingRecord, ChannelLedger};

/// A `SpilmanHost` that serves funding records out of the durable channel ledger.
///
/// Borrows the ledger rather than owning one: the rail already holds it, and the
/// bridge is constructed per call (it is a thin wrapper over `&H`).
#[derive(Debug)]
pub struct LedgerPayeeHost<'a> {
    ledger: &'a ChannelLedger,
    receiver: Option<&'a cashu::nuts::SecretKey>,
    close_keyset: Option<(&'a str, &'a str)>,
}

impl<'a> LedgerPayeeHost<'a> {
    pub fn for_close(
        ledger: &'a ChannelLedger,
        receiver: &'a cashu::nuts::SecretKey,
        mint: &'a str,
        keyset: &'a str,
    ) -> Self {
        Self {
            ledger,
            receiver: Some(receiver),
            close_keyset: Some((mint, keyset)),
        }
    }

    /// Wrap a ledger as a cdk-spilman payee host.
    pub fn new(ledger: &'a ChannelLedger) -> Self {
        Self {
            ledger,
            receiver: None,
            close_keyset: None,
        }
    }

    /// A host that holds `receiver` and no keyset cache.
    ///
    /// The shape a **funding-time policy** check needs: the receiver-key question can
    /// be answered, the keyset question cannot (and answers `false`). Used by
    /// `SpilmanRail::register_channel` so that the "is this channel addressed to me?"
    /// decision has exactly one implementation — this trait impl — instead of a second
    /// copy in the rail.
    pub fn with_receiver(ledger: &'a ChannelLedger, receiver: &'a cashu::nuts::SecretKey) -> Self {
        Self {
            ledger,
            receiver: Some(receiver),
            close_keyset: None,
        }
    }
}

/// Read `capacity` out of a channel's serialized params.
///
/// Upstream's own `validate_payment` reads it the same way (bridge.rs:1330). An
/// unparseable params blob yields `None`; the caller decides, and in every caller
/// here that becomes a refusal rather than a default.
fn capacity_from_params_json(params_json: &str) -> Option<u64> {
    serde_json::from_str::<serde_json::Value>(params_json)
        .ok()?
        .get("capacity")?
        .as_u64()
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The mint and keyset this host will accept a channel against.
///
/// `for_close` supplies both explicitly, because the close path fetches the output
/// keyset from the *configured* mint and nothing else may be substituted. A host with
/// neither (i.e. [`LedgerPayeeHost::new`], which serves the verification path only)
/// answers `false`: it holds no keyset cache, so it has no honest way to say a keyset
/// is the one this payee trusts.
fn accepts_keyset(close_keyset: Option<(&str, &str)>, mint: &str, keyset_id: &Id) -> bool {
    let Some((trusted_mint, json)) = close_keyset else {
        return false;
    };
    if trusted_mint != mint {
        return false;
    }
    cdk_spilman::parse_keyset_info_from_json(json)
        .map(|info| &info.keyset_id == keyset_id)
        .unwrap_or(false)
}

impl SpilmanHost for LedgerPayeeHost<'_> {
    /// Accept a channel only if it is addressed to the receiver key this host holds.
    ///
    /// # Why this is a real comparison and not a constant
    ///
    /// The payer names the receiver pubkey in the channel params, and every close
    /// signature this payee produces is signed with **this** key. A host that
    /// answered `true` for anything would let a payer open a channel against a
    /// throwaway key; the open would fund at the mint and the close would then fail
    /// forever (`sign_with_tweaked_key` → "receiver key mismatch"), which is exactly
    /// the HTTP 409 seen at `POST /spilman/close` on real hardware.
    ///
    /// `false` remains the answer when the host holds no key at all (read-only ledger
    /// contexts, e.g. [`LedgerPayeeHost::new`]): such a host cannot sign a close, so
    /// there is no key it could honestly accept.
    fn receiver_key_is_acceptable(&self, receiver_pubkey: &PublicKey) -> bool {
        match self.receiver {
            Some(key) => &key.public_key() == receiver_pubkey,
            None => false,
        }
    }

    /// Accept exactly the *(mint, keyset)* pair this host was constructed with.
    ///
    /// Honest rather than constant: `for_close` is given the mint URL from the rail's
    /// own configured `mint_url` and the keyset JSON fetched from that mint, so the
    /// comparison is against real, trusted bytes. A host constructed without them
    /// answers `false`.
    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset_id: &Id) -> bool {
        accepts_keyset(self.close_keyset, mint, keyset_id)
    }

    /// The channel's durable funding record — the five values upstream's
    /// `verify_signature` runs on.
    ///
    /// An unreadable ledger returns `None` rather than propagating, because the
    /// trait cannot: upstream then reports `UnknownChannel` and refuses. Fail
    /// closed, but loud.
    fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding> {
        match self.ledger.get_channel_funding(channel_id) {
            Ok(Some(record)) => Some(ChannelFunding {
                params_json: record.params_json,
                funding_proofs_json: record.funding_proofs_json,
                channel_secret_hex: record.channel_secret_hex,
                keyset_info_json: record.keyset_info_json,
            }),
            Ok(None) => None,
            Err(e) => {
                tracing::error!(channel_id, error = %e, "spilman funding read failed; treating the channel as unknown");
                None
            }
        }
    }

    /// Persist a funding record handed over by the bridge's own first-use path.
    ///
    /// The rail does not depend on this: `SpilmanRail::record_payment` verifies
    /// through `validate_payment` and the payee writes funding records explicitly
    /// at open time. It is implemented anyway so that a caller who *does* drive
    /// `process_payment` does not get a silent lie — the record lands, or the
    /// failure is logged and the channel simply stays unverifiable (refused later).
    ///
    /// `capacity` is taken from the params, exactly as upstream does. If it cannot
    /// be read, the record is still stored with capacity 0 — which refuses every
    /// payment, the safe direction.
    fn save_funding(
        &self,
        channel_id: &str,
        funding: ChannelFunding,
        _initial_payment: PaymentProof,
    ) {
        let record = ChannelFundingRecord {
            channel_id: channel_id.to_string(),
            capacity: capacity_from_params_json(&funding.params_json).unwrap_or(0),
            params_json: funding.params_json,
            funding_proofs_json: funding.funding_proofs_json,
            channel_secret_hex: funding.channel_secret_hex,
            keyset_info_json: funding.keyset_info_json,
            created_at: now_seconds(),
        };
        if let Err(e) = self.ledger.save_channel_funding(&record) {
            tracing::error!(
                channel_id,
                error = %e,
                "spilman save_funding failed; the channel will not be verifiable and every \
                 payment for it will be refused"
            );
        }
    }

    /// The stored balance — what upstream compares the offered balance against.
    ///
    /// A read failure answers `0`, which makes upstream demand `balance >= 0`… i.e.
    /// it does **not** refuse on this hook. That is fine and deliberate: this value
    /// only ever *raises* the bar, and the value that actually grants credit is the
    /// CAS write in [`crate::spilman::ledger::ChannelLedger::record_payment`], which
    /// still refuses a balance that does not advance the stored one. An unreadable
    /// ledger therefore cannot turn into credit — the CAS sees the same failure and
    /// refuses.
    fn get_amount_due(&self, channel_id: &str, _context: Option<&String>) -> u64 {
        match self.ledger.get_balance(channel_id) {
            Ok(Some(balance)) => balance,
            Ok(None) => 0,
            Err(e) => {
                tracing::error!(channel_id, error = %e, "spilman balance read failed; reporting 0 due");
                0
            }
        }
    }

    /// NOT ON THE VERIFICATION PATH — a no-op, on purpose.
    ///
    /// This hook belongs to the bridge's all-in-one `process_payment` path, which
    /// writes a balance monotonically. Credit in this rail is granted **only** by
    /// the CAS ledger write, and a hook that also wrote a balance would create a
    /// second, weaker writer — the exact shape of the bug in
    /// `CRITICAL-UNVERIFIED-PAYMENT.md`. Leaving it inert can only mean a balance
    /// is never recorded, i.e. the payee serves nothing.
    fn record_payment(&self, _channel_id: &str, _payment: PaymentProof, _context: &String) {}

    /// Durable lifecycle state for a funded channel, `None` otherwise.
    ///
    /// This is the gate `validate_payment` passes first (`validate_payment_request`,
    /// bridge.rs:1451): anything other than `Some(Open)` is `UnknownChannel`. So the
    /// answer must be driven by the *durable funding record* — not by the presence of
    /// a balance row, which is exactly the state a forgery creates.
    fn get_channel_state(&self, channel_id: &str) -> Result<Option<ChannelState>, String> {
        match self.ledger.get_channel_funding(channel_id) {
            Ok(Some(_)) => match self
                .ledger
                .close_journal(channel_id)
                .map_err(|e| e.to_string())?
            {
                Some((_, state, _)) if state == "closed" => Ok(Some(ChannelState::Closed)),
                Some(_) => Ok(Some(ChannelState::Closing)),
                None => Ok(Some(ChannelState::Open)),
            },
            Ok(None) => Ok(None),
            // A read failure must be an error, never `None`-as-"not open" and never
            // `Open`: upstream propagates it and refuses.
            Err(e) => Err(e.to_string()),
        }
    }

    /// NOT ON THE VERIFICATION PATH — the close lifecycle has no home in this
    /// ledger. Refuses rather than pretending the channel is closing.
    fn mark_channel_closing(
        &self,
        channel_id: &str,
        _expiry_timestamp: u64,
        _payment: PaymentProof,
    ) -> Result<(), String> {
        Err(format!(
            "channel {channel_id}: this payee does not implement the Spilman close lifecycle"
        ))
    }

    /// NOT ON THE VERIFICATION PATH — nothing is ever marked closing, so nothing
    /// can be read back. `None` is the honest answer.
    fn get_closing_data(&self, _channel_id: &str) -> Option<ClosingData> {
        None
    }

    /// NOT ON THE VERIFICATION PATH — funding-time policy. `None` makes upstream
    /// report `UnsupportedUnit`, i.e. refuse.
    fn get_channel_policy(&self, _unit: &str) -> Option<ChannelPolicy> {
        None
    }

    /// Real wall-clock seconds. Upstream uses this for expiry arithmetic only.
    fn now_seconds(&self) -> u64 {
        now_seconds()
    }

    /// The latest `(balance, signature)` the payee holds — the pair a unilateral
    /// exit (or a settlement) needs. A plain ledger read.
    fn get_balance_and_signature_for_unilateral_exit(
        &self,
        channel_id: &str,
    ) -> Option<PaymentProof> {
        match self.ledger.get_latest_payment(channel_id) {
            Ok(Some(stored)) => Some(PaymentProof {
                balance: stored.balance,
                signature: stored.signature,
            }),
            Ok(None) => None,
            Err(e) => {
                tracing::error!(channel_id, error = %e, "spilman exit-pair read failed");
                None
            }
        }
    }

    /// Close preparation uses the mint-fetched keyset explicitly supplied by the caller.
    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id> {
        self.close_keyset
            .and_then(|(m, json)| {
                cdk_spilman::parse_keyset_info_from_json(json)
                    .ok()
                    .filter(|k| m == mint && &k.unit == unit)
            })
            .map(|k| vec![k.keyset_id])
            .unwrap_or_default()
    }

    /// NOT ON THE VERIFICATION PATH — no keyset cache, so `false`.
    fn has_keysets_for_unit(&self, _mint: &str, _unit: &CurrencyUnit) -> bool {
        false
    }

    /// NOT ON THE VERIFICATION PATH — no keyset cache.
    ///
    /// Note the verification path does *not* come through here: it reads
    /// `keyset_info_json` straight off the funding record, which is the copy the
    /// signature was actually verified against when the channel was opened.
    fn get_keyset_info(&self, mint: &str, keyset_id: &Id) -> Option<String> {
        let (m, json) = self.close_keyset?;
        let info = cdk_spilman::parse_keyset_info_from_json(json).ok()?;
        (m == mint && &info.keyset_id == keyset_id).then(|| json.to_string())
    }

    /// NOT ON THE VERIFICATION PATH — see `mark_channel_closing`.
    #[allow(clippy::too_many_arguments)]
    fn mark_channel_closed(
        &self,
        channel_id: &str,
        _expiry_timestamp: u64,
        _balance: u64,
        _receiver_proofs_json: &str,
        _sender_proofs_json: &str,
        _receiver_sum: u64,
        _sender_sum: u64,
    ) -> Result<(), String> {
        Err(format!(
            "channel {channel_id}: this payee does not implement the Spilman close lifecycle"
        ))
    }

    /// NOT ON THE VERIFICATION PATH — no receiver secret lives in this host.
    ///
    /// The channel secret a payment is verified against is the one persisted in the
    /// funding record (`channel_secret_hex`), which was derived when the channel was
    /// opened. Deriving it here would be a second source of truth for the value the
    /// signature is checked against, so this refuses.
    fn compute_channel_secret(
        &self,
        receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
    ) -> Result<String, String> {
        Err(format!(
            "this payee does not derive channel secrets ({receiver_pubkey_hex}, {sender_pubkey_hex}); \
             the secret is persisted in the funding record"
        ))
    }

    /// Sign using upstream parity/tweak handling and only the explicitly installed receiver key.
    fn sign_with_tweaked_key(
        &self,
        signer_pubkey_hex: &str,
        message_hex: &str,
        tweak_scalar_hex: &str,
    ) -> Result<String, String> {
        let key = self.receiver.ok_or("receiver signing key unavailable")?;
        if key.public_key().to_hex() != signer_pubkey_hex {
            return Err("receiver key mismatch".into());
        }
        cdk_spilman::sign_with_tweaked_key_util(
            &hex::encode(key.secret_bytes()),
            message_hex,
            tweak_scalar_hex,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spilman::ledger::ChannelLedger;

    /// A self-consistent keyset blob, in the shape `parse_keyset_info_from_json` reads.
    fn keyset_json() -> (String, Id) {
        let keys = cashu::nuts::Keys::new(
            [(
                cashu::Amount::from(1u64),
                cashu::nuts::SecretKey::generate().public_key(),
            )]
            .into_iter()
            .collect(),
        );
        let keyset_id = Id::v1_from_keys(&keys);
        let json = serde_json::json!({
            "keysetId": keyset_id.to_string(),
            "unit": "sat",
            "inputFeePpk": 0,
            "keys": keys.iter()
                .map(|(amount, key)| (amount.to_string(), key.to_hex()))
                .collect::<std::collections::BTreeMap<String, String>>(),
        })
        .to_string();
        (json, keyset_id)
    }

    /// The policy is only honest if it answers for the key this host actually holds.
    ///
    /// Reverting `receiver_key_is_acceptable` to `false` makes the first assertion
    /// fail, which is exactly the regression that let a whole suite stay green while
    /// no real payer could ever be accepted.
    #[test]
    fn a_host_accepts_only_its_own_receiver_key() {
        let ledger = ChannelLedger::open_in_memory().expect("ledger");
        let (json, keyset_id) = keyset_json();
        let ours = cashu::nuts::SecretKey::generate();
        let theirs = cashu::nuts::SecretKey::generate();

        let host = LedgerPayeeHost::for_close(&ledger, &ours, "https://mint.example", &json);
        assert!(
            host.receiver_key_is_acceptable(&ours.public_key()),
            "the payee must accept a channel addressed to the key it holds"
        );
        assert!(
            !host.receiver_key_is_acceptable(&theirs.public_key()),
            "the payee must refuse a channel addressed to somebody else's key"
        );

        // A host with no key has no honest way to say yes: still fail closed.
        let keyless = LedgerPayeeHost::new(&ledger);
        assert!(
            !keyless.receiver_key_is_acceptable(&ours.public_key()),
            "a host that holds no receiver key must refuse, even the right key"
        );

        // And the keyset policy answers for the keyset this host holds.
        let (other_json, other_id) = keyset_json();
        assert!(host.mint_and_keyset_is_acceptable("https://mint.example", &keyset_id));
        assert!(!host.mint_and_keyset_is_acceptable("https://other.example", &keyset_id));
        assert!(!host.mint_and_keyset_is_acceptable("https://mint.example", &other_id));
        assert!(!keyless.mint_and_keyset_is_acceptable("https://mint.example", &keyset_id));
        let _ = other_json;
    }
}
