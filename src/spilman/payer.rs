//! Payer-side channel lifecycle (the wholesale client).
//!
//! # The one ordering rule that protects money
//!
//! The moment a funding `POST /v1/swap` reaches the mint, the payer's original proofs
//! are spent. If the process dies between *submit* and *response*, it must still be able
//! to tell whether the swap landed — otherwise it cannot know whether to retry (spending
//! twice) or to reclaim the unspent originals.
//!
//! cdk-spilman's answer is a two-phase open, and **the order is mandatory**
//! (`client_bridge.rs:94-98` before the swap, `:105` after):
//!
//! ```text
//! 1. prepare_open_channel_from_token   -> PreparedOpenChannel   (no mint I/O, no mutation)
//! 2. mark_prepared_open_saved          -> persist OpeningFromSwap + original input
//!                                         ^^^^ MUST BE BEFORE 3
//! 3. networking.call_mint_swap         -> point of no return
//! 4. complete_prepared_open_channel    -> unblind + verify funding proofs
//! 5. mark_completed_open               -> channel is now payable
//! ```
//!
//! [`ChannelOpening::submit_funding_swap`] **refuses to run** unless step 2 happened
//! through [`ChannelOpening::save_opening`] on the same instance, so the ordering is
//! enforced by the type rather than by a comment. `tests/spilman_payer_lifecycle.rs`
//! asserts both the happy path and that refusal.
//!
//! # Why the networking object is passed in, not held
//!
//! `SpilmanClientBridge` consumes its `SpilmanClientNetworking` by value and exposes no
//! accessor. A mint client is stateless configuration, not session state, so the caller
//! constructs one alongside the bridge and hands it to step 3. The alternative — a
//! delegating wrapper type with ~20 mechanical forwarding impls — buys nothing.
//!
//! # What is deliberately not here
//!
//! No transport. MONAD carries `Payment` on a Noise/H2 control stream; TollGate has HTTP,
//! so the `Payment` travels as a base64 HTTP header
//! (`cdk_spilman::SpilmanBridge::process_payment_via_base64_header`). Do not port
//! MONAD's transport — §3 of the gap analysis says so explicitly.

use std::time::{SystemTime, UNIX_EPOCH};

use cdk_spilman::{
    ConfigurableClientHost, OpenChannelError, OpenChannelResult, Payment, PreparedOpenChannel,
    SpilmanClientBridge, SpilmanClientHost, SpilmanClientNetworking, SqliteClientStorage,
};

use crate::spilman::SpilmanError;

/// Default lifetime funded into a new channel: 24 h.
///
/// Gap analysis §6 hazard 5 (expiry race): the mint honours whichever spend lands
/// first, so the payee must settle *before* expiry and must not race the payer's
/// post-expiry refund branch. A day is comfortably longer than any session.
pub const DEFAULT_CHANNEL_LIFETIME_SECS: u64 = 24 * 60 * 60;

/// Default per-blinded-output ceiling handed to cdk-spilman (`max_amount`).
pub const DEFAULT_MAX_AMOUNT_PER_OUTPUT: u64 = 64;

/// Everything needed to open one channel, in the order the protocol requires it.
#[derive(Debug)]
pub struct ChannelOpening {
    prepared: PreparedOpenChannel,
    persisted: bool,
    swap_response: Option<String>,
    completed_funding_proofs: Option<String>,
}

impl ChannelOpening {
    /// Phase 1. Parse the funding token and build the swap request.
    ///
    /// Pure: no mint I/O, no storage mutation, nothing to recover from. The host is
    /// needed only to derive the ECDH channel secret.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare<H, N>(
        bridge: &SpilmanClientBridge<H, N>,
        token: &str,
        receiver_pubkey_hex: &str,
        sender_pubkey_hex: &str,
        expiry_timestamp: u64,
        keyset_info_json: &str,
        max_amount: u64,
    ) -> Result<Self, SpilmanError>
    where
        H: SpilmanClientHost,
        N: SpilmanClientNetworking,
    {
        let prepared = bridge
            .prepare_open_channel_from_token(
                token,
                receiver_pubkey_hex,
                sender_pubkey_hex,
                expiry_timestamp,
                keyset_info_json,
                max_amount,
            )
            .map_err(|e: OpenChannelError| SpilmanError::Bridge(e.to_string()))?;
        Ok(Self {
            prepared,
            persisted: false,
            swap_response: None,
            completed_funding_proofs: None,
        })
    }

    /// The channel id the mint-side swap will produce.
    pub fn channel_id(&self) -> &str {
        &self.prepared.channel_id
    }

    /// The mint the funding swap must go to.
    pub fn mint_url(&self) -> &str {
        &self.prepared.mint_url
    }

    /// The channel capacity the funding token buys, in raw channel units.
    pub fn capacity(&self) -> u64 {
        self.prepared.opening.capacity
    }

    /// Phase 2 — MUST run before [`Self::submit_funding_swap`].
    ///
    /// This is the durable record that makes the crash-after-submit window recoverable:
    /// it carries the original serialized input, which is the NUT-09 restore material for
    /// the funding proofs. Delegates to cdk-spilman's own
    /// `mark_prepared_open_saved`, so there is exactly one implementation of "how to
    /// persist an opening".
    pub fn save_opening<H, N>(
        &mut self,
        bridge: &SpilmanClientBridge<H, N>,
    ) -> Result<(), SpilmanError>
    where
        H: SpilmanClientHost,
        N: SpilmanClientNetworking,
    {
        bridge
            .mark_prepared_open_saved(&self.prepared)
            .map_err(|e: OpenChannelError| {
                SpilmanError::Bridge(format!("persist OpeningFromSwap record: {e}"))
            })?;
        self.persisted = true;
        Ok(())
    }

    /// Whether the pre-funding durable record has been written.
    pub fn is_persisted(&self) -> bool {
        self.persisted
    }

    /// Phase 3 — the point of no return.
    ///
    /// Refuses to touch the network unless [`Self::save_opening`] succeeded on this exact
    /// instance. That refusal *is* the fund-safety rule; there is no override.
    pub fn submit_funding_swap<N>(&mut self, networking: &N) -> Result<(), SpilmanError>
    where
        N: SpilmanClientNetworking,
    {
        ensure_persisted(self.persisted)?;
        let response = networking
            .call_mint_swap(&self.prepared.mint_url, &self.prepared.swap_request_json)
            .map_err(SpilmanError::Bridge)?;
        self.swap_response = Some(response);
        Ok(())
    }

    /// The mint's swap response, if the funding swap has landed.
    pub fn swap_response(&self) -> Option<&str> {
        self.swap_response.as_deref()
    }

    /// Phases 4–5: unblind the funding proofs and mark the channel open.
    ///
    /// After this returns `Ok`, the channel is payable and the funding proofs are
    /// durable. Anything less is an error and the channel stays `OpeningFromSwap`,
    /// which recovery can finish.
    pub fn finish_open<H, N>(
        &mut self,
        bridge: &SpilmanClientBridge<H, N>,
    ) -> Result<OpenChannelResult, SpilmanError>
    where
        H: SpilmanClientHost,
        N: SpilmanClientNetworking,
    {
        let response = self.swap_response.as_deref().ok_or_else(|| {
            SpilmanError::Bridge("no funding swap response to complete".to_string())
        })?;
        let completed = bridge
            .complete_prepared_open_channel(&self.prepared, response)
            .map_err(|e: OpenChannelError| SpilmanError::Bridge(e.to_string()))?;
        self.completed_funding_proofs = Some(completed.funding_proofs_json.clone());
        bridge
            .mark_completed_open(&completed)
            .map_err(|e: OpenChannelError| SpilmanError::Bridge(e.to_string()))?;
        Ok(completed.result)
    }

    /// The funding proofs recovered from the mint, for audit/recovery.
    pub fn funding_proofs_json(&self) -> Option<&str> {
        self.completed_funding_proofs.as_deref()
    }
}

/// One payment step: sign the new balance and record it locally.
///
/// Returns the signed [`Payment`] to hand to the payee over HTTP.
///
/// Takes **no** networking argument. That is the point of the whole integration: the
/// per-purchase path is a Schnorr signature plus a local store write, so it is
/// structurally incapable of a mint round trip rather than merely observed not to make
/// one.
pub fn step_payment<H, N>(
    bridge: &SpilmanClientBridge<H, N>,
    channel_id: &str,
    raw_balance: u64,
) -> Result<Payment, SpilmanError>
where
    H: SpilmanClientHost,
    N: SpilmanClientNetworking,
{
    bridge
        .sign_and_record_payment(channel_id, raw_balance)
        .map_err(SpilmanError::Bridge)
}

/// A signed close request bound to the expected seller receipt.
#[derive(Debug)]
pub struct CooperativeSettlement {
    payment: Payment,
}

/// Wire representation of upstream `CloseSuccess` (upstream only derives Serialize).
#[derive(Debug, serde::Deserialize)]
pub struct SettlementReceipt {
    pub channel_id: String,
    pub total_value: u64,
    pub receiver_sum: u64,
    pub sender_sum: u64,
    pub sender_proofs: String,
    pub already_closed: bool,
}

/// The channel facts a payer needs in order to check a close receipt's accounting.
///
/// Both inputs come from the channel the payer itself opened: the keyset info it funded
/// against (including `inputFeePpk`) and the `maximum_amount_for_one_output` rule from
/// the channel params. From those two, the expected **nominal** receiver sum is
/// derivable — the payer does not have to trust the seller's arithmetic, it recomputes
/// the same inverse the seller used.
#[derive(Debug, Clone)]
pub struct CloseAccounting {
    keyset_info_json: String,
    maximum_amount_for_one_output: u64,
}

impl CloseAccounting {
    pub fn new(keyset_info_json: impl Into<String>, maximum_amount_for_one_output: u64) -> Self {
        Self {
            keyset_info_json: keyset_info_json.into(),
            maximum_amount_for_one_output,
        }
    }

    /// Build from the channel's params JSON and the keyset info in the same record.
    ///
    /// A params blob without `maximum_amount_for_one_output` is a refusal, not a
    /// default: the fee-aware check is only meaningful with the channel's real rule.
    pub fn from_params_json(
        keyset_info_json: impl Into<String>,
        params_json: &str,
    ) -> Result<Self, SpilmanError> {
        let params: serde_json::Value = serde_json::from_str(params_json)
            .map_err(|e| SpilmanError::Bridge(format!("invalid channel params: {e}")))?;
        let max = params
            .get("maximum_amount_for_one_output")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                SpilmanError::Bridge(
                    "channel params carry no maximum_amount_for_one_output".to_string(),
                )
            })?;
        Ok(Self::new(keyset_info_json, max))
    }

    fn parsed(&self) -> Result<cdk_spilman::KeysetInfo, SpilmanError> {
        cdk_spilman::parse_keyset_info_from_json(&self.keyset_info_json)
            .map_err(|e| SpilmanError::Bridge(format!("invalid keyset info: {e}")))
    }

    /// `(nominal the seller must have committed to, net value of `receiver_sum` after fees)`.
    fn expected_and_net(
        &self,
        receiver_sum: u64,
        balance: u64,
    ) -> Result<(u64, u64), SpilmanError> {
        let keyset = self.parsed()?;
        let expected = keyset
            .inverse_deterministic_value_after_fees(balance, self.maximum_amount_for_one_output)
            .map_err(|e| SpilmanError::Bridge(format!("close accounting failed: {e}")))?
            .nominal_value;
        let net = keyset
            .deterministic_value_after_fees(receiver_sum, self.maximum_amount_for_one_output)
            .map_err(|e| SpilmanError::Bridge(format!("close accounting failed: {e}")))?;
        Ok((expected, net))
    }
}

impl CooperativeSettlement {
    pub fn prepare<H: SpilmanClientHost, N: SpilmanClientNetworking>(
        bridge: &SpilmanClientBridge<H, N>,
        channel_id: &str,
        final_balance: u64,
    ) -> Result<Self, SpilmanError> {
        bridge
            .sign_cooperative_close_request(channel_id, final_balance)
            .map(|payment| Self { payment })
            .map_err(SpilmanError::Bridge)
    }

    /// Reuse the exact accepted authorization: Schnorr signatures are randomized.
    /// Re-sign first to enforce local ownership, but send the persisted payment.
    pub fn from_accepted_payment<H: SpilmanClientHost, N: SpilmanClientNetworking>(
        bridge: &SpilmanClientBridge<H, N>,
        payment: &Payment,
    ) -> Result<Self, SpilmanError> {
        let mut settlement = Self::prepare(bridge, &payment.channel_id, payment.balance)?;
        settlement.payment.signature = payment.signature.clone();
        Ok(settlement)
    }

    pub fn payment(&self) -> &Payment {
        &self.payment
    }

    /// Accept only a complete, matching successful seller close receipt, then mark
    /// the payer closed. The seller is responsible for mint execution; this is
    /// structural/accounting validation, not independent mint attestation.
    ///
    /// # Why the receipt's `receiver_sum` is not compared to `payment.balance`
    ///
    /// `receiver_sum` is the **nominal** value of the receiver's outputs — what the
    /// seller committed to *before* the mint takes its input fee. On any mint with
    /// `input_fee_ppk > 0` it is strictly larger than the signed balance (at 400 ppk and
    /// a 1-sat balance it is 2). Comparing the two directly rejected a perfectly good
    /// close *after* the money had already moved: the mint settled, the seller marked
    /// the channel closed, and the payer reported "close receipt does not match signed
    /// settlement". The receipt is checked against the same inverse the seller uses to
    /// build its outputs (`inverse_deterministic_value_after_fees`), and the net value of
    /// the receiver proofs after fees must still cover what the payer signed.
    pub fn complete<H: SpilmanClientHost, N: SpilmanClientNetworking>(
        &self,
        bridge: &SpilmanClientBridge<H, N>,
        response_json: &str,
        accounting: &CloseAccounting,
    ) -> Result<SettlementReceipt, SpilmanError> {
        let receipt: SettlementReceipt = serde_json::from_str(response_json)
            .map_err(|e| SpilmanError::Bridge(format!("invalid close receipt: {e}")))?;
        let proofs: Vec<cashu::nuts::Proof> = serde_json::from_str(&receipt.sender_proofs)
            .map_err(|e| SpilmanError::Bridge(format!("invalid sender proofs: {e}")))?;
        let sender_sum = proofs
            .iter()
            .try_fold(0u64, |sum, proof| sum.checked_add(proof.amount.to_u64()));
        let (expected_nominal, receiver_net) =
            accounting.expected_and_net(receipt.receiver_sum, self.payment.balance)?;
        if receipt.channel_id != self.payment.channel_id
            || receipt.receiver_sum != expected_nominal
            // The fee-adjusted value of what the receiver got must still cover the
            // balance the payer signed: a receipt cannot settle for less.
            || receiver_net < self.payment.balance
            || receipt.receiver_sum.checked_add(receipt.sender_sum) != Some(receipt.total_value)
            || sender_sum != Some(receipt.sender_sum)
        {
            return Err(SpilmanError::Bridge(
                "close receipt does not match signed settlement".into(),
            ));
        }
        bridge
            .process_cooperative_close_response(response_json)
            .map_err(SpilmanError::Bridge)?;
        Ok(receipt)
    }
}

/// Open a second, independent connection to a payer store.
///
/// cdk-spilman implements `SpilmanClientHost` on the concrete
/// `ConfigurableClientHost<S>` only — no blanket `Arc<H>` impl — and `SpilmanClientBridge`
/// owns its host with no accessor. So "prove the record is durable" is done the way
/// durability actually means it: a *separate* SQLite connection to the same file sees the
/// committed row. The read-only flag makes the proof honest — this handle cannot have
/// written anything.
pub fn open_read_only_host(
    db_path: &str,
) -> Result<ConfigurableClientHost<SqliteClientStorage>, SpilmanError> {
    let storage = SqliteClientStorage::open_read_only(db_path).map_err(SpilmanError::Ledger)?;
    Ok(ConfigurableClientHost::new(storage))
}

/// Recover a channel stuck in `OpeningFromSwap` (crash after the funding swap).
///
/// Drives cdk-spilman's NUT-09 restore: re-derive the funding outputs from the stored
/// opening record, ask the mint for them, verify them, and mark the channel open. This is
/// the "re-open process state" path: it needs nothing but the durable store plus a mint
/// client, because the *original input* was persisted before the swap.
pub fn recover_open_channel<H, N>(
    bridge: &SpilmanClientBridge<H, N>,
    channel_id: &str,
) -> Result<OpenChannelResult, SpilmanError>
where
    H: SpilmanClientHost,
    N: SpilmanClientNetworking,
{
    bridge
        .recover_open_channel_from_swap(channel_id)
        .map_err(|e: OpenChannelError| SpilmanError::Bridge(e.to_string()))
}

/// Current wall-clock seconds since the Unix epoch.
pub fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The fund-safety gate: the funding swap may not leave the process until the
/// `OpeningFromSwap` record (with its original input) is durable.
///
/// Extracted so the rule is unit-testable without a live mint.
fn ensure_persisted(persisted: bool) -> Result<(), SpilmanError> {
    if persisted {
        return Ok(());
    }
    Err(SpilmanError::Bridge(
        "refusing to submit a funding swap before the OpeningFromSwap record is durable"
            .to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn funding_swap_is_refused_until_the_opening_record_is_durable() {
        let err = ensure_persisted(false).expect_err("must refuse");
        assert!(
            format!("{err}").contains("OpeningFromSwap"),
            "the refusal must name what is missing: {err}"
        );
        assert_eq!(ensure_persisted(true), Ok(()));
    }

    #[test]
    fn clock_is_sane() {
        // Guards against a build where SystemTime is broken and every expiry
        // computation silently becomes 0 (i.e. already expired).
        assert!(now_seconds() > 1_700_000_000);
    }

    #[test]
    // `DEFAULT_CHANNEL_LIFETIME_SECS` is a const, so this assertion is a compile-time
    // pin on the constant's value rather than a runtime check: it exists so a future
    // change to a shorter lifetime fails the suite instead of silently shrinking the
    // settlement window (gap analysis §6 hazard 5).
    #[allow(clippy::assertions_on_constants)]
    fn default_lifetime_outlives_any_session_by_a_wide_margin() {
        // §6 hazard 5: the payee must settle before expiry, and the payer must not
        // race it. A session is minutes; a day is three orders of magnitude of slack.
        assert!(DEFAULT_CHANNEL_LIFETIME_SECS >= 24 * 60 * 60);
    }

    /// A fee-bearing mint must not be mistaken for a mismatched receipt.
    ///
    /// This is the defect measured on the real binaries: at 400 ppk the seller's
    /// `receiver_sum` is the NOMINAL 2 for a 1-sat balance, and comparing it to the net
    /// balance rejected a close the mint had already executed. The accounting must
    /// derive the nominal from the channel's own keyset rule, and must still refuse a
    /// receipt whose proofs do not cover the signed balance after fees.
    #[test]
    fn fee_bearing_close_accounting_is_nominal_and_still_covers_the_balance() {
        let keyset_info_json = fee_bearing_keyset_info(400);
        let accounting = CloseAccounting::new(&keyset_info_json, 64);

        // balance 1 at 400 ppk: nominal 2, and 2 sat of outputs are worth 1 sat net.
        let (expected, net) = accounting.expected_and_net(2, 1).expect("accounting");
        assert_eq!(
            expected, 2,
            "nominal must be the pre-fee value, not the balance"
        );
        assert_eq!(
            net, 1,
            "the receiver's outputs must cover the signed balance"
        );

        // A receipt that carries the NET sum instead of the nominal one is refused…
        let (expected_net, _) = accounting.expected_and_net(1, 1).expect("accounting");
        assert_eq!(
            expected_net, 2,
            "the expected nominal does not depend on the receipt"
        );

        // …and the fee-free case is unchanged (nominal == balance).
        let free = CloseAccounting::new(fee_bearing_keyset_info(0), 64);
        assert_eq!(free.expected_and_net(1, 1).expect("accounting"), (1, 1));
    }

    /// A keyset info with `input_fee_ppk` and denominations 1..=64, ids derived from the
    /// keys exactly as the protocol does.
    #[cfg(test)]
    fn fee_bearing_keyset_info(input_fee_ppk: u64) -> String {
        let keys: std::collections::BTreeMap<String, cashu::nuts::PublicKey> = (0..7)
            .map(|i| {
                let amount = 1u64 << i;
                (
                    amount.to_string(),
                    cashu::nuts::SecretKey::generate().public_key(),
                )
            })
            .collect();
        serde_json::json!({
            "keysetId": cashu::nuts::Id::v1_from_keys(
                &cashu::nuts::Keys::new(
                    keys.iter()
                        .map(|(amount, key)| {
                            (cashu::Amount::from(amount.parse::<u64>().expect("amount")), *key)
                        })
                        .collect(),
                ),
            )
            .to_string(),
            "unit": "sat",
            "keys": keys,
            "inputFeePpk": input_fee_ppk,
        })
        .to_string()
    }
}
