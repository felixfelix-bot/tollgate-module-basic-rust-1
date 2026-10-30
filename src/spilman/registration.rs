//! Payee-side channel **registration** — turning a payer's opened channel into a
//! durable funding record this payee can verify later payments against.
//!
//! # The gap this closes
//!
//! Phase 4 gave the payee a working verifier: `SpilmanRail::record_payment`
//! reconstructs the channel from the persisted funding record and hands it to
//! upstream's `SpilmanBridge::validate_payment`. But nothing outside the process
//! could *write* that record — the funding record only ever got created by
//! in-process code in the integration tests. So a payer standing up a channel had
//! no way to tell a **running** module about it, and the physical-router channel
//! E2E could not exercise the protocol at all.
//!
//! # What registration is, and what it is not
//!
//! Registration persists the five values upstream's verifier needs
//! (`params_json`, `funding_proofs_json`, `channel_secret_hex`,
//! `keyset_info_json`, `capacity`) and **nothing else**. It credits nothing. It
//! is the payee writing down "here is the channel I will check signatures
//! against".
//!
//! Credit is granted only by [`crate::spilman::SpilmanRail::record_payment`],
//! which verifies a BIP-340 signature over `(channel_id, balance)` against that
//! record *before* the durable CAS write. That ordering is why a forged
//! registration cannot mint credit by itself: a wrong record makes verification
//! **fail**, not pass. See `REPORT.md` for the caveat that remains — the record is
//! only as trustworthy as the mint and keyset it names, and there is no policy
//! here yet that says which those are.
//!
//! # Why the wire names match the ledger's
//!
//! There is exactly one name for each field, from the payer's HTTP body through to
//! the SQLite column. A translation layer between them would be a second place for
//! a byte to change, and the whole point of the round-trip guarantee in
//! [`crate::spilman::ledger::ChannelFundingRecord`] is that no byte does.

use cashu::nuts::SecretKey;
use cdk_spilman::{parse_keyset_info_from_json, ChannelParameters, Payment};

use crate::spilman::ledger::ChannelFundingRecord;
use crate::spilman::SpilmanError;

/// What a payer POSTs to `/spilman/channel` to register an opened channel.
///
/// Field names and semantics are the ledger's own (see
/// [`crate::spilman::ledger::ChannelFundingRecord`]); `created_at` is the only
/// field not present, because it is the **payee's** clock and letting a client set
/// it would let a client rewrite their own audit trail.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ChannelRegistrationRequest {
    pub channel_id: String,
    /// Serialized channel parameters, verbatim as the payer built them.
    pub params_json: String,
    /// Serialized funding proofs, verbatim.
    pub funding_proofs_json: String,
    /// Hex-encoded ECDH channel secret.
    pub channel_secret_hex: String,
    /// Serialized keyset info for the channel's keyset, verbatim.
    pub keyset_info_json: String,
    /// Largest balance the payer may sign for this channel.
    pub capacity: u64,
}

impl ChannelRegistrationRequest {
    /// Build the registration payload from a payer's signed channel registration.
    ///
    /// Used by the payer driver (`tests/spilman_payer_driver.rs`) after
    /// `finish_open`, so the bytes that reach the payee are exactly the bytes
    /// cdk-spilman's client bridge produced — no re-serialisation of the params or
    /// proofs happens anywhere on the way.
    pub fn from_registration(registration: &Payment) -> Result<Self, SpilmanError> {
        let params_json = match &registration.params {
            Some(params) => params.to_string(),
            None => {
                return Err(invalid(
                    "<none>",
                    "registration carries no channel params — is the channel funded?",
                ))
            }
        };
        let funding_proofs_json = match &registration.funding_proofs {
            Some(proofs) => serde_json::to_string(proofs)
                .map_err(|e| invalid("<none>", &format!("cannot serialize funding proofs: {e}")))?,
            None => {
                return Err(invalid(
                    "<none>",
                    "registration carries no funding proofs — is the channel funded?",
                ))
            }
        };
        let capacity = serde_json::from_str::<serde_json::Value>(&params_json)
            .ok()
            .and_then(|value| value.get("capacity").and_then(serde_json::Value::as_u64))
            .ok_or_else(|| invalid("<none>", "channel params carry no capacity"))?;

        // The channel secret is not part of `Payment`; it is the ECDH secret only the
        // payer and this payee can derive (payer: their secret + payee's pubkey).
        let channel_secret_hex = String::new();
        Ok(Self {
            channel_id: registration.channel_id.clone(),
            params_json,
            funding_proofs_json,
            channel_secret_hex,
            keyset_info_json: String::new(),
            capacity,
        })
    }

    /// Attach the channel secret and keyset info the payer derived at open time.
    ///
    /// Split out from [`Self::from_registration`] on purpose: `Payment` does not
    /// carry either value, and deriving them needs a secret the payee should hand
    /// over explicitly rather than have a driver guess. `my_secret` is the payer's
    /// channel key; `their_pubkey_hex` is the payee's published one.
    pub fn with_channel_secret(
        mut self,
        my_secret: &SecretKey,
        their_pubkey_hex: &str,
    ) -> Result<Self, SpilmanError> {
        let their_pubkey: cashu::nuts::PublicKey = their_pubkey_hex.parse().map_err(|e| {
            invalid(
                &self.channel_id,
                &format!("payee pubkey is not a valid public key: {e}"),
            )
        })?;
        self.channel_secret_hex = hex::encode(cdk_spilman::compute_channel_secret(
            my_secret,
            &their_pubkey,
        ));
        Ok(self)
    }

    /// Attach the serialized keyset info for the channel's keyset.
    pub fn with_keyset_info_json(mut self, keyset_info_json: impl Into<String>) -> Self {
        self.keyset_info_json = Into::into(keyset_info_json);
        self
    }
}

/// Refuse a registration with a reason that names the channel it came from.
fn invalid(channel_id: &str, detail: &str) -> SpilmanError {
    SpilmanError::InvalidRegistration {
        channel_id: channel_id.to_string(),
        detail: detail.to_string(),
    }
}

/// Decode the channel secret: `hex` into the fixed 32-byte scalar the protocol uses.
///
/// A wrong-length secret is a refusal, not a panic — this is on the path from an
/// untrusted HTTP body, and `panic = "abort"` is set in release.
fn decode_channel_secret(
    channel_id: &str,
    channel_secret_hex: &str,
) -> Result<[u8; 32], SpilmanError> {
    let bytes = hex::decode(channel_secret_hex)
        .map_err(|e| invalid(channel_id, &format!("channel_secret_hex is not hex: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| invalid(channel_id, "channel_secret_hex must be exactly 32 bytes"))
}

/// Validate a registration and turn it into the record the ledger stores.
///
/// # What is checked, with upstream's own code
///
/// - **The keyset info parses** — `parse_keyset_info_from_json`.
/// - **The params reconstruct into a channel** —
///   `ChannelParameters::from_json_with_channel_secret` is upstream's own
///   definition of "these bytes *are* this channel". It is what payment
///   verification will re-run on every payment, so refusing here means the payee
///   never stores a record it cannot use.
/// - **The channel id binds** — the id derived from params + secret + keyset must
///   equal the id the payer claims. A record whose bytes derive a different id
///   would be an unverifiable row that silently shadows a real channel.
/// - **The capacity agrees** — the `capacity` field must equal the capacity inside
///   the params. They are stored separately (the verifier reads the params; the
///   ledger keeps the ceiling for its own accounting), so a disagreement is
///   either a corrupt record or a payer trying to write two different ceilings.
/// - **The unit is the one this rail prices** — `RAIL_UNIT`. A channel denominated
///   in anything else would have its balance misread as sats by
///   `authorize_bytes`, which is a credit bug, so it is refused at the door.
/// - **The funding proofs are well-formed JSON** — an array. Their *contents* are
///   verified by upstream at payment time; asserting their shape here only stops
///   obviously corrupt bodies from becoming durable.
///
/// # What is deliberately NOT checked here
///
/// The full funding-proof check ([`cdk_spilman::verify_valid_channel`],
/// internally `verify_valid_channel`) proves the proofs are self-consistent with
/// the keyset **the record itself carries** — which is precisely the part an
/// attacker chooses when they register a channel they minted for themselves. It is
/// therefore a check that always passes for the attacker and cannot be the control
/// that makes registration safe; that control is a trusted *(mint, keyset)* policy,
/// which this payee has no registry for. Inventorying it here and reporting it in
/// `REPORT.md` beats silently picking a policy the module cannot honestly answer.
pub fn validate_registration(
    req: &ChannelRegistrationRequest,
) -> Result<ChannelFundingRecord, SpilmanError> {
    let channel_id = req.channel_id.trim();
    if channel_id.is_empty() {
        return Err(invalid(&req.channel_id, "channel_id is empty"));
    }

    let keyset_info = parse_keyset_info_from_json(&req.keyset_info_json)
        .map_err(|e| invalid(channel_id, &format!("keyset_info_json: {e}")))?;

    let secret = decode_channel_secret(channel_id, &req.channel_secret_hex)?;

    let params =
        ChannelParameters::from_json_with_channel_secret(&req.params_json, keyset_info, secret)
            .map_err(|e| invalid(channel_id, &format!("params_json: {e}")))?;

    // The id is *derived* from the record, never taken from the request: this is
    // the check that stops one channel's bytes from registering under another's id.
    let derived = params.get_channel_id();
    if derived != channel_id {
        return Err(invalid(
            channel_id,
            &format!("params + secret + keyset derive channel id {derived}, not this one"),
        ));
    }

    let params_capacity = params.get_capacity();
    if params_capacity != req.capacity {
        return Err(invalid(
            channel_id,
            &format!(
                "capacity {capacity} disagrees with the capacity in params_json ({params_capacity})",
                capacity = req.capacity
            ),
        ));
    }

    // Only the unit this rail knows how to price may be registered. The rail's
    // conversion is `raw_units_to_msats(RAIL_UNIT, ..)`; anything else would be
    // arithmetically valid and economically wrong.
    if params.unit.to_string() != crate::spilman::rail::RAIL_UNIT {
        return Err(invalid(
            channel_id,
            &format!(
                "unit {} is not supported by this rail (only {})",
                params.unit,
                crate::spilman::rail::RAIL_UNIT
            ),
        ));
    }

    // Structural only: must be a JSON array of proofs. Their cryptographic
    // validity is decided by upstream's validator when a payment is recorded.
    serde_json::from_str::<Vec<serde_json::Value>>(&req.funding_proofs_json).map_err(|e| {
        invalid(
            channel_id,
            &format!("funding_proofs_json is not a JSON array: {e}"),
        )
    })?;

    Ok(ChannelFundingRecord {
        channel_id: channel_id.to_string(),
        params_json: req.params_json.clone(),
        funding_proofs_json: req.funding_proofs_json.clone(),
        channel_secret_hex: req.channel_secret_hex.clone(),
        keyset_info_json: req.keyset_info_json.clone(),
        capacity: req.capacity,
        created_at: crate::spilman::payer::now_seconds(),
    })
}

// Registration is only reachable through the rail, which is where the "decisions,
// not the handlers" rule puts it. These unit tests stay cheap (no mint) because
// the checks above are structural.
#[cfg(test)]
pub(crate) mod test_support {
    //! A self-consistent registration body for tests that need one.
    //!
    //! Shared by this module's unit tests, `src/http/spilman_mount_test.rs` and
    //! `tests/spilman_registration.rs`, so there is exactly one definition of
    //! "a body that *should* be accepted". A second, hand-copied fixture is how a
    //! suite ends up asserting against JSON the real producer would never emit.

    use super::*;
    use cashu::nuts::Id;

    /// Build a registration whose params, secret and keyset are mutually
    /// consistent — i.e. one `validate_registration` accepts.
    ///
    /// `override_id` keeps the caller's id verbatim, which is how the "id does not
    /// bind to the params" refusal is built; `None` derives the real id from the
    /// bytes so the body is self-consistent.
    pub fn consistent_registration(
        capacity: u64,
        override_id: Option<String>,
    ) -> ChannelRegistrationRequest {
        consistent_registration_for(&SecretKey::generate(), capacity, override_id)
    }

    /// The same body, addressed to a **caller-chosen** receiver key.
    ///
    /// Needed because registration now *refuses* a channel addressed to a key the payee
    /// does not hold: a fixture that generated its own receiver could only ever build a
    /// body the payee must reject. Tests that expect acceptance must therefore choose the
    /// key the rail holds.
    pub fn consistent_registration_for(
        receiver: &SecretKey,
        capacity: u64,
        override_id: Option<String>,
    ) -> ChannelRegistrationRequest {
        consistent_registration_addressed_to(
            receiver,
            "https://mint.example",
            capacity,
            override_id,
        )
    }

    /// The same body, addressed to `receiver` **and funded at `mint`**.
    ///
    /// `mint` is part of the channel id's derivation, so a test that changes it must
    /// rebuild the body rather than string-patch it — otherwise the id no longer binds
    /// and the refusal under test is replaced by "id does not bind to the params".
    pub fn consistent_registration_addressed_to(
        receiver: &SecretKey,
        mint: &str,
        capacity: u64,
        override_id: Option<String>,
    ) -> ChannelRegistrationRequest {
        let sender = SecretKey::generate();
        let receiver = receiver.clone();
        let secret = cdk_spilman::compute_channel_secret(&receiver, &sender.public_key());

        // A v1 keyset id: 8 bytes, hex. Mint keys are arbitrary here because
        // `from_json_with_channel_secret` only checks that params and keyset agree.
        let keys = cashu::nuts::Keys::new(
            [(
                cashu::Amount::from(1u64),
                SecretKey::generate().public_key(),
            )]
            .into_iter()
            .collect(),
        );
        let keyset_id = Id::v1_from_keys(&keys);
        let input_fee_ppk = 0u64;
        let funding_token_amount = capacity * 2;

        let params_json = serde_json::json!({
            "mint": mint,
            "unit": "sat",
            "capacity": capacity,
            "funding_token_amount": funding_token_amount,
            "maximum_amount_for_one_output": 64,
            "setup_timestamp": 1_700_000_000u64,
            "sender_pubkey": sender.public_key().to_hex(),
            "receiver_pubkey": receiver.public_key().to_hex(),
            "expiry_timestamp": 1_700_000_000u64 + 86_400,
            "keyset_id": keyset_id.to_string(),
            "input_fee_ppk": input_fee_ppk,
        })
        .to_string();

        let keyset_info_json = serde_json::json!({
            "keysetId": keyset_id.to_string(),
            "unit": "sat",
            "inputFeePpk": input_fee_ppk,
            "keys": keys.iter()
                .map(|(amount, key)| (amount.to_string(), key.to_hex()))
                .collect::<std::collections::BTreeMap<String, String>>(),
        })
        .to_string();

        let mut req = ChannelRegistrationRequest {
            channel_id: String::new(),
            params_json,
            funding_proofs_json: "[]".to_string(),
            channel_secret_hex: hex::encode(secret),
            keyset_info_json,
            capacity,
        };

        req.channel_id = match override_id {
            Some(id) => id,
            None => ChannelParameters::from_json_with_channel_secret(
                &req.params_json,
                parse_keyset_info_from_json(&req.keyset_info_json).expect("keyset parses"),
                secret,
            )
            .expect("params reconstruct")
            .get_channel_id(),
        };
        req
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::consistent_registration;
    use super::*;
    use cashu::nuts::CurrencyUnit;

    fn consistent_request(override_id: Option<String>) -> ChannelRegistrationRequest {
        consistent_registration(64, override_id)
    }

    #[test]
    fn a_self_consistent_registration_is_accepted() {
        let req = consistent_request(None);
        let record = validate_registration(&req).expect("a consistent registration must validate");
        assert_eq!(record.channel_id, req.channel_id);
        assert_eq!(record.params_json, req.params_json);
        assert_eq!(record.funding_proofs_json, req.funding_proofs_json);
        assert_eq!(record.channel_secret_hex, req.channel_secret_hex);
        assert_eq!(record.keyset_info_json, req.keyset_info_json);
        assert_eq!(record.capacity, req.capacity);
    }

    #[test]
    fn an_empty_channel_id_is_refused() {
        let req = ChannelRegistrationRequest {
            channel_id: "   ".to_string(),
            ..consistent_request(None)
        };
        assert!(matches!(
            validate_registration(&req),
            Err(SpilmanError::InvalidRegistration { .. })
        ));
    }

    #[test]
    fn an_id_that_does_not_bound_to_the_params_is_refused() {
        // Params from one channel, id of another: proof that the id is *derived*.
        let req = consistent_request(Some("deadbeef".repeat(8)));
        let stored = validate_registration(&req).expect_err("mismatched id must be refused");
        assert!(matches!(stored, SpilmanError::InvalidRegistration { .. }));
    }

    #[test]
    fn a_capacity_that_disagrees_with_the_params_is_refused() {
        let req = ChannelRegistrationRequest {
            capacity: 999_999,
            ..consistent_request(None)
        };
        let err = validate_registration(&req).expect_err("capacity disagreement must be refused");
        assert!(matches!(err, SpilmanError::InvalidRegistration { .. }));
    }

    #[test]
    fn a_bad_secret_is_refused() {
        let req = ChannelRegistrationRequest {
            channel_secret_hex: "zz".to_string(),
            ..consistent_request(None)
        };
        assert!(matches!(
            validate_registration(&req),
            Err(SpilmanError::InvalidRegistration { .. })
        ));
    }

    #[test]
    fn a_short_secret_is_refused() {
        let req = ChannelRegistrationRequest {
            channel_secret_hex: "00".to_string(),
            ..consistent_request(None)
        };
        assert!(matches!(
            validate_registration(&req),
            Err(SpilmanError::InvalidRegistration { .. })
        ));
    }

    #[test]
    fn proofs_that_are_not_an_array_are_refused() {
        let req = ChannelRegistrationRequest {
            funding_proofs_json: "{\"not\":\"an array\"}".to_string(),
            ..consistent_request(None)
        };
        assert!(matches!(
            validate_registration(&req),
            Err(SpilmanError::InvalidRegistration { .. })
        ));
    }

    #[test]
    fn a_badly_formed_keyset_is_refused() {
        let req = ChannelRegistrationRequest {
            keyset_info_json: "{}".to_string(),
            ..consistent_request(None)
        };
        assert!(matches!(
            validate_registration(&req),
            Err(SpilmanError::InvalidRegistration { .. })
        ));
    }

    #[test]
    fn the_rail_unit_is_the_accepted_boundary() {
        // Documents the constant this check compares against, so a change to
        // RAIL_UNIT fails the suite rather than silently re-pricing channels.
        assert_eq!(
            crate::spilman::rail::RAIL_UNIT,
            CurrencyUnit::Sat.to_string()
        );
    }
}
