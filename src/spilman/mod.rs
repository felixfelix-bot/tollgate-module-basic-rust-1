//! Spilman payment-channel rail (wholesale path).
//!
//! # Where this sits
//!
//! TollGate's retail path is `POST /` → `routes::pay::handle_pay` → `TollWallet::receive`
//! → a fresh CDK token per purchase. `handle_pay` stays exactly that. This module is the
//! *second*, wholesale rail: a router buys a channel from an upstream router once and then
//! pays per-megabyte by signing a balance update, with no mint round trip on the hot path.
//!
//! The seam is a trait + an `Option` on `AppState`, deliberately **not** a generic
//! `TollWallet`. `TollWallet` is a concrete struct holding per-mint CDK wallets
//! (`src/wallet/wallet.rs:62`), and making it generic would touch every retail call site
//! for a payment method that does not share retail's lifecycle at all.
//!
//! ```text
//! retail:  token --verify--> wallet.receive --> session
//! spilman: Payment{channel_id, balance, signature} --CAS ledger--> credit
//! ```
//!
//! # Money rules encoded here
//!
//! - Billing is exact integer arithmetic (`billing`, `pricing`); no floats.
//! - A msat bill becomes a sat channel balance by rounding **up** (`payment_units`).
//! - `record_payment` is a compare-and-swap against the exact previous balance and is
//!   durable **before** the caller may serve a byte (`ledger`). With
//!   `panic = "abort"` in release, every `Result` in this module is fatal-path code:
//!   the caller must handle it, never unwrap it.

pub mod billing;
pub mod ledger;
/// The **remote**-mint funding leg for the payer driver. Opt-in only: see the
/// module docs and the `payer-driver` feature in `Cargo.toml`. A normal build
/// must not contain a path that asks a mint for free money.
#[cfg(feature = "payer-driver")]
pub mod mint_http;
pub mod payee_host;

pub mod payer;
pub mod payer_driver;
pub mod payment_units;
pub mod pricing;
pub mod rail;
/// The payee's persisted receiver key. Public so `/spilman/params` can advertise it and
/// so the module's restart/durability properties are testable from outside.
pub mod receiver_key;
pub mod registration;

use async_trait::async_trait;

pub use ledger::{
    ChannelFundingRecord, ChannelLedger, FundingRegistration, LedgerOutcome, StoredPayment,
};
pub use payee_host::LedgerPayeeHost;
pub use pricing::{
    PricingModel, SessionPricing, StepPricing, DEFAULT_IN_BYTES_PER_MILLISAT,
    TOLLGATE_PARITY_IN_BYTES_PER_MILLISAT, TOLLGATE_PRICE_PER_STEP_MILLISATS,
    TOLLGATE_STEP_SIZE_BYTES,
};
pub use rail::SpilmanRail;
pub use registration::{validate_registration, ChannelRegistrationRequest};

/// Errors produced by the Spilman rail.
///
/// Every variant is a *refusal*, not a warning: the rail must fail closed, because the
/// alternatives are serving bytes for money it cannot prove, or double-crediting a
/// retried payment.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SpilmanError {
    #[error("billing error: {0}")]
    Billing(#[from] billing::PricingError),

    #[error("unsupported channel unit: {0}")]
    UnsupportedUnit(String),

    #[error("arithmetic overflow: {0}")]
    Overflow(String),

    #[error("spilman ledger error: {0}")]
    Ledger(String),

    #[error("io error at {path}: {detail}")]
    Io { path: String, detail: String },

    /// The offered balance does not strictly advance the stored one. Covers replay
    /// (equal), rollback (lower) and same-balance/different-signature retries.
    #[error(
        "balance {offered} does not advance channel {channel_id} (stored balance {stored}); refusing to credit it"
    )]
    BalanceNotAdvanced {
        channel_id: String,
        stored: u64,
        offered: u64,
    },

    #[error("spilman bridge error: {0}")]
    Bridge(String),

    /// A payment was offered for a channel this payee has no funding record for.
    ///
    /// Spilman payment authenticity is verified against the channel's funding
    /// params, funding proofs, channel secret and keyset info. Without that record
    /// there is **nothing to verify against**, so the payment cannot be accepted —
    /// see `CRITICAL-UNVERIFIED-PAYMENT.md`. This is a refusal, not an error in the
    /// request: the caller may open a channel first.
    #[error(
        "channel {channel_id} has no funding record; cannot verify the balance signature, refusing to credit it"
    )]
    UnknownChannel { channel_id: String },

    /// The offered balance did not verify against the channel's funding record.
    ///
    /// This is the refusal that `CRITICAL-UNVERIFIED-PAYMENT.md` was about: the
    /// signature was checked by upstream's own `SpilmanBridge::validate_payment`
    /// against the persisted funding params, funding proofs, channel secret and
    /// keyset info, and it did not hold — or the balance exceeded the channel's
    /// capacity, or the channel is closing/closed. `detail` carries upstream's
    /// reason so the refusal is diagnosable without a debugger.
    #[error(
        "channel {channel_id} payment of balance {balance} did not verify ({detail}); refusing to credit it"
    )]
    PaymentNotVerified {
        channel_id: String,
        balance: u64,
        detail: String,
    },

    /// A registration body this payee cannot turn into a usable funding record.
    ///
    /// Either the JSON is malformed or the pieces contradict each other (params
    /// that do not reconstruct, an id the bytes do not derive, a capacity that
    /// disagrees with the params). Nothing is written; refuse at the door rather
    /// than store a row that can never verify a payment.
    #[error("invalid channel registration for {channel_id}: {detail}")]
    InvalidRegistration { channel_id: String, detail: String },

    /// The channel id is already registered with **different** funding data.
    ///
    /// The stored record is untouched. A duplicate registration with identical
    /// data is not this error — it succeeds idempotently
    /// ([`FundingRegistration::AlreadyRegistered`]) — because the state the payer
    /// asked for is the state that already exists. This error is reserved for a
    /// genuine conflict, which is either two payers colliding on an id or someone
    /// trying to move the capacity ceiling / channel secret a signature is checked
    /// against.
    #[error(
        "channel {channel_id} is already registered with different funding data; refusing to overwrite it"
    )]
    ChannelAlreadyRegistered { channel_id: String },

    #[error("spilman config error: {0}")]
    Config(String),

    /// A failure on the payer's mint leg (quote, keys, or the funding swap).
    ///
    /// Separate from [`SpilmanError::Config`] because the cause is the *mint*, not
    /// this router's configuration: "the quote was never paid" and "the operator
    /// left `channel_db_path` unset" want different fixes, and collapsing them
    /// into one string is how a bench failure gets misdiagnosed as a config typo.
    /// Only constructed by the `payer-driver` feature; the variant exists
    /// unconditionally so the enum has one shape in every build.
    #[error("spilman mint error: {0}")]
    Mint(String),
}

/// What a rail decides about serving the next bytes of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RailDecision {
    /// This rail declines to decide; the caller keeps its existing behaviour.
    ///
    /// This is what the default (disabled) rail returns, which is how "zero behavioural
    /// change when Spilman is off" is enforced structurally rather than by a flag check
    /// at every call site.
    Abstain,
    /// Credit covers the request; serve it.
    Allow,
    /// Credit does not cover the request; the client must pay first.
    Deny,
}

/// A payment rail the HTTP layer can consult without knowing its mechanism.
///
/// Async because a real rail may need to flush a durable write; the no-op rail is
/// async-identical so callers never branch on the implementor.
// `async_trait`'s expansion re-applies `#[must_use]` to the desugared methods,
// which already return `#[must_use]` types. It is generated code, not ours, so the
// lint is allowed here rather than restructured around.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait PaymentRail: Send + Sync + std::fmt::Debug {
    /// Stable name for logs and `/spilman/params`-style diagnostics.
    fn name(&self) -> &'static str;

    /// Decide whether `bytes_in` + `bytes_out` (cumulative for the channel) are covered
    /// by credit the payee has already recorded.
    async fn authorize_bytes(
        &self,
        channel_id: &str,
        bytes_in: u64,
        bytes_out: u64,
    ) -> RailDecision;

    /// Durably record a signed balance update before any bytes are served.
    async fn record_payment(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
    ) -> Result<LedgerOutcome, SpilmanError>;
}

/// The default rail: present, inert, and honest about it.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopRail;

#[async_trait]
impl PaymentRail for NoopRail {
    fn name(&self) -> &'static str {
        "noop"
    }

    async fn authorize_bytes(
        &self,
        _channel_id: &str,
        _bytes_in: u64,
        _bytes_out: u64,
    ) -> RailDecision {
        RailDecision::Abstain
    }

    async fn record_payment(
        &self,
        _channel_id: &str,
        _balance: u64,
        _signature: &str,
    ) -> Result<LedgerOutcome, SpilmanError> {
        Err(SpilmanError::Config(
            "spilman rail is disabled; refusing to record a channel payment".to_string(),
        ))
    }
}
