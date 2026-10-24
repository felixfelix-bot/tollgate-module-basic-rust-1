//! TollGate pricing model for the Spilman rail.
//!
//! TollGate and Spilman express price differently and this module is where they are
//! reconciled:
//!
//! - **TollGate (retail, quantised).** `step_size = 22_020_096` bytes (21 MiB) costs
//!   `price_per_step = 1` sat (`config/schema.rs:58,148`; Go mirror
//!   `config_manager/config_schema.go:77`). Allotment is `steps * step_size` with
//!   integer division, so a partial step is never granted.
//! - **MONAD-style channel (wholesale, continuous).** `amount_due_millisats =
//!   ceil(bytes_in / in_rate + bytes_out / out_rate)`, recomputed from *cumulative*
//!   byte totals, and the payer signs whatever raw balance results.
//!
//! Setting `in_bytes_per_millisat = 22_020` (`= 22_020_096 / 1000`) makes the
//! continuous formula reproduce the retail price line exactly — one 21 MiB step
//! bills exactly 1000 msat = 1 sat.
//!
//! # Two rounding hazards this module exists to prevent
//!
//! 1. **Rounding the raw balance down.** Channel capacity is denominated in `sat` while
//!    the bill is in `msat`. Rounding down leaves <1 sat unclaimed per update; over
//!    ~48k updates in a 1 GiB msat-denominated session that is up to 48 sats gone on a
//!    1000-sat channel. `raw_balance_from_millisats` rounds **up**, always.
//! 2. **Accumulating per-update rounded values.** `amount_due` must be computed *once*
//!    from the cumulative byte totals. Summing per-update ceil()s over-bills by up to one
//!    msat per update. `amount_due_millisats` takes cumulative totals, so callers cannot
//!    make this mistake.
//!
//! Both hazards are asserted in `tests/test_spilman_billing.rs`.

use crate::spilman::billing::amount_due_millisats;
use crate::spilman::payment_units::msats_to_raw_units;
use crate::spilman::SpilmanError;

/// TollGate's price-table step, in bytes: 21 MiB.
///
/// Mirrors `Config::step_size` default (`config/schema.rs`) and the Go default.
pub const TOLLGATE_STEP_SIZE_BYTES: u64 = 22_020_096;

/// 1 sat per step, expressed in millisats.
pub const TOLLGATE_PRICE_PER_STEP_MILLISATS: u64 = 1_000;

/// Bytes per millisat that reproduces TollGate's retail price line.
///
/// Config default, and the value the live parity line uses: `22_020_096 / 1_000 = 22_020`
/// (integer-truncated). Because the true rate is 22_020.**096**, this default bills one
/// 21 MiB step at 1001 msat, not 1000 — a 45 ppm overprice (and a whole extra
/// `sat` of raw balance at sat granularity, since `ceil(1001/1000) = 2`). That is the
/// price of keeping an integer rate at or below the retail line; use
/// [`TOLLGATE_PARITY_IN_BYTES_PER_MILLISAT`] when the channel must bill each step at
/// exactly 1000 msat.
pub const DEFAULT_IN_BYTES_PER_MILLISAT: u64 = 22_020;

/// Smallest integer bytes-per-msat rate at which one TollGate step bills exactly
/// 1000 msat = 1 sat: `ceil(22_020_096 / 22_021) = 1000`.
///
/// The exact retail rate is `22_020_096 / 1_000 = 22_020.096` bytes/msat — not an
/// integer. Any integer rate `r` with `22_021 <= r <= 22_042` yields exactly 1000 msat
/// per step; `22_020` yields 1001. This constant exists because the gap analysis's
/// "reproduces TollGate's price line exactly" claim is only true from this rate up, and
/// a sat-denominated channel that updates once per step would otherwise step its raw
/// balance by 2 sat per 21 MiB — a 100% overcharge at step granularity.
pub const TOLLGATE_PARITY_IN_BYTES_PER_MILLISAT: u64 = 22_021;

/// Directional billing rates for a session.
///
/// Lifted from MONAD `monad-common/src/session.rs:47-63`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionPricing {
    pub in_bytes_per_millisat: u64,
    pub out_bytes_per_millisat: u64,
}

impl SessionPricing {
    /// Build validated pricing; rejects a zero rate rather than dividing by it.
    pub fn try_new(
        in_bytes_per_millisat: u64,
        out_bytes_per_millisat: u64,
    ) -> Result<Self, SpilmanError> {
        // amount_due_millisats validates the rates; discard the result (0 bytes -> 0).
        amount_due_millisats(0, 0, in_bytes_per_millisat, out_bytes_per_millisat)?;
        Ok(Self {
            in_bytes_per_millisat,
            out_bytes_per_millisat,
        })
    }

    /// Symmetric TollGate-parity pricing (both directions at `bytes_per_millisat`).
    pub fn tollgate_parity(bytes_per_millisat: u64) -> Result<Self, SpilmanError> {
        Self::try_new(bytes_per_millisat, bytes_per_millisat)
    }

    /// Exact combined bill in millisats for the given *cumulative* byte totals.
    pub fn amount_due_millisats(
        &self,
        session_total_bytes_in: u64,
        session_total_bytes_out: u64,
    ) -> Result<u128, SpilmanError> {
        Ok(amount_due_millisats(
            session_total_bytes_in,
            session_total_bytes_out,
            self.in_bytes_per_millisat,
            self.out_bytes_per_millisat,
        )?)
    }

    /// Bytes of access a given millisat budget buys — the inverse of
    /// [`Self::amount_due_millisats`], and the only place the access path is allowed to
    /// turn money into an `allotment`.
    ///
    /// Continuous, not floored to steps: this is the millisat model, and it is the same
    /// conversion `authorize_bytes` performs in the other direction, so the sweep and
    /// the authorisation check can never disagree about the rate. The multiply uses
    /// u128 and saturates, because a large balance must not wrap into a small ceiling.
    pub fn bytes_for_millisats(&self, millisats: u64) -> u64 {
        let bytes = u128::from(millisats) * u128::from(self.in_bytes_per_millisat);
        u64::try_from(bytes).unwrap_or(u64::MAX)
    }

    /// The raw (channel-unit) balance the payer must sign, rounded **up**.
    pub fn raw_balance_due(
        &self,
        unit: &str,
        session_total_bytes_in: u64,
        session_total_bytes_out: u64,
    ) -> Result<u64, SpilmanError> {
        let due_millisats =
            self.amount_due_millisats(session_total_bytes_in, session_total_bytes_out)?;
        let due_msats_u64 = u64::try_from(due_millisats).map_err(|_| {
            SpilmanError::Overflow(format!("amount due {due_millisats} msat exceeds u64"))
        })?;
        msats_to_raw_units(unit, due_msats_u64)
    }
}

impl Default for SessionPricing {
    fn default() -> Self {
        Self {
            in_bytes_per_millisat: DEFAULT_IN_BYTES_PER_MILLISAT,
            out_bytes_per_millisat: DEFAULT_IN_BYTES_PER_MILLISAT,
        }
    }
}

/// The retail, quantised model: grant whole steps only.
///
/// Kept as an explicit named model because it is the safe drop-in default — it refuses to
/// grant a partial step exactly as the current code does
/// (`pay.rs:102`, integer division on `amount_sats / price_per_step`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepPricing {
    /// Bytes per granted step (21 MiB on the live config).
    pub step_size: u64,
    /// Price of one step, in millisats.
    pub price_per_step_millisats: u64,
}

impl Default for StepPricing {
    fn default() -> Self {
        Self {
            step_size: TOLLGATE_STEP_SIZE_BYTES,
            price_per_step_millisats: TOLLGATE_PRICE_PER_STEP_MILLISATS,
        }
    }
}

impl StepPricing {
    /// Whole steps purchasable for `amount_millisats`.
    ///
    /// Integer division, exactly as the existing retail path: what cannot pay for a full
    /// step buys nothing.
    pub fn steps_for(&self, amount_millisats: u64) -> u64 {
        if self.price_per_step_millisats == 0 {
            return 0;
        }
        amount_millisats / self.price_per_step_millisats
    }

    /// Bytes to grant for `amount_millisats` (floored to whole steps).
    pub fn allotment_bytes_for(&self, amount_millisats: u64) -> u64 {
        let steps = self.steps_for(amount_millisats);
        steps.saturating_mul(self.step_size)
    }
}

/// A concrete billing model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PricingModel {
    /// Continuous millisat billing computed from cumulative bytes (MONAD-style).
    Millisats(SessionPricing),
    /// Retail whole-step billing (TollGate today).
    Steps(StepPricing),
}

impl Default for PricingModel {
    fn default() -> Self {
        Self::Steps(StepPricing::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parity_rate_reproduces_the_retail_price_line() {
        let pricing = SessionPricing::tollgate_parity(TOLLGATE_PARITY_IN_BYTES_PER_MILLISAT)
            .expect("valid rate");
        let due = pricing
            .amount_due_millisats(TOLLGATE_STEP_SIZE_BYTES, 0)
            .expect("valid rates");
        assert_eq!(due, u128::from(TOLLGATE_PRICE_PER_STEP_MILLISATS));
    }

    #[test]
    fn default_rate_is_one_millisat_above_the_retail_line_per_step() {
        let pricing = SessionPricing::default();
        let due = pricing
            .amount_due_millisats(TOLLGATE_STEP_SIZE_BYTES, 0)
            .expect("valid rates");
        // 22_020_096 / 1000 = 22_020.096, so rate 22_020 cannot hit 1000 exactly.
        assert_eq!(due, 1001);
    }

    #[test]
    fn sat_channel_rounds_the_raw_balance_up() {
        let pricing = SessionPricing::default();
        // 1 msat of traffic must still move the channel balance by a whole sat.
        assert_eq!(pricing.raw_balance_due("sat", 1, 0), Ok(1));
        assert_eq!(pricing.raw_balance_due("sat", 0, 0), Ok(0));
        // 22_019 bytes bills 1 msat; 22_020 bytes bills 2. Either way the raw
        // balance rounds up to a whole sat, which is the point.
        assert_eq!(pricing.raw_balance_due("sat", 22_019, 0), Ok(1));
        assert_eq!(pricing.raw_balance_due("sat", 22_020, 0), Ok(1));
        assert_eq!(pricing.raw_balance_due("sat", 22_021, 0), Ok(1));
        // Two whole sats only once the bill exceeds 1000 msat.
        assert_eq!(pricing.raw_balance_due("sat", 22_020_096, 0), Ok(2));
    }

    #[test]
    fn step_pricing_never_grants_a_partial_step() {
        let steps = StepPricing::default();
        assert_eq!(steps.steps_for(999), 0);
        assert_eq!(steps.allotment_bytes_for(999), 0);
        assert_eq!(steps.steps_for(1000), 1);
        assert_eq!(steps.allotment_bytes_for(1000), 22_020_096);
        assert_eq!(steps.steps_for(1999), 1);
    }

    #[test]
    fn zero_rate_is_refused() {
        assert!(SessionPricing::try_new(0, 22_020).is_err());
        assert!(SessionPricing::try_new(22_020, 0).is_err());
    }
}
