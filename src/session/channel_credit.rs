//! Access-path wiring: a Spilman channel must be able to **extend a live session's
//! credit** without a mint round trip, and must never grant more than it has a
//! verified signature for.
//!
//! # Why this file exists
//!
//! Everything proven so far — signature verification, the HTTP surface, the on-router
//! protocol run — is real but sits **off the access path**. `terminal_sessions` decides
//! access purely from `CustomerSession.allotment`, and a channel had no way to
//! influence it, so a channel bought a client nothing.
//!
//! # The shape of the fix
//!
//! `allotment` stays as the **effective** ceiling; a new `retail_allotment` keeps the
//! original token-purchased number, and `channel_id` binds a session to a channel.
//!
//!   effective_allotment = retail_allotment + channel_verified_bytes(channel_id)
//!
//! The channel **raises a floor, it never lowers it**, and with no channel bound the
//! two numbers are equal — which is what makes the rail-off path bit-identical rather
//! than merely similar.
//!
//! # The rule that matters most
//!
//! A channel that cannot be *read* is not a channel that is *paid*. Every failure mode
//! here — unknown channel, DB error, verification failure — resolves to "no credit
//! added", never to "assume the retail allotment is still fine". A failure to read a
//! payment is not evidence of payment.

use super::{CustomerSession, SessionManager, terminal_sessions};

/// Bytes of access a channel's verified balance buys, in the unit `allotment` uses.
///
/// Returns `None` when the channel cannot be trusted for any bytes right now — an
/// unknown channel, an unreadable ledger, or a balance that does not verify. `None`
/// is deliberately distinct from `Some(0)`: "we cannot say" and "it buys nothing" lead
/// to the same denial here, but keeping them distinct means a future caller cannot
/// accidentally treat an error as a confirmed zero.
pub fn channel_credit_bytes(rail: &crate::spilman::rail::SpilmanRail, channel_id: &str) -> Option<u64> {
    let balance = rail.channel_balance(channel_id).ok()??;
    // The rail's own pricing is the single source of truth for "how many bytes does
    // this balance buy" — the same function `authorize_bytes` uses, so the access path
    // and the authorisation check can never disagree about the rate.
    rail.bytes_for_raw_balance(balance).ok()
}

/// Recompute the effective allotment for a channel-bound session.
///
/// Pure with respect to the session: it reads the channel and returns the number the
/// caller should store. Keeping it separate from the sweep makes the interesting cases
/// (error, unknown channel, exhausted channel) testable without a router or a timer.
pub fn effective_allotment(
    session: &CustomerSession,
    rail: Option<&crate::spilman::rail::SpilmanRail>,
) -> u64 {
    let Some(channel_id) = session.channel_id.as_deref() else {
        // No channel: the retail number IS the answer, unchanged and unexamined.
        return session.retail_allotment;
    };
    let Some(rail) = rail else {
        // A session claims a channel but no rail exists (config flipped off under a
        // live session). Grant nothing beyond what was actually bought with tokens:
        // the client keeps the credit it paid for, and no more.
        return session.retail_allotment;
    };
    match channel_credit_bytes(rail, channel_id) {
        Some(bytes) => session.retail_allotment.saturating_add(bytes),
        // Fail closed on the channel half. The retail half survives, because that
        // money was really spent and revoking it would be theft.
        None => session.retail_allotment,
    }
}

/// Refresh every session's effective allotment from the rail, then return the terminal
/// set. This is the sweep's decision step.
///
/// Recomputing on every tick is the point: a payment that landed since the last sweep
/// must extend access **without** a new gate-open, and a channel whose credit has been
/// consumed must stop granting. Both fall out of asking the ledger each time rather
/// than remembering a number from grant time.
pub fn sweep_with_channel_credit(
    sessions: &mut SessionManager,
    rail: Option<&crate::spilman::rail::SpilmanRail>,
    now: u64,
) -> Vec<String> {
    // Recompute first, decide second: `terminal_sessions` must see the refreshed
    // numbers, otherwise it would judge this tick's usage against last tick's credit.
    for session in sessions.sessions.values_mut() {
        session.allotment = effective_allotment(session, rail);
    }
    terminal_sessions(&sessions.sessions, now)
}
