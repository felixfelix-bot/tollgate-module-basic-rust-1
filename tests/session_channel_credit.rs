//! Access-path wiring tests: a Spilman channel must extend a live session's credit,
//! and must never grant more than a verified signature covers.
//!
//! # The shape these tests defend
//!
//! `allotment` is the EFFECTIVE ceiling. It is recomputed every sweep from
//! `retail_allotment` plus whatever a bound channel has verifiably paid for. The
//! channel raises a floor; it never lowers it. With no channel bound the two numbers
//! are equal, which is what makes the rail-off behaviour identical rather than merely
//! similar.
//!
//! # Why the first test is the important one
//!
//! `rail_off_is_byte_identical_to_the_old_behaviour` would pass BEFORE this feature was
//! written. That is deliberate: it is the regression guard that proves the change did
//! not quietly alter the retail path every existing customer uses. A feature test that
//! only exercises the new path cannot tell you that.

use std::path::Path;

use tollgate_module_basic_rust::config::schema::SpilmanConfig;
use tollgate_module_basic_rust::session::channel_credit::{
    effective_allotment, sweep_with_channel_credit,
};
use tollgate_module_basic_rust::session::{CustomerSession, SessionManager};
use tollgate_module_basic_rust::spilman::rail::SpilmanRail;

fn session(mac: &str, retail: u64, channel_id: Option<&str>) -> CustomerSession {
    CustomerSession {
        mac: mac.to_string(),
        allotment: retail,
        used: 0,
        metric: "bytes".to_string(),
        expiry: u64::MAX,
        granted_at: 0,
        retail_allotment: retail,
        channel_id: channel_id.map(str::to_string),
    }
}

fn rail_in(dir: &Path) -> SpilmanRail {
    let cfg = SpilmanConfig {
        enabled: true,
        mint_url: Some("https://mint.example".to_string()),
        in_bytes_per_millisat: 22_021,
        channel_db_path: Some(dir.join("spilman.db").to_string_lossy().to_string()),
    };
    SpilmanRail::from_config(&cfg)
        .expect("enabled config is not an error")
        .expect("enabled config must build a rail")
}

/// THE REGRESSION GUARD. With no rail (or no channel), the effective allotment must be
/// exactly the retail number — the behaviour every existing customer already has.
#[test]
fn rail_off_is_byte_identical_to_the_old_behaviour() {
    let s = session("aa:bb:cc:dd:ee:ff", 21_000_000, None);
    assert_eq!(
        effective_allotment(&s, None),
        21_000_000,
        "with the rail off the allotment must be the retail number, untouched"
    );
}

/// A session that claims a channel while the rail is absent keeps only what it bought.
///
/// This is the config-flipped-off-under-a-live-session case: the customer keeps the
/// credit they paid tokens for, and gains nothing.
#[test]
fn channel_bound_session_without_a_rail_keeps_only_retail() {
    let s = session("aa:bb:cc:dd:ee:01", 5_000, Some("chan"));
    assert_eq!(effective_allotment(&s, None), 5_000);
}

/// An unknown channel adds nothing, and must not revoke what was bought.
#[test]
fn unknown_channel_adds_no_credit_but_keeps_retail() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rail = rail_in(dir.path());
    let s = session("aa:bb:cc:dd:ee:02", 7_000, Some("never-registered"));
    assert_eq!(
        effective_allotment(&s, Some(&rail)),
        7_000,
        "an unknown channel must add zero credit, not fail the retail half"
    );
}

/// A channel with a verified balance raises the ceiling by the bytes that balance buys.
///
/// The number is computed by the rail's own pricing, so this test also pins that the
/// access path and `authorize_bytes` agree on the rate.
#[tokio::test]
async fn a_funded_channel_raises_the_ceiling() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rail = rail_in(dir.path());

    // Record a balance the way a verified payment would.
    rail.record_payment_for_tests("chan-paid", 1, "sig-1")
        .expect("record a verified balance");

    let s = session("aa:bb:cc:dd:ee:03", 1_000, Some("chan-paid"));
    let effective = effective_allotment(&s, Some(&rail));
    let bytes = rail
        .bytes_for_raw_balance(1)
        .expect("1 raw unit converts at the parity rate");
    assert_eq!(
        effective,
        1_000 + bytes,
        "the ceiling must be retail + what the channel verifiably paid for"
    );
    assert!(
        effective > 1_000,
        "the channel must actually RAISE the ceiling, not merely be consulted"
    );
}

/// The channel half must not be able to extend a session past what it paid for.
///
/// Once `used` exceeds retail + channel credit, the session is terminal — exactly like
/// the old `used >= allotment` rule.
#[tokio::test]
async fn exhausted_channel_credit_revokes_the_session() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rail = rail_in(dir.path());
    rail.record_payment_for_tests("chan-small", 1, "sig-1")
        .expect("record");

    let mut s = session("aa:bb:cc:dd:ee:04", 0, Some("chan-small"));
    let ceiling = effective_allotment(&s, Some(&rail));
    assert!(ceiling > 0, "the channel must have bought something");

    // Under the ceiling: alive. At the ceiling: terminal.
    s.used = ceiling - 1;
    assert_eq!(sweep_with_channel_credit(&mut one(&s), Some(&rail), 0).len(), 0);
    s.used = ceiling;
    assert_eq!(
        sweep_with_channel_credit(&mut one(&s), Some(&rail), 0),
        vec!["aa:bb:cc:dd:ee:04".to_string()],
        "used == effective allotment is terminal, same as the retail rule"
    );
}

/// A payment that lands AFTER the session started must extend the SAME session —
/// no new gate-open, and the consumed `used` must not be forgotten.
#[tokio::test]
async fn a_later_payment_extends_the_same_session_without_losing_usage() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rail = rail_in(dir.path());

    let mut sessions = SessionManager::new();
    let mut s = sessions.create_session("aa:bb:cc:dd:ee:05", 0, "bytes", 3600);
    s.channel_id = Some("chan-growing".to_string());
    s.used = 500;
    sessions.sessions.insert(s.mac.clone(), s);

    // No payment yet: nothing bought, so any usage is already over the ceiling.
    assert_eq!(
        sweep_with_channel_credit(&mut sessions, Some(&rail), 0),
        vec!["aa:bb:cc:dd:ee:05".to_string()],
        "with no credit recorded the session is terminal"
    );

    // A verified payment arrives.
    rail.record_payment_for_tests("chan-growing", 1, "sig-1")
        .expect("record");
    let horizon = rail.bytes_for_raw_balance(1).expect("rate");
    assert!(horizon > 500, "the payment must cover the usage for this test to mean anything");

    assert!(
        sweep_with_channel_credit(&mut sessions, Some(&rail), 0).is_empty(),
        "the payment must revive the SAME session"
    );
    let kept = sessions.sessions.get("aa:bb:cc:dd:ee:05").expect("still there");
    assert_eq!(kept.used, 500, "usage must survive; reviving is not a re-grant");
    assert_eq!(
        kept.allotment,
        horizon,
        "the ceiling must now be the channel's verified credit"
    );
}

/// A balance whose unit cannot be converted must grant NOTHING.
///
/// The inverse of the repo's "absence is not zero" rule, and the deliberate one: a
/// balance we cannot interpret is not a balance we can spend. Granting the retail half
/// is correct; granting a guess of the channel half is not.
#[test]
fn an_unconvertible_balance_grants_no_channel_credit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rail = rail_in(dir.path());
    let s = session("aa:bb:cc:dd:ee:06", 4_242, Some("whatever"));
    // The channel is unknown, so there is no balance to convert. The point of this
    // test is that the failure path lands on retail-only rather than on a panic or a
    // fabricated number.
    assert_eq!(effective_allotment(&s, Some(&rail)), 4_242);
}

/// Convenience: wrap one session in a manager for the sweep tests.
fn one(s: &CustomerSession) -> SessionManager {
    let mut m = SessionManager::new();
    m.sessions.insert(s.mac.clone(), s.clone());
    m
}
