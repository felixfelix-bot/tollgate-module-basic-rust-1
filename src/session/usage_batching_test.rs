//! ADR-0002 — batched usage-counter writes.
//!
//! `used` is a cache of a value the dataplane already knows (`ndsctl`), not the source
//! of truth. Paying a fsync per metering tick for it is the money rule applied to the
//! wrong thing. But *not* persisting it at all is worse: `ndsctl` counters reset on
//! daemon restart and on re-association, so a restart would hand a client a fresh
//! allotment it had already consumed.
//!
//! So: batch, with three triggers —
//!   * 5 seconds since the last flush,
//!   * >= 5% of the allotment moved since the last flush,
//!   * any terminal transition (revoke / expire / close) always flushes exactly.
//!
//! The third one is the one that matters for disputes: the persisted number must be
//! EXACT at the moment the session stops mattering to write more.

use super::store::SessionStore;
use super::SessionManager;
use std::path::{Path, PathBuf};

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "tg-0002-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Read the persisted value straight from the store, bypassing the in-memory cache.
fn persisted(path: &Path, mac: &str) -> Option<u64> {
    let st = SessionStore::open(path).ok()?;
    st.load_sessions()
        .ok()?
        .into_iter()
        .find(|s| s.mac == mac)
        .map(|s| s.used)
}

/// Small deltas below both thresholds must NOT hit the disk.
#[test]
fn small_delta_does_not_flush() {
    let dir = tmpdir("small");
    let path = dir.join("state.db");
    let mut mgr = SessionManager::open(&path).unwrap();
    mgr.create_session("aa:00:00:00:00:01", 10_000, "bytes", 3_600);

    // 1% of allotment, immediately after create -> neither trigger fires.
    mgr.update_usage("aa:00:00:00:00:01", 100);
    assert_eq!(
        persisted(&path, "aa:00:00:00:00:01"),
        Some(0),
        "a 1% delta flushed; the whole point is to avoid per-tick fsyncs"
    );
    // In-memory value must still be current, though.
    assert_eq!(mgr.get_session("aa:00:00:00:00:01").unwrap().used, 100);
}

/// Crossing 5% of the allotment must flush.
#[test]
fn five_percent_delta_flushes() {
    let dir = tmpdir("pct");
    let path = dir.join("state.db");
    let mut mgr = SessionManager::open(&path).unwrap();
    mgr.create_session("aa:00:00:00:00:02", 10_000, "bytes", 3_600);

    mgr.update_usage("aa:00:00:00:00:02", 500); // exactly 5%
    assert_eq!(
        persisted(&path, "aa:00:00:00:00:02"),
        Some(500),
        "5% of allotment must flush: otherwise a fast link can overshoot a meaningful \
         fraction of what the customer paid for"
    );
}

/// Elapsed time is the other trigger.
#[test]
fn elapsed_time_flushes() {
    let dir = tmpdir("time");
    let path = dir.join("state.db");
    let mut mgr = SessionManager::open(&path).unwrap();
    mgr.create_session("aa:00:00:00:00:03", 1_000_000, "bytes", 3_600);

    mgr.update_usage("aa:00:00:00:00:03", 10); // below the 5% threshold
    assert_eq!(persisted(&path, "aa:00:00:00:00:03"), Some(0));

    // Force the time trigger without sleeping: the manager exposes the last-flush
    // instant for exactly this reason (a 5-second sleep in a unit test is a smell).
    mgr.force_flush_after_for_test(6);
    mgr.update_usage("aa:00:00:00:00:03", 20);
    assert_eq!(
        persisted(&path, "aa:00:00:00:00:03"),
        Some(20),
        "after 5s elapsed the next update must flush"
    );
}

/// Revocation must persist the FINAL value exactly — this is the audit number.
#[test]
fn revoke_flushes_final_value() {
    let dir = tmpdir("revoke");
    let path = dir.join("state.db");
    let mut mgr = SessionManager::open(&path).unwrap();
    mgr.create_session("aa:00:00:00:00:04", 10_000, "bytes", 3_600);

    mgr.update_usage("aa:00:00:00:00:04", 137); // below threshold -> not flushed
    assert_eq!(persisted(&path, "aa:00:00:00:00:04"), Some(0));

    // Terminal transition: the pending delta must be written before the row is deleted.
    mgr.revoke_session("aa:00:00:00:00:04");
    // The row is gone from `sessions`, so read the audit trail the revoke leaves behind.
    let st = SessionStore::open(&path).unwrap();
    let audit = st
        .last_closed_usage("aa:00:00:00:00:04")
        .expect("revoke must record the final usage for audit");
    assert_eq!(
        audit, 137,
        "revocation persisted {audit} instead of the exact final usage; a dispute would \
         be settled against a stale number"
    );
}

/// Expiry (cleanup_expired) is also terminal.
#[test]
fn expire_flushes_final_value() {
    let dir = tmpdir("expire");
    let path = dir.join("state.db");
    // Pre-existing site: `mgr` is deliberately opened-but-unused, to prove that
    // `open` itself (not a later call) performs the recovery close asserted below.
    let _mgr = SessionManager::open(&path).unwrap();
    // Already-expired session, seeded directly.
    {
        let st = SessionStore::open(&path).unwrap();
        st.upsert_session(&super::CustomerSession {
            mac: "aa:00:00:00:00:05".into(),
            allotment: 10_000,
            used: 4_200,
            metric: "bytes".into(),
            expiry: now() - 1,
            granted_at: now() - 100,
            retail_allotment: now() - 100,
            channel_id: None,
        })
        .unwrap();
    }
    let mut mgr2 = SessionManager::open(&path).unwrap();
    // `open` already closed it during recovery; the audit must carry 4_200.
    let _ = &mut mgr2;
    let st = SessionStore::open(&path).unwrap();
    let audit = st.last_closed_usage("aa:00:00:00:00:05");
    assert_eq!(
        audit,
        Some(4_200),
        "an expired-while-down session must record its final usage for audit"
    );
}
