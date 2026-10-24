//! P1 — durable sessions and quotes.
//!
//! Every test here fails against an in-memory `SessionManager`: the point of this
//! module is that a restart must not lose a paid session and must not resurrect an
//! expired one. A test that would pass without a store proves nothing, so each case
//! below reloads from the file rather than trusting the in-memory value.

use super::store::{SessionStore, StoreError};
use super::{CustomerSession, SessionManager};
use std::path::PathBuf;

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "tg-p1-{}-{}-{}",
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

fn sess(mac: &str, allotment: u64, used: u64, expiry: u64) -> CustomerSession {
    CustomerSession {
        mac: mac.to_string(),
        allotment,
        used,
        metric: "bytes".to_string(),
        expiry,
        granted_at: now(),
        retail_allotment: now(),
        channel_id: None,
    }
}

/// The headline promise: a paying customer survives a restart, and their consumed
/// bytes are still consumed. Resetting `used` to 0 would grant free bytes on every
/// restart, which is worse than losing the session.
#[test]
fn session_survives_restart_with_usage_intact() {
    let dir = tmpdir("restart");
    let path = dir.join("state.db");

    {
        let mut mgr = SessionManager::open(&path).expect("open");
        mgr.create_session("aa:bb:cc:dd:ee:ff", 5_000, "bytes", 3_600);
        mgr.update_usage("aa:bb:cc:dd:ee:ff", 1_500);
    } // dropped: simulates process exit

    let mgr = SessionManager::open(&path).expect("reopen");
    let s = mgr.get_session("aa:bb:cc:dd:ee:ff").expect("session lost");
    assert_eq!(s.used, 1_500, "consumed bytes were reset on restart");
    assert_eq!(s.allotment, 5_000);
}

/// A session whose expiry passed while the process was down is CLOSED, not
/// resurrected. Restarting must not extend access.
#[test]
fn session_expired_while_down_is_closed() {
    let dir = tmpdir("expired");
    let path = dir.join("state.db");

    {
        let store = SessionStore::open(&path).expect("open");
        store
            .upsert_session(&sess("11:22:33:44:55:66", 1_000, 10, now() - 60))
            .expect("seed expired");
    }

    let mgr = SessionManager::open(&path).expect("reopen");
    assert!(
        mgr.get_session("11:22:33:44:55:66").is_none(),
        "an expired session was resurrected as valid"
    );
}

/// A still-valid session is reloaded AND is reported active — the reload must
/// preserve enough state for `is_active` to answer correctly.
#[test]
fn valid_session_reloads_and_is_active() {
    let dir = tmpdir("active");
    let path = dir.join("state.db");

    {
        let store = SessionStore::open(&path).expect("open");
        store
            .upsert_session(&sess("de:ad:be:ef:00:01", 2_000, 100, now() + 3_600))
            .expect("seed valid");
    }

    let mgr = SessionManager::open(&path).expect("reopen");
    assert!(
        mgr.is_active("de:ad:be:ef:00:01"),
        "a valid session was not active after reload"
    );
}

/// An exhausted session (used >= allotment) must not come back active.
#[test]
fn exhausted_session_is_not_active_after_reload() {
    let dir = tmpdir("exhausted");
    let path = dir.join("state.db");

    {
        let store = SessionStore::open(&path).expect("open");
        store
            .upsert_session(&sess("de:ad:be:ef:00:02", 1_000, 1_000, now() + 3_600))
            .expect("seed exhausted");
    }

    let mgr = SessionManager::open(&path).expect("reopen");
    assert!(
        !mgr.is_active("de:ad:be:ef:00:02"),
        "an exhausted session was reported active after reload"
    );
}

/// FAIL CLOSED. An unreadable store must never be read as "no sessions" — that
/// would silently grant fresh access to every client. Refusing to start is
/// strictly safer than starting empty.
#[test]
fn corrupt_store_refuses_to_open() {
    let dir = tmpdir("corrupt");
    let path = dir.join("state.db");
    std::fs::write(&path, b"this is not a sqlite database at all").unwrap();

    match SessionManager::open(&path) {
        Err(StoreError::Corrupt { .. }) | Err(StoreError::Sqlite { .. }) => {}
        Err(e) => panic!("wrong error for a corrupt store: {e:?}"),
        Ok(_) => panic!("a corrupt store opened cleanly and would have lost every session"),
    }
}

/// A schema we do not understand must be refused, not silently migrated by luck.
#[test]
fn unknown_schema_version_refuses_to_open() {
    let dir = tmpdir("schema");
    let path = dir.join("state.db");

    {
        let store = SessionStore::open(&path).expect("open");
        drop(store);
    }
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.pragma_update(None, "user_version", 9_999_i32).unwrap();
    }

    match SessionManager::open(&path) {
        Err(StoreError::UnknownSchema { found }) => assert_eq!(found, 9_999),
        Err(e) => panic!("wrong error for an unknown schema: {e:?}"),
        Ok(_) => panic!("an unknown schema version opened cleanly"),
    }
}

/// The durability settings are part of the decision, not an implementation detail:
/// WAL without FULL can lose the last transactions on power loss, and what is being
/// stored is paid access. Read them back from the database rather than trusting the
/// source, so a silent regression to `NORMAL` fails here.
#[test]
fn journal_and_synchronous_are_read_back_from_db() {
    let dir = tmpdir("pragma");
    let path = dir.join("state.db");
    let store = SessionStore::open(&path).expect("open");

    let journal: String = store
        .raw_query_one("PRAGMA journal_mode")
        .expect("read journal_mode");
    assert_eq!(
        journal.to_lowercase(),
        "wal",
        "journal_mode is not WAL — power loss can corrupt the store"
    );

    let sync: i64 = store
        .raw_query_one("PRAGMA synchronous")
        .expect("read synchronous");
    // rusqlite/sqlite constants: 0=OFF 1=NORMAL 2=FULL 3=EXTRA
    assert_eq!(sync, 2, "synchronous is not FULL — paid access can be lost");
}

/// Quotes are money-adjacent too: a paid quote whose state was lost cannot be
/// redeemed. Same restart guarantee, different table.
#[test]
fn quote_state_survives_restart() {
    let dir = tmpdir("quote");
    let path = dir.join("state.db");

    {
        let store = SessionStore::open(&path).expect("open");
        store
            .upsert_quote("q-1", 21, "sat", "paid", now(), now() + 600, "lnbc1xyz")
            .expect("seed quote");
    }

    let store = SessionStore::open(&path).expect("reopen");
    let q = store
        .get_quote("q-1")
        .expect("query failed")
        .expect("quote lost");
    assert_eq!(q.state, "paid", "a paid quote came back unpaid");
    assert_eq!(q.request, "lnbc1xyz");
}

/// Revoking must persist: a revoked session that reappears after restart is a
/// refund-free re-grant.
#[test]
fn revoked_session_does_not_return() {
    let dir = tmpdir("revoke");
    let path = dir.join("state.db");

    {
        let mut mgr = SessionManager::open(&path).expect("open");
        mgr.create_session("ab:cd:ef:01:23:45", 9_000, "bytes", 3_600);
        mgr.revoke_session("ab:cd:ef:01:23:45");
    }

    let mgr = SessionManager::open(&path).expect("reopen");
    assert!(
        mgr.get_session("ab:cd:ef:01:23:45").is_none(),
        "a revoked session returned after restart"
    );
}
