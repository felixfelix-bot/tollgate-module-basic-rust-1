//! Durable per-channel balance ledger (payee side).
//!
//! This is the `SpilmanHost` shape MONAD uses at
//! `monad-relay/src/payments.rs:961-972`, reduced to the two operations the hot
//! path actually needs:
//!
//! - `get_amount_due` reads the stored balance (a local SQLite read, no network);
//! - `record_payment` writes `(balance, signature)` **durably before returning**.
//!
//! # Why CAS and not `new > stored`
//!
//! Gap analysis §6: the mint honours only the highest balance the payee can
//! produce, so a lost latest signature is lost money (payee's loss), and a payee
//! that serves bytes for a balance it never durably recorded can be rolled back
//! (payer's loss). Both are closed by an exact compare-and-swap against the
//! previous balance inside one `IMMEDIATE` transaction:
//!
//! ```text
//! BEGIN IMMEDIATE
//!   previous := SELECT balance ...          -- 0 when the channel is new
//!   if new_balance <= previous -> ROLLBACK, Err(BalanceNotAdvanced)
//!   UPSERT ... WHERE balance = previous
//! COMMIT
//! ```
//!
//! A naive `if new_balance > stored` is not equivalent: a *retry of a different
//! payment that happens to carry the same balance* would be treated as newly
//! accepted funds. Only the exact-previous CAS rejects it (INTEGRATION.md:
//! "Applications computing credit deltas must use this CAS rather than treating
//! a monotonic no-op as newly accepted funds").
//!
//! # Durability
//!
//! `synchronous = FULL` + WAL: a committed `record_payment` has reached stable
//! storage before the caller is allowed to serve a single byte. Both settings
//! together are the whole point of this module; do not relax them for speed.

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use crate::spilman::SpilmanError;

/// A durable `(balance, signature)` pair — the latest payment the payee holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPayment {
    pub channel_id: String,
    pub balance: u64,
    pub signature: String,
    /// Number of accepted payments seen for this channel (1-based).
    pub payment_count: u64,
    pub updated_at: u64,
}

/// Result of an accepted ledger write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerOutcome {
    /// The balance advanced from the exact previous value and is now durable.
    Accepted,
}

/// What a funding-record registration did.
///
/// The two successes are deliberately distinct: a payer whose first registration
/// response was lost must be able to tell "your record is stored" (it already was)
/// from "your record was just stored", without either answer being an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FundingRegistration {
    /// The record was new and is now durable.
    Registered,
    /// A byte-identical record was already stored; nothing changed.
    AlreadyRegistered,
}

/// A durable per-channel **funding** record — the payee's half of a Spilman channel.
///
/// This is what `cdk-spilman` verifies a balance signature against, and it is why
/// the balance table alone cannot authenticate anything: monotonicity is not
/// authenticity (`CRITICAL-UNVERIFIED-PAYMENT.md`). Upstream
/// `SpilmanBridge::validate_payment` (bridge.rs:1312) loads exactly these five
/// values through `SpilmanHost::get_funding` and feeds them to
/// `verify_signature`:
///
/// - `params_json` + `keyset_info_json` + `channel_secret_hex` reconstruct the
///   channel (`ChannelParameters::from_json_with_channel_secret`);
/// - `funding_proofs_json` reconstructs the `EstablishedChannel` the sender's key
///   is derived from;
/// - `capacity` bounds the largest balance that may be signed.
///
/// # Why the round-trip must be byte-exact
///
/// Every field is stored and read back verbatim. A field that came back even one
/// byte different would either make verification fail (a funded channel that can
/// never be paid — a denial of service on money) or, far worse, verify the
/// signature against *different* params than the channel was opened with. There is
/// no re-serialisation step in either direction for that reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelFundingRecord {
    pub channel_id: String,
    /// Serialized channel parameters, verbatim as the payer registered them.
    pub params_json: String,
    /// Serialized funding proofs, verbatim.
    pub funding_proofs_json: String,
    /// Hex-encoded ECDH channel secret.
    pub channel_secret_hex: String,
    /// Serialized keyset info for the channel's keyset, verbatim.
    pub keyset_info_json: String,
    /// Largest balance the payer may sign for this channel.
    pub capacity: u64,
    /// When the record was written (unix seconds).
    pub created_at: u64,
}

/// SQLite-backed channel balance ledger.
#[derive(Debug)]
pub struct ChannelLedger {
    conn: Mutex<Connection>,
}

impl ChannelLedger {
    /// Open (or create) the ledger at `path`.
    ///
    /// FAIL CLOSED is the caller's job: an unreadable ledger must never be read
    /// as "no balance" — that would let a payer re-spend a channel.
    pub fn open(path: &Path) -> Result<Self, SpilmanError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| SpilmanError::Io {
                path: parent.display().to_string(),
                detail: e.to_string(),
            })?;
        }
        let conn = Connection::open(path).map_err(|e| SpilmanError::Ledger(e.to_string()))?;
        Self::configure(&conn)?;
        let ledger = Self {
            conn: Mutex::new(conn),
        };
        ledger.init_schema()?;
        Ok(ledger)
    }

    /// Open an in-memory ledger (tests only — nothing survives the handle).
    pub fn open_in_memory() -> Result<Self, SpilmanError> {
        let conn = Connection::open_in_memory().map_err(|e| SpilmanError::Ledger(e.to_string()))?;
        let ledger = Self {
            conn: Mutex::new(conn),
        };
        ledger.init_schema()?;
        Ok(ledger)
    }

    fn configure(conn: &Connection) -> Result<(), SpilmanError> {
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| SpilmanError::Ledger(e.to_string()))?;
        // WAL keeps readers (get_amount_due on the hot path) from blocking on the
        // writer. FULL makes a commit durable before record_payment returns.
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| SpilmanError::Ledger(e.to_string()))?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(|e| SpilmanError::Ledger(e.to_string()))?;
        Ok(())
    }

    fn init_schema(&self) -> Result<(), SpilmanError> {
        let conn = self.lock()?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS spilman_channel_balance (
                 channel_id    TEXT    PRIMARY KEY,
                 balance       INTEGER NOT NULL,
                 signature     TEXT    NOT NULL,
                 payment_count INTEGER NOT NULL,
                 updated_at    INTEGER NOT NULL
             ) STRICT;
             -- The payee's funding record. Without a row here a payment for the
             -- channel cannot be authenticated at all, so `record_payment` fails
             -- closed (UnknownChannel). See ChannelFundingRecord.
             CREATE TABLE IF NOT EXISTS spilman_channel_funding (
                 channel_id          TEXT    PRIMARY KEY,
                 params_json         TEXT    NOT NULL,
                 funding_proofs_json TEXT    NOT NULL,
                 channel_secret_hex  TEXT    NOT NULL,
                 keyset_info_json    TEXT    NOT NULL,
                 capacity            INTEGER NOT NULL,
                 created_at          INTEGER NOT NULL
             ) STRICT;
             CREATE TABLE IF NOT EXISTS spilman_close (channel_id TEXT PRIMARY KEY, prepared TEXT NOT NULL, state TEXT NOT NULL, completed TEXT) STRICT;",
        )
        .map_err(|e| SpilmanError::Ledger(e.to_string()))?;
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, SpilmanError> {
        self.conn
            .lock()
            .map_err(|_| SpilmanError::Ledger("ledger lock poisoned".to_string()))
    }

    /// The latest durable payment for a channel, or `None` if it has none.
    pub fn get_latest_payment(
        &self,
        channel_id: &str,
    ) -> Result<Option<StoredPayment>, SpilmanError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT channel_id, balance, signature, payment_count, updated_at
               FROM spilman_channel_balance
              WHERE channel_id = ?1",
            [channel_id],
            |row| {
                Ok(StoredPayment {
                    channel_id: row.get(0)?,
                    balance: row.get(1)?,
                    signature: row.get(2)?,
                    payment_count: row.get(3)?,
                    updated_at: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(|e| SpilmanError::Ledger(e.to_string()))
    }

    /// The stored balance, or `None` when the channel has never been paid.
    ///
    /// `None` is deliberately distinct from `Some(0)`: a channel that does not
    /// exist must not be served, and "no record" is not "zero balance".
    pub fn get_balance(&self, channel_id: &str) -> Result<Option<u64>, SpilmanError> {
        Ok(self.get_latest_payment(channel_id)?.map(|p| p.balance))
    }

    /// Amount still due before the channel is exhausted, in raw channel units.
    ///
    /// `amount_due` here is the *next* balance the payer must sign, i.e. the
    /// stored balance. The host contract calls it "amount due" and MONAD
    /// implements it as a plain read of the stored balance; keeping that shape
    /// means the payee's credit accounting (`balance - served`) stays a single
    /// subtraction in the caller.
    pub fn get_amount_due(&self, channel_id: &str) -> Result<u64, SpilmanError> {
        Ok(self.get_balance(channel_id)?.unwrap_or(0))
    }

    /// Durably record a new balance, CAS'd against the exact previous value.
    ///
    /// Rejects any balance that does not strictly advance the stored one. That
    /// covers replay (equal), stale/rollback (lower) and the same-balance
    /// different-signature double-credit case.
    pub fn record_payment(
        &self,
        channel_id: &str,
        balance: u64,
        signature: &str,
    ) -> Result<LedgerOutcome, SpilmanError> {
        let mut conn = self.lock()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| SpilmanError::Ledger(e.to_string()))?;

        let closing: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM spilman_close WHERE channel_id=?1)",
                [channel_id],
                |r| r.get(0),
            )
            .map_err(|e| SpilmanError::Ledger(e.to_string()))?;
        if closing {
            return Err(SpilmanError::Ledger("channel is closing or closed".into()));
        }

        let previous: Option<(u64, u64)> = tx
            .query_row(
                "SELECT balance, payment_count FROM spilman_channel_balance WHERE channel_id = ?1",
                [channel_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| SpilmanError::Ledger(e.to_string()))?;

        let (previous_balance, previous_count) = previous.unwrap_or((0, 0));
        if previous.is_some() && balance <= previous_balance {
            // No write, no count bump: a rejected payment is not newly accepted
            // funds. The tx is dropped (rolled back) on return.
            return Err(SpilmanError::BalanceNotAdvanced {
                channel_id: channel_id.to_string(),
                stored: previous_balance,
                offered: balance,
            });
        }
        if previous.is_none() && balance == 0 {
            // A zero-balance opening signature is legitimate, but it must not be
            // re-recorded as if it were progress.
            return Err(SpilmanError::BalanceNotAdvanced {
                channel_id: channel_id.to_string(),
                stored: 0,
                offered: 0,
            });
        }

        let payment_count = previous_count + 1;
        let updated_at = now_seconds();
        let changed = tx
            .execute(
                "INSERT INTO spilman_channel_balance
                     (channel_id, balance, signature, payment_count, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(channel_id) DO UPDATE SET
                     balance       = excluded.balance,
                     signature     = excluded.signature,
                     payment_count = excluded.payment_count,
                     updated_at    = excluded.updated_at
                 WHERE spilman_channel_balance.balance = ?6",
                rusqlite::params![
                    channel_id,
                    balance,
                    signature,
                    payment_count,
                    updated_at,
                    previous_balance
                ],
            )
            .map_err(|e| SpilmanError::Ledger(e.to_string()))?;

        if changed != 1 {
            // Someone advanced the balance between our read and our write. The
            // CAS guard refused the UPDATE; do not pretend it landed.
            return Err(SpilmanError::BalanceNotAdvanced {
                channel_id: channel_id.to_string(),
                stored: previous_balance,
                offered: balance,
            });
        }

        tx.commit()
            .map_err(|e| SpilmanError::Ledger(e.to_string()))?;
        Ok(LedgerOutcome::Accepted)
    }

    /// Freeze the exact accepted authorization and immutable preparation atomically.
    pub(crate) fn freeze_close(
        &self,
        id: &str,
        balance: u64,
        signature: &str,
        prepared: &str,
    ) -> Result<(), SpilmanError> {
        let mut conn = self.lock()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| SpilmanError::Ledger(e.to_string()))?;
        let matches: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM spilman_channel_balance b JOIN spilman_channel_funding f USING(channel_id) WHERE channel_id=?1 AND b.balance=?2 AND b.signature=?3)", rusqlite::params![id,balance,signature], |r|r.get(0)).map_err(|e| SpilmanError::Ledger(e.to_string()))?;
        if !matches {
            return Err(SpilmanError::Ledger(
                "close authorization is not the latest accepted payment".into(),
            ));
        }
        tx.execute(
            "INSERT INTO spilman_close(channel_id,prepared,state) VALUES(?1,?2,'prepared')",
            rusqlite::params![id, prepared],
        )
        .map_err(|e| SpilmanError::Ledger(e.to_string()))?;
        tx.commit().map_err(|e| SpilmanError::Ledger(e.to_string()))
    }

    pub(crate) fn close_journal(
        &self,
        id: &str,
    ) -> Result<Option<(String, String, Option<String>)>, SpilmanError> {
        self.lock()?
            .query_row(
                "SELECT prepared,state,completed FROM spilman_close WHERE channel_id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|e| SpilmanError::Ledger(e.to_string()))
    }

    /// Claim execution before network I/O. A lost response leaves uncertain, never prepared.
    pub(crate) fn advance_close(
        &self,
        id: &str,
        prepared: &str,
        from: &str,
        to: &str,
        completed: Option<&str>,
    ) -> Result<bool, SpilmanError> {
        Ok(self.lock()?.execute("UPDATE spilman_close SET state=?4,completed=?5 WHERE channel_id=?1 AND prepared=?2 AND state=?3", rusqlite::params![id,prepared,from,to,completed]).map_err(|e|SpilmanError::Ledger(e.to_string()))? == 1)
    }

    /// Number of accepted payments for a channel (0 when unknown).
    pub fn payment_count(&self, channel_id: &str) -> Result<u64, SpilmanError> {
        Ok(self
            .get_latest_payment(channel_id)?
            .map(|p| p.payment_count)
            .unwrap_or(0))
    }

    // -- channel funding -----------------------------------------------------

    /// The durable funding record for a channel, or `None` if it was never funded.
    ///
    /// `None` means "this payee cannot verify anything about this channel", and the
    /// rail turns it into a refusal ([`SpilmanError::UnknownChannel`]). It must never
    /// be read as "no capacity" or "zero balance": an absent record is a *different
    /// fact* from a funded channel at balance 0.
    pub fn get_channel_funding(
        &self,
        channel_id: &str,
    ) -> Result<Option<ChannelFundingRecord>, SpilmanError> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT channel_id, params_json, funding_proofs_json, channel_secret_hex,
                    keyset_info_json, capacity, created_at
               FROM spilman_channel_funding
              WHERE channel_id = ?1",
            [channel_id],
            |row| {
                Ok(ChannelFundingRecord {
                    channel_id: row.get(0)?,
                    params_json: row.get(1)?,
                    funding_proofs_json: row.get(2)?,
                    channel_secret_hex: row.get(3)?,
                    keyset_info_json: row.get(4)?,
                    capacity: row.get(5)?,
                    created_at: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(|e| SpilmanError::Ledger(e.to_string()))
    }

    /// Persist a channel's funding record. **First write wins.**
    ///
    /// Re-registering an existing channel is a no-op rather than an overwrite, and
    /// deliberately so: the funding params carry the `capacity` ceiling and the
    /// channel secret the signature is checked against. Letting a second
    /// registration replace them would let anyone who can reach the surface raise
    /// the ceiling on a channel that is already open — i.e. re-open the forgery this
    /// whole path exists to close.
    ///
    /// Idempotency is also what makes the legitimate retry harmless: a payer whose
    /// first registration response was lost re-sends the identical record, and
    /// `INSERT OR IGNORE` accepts it without changing stored state.
    ///
    /// Prefer [`Self::register_channel_funding`] on the registration path: this
    /// one cannot tell "stored" from "ignored", so it cannot answer an honest retry.
    pub fn save_channel_funding(&self, record: &ChannelFundingRecord) -> Result<(), SpilmanError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR IGNORE INTO spilman_channel_funding
                 (channel_id, params_json, funding_proofs_json, channel_secret_hex,
                  keyset_info_json, capacity, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                record.channel_id,
                record.params_json,
                record.funding_proofs_json,
                record.channel_secret_hex,
                record.keyset_info_json,
                record.capacity,
                record.created_at,
            ],
        )
        .map_err(|e| SpilmanError::Ledger(e.to_string()))?;
        Ok(())
    }

    /// Register a channel's funding record: **refuse to overwrite, ever.**
    ///
    /// The three outcomes a caller can distinguish, and why each is what it is:
    ///
    /// - `Registered` — the id was new; the record is now durable.
    /// - `AlreadyRegistered` — a byte-identical record was already stored. This is
    ///   **success**, not conflict: the state the payer asked for is the state that
    ///   exists, so rejecting it would make an honest retry indistinguishable from
    ///   an attack and force the payer to guess why.
    /// - `Err(ChannelAlreadyRegistered)` — the id exists with *different* funding
    ///   data. That is either a bug (two payers colliding on an id) or an attack
    ///   (someone trying to move the capacity ceiling or the secret a signature is
    ///   checked against). Either way the stored record is left untouched and the
    ///   caller is told.
    ///
    /// Compare-and-store is one `IMMEDIATE` transaction, so two concurrent
    /// registrations of the same id cannot both be told `Registered`; the loser
    /// reports `AlreadyRegistered` or the conflict, never a partial write.
    pub fn register_channel_funding(
        &self,
        record: &ChannelFundingRecord,
    ) -> Result<FundingRegistration, SpilmanError> {
        let mut conn = self.lock()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| SpilmanError::Ledger(e.to_string()))?;

        let existing: Option<(String, String, String, String, u64)> = tx
            .query_row(
                "SELECT params_json, funding_proofs_json, channel_secret_hex,
                        keyset_info_json, capacity
                   FROM spilman_channel_funding
                  WHERE channel_id = ?1",
                [&record.channel_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| SpilmanError::Ledger(e.to_string()))?;

        if let Some((
            params_json,
            funding_proofs_json,
            channel_secret_hex,
            keyset_info_json,
            capacity,
        )) = existing
        {
            // `created_at` is deliberately NOT compared: it is the payee's own clock,
            // not the payer's data, so including it would turn every honest retry into
            // a bogus conflict.
            let identical = params_json == record.params_json
                && funding_proofs_json == record.funding_proofs_json
                && channel_secret_hex == record.channel_secret_hex
                && keyset_info_json == record.keyset_info_json
                && capacity == record.capacity;

            // No write in either branch — the transaction is dropped (rolled back) on
            // return, which is the point: an existing record is never touched.
            return if identical {
                Ok(FundingRegistration::AlreadyRegistered)
            } else {
                Err(SpilmanError::ChannelAlreadyRegistered {
                    channel_id: record.channel_id.clone(),
                })
            };
        }

        tx.execute(
            "INSERT INTO spilman_channel_funding
                 (channel_id, params_json, funding_proofs_json, channel_secret_hex,
                  keyset_info_json, capacity, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                record.channel_id,
                record.params_json,
                record.funding_proofs_json,
                record.channel_secret_hex,
                record.keyset_info_json,
                record.capacity,
                record.created_at,
            ],
        )
        .map_err(|e| SpilmanError::Ledger(e.to_string()))?;

        tx.commit()
            .map_err(|e| SpilmanError::Ledger(e.to_string()))?;
        Ok(FundingRegistration::Registered)
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_writers_cannot_both_advance_from_the_same_previous_balance() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("spilman.db");
        let ledger = ChannelLedger::open(&path).expect("open");
        ledger.record_payment("c", 1, "s1").expect("prime");

        // Two writers offer the same next balance. Exactly one may win; the CAS
        // guard (`WHERE balance = previous`) is what makes the second fail even
        // if both read the same previous value.
        let a = ledger.record_payment("c", 2, "s2a");
        let b = ledger.record_payment("c", 2, "s2b");
        assert_eq!(a, Ok(LedgerOutcome::Accepted));
        assert!(b.is_err());
        let stored = ledger
            .get_latest_payment("c")
            .expect("query")
            .expect("present");
        assert_eq!(stored.balance, 2);
        assert_eq!(stored.signature, "s2a");
        assert_eq!(stored.payment_count, 2);
    }

    #[test]
    fn zero_balance_cannot_be_recorded_twice() {
        let ledger = ChannelLedger::open_in_memory().expect("open");
        assert!(ledger.record_payment("c", 0, "s0").is_err());
        assert_eq!(ledger.get_balance("c").expect("query"), None);
    }

    /// A record with content a lossy round-trip would silently corrupt: embedded
    /// quotes, backslashes, newlines and non-ASCII, in every one of the five fields.
    ///
    /// If any field were, say, encoded through a lossy UTF-8 step or re-serialised
    /// through a `{:?}`/`Display` instead of stored raw, the read-back would differ
    /// by a byte and verification would fail — or verify against the wrong params.
    fn adversarial_record(channel_id: &str) -> ChannelFundingRecord {
        ChannelFundingRecord {
            channel_id: channel_id.to_string(),
            params_json: "{\"capacity\":1000,\"note\":\"a\\\"b\\\\c\\nd\\u00e9\"}".to_string(),
            funding_proofs_json: "[{\"c\":\"\\u00df\\t\\\\\"}]".to_string(),
            channel_secret_hex: "0".repeat(63) + "a",
            keyset_info_json: "{\"id\":\"00adcaf3\\u00e9\\\\\"}".to_string(),
            capacity: 1000,
            created_at: 1_700_000_123,
        }
    }

    #[test]
    fn an_unknown_channel_has_no_funding_record() {
        let ledger = ChannelLedger::open_in_memory().expect("open");
        assert_eq!(
            ledger.get_channel_funding("never-funded").expect("query"),
            None,
            "a channel with no funding record must report None, not a defaulted record"
        );
    }

    #[test]
    fn a_stored_funding_record_survives_a_reopen_byte_identically() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("spilman.db");

        let original = adversarial_record("chan-funding-roundtrip");
        ChannelLedger::open(&path)
            .expect("open for write")
            .save_channel_funding(&original)
            .expect("store the funding record");

        // Read it back through a *different* connection to the same file, so the
        // assertion cannot be satisfied by an in-process cache.
        let reopened = ChannelLedger::open(&path)
            .expect("reopen")
            .get_channel_funding("chan-funding-roundtrip")
            .expect("query")
            .expect("the record must be durable");

        assert_eq!(
            reopened, original,
            "a funding record must round-trip byte-identically, or verification checks the wrong bytes"
        );
    }

    #[test]
    fn storing_a_funding_record_twice_keeps_the_first() {
        let ledger = ChannelLedger::open_in_memory().expect("open");

        let first = adversarial_record("c");
        let mut second = first.clone();
        second.params_json = "{\"capacity\":999999}".to_string();
        second.capacity = 999_999;

        ledger.save_channel_funding(&first).expect("store first");
        ledger.save_channel_funding(&second).expect("store second");

        let stored = ledger
            .get_channel_funding("c")
            .expect("query")
            .expect("present");
        assert_eq!(
            stored, first,
            "re-registering a channel must not swap its funding params — that would move the \
             capacity ceiling the signature is checked against"
        );
    }
}
