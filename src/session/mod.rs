//! CustomerSession and SessionManager — session tracking.
//!
//! Two modes, deliberately:
//!
//! * `SessionManager::new()` is in-memory. Kept for tests and for callers that
//!   genuinely want a throwaway manager.
//! * `SessionManager::open(path)` is durable (see `store`). A process restart
//!   preserves a paid session; an expired one is closed rather than resurrected.
//!
//! The in-memory mode is NOT the production path. Losing a paid session on
//! restart silently cuts off a paying customer, which is why P1 exists.

pub mod store;

use std::collections::HashMap;
use std::path::Path;

/// ADR-0006 §4: how often the gate-close sweep runs. 30s was the operator-accepted
/// proposal: an overrun of up to one interval is a bounded, explainable loss, and each
/// tick costs one ndsctl exec per terminal session.
pub const SWEEP_INTERVAL_SECS: u64 = 30;

/// ADR-0006 §1/§3: which sessions are TERMINAL (their gate must close) at sweep time.
/// Pure decision over the map so it is testable without a router.
/// Terminal = expired (expiry <= now) or exhausted (used >= allotment).
pub fn terminal_sessions(
    sessions: &std::collections::HashMap<String, CustomerSession>,
    now: u64,
) -> Vec<String> {
    sessions
        .iter()
        .filter(|(_, s)| s.expiry <= now || s.used >= s.allotment)
        .map(|(mac, _)| mac.clone())
        .collect()
}

pub use store::{SessionStore, StoreError, StoredQuote};

pub mod channel_credit;

/// A single customer session keyed by MAC address.
#[derive(Debug, Clone)]
pub struct CustomerSession {
    /// Client MAC address — the primary key.
    pub mac: String,
    /// Total allotment in millisatoshis (time metric) or bytes (bytes metric).
    pub allotment: u64,
    /// How much has been consumed so far.
    pub used: u64,
    /// Metric type: "bytes" or "time".
    pub metric: String,
    /// Unix timestamp when the session expires.
    pub expiry: u64,
    /// Unix timestamp when the session was granted.
    pub granted_at: u64,
    /// Allotment bought with tokens.
    ///
    /// Kept separate from `allotment` because `allotment` is the EFFECTIVE ceiling:
    /// it is this number plus whatever a bound Spilman channel has verifiably paid
    /// for. With no channel bound the two are equal, which is what makes the
    /// rail-off path bit-identical to the old behaviour rather than merely similar.
    pub retail_allotment: u64,
    /// The Spilman channel this session draws credit from, if any.
    ///
    /// `None` is the retail path and is the overwhelmingly common case.
    pub channel_id: Option<String>,
}

/// Session manager. `store == None` means in-memory (tests / throwaway);
/// `Some` means every mutation is durable.
pub struct SessionManager {
    pub sessions: HashMap<String, CustomerSession>,
    store: Option<SessionStore>,
    /// ADR-0002: per-MAC batching state for the usage counter.
    pending: HashMap<String, UsageFlush>,
}

/// ADR-0002 batching state for one session's `used` counter.
#[derive(Debug, Clone, Copy)]
struct UsageFlush {
    /// Value currently on disk.
    persisted: u64,
    /// When the last successful flush happened (unix seconds).
    last_flush: u64,
}

/// Flush the usage counter at most this often.
const USAGE_FLUSH_SECS: u64 = 5;
/// ...or once this fraction of the allotment has moved (parts per hundred).
const USAGE_FLUSH_PERCENT: u64 = 5;

impl SessionManager {
    /// Create a new empty in-memory SessionManager.
    pub fn new() -> Self {
        SessionManager {
            sessions: HashMap::new(),
            store: None,
            pending: HashMap::new(),
        }
    }

    /// Open a durable manager at `path`.
    ///
    /// Recovery is conservative and explicit:
    /// * sessions whose expiry passed while we were down are **closed**, not
    ///   revived — restarting must not extend access;
    /// * still-valid sessions are reloaded with `used` intact — resetting it
    ///   would hand out free bytes on every restart;
    /// * unpaid quotes past their deadline are marked expired, never deleted
    ///   (a paid one must stay redeemable).
    ///
    /// Returns `Err` on a corrupt or unknown-schema store. Refusing to start is
    /// deliberate: starting empty would grant fresh access to every client.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let store = SessionStore::open(path)?;
        let now = now_secs();

        let closed = store.close_expired(now)?;
        for s in &closed {
            let down_for = now.saturating_sub(s.expiry);
            // ADR-0002: an expired-while-down session is a terminal transition, so its
            // final usage is recorded for audit before the row disappears.
            let _ = store.record_closed_usage(&s.mac, s.used);
            tracing::info!(
                mac = %s.mac,
                expired_for_secs = down_for,
                used = s.used,
                allotment = s.allotment,
                "closed session that expired while the daemon was down"
            );
        }
        let expired_quotes = store.expire_unpaid_quotes(now)?;
        if expired_quotes > 0 {
            tracing::info!(count = expired_quotes, "expired unpaid mint quotes");
        }

        let mut sessions = HashMap::new();
        for s in store.load_sessions()? {
            sessions.insert(s.mac.clone(), s);
        }

        Ok(SessionManager {
            sessions,
            store: Some(store),
            pending: HashMap::new(),
        })
    }

    /// Whether this manager persists to disk.
    pub fn is_durable(&self) -> bool {
        self.store.is_some()
    }

    /// The underlying store, if durable. Used by the quote registry.
    pub fn store(&self) -> Option<&SessionStore> {
        self.store.as_ref()
    }

    /// Create and store a new session for the given MAC.
    /// Overwrites any existing session for the same MAC.
    pub fn create_session(
        &mut self,
        mac: &str,
        allotment: u64,
        metric: &str,
        duration_secs: u64,
    ) -> CustomerSession {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let session = CustomerSession {
            mac: mac.to_string(),
            allotment,
            used: 0,
            metric: metric.to_string(),
            expiry: now + duration_secs,
            granted_at: now,
            // No channel by default: a token purchase is the retail path.
            retail_allotment: allotment,
            channel_id: None,
        };
        self.sessions.insert(mac.to_string(), session.clone());
        self.pending.insert(
            mac.to_string(),
            UsageFlush {
                persisted: 0,
                last_flush: now_secs(),
            },
        );
        if let Some(st) = &self.store {
            if let Err(e) = st.upsert_session(&session) {
                // A session we could not persist is a session we do not have:
                // remove it from memory so we never advertise unbacked access.
                self.sessions.remove(mac);
                tracing::error!(mac = %mac, error = %e, "failed to persist session; refusing to grant");
                return CustomerSession {
                    allotment: 0,
                    expiry: 0,
                    ..session
                };
            }
        }
        session
    }

    /// All sessions, cloned out. Used by the boot-time continuity restore, which must
    /// not hold the lock while awaiting ndsctl.
    pub fn snapshot(&self) -> Vec<CustomerSession> {
        self.sessions.values().cloned().collect()
    }

    /// A live reference to the session map, for the sweep's terminal-sessions filter.
    pub fn map_ref(&self) -> &HashMap<String, CustomerSession> {
        &self.sessions
    }

    /// Move a session record from one MAC to another (rebind): the paid
    /// allotment, the usage counter and the expiry all follow the customer.
    /// Persisted, so a restart does not split the session across two addresses.
    pub async fn move_session(&mut self, from: &str, to: &str) -> Result<(), String> {
        let Some(s) = self.sessions.remove(from) else {
            return Ok(()); // nothing to move; the ticket already moved
        };
        if let Some(st) = &self.store {
            let _ = st.delete_session(from);
            let _ = st.upsert_session(&s);
        }
        if let Some(p) = self.pending.remove(from) {
            self.pending.insert(to.to_string(), p);
        }
        self.sessions.insert(to.to_string(), s);
        Ok(())
    }

    /// Look up a session by MAC address.
    pub fn get_session(&self, mac: &str) -> Option<&CustomerSession> {
        self.sessions.get(mac)
    }

    /// Check whether the session for `mac` is active (not expired, usage
    /// under allotment). Returns false if no session exists.
    /// Add `extra` to a live session's allotment, preserving usage.
    ///
    /// A second purchase must EXTEND a session, not replace it. Replacing would reset
    /// `used`, so a device that bought again mid-session would appear to have consumed
    /// nothing — an accounting divergence, not a convenience.
    ///
    /// Returns the new allotment, or `None` when there is no live session to extend.
    pub fn extend_session(
        &mut self,
        mac: &str,
        extra: u64,
        metric: &str,
        ttl_secs: u64,
    ) -> Option<u64> {
        let (used, total) = {
            let s = self.sessions.get(mac)?;
            (s.used, s.allotment.saturating_add(extra))
        };
        // `create_session` persists the row; restore `used` afterwards so the extension
        // is additive rather than resetting the client's consumption to zero.
        self.create_session(mac, total, metric, ttl_secs);
        self.update_usage(mac, used);
        Some(total)
    }

    pub fn is_active(&self, mac: &str) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        match self.sessions.get(mac) {
            Some(s) => s.expiry > now && s.used < s.allotment,
            None => false,
        }
    }

    /// Remove a session by MAC. No-op if the MAC has no session.
    ///
    /// Deletion is persisted: a revoked session that reappeared after restart
    /// would be a re-grant nobody paid for.
    pub fn revoke_session(&mut self, mac: &str) {
        // Terminal: persist the exact final value BEFORE deleting the row.
        self.flush_usage(mac);
        if let Some(st) = &self.store {
            if let Some(s) = self.sessions.get(mac) {
                let _ = st.record_closed_usage(mac, s.used);
            }
        }
        self.sessions.remove(mac);
        self.pending.remove(mac);
        if let Some(st) = &self.store {
            if let Err(e) = st.delete_session(mac) {
                tracing::error!(mac = %mac, error = %e, "failed to delete revoked session");
            }
        }
    }

    /// Remove all expired sessions. Returns the number removed.
    pub fn cleanup_expired(&mut self) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expired_macs: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.expiry <= now)
            .map(|(mac, _)| mac.clone())
            .collect();
        let count = expired_macs.len();
        for mac in &expired_macs {
            self.flush_usage(mac);
            if let Some(st) = &self.store {
                if let Some(s) = self.sessions.get(mac) {
                    let _ = st.record_closed_usage(mac, s.used);
                }
            }
            self.sessions.remove(mac);
            self.pending.remove(mac);
            if let Some(st) = &self.store {
                if let Err(e) = st.delete_session(mac) {
                    tracing::error!(mac = %mac, error = %e, "failed to delete expired session");
                }
            }
        }
        count
    }

    /// Update the `used` field for a session. No-op if session doesn't exist.
    ///
    /// ADR-0002: the in-memory value is always current, but the disk write is
    /// BATCHED. `used` is a cache of a value `ndsctl` already knows, so paying a
    /// fsync per metering tick applies the money rule to the wrong thing -- while
    /// never persisting it is worse, because `ndsctl` counters reset on daemon
    /// restart and a client would be handed a fresh allotment it already consumed.
    ///
    /// Flush when either trigger fires:
    ///   * `USAGE_FLUSH_SECS` elapsed since the last flush, or
    ///   * the counter moved by `USAGE_FLUSH_PERCENT` of the allotment, or
    ///   * a terminal transition (see `flush_usage`, called by revoke/expire).
    pub fn update_usage(&mut self, mac: &str, used: u64) {
        let allotment = match self.sessions.get_mut(mac) {
            Some(s) => {
                s.used = used;
                s.allotment
            }
            None => return,
        };
        if self.store.is_none() {
            return;
        }

        let now = now_secs();
        let state = self.pending.entry(mac.to_string()).or_insert(UsageFlush {
            // A session we did not create (reloaded from disk) starts from whatever
            // was persisted, so the first small delta is not treated as a jump.
            persisted: used,
            last_flush: now,
        });

        let elapsed = now.saturating_sub(state.last_flush) >= USAGE_FLUSH_SECS;
        let delta = used.saturating_sub(state.persisted);
        let pct_trigger =
            allotment > 0 && delta.saturating_mul(100) >= allotment * USAGE_FLUSH_PERCENT;

        if elapsed || pct_trigger {
            state.persisted = used;
            state.last_flush = now;
            if let Some(st) = &self.store {
                if let Err(e) = st.set_usage(mac, used) {
                    tracing::error!(mac = %mac, used, error = %e, "failed to persist usage");
                }
            }
        }
    }

    /// Terminal-transition flush, callable from the sweep (ADR-0006 + ADR-0002).
    pub fn flush_for_sweep(&mut self, mac: &str) {
        self.flush_usage(mac);
    }

    /// Write the pending usage for `mac` immediately, if any.
    ///
    /// Called by every terminal transition (revoke / expire / close) so the persisted
    /// number is EXACT at the moment the session stops mattering to write more. That
    /// is the number a dispute would be settled against.
    fn flush_usage(&mut self, mac: &str) {
        let Some(st) = &self.store else { return };
        let Some(s) = self.sessions.get(mac) else {
            return;
        };
        let used = s.used;
        let should = self
            .pending
            .get(mac)
            .map(|p| p.persisted != used)
            .unwrap_or(true);
        if should {
            if let Err(e) = st.set_usage(mac, used) {
                tracing::error!(mac = %mac, used, error = %e, "failed to flush usage");
            }
        }
        if let Some(p) = self.pending.get_mut(mac) {
            p.persisted = used;
            p.last_flush = now_secs();
        }
    }

    /// Test-only: pretend the last flush happened `secs` seconds ago, so the time
    /// trigger can be exercised without sleeping in a unit test.
    #[doc(hidden)]
    pub fn force_flush_after_for_test(&mut self, secs: u64) {
        for p in self.pending.values_mut() {
            p.last_flush = p.last_flush.saturating_sub(secs);
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod store_test;

#[cfg(test)]
mod usage_batching_test;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod gate_close_test;
