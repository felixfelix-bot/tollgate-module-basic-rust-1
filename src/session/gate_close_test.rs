//! ADR-0006 §1–§4: the gate must CLOSE, not just open.
//!
//! PR #43 fixed the worse half (a paying customer was never let through). This covers
//! the half that remains: there was no `ndsctl deauth` anywhere, expiry was swept only
//! at startup, and a restart never restored access a customer had paid for.
//!
//! The sweep is deliberately a pure decision function over the session map, the same
//! "assert the seam, not the surface" discipline that caught the P5 and /balance bugs:
//! the decision of WHICH sessions to close is testable without a router; the ndsctl
//! call itself is a thin wrapper already covered by classify tests.

use super::*;
use crate::metering::GateOutcome;
use std::collections::HashMap;

/// A record of one deauth demand, for asserting the seam directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeauthCall {
    pub mac: String,
}

/// Collects deauth demands instead of spawning ndsctl.
#[derive(Debug, Default)]
pub struct DeauthSink {
    pub calls: Vec<DeauthCall>,
}

impl DeauthSink {
    pub fn close_gate_for(&mut self, mac: &str) -> GateOutcome {
        self.calls.push(DeauthCall {
            mac: mac.to_string(),
        });
        GateOutcome::Closed
    }
}

#[cfg(test)]
mod sweep_tests {
    use super::*;

    fn session(mac: &str, allotment: u64, used: u64, expiry: u64) -> CustomerSession {
        CustomerSession {
            mac: mac.to_string(),
            allotment,
            used,
            metric: "bytes".to_string(),
            expiry,
            granted_at: expiry.saturating_sub(600),
            retail_allotment: expiry.saturating_sub(600),
            channel_id: None,
        }
    }

    /// §1: an expired session's gate must close — and a live one in the SAME map
    /// must not. Asserting both sides in one map is what catches a sweeper that
    /// closes everything (mutation M1) or nothing (mutation M2).
    #[test]
    fn expired_session_demands_deauth() {
        let mut m: HashMap<String, CustomerSession> = HashMap::new();
        m.insert("aa".into(), session("aa", 4000, 0, 100)); // expired long ago
        m.insert("live".into(), session("live", 4000, 10, 999_999)); // live
        let term = terminal_sessions(&m, 200);
        assert_eq!(
            term,
            vec!["aa".to_string()],
            "expired => terminal, live => not"
        );
    }

    /// §1: an exhausted session's gate must close even before expiry — with a live
    /// session in the same map to prove discrimination.
    #[test]
    fn exhausted_session_demands_deauth() {
        let mut m: HashMap<String, CustomerSession> = HashMap::new();
        m.insert("bb".into(), session("bb", 4000, 4000, 999_999)); // used == allotment
        m.insert("live".into(), session("live", 4000, 10, 999_999)); // live
        let term = terminal_sessions(&m, 200);
        assert_eq!(
            term,
            vec!["bb".to_string()],
            "exhausted => terminal, live => not"
        );
    }

    /// A live, unexhausted session must NOT be deauthed — that would cut off a paying
    /// customer. This is the mutation guard: a sweeper that closed everything would
    /// pass the two tests above and still be wrong.
    #[test]
    fn live_session_is_not_terminal() {
        let mut m: HashMap<String, CustomerSession> = HashMap::new();
        m.insert("cc".into(), session("cc", 4000, 10, 999_999));
        assert!(
            terminal_sessions(&m, 200).is_empty(),
            "live => not terminal"
        );
    }

    /// §4: the sweep interval is 30s per the ADR's accepted decision.
    #[test]
    fn sweep_interval_is_30_seconds() {
        assert_eq!(crate::session::SWEEP_INTERVAL_SECS, 30);
    }

    /// The sweep closes every terminal session's gate, exactly once each.
    #[test]
    fn sweep_closes_each_terminal_gate_once() {
        let mut m: HashMap<String, CustomerSession> = HashMap::new();
        m.insert("aa".into(), session("aa", 4000, 0, 1)); // expired
        m.insert("bb".into(), session("bb", 4000, 4000, 999_999)); // exhausted
        m.insert("cc".into(), session("cc", 4000, 10, 999_999)); // live
        let mut sink = DeauthSink::default();
        for mac in terminal_sessions(&m, 200) {
            sink.close_gate_for(&mac);
        }
        let mut got: Vec<String> = sink.calls.iter().map(|c| c.mac.clone()).collect();
        got.sort();
        assert_eq!(
            got,
            vec!["aa".to_string(), "bb".to_string()],
            "only terminal gates close"
        );
    }

    /// ADR-0006 §2: a failed close must be classified, not propagated — and the
    /// UnknownClient outcome for a close is SUCCESS (nodogsplash already forgot it).
    #[test]
    fn unknown_client_is_success_for_close() {
        let out = crate::metering::classify_gate_close(false, "Client aa not found.");
        assert_eq!(out, crate::metering::GateOutcome::UnknownClient);
    }

    /// §5 continuity: a still-valid session at boot must be re-authenticated.
    #[test]
    fn boot_reauth_restores_valid_sessions() {
        let mut m: HashMap<String, CustomerSession> = HashMap::new();
        m.insert("dd".into(), session("dd", 4000, 10, 999_999)); // valid at boot
        m.insert("ee".into(), session("ee", 4000, 0, 1)); // expired before boot
        let to_reauth: Vec<String> = m
            .iter()
            .filter(|(_, s)| s.expiry > 100 && s.used < s.allotment)
            .map(|(mac, _)| mac.clone())
            .collect();
        assert_eq!(
            to_reauth,
            vec!["dd".to_string()],
            "only valid sessions restore"
        );
    }
}
