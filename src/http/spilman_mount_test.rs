//! `/spilman` mount test — the OBSERVABLE half of "`enabled: false` changes nothing".
//!
//! `tests/spilman_rail_wiring.rs` proves the structural half: a disabled config
//! builds **no rail object**, so no call site can branch on one. That is necessary
//! but not sufficient — a surface could still exist and answer something.
//!
//! This file proves the observable half: with the rail off, **every `/spilman`
//! path answers 404 and no handler runs**; with the rail on, the surface responds.
//!
//! It exists because the phase-4 commit's docstring referenced it while the file
//! was absent — a claim of coverage that was not coverage.

use crate::config::schema::{Config, SpilmanConfig};
use crate::http::{create_test_router, AppState};
use crate::spilman::rail::SpilmanRail;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tower::ServiceExt;

/// A state whose config has Spilman disabled, and therefore `spilman: None`.
fn state_disabled() -> AppState {
    let mut cfg = Config::default();
    cfg.spilman = SpilmanConfig::default();
    build_state(cfg, None)
}

/// A state with the rail enabled and a real ledger on disk.
fn state_enabled(dir: &std::path::Path) -> AppState {
    let mut cfg = Config::default();
    cfg.spilman = SpilmanConfig {
        enabled: true,
        mint_url: Some("https://mint.example".to_string()),
        in_bytes_per_millisat: 22_021,
        channel_db_path: Some(dir.join("spilman.db").to_string_lossy().to_string()),
    };
    let rail = SpilmanRail::from_config(&cfg.spilman)
        .expect("enabled config is not an error")
        .expect("enabled config must build a rail");
    build_state(cfg, Some(Arc::new(rail)))
}

fn build_state(cfg: Config, spilman: Option<Arc<SpilmanRail>>) -> AppState {
    // Same construction as the sibling router tests (parity_routes_test.rs:13):
    // a fresh keypair, because MerchantIdentity has no test-only constructor.
    let secp = secp256k1::Secp256k1::new();
    let (sk, _) = secp.generate_keypair(&mut rand::thread_rng());
    AppState {
        config: Arc::new(cfg),
        identity: Arc::new(crate::identity::MerchantIdentity {
            name: "spilman-mount-test".into(),
            secret_key: sk,
        }),
        wallet: Arc::new(tokio::sync::Mutex::new(None)),
        sessions: Arc::new(tokio::sync::Mutex::new(
            crate::session::SessionManager::new(),
        )),
        quotes: Arc::new(std::sync::Mutex::new(
            crate::http::routes::quote::MintQuoteRegistry::new(),
        )),
        spilman,
    }
}

async fn get(router: axum::Router, uri: &str) -> StatusCode {
    router
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .expect("router call")
        .status()
}

async fn post_json(router: axum::Router, uri: &str, body: &str) -> StatusCode {
    router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .expect("router call")
        .status()
}

/// Like [`post_json`], but also hands back the response body so a test can assert
/// *what* the payee said, not only which status it chose.
async fn post_json_body(router: axum::Router, uri: &str, body: &str) -> (StatusCode, String) {
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .expect("router call");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).to_string())
}

/// The load-bearing assertion: with the rail OFF, the surface does not exist.
#[tokio::test]
async fn every_spilman_path_404s_when_disabled() {
    for uri in ["/spilman/params", "/spilman/status?channel_id=deadbeef"] {
        let code = get(create_test_router(state_disabled()), uri).await;
        assert_eq!(
            code,
            StatusCode::NOT_FOUND,
            "{uri} must 404 when the rail is disabled — the surface must not exist"
        );
    }

    let code = post_json(
        create_test_router(state_disabled()),
        "/spilman/payment",
        r#"{"channel_id":"deadbeef","balance":1,"signature":"00"}"#,
    )
    .await;
    assert_eq!(
        code,
        StatusCode::NOT_FOUND,
        "/spilman/payment must 404 when the rail is disabled"
    );

    // The registration endpoint is part of the same surface, so it inherits the
    // same rule: no rail -> no route -> 404, with no handler running. A body that
    // would otherwise be a perfectly good registration must still 404 here.
    let (_, body, _) = registration();
    let code = post_json_body(
        create_test_router(state_disabled()),
        "/spilman/channel",
        &body,
    )
    .await
    .0;
    assert_eq!(
        code,
        StatusCode::NOT_FOUND,
        "/spilman/channel must 404 when the rail is disabled"
    );
}

/// The retail surface must be unaffected in both directions. If enabling the rail
/// changed `/` or `/usage`, "zero behavioural change" would be false.
#[tokio::test]
async fn retail_routes_are_unaffected_either_way() {
    let dir = tempfile::tempdir().expect("tempdir");
    for uri in ["/whoami", "/usage", "/session-state"] {
        let off = get(create_test_router(state_disabled()), uri).await;
        let on = get(create_test_router(state_enabled(dir.path())), uri).await;
        assert_eq!(
            off, on,
            "{uri} must answer identically whether the rail is off or on"
        );
        assert_ne!(off, StatusCode::NOT_FOUND, "{uri} should exist at all");
    }
}

/// And with the rail ON the surface responds — otherwise "404 when disabled" could
/// pass trivially because the route never existed in the first place.
#[tokio::test]
async fn spilman_paths_respond_when_enabled() {
    let dir = tempfile::tempdir().expect("tempdir");
    let code = get(
        create_test_router(state_enabled(dir.path())),
        "/spilman/params",
    )
    .await;
    assert_eq!(
        code,
        StatusCode::OK,
        "/spilman/params must answer when the rail is enabled"
    );
}

#[tokio::test]
async fn close_authenticates_before_contacting_mint() {
    let dir = tempfile::tempdir().unwrap();
    let (code, body) = post_json_body(
        create_test_router(state_enabled(dir.path())),
        "/spilman/close",
        r#"{"channel_id":"deadbeef","balance":1,"signature":"00"}"#,
    )
    .await;
    assert_eq!(code, StatusCode::CONFLICT, "{body}");
    assert!(!body.contains("proofs"));
    assert_eq!(
        post_json(create_test_router(state_disabled()), "/spilman/close", "{}").await,
        StatusCode::NOT_FOUND
    );
}

// ── POST /spilman/channel — registration ──────────────────────────────────
//
// The unit-level pins for the registration surface. The proof that a *real*
// mint-funded channel is accepted, and that a genuinely signed payment then
// verifies against it, is in `tests/spilman_payee_verification.rs`; the full
// open -> register -> pay flow over real HTTP is in `tests/spilman_registration.rs`.

/// A registration that `validate_registration` accepts, plus its serialized body
/// and the channel id it registers.
///
/// Returned together on purpose: the fixture generates fresh keys on every call, so
/// asking for the body and the id separately would produce two *different* channels
/// and quietly assert nothing.
fn registration() -> (crate::spilman::ChannelRegistrationRequest, String, String) {
    let req = crate::spilman::registration::test_support::consistent_registration(64, None);
    let body = serde_json::to_string(&req).expect("serialize registration");
    let channel_id = req.channel_id.clone();
    (req, body, channel_id)
}

/// TEST 1 — registering a channel makes it known: `/status` stops answering 404.
///
/// This is the whole point of the endpoint. Before it, a channel could only exist
/// in-process, so a *running* module could not be told about one and every payment
/// for it was refused as `UnknownChannel`.
#[tokio::test]
async fn registering_a_channel_makes_status_find_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = state_enabled(dir.path());
    let (_req, body, channel_id) = registration();

    // Before: the channel does not exist, and the payee says so with a 404.
    let before = get(
        create_test_router(state.clone()),
        &format!("/spilman/status?channel_id={channel_id}"),
    )
    .await;
    assert_eq!(
        before,
        StatusCode::NOT_FOUND,
        "an unregistered channel must be unknown to /status"
    );

    let (code, response) =
        post_json_body(create_test_router(state.clone()), "/spilman/channel", &body).await;
    assert_eq!(
        code,
        StatusCode::OK,
        "a self-consistent registration must be accepted: {response}"
    );
    assert!(
        response.contains("registered"),
        "the response must say what happened: {response}"
    );

    // After: the channel is known. `/status` must answer something other than the
    // 404 it reserves for an unknown channel.
    let after = get(
        create_test_router(state),
        &format!("/spilman/status?channel_id={channel_id}"),
    )
    .await;
    assert_ne!(
        after,
        StatusCode::NOT_FOUND,
        "a registered channel must not be reported as unknown"
    );
}

/// TEST 2 — a duplicate registration with IDENTICAL data is idempotent.
///
/// **Chosen semantics: 200 with `outcome == "already_registered"`.** Justification:
/// the payer's intent is "make sure this record is stored", and after the second
/// POST the record *is* stored. Answering 409 would make a legitimate retry (whose
/// first response was lost in transit) indistinguishable from a real conflict, and
/// would push every payer into special-casing a non-error. The two success outcomes
/// stay distinguishable in the body, so a client that cares can tell them apart.
#[tokio::test]
async fn a_duplicate_identical_registration_is_idempotent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = state_enabled(dir.path());
    let (_req, body, _channel_id) = registration();

    let first = post_json_body(create_test_router(state.clone()), "/spilman/channel", &body).await;
    assert_eq!(first.0, StatusCode::OK, "first registration: {}", first.1);

    let second = post_json_body(create_test_router(state), "/spilman/channel", &body).await;
    assert_eq!(
        second.0,
        StatusCode::OK,
        "an identical re-registration is not an error: {}",
        second.1
    );
    assert!(
        second.1.contains("already_registered"),
        "the second response must say the record was already held, not that it was \
         freshly written: {}",
        second.1
    );
}

/// TEST 3 — a duplicate registration with DIFFERENT data is refused (409) and the
/// stored record is **untouched, byte-identical**.
///
/// This is the attack the endpoint has to survive: raising the capacity ceiling on
/// a channel that is already open, by re-registering it at a higher capacity. The
/// assertion is on the *stored record*, not only on the response, because a refusal
/// that still wrote would be the worst of both.
#[tokio::test]
async fn a_duplicate_with_different_data_is_refused_and_does_not_overwrite() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = state_enabled(dir.path());
    let (original, original_body, channel_id) = registration();

    let first = post_json_body(
        create_test_router(state.clone()),
        "/spilman/channel",
        &original_body,
    )
    .await;
    assert_eq!(first.0, StatusCode::OK, "first registration: {}", first.1);

    // Same channel id, different funding data. Note *which* field can differ here:
    // the channel id is a hash over every params field (mint, unit, capacity,
    // funding_token_amount, keyset, timestamps, both pubkeys, expiry) plus the
    // channel secret, so a record with a different capacity is a *different channel*
    // and can never collide. The only field that can change under a fixed id is the
    // funding-proof set — which is exactly the substitution a silent overwrite would
    // enable: swap the proofs a signature is checked against, keep the id.
    let mut forged = original.clone();
    forged.funding_proofs_json = r#"[{"amount":1,"id":"00","secret":"x","C":"00"}]"#.to_string();
    let forged_body = serde_json::to_string(&forged).expect("serialize forged");

    let second = post_json_body(
        create_test_router(state.clone()),
        "/spilman/channel",
        &forged_body,
    )
    .await;
    assert_eq!(
        second.0,
        StatusCode::CONFLICT,
        "a conflicting re-registration must be refused, not accepted: {}",
        second.1
    );

    // The stored record must still be the ORIGINAL, byte for byte. Read through the
    // rail, i.e. the same door payment verification uses.
    let stored = state
        .spilman
        .as_ref()
        .expect("rail is enabled")
        .channel_funding(&channel_id)
        .expect("read funding")
        .expect("the original record must still be there");
    assert_eq!(
        stored.params_json, original.params_json,
        "a refused re-registration must not move the params the signature is checked against"
    );
    assert_eq!(
        stored.capacity, original.capacity,
        "the capacity ceiling must not be raisable by re-registering"
    );
    assert_eq!(stored.channel_secret_hex, original.channel_secret_hex);
    assert_eq!(stored.keyset_info_json, original.keyset_info_json);
    assert_eq!(stored.funding_proofs_json, original.funding_proofs_json);
}

/// TEST 4 — a malformed body is a 400 and nothing is persisted.
///
/// Three flavours, one status: not JSON at all; JSON that is not a registration;
/// and JSON that parses but is not a coherent channel (an id its params do not
/// derive). None may leave a row behind.
#[tokio::test]
async fn a_malformed_registration_is_400_and_persists_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = state_enabled(dir.path());

    // A registration whose id its own params do not derive. The id is tracked so
    // the "nothing was persisted" assertion below names the *real* id that was
    // offered, not an unrelated one.
    let (_, valid_body, valid_id) = registration();
    let unbound_id = "ab".repeat(32);
    let unbound_body = serde_json::to_string(
        &crate::spilman::registration::test_support::consistent_registration(
            64,
            Some(unbound_id.clone()),
        ),
    )
    .expect("serialize");
    // The valid body with its id replaced: params that derive a *different* id.
    let mismatched_id_body = valid_body.replace(&valid_id, &unbound_id);

    for (bad, label) in [
        ("not json at all".to_string(), "not JSON"),
        (
            r#"{"hello":"world"}"#.to_string(),
            "JSON, but not a registration",
        ),
        (unbound_body, "an id its own params do not derive"),
        (
            mismatched_id_body,
            "a valid body relabelled with another id",
        ),
    ] {
        let (code, response) =
            post_json_body(create_test_router(state.clone()), "/spilman/channel", &bad).await;
        assert_eq!(
            code,
            StatusCode::BAD_REQUEST,
            "{label} must be 400: {response}"
        );
    }

    // Nothing was written — asserted through the rail's own read, so an
    // in-memory-only write would be caught too, and for the *offered* id rather
    // than a convenient one.
    let rail = state.spilman.as_ref().expect("rail is enabled");
    for id in [&valid_id, &unbound_id] {
        assert!(
            rail.channel_funding(id).expect("read funding").is_none(),
            "a refused registration must not persist channel {id}"
        );
    }
}

/// A registration for a channel whose unit this rail cannot price must be refused.
///
/// `authorize_bytes` converts the stored balance with `raw_units_to_msats(RAIL_UNIT,
/// ..)`, so a `usd`-denominated channel would have its balance read as sats.
/// Registration is the only place that can be caught before money is involved.
#[tokio::test]
async fn a_registration_in_an_unsupported_unit_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = state_enabled(dir.path());

    let (mut req, _, _) = registration();
    req.params_json = req
        .params_json
        .replace("\"unit\":\"sat\"", "\"unit\":\"usd\"");
    req.keyset_info_json = req
        .keyset_info_json
        .replace("\"unit\":\"sat\"", "\"unit\":\"usd\"");

    let (code, body) = post_json_body(
        create_test_router(state),
        "/spilman/channel",
        &serde_json::to_string(&req).expect("serialize"),
    )
    .await;
    assert_eq!(
        code,
        StatusCode::BAD_REQUEST,
        "a non-sat channel must be refused at the door: {body}"
    );
}
