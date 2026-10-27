//! `/spilman` channel routes — the payee-side HTTP surface a channel client talks to.
//!
//! # Why this exists
//!
//! `AppState.spilman` was wired by the config work but **no route was ever
//! mounted**, so a channel client had nothing to talk to and the physical-router
//! lane's four assertions could not be wired. This module closes that gap.
//!
//! # The `enabled: false` contract, observably
//!
//! When the rail is off there is **no rail object** (`AppState.spilman == None`)
//! and every route here answers `404`. That is the observable half of "enabled:
//! false changes nothing": it is not enough that the rail abstains — the surface
//! must not exist. `src/http/spilman_mount_test.rs` pins both directions.
//!
//! # Why the routes are thin
//!
//! Every decision lives in the rail (`PaymentRail::authorize_bytes` /
//! `record_payment`), never here. A handler that re-derives credit is how a payee
//! ends up serving a byte the payer's signature does not cover.

use crate::http::AppState;
use crate::spilman::rail::SpilmanRail;
use crate::spilman::{PaymentRail, SpilmanError};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Fetch the rail, or `None` when Spilman is disabled.
///
/// Returning `None` here is what makes every handler below answer 404 rather than
/// 500: a disabled rail is not an error, it is an absent surface.
fn rail(state: &AppState) -> Option<Arc<SpilmanRail>> {
    state.spilman.clone()
}

/// GET /spilman/params — what a payer needs in order to open a channel.
///
/// Deliberately does NOT leak the channel ledger or any balance: this is public
/// configuration, and a discovery endpoint that exposes state is a privacy bug.
///
/// # `receiver_pubkey`
///
/// The key a payer must name as the channel's `receiver_pubkey`. Without it a payer
/// can only open a channel against a key of its own choosing — which this payee can
/// never sign a close with, so the channel would fund at the mint and then fail at
/// `POST /spilman/close` forever (measured as HTTP 409 on real hardware). It is
/// `null` when the rail holds no receiver key: advertising a key the payee cannot
/// sign with is worse than advertising none.
///
/// Encoding is `cashu::nuts::PublicKey::to_hex()` — 33-byte compressed secp256k1, the
/// same encoding `registration.rs` puts in the channel params and the same one
/// upstream's `PublicKey::from_hex` insists on.
#[derive(Debug, Serialize)]
pub struct ParamsResponse {
    pub status: u8,
    pub mint_url: Option<String>,
    pub in_bytes_per_millisat: u64,
    /// The receiver key this payee will accept a channel for, hex-encoded compressed
    /// secp256k1. `null` when the rail holds none.
    pub receiver_pubkey: Option<String>,
}

pub async fn handle_params(State(state): State<AppState>) -> impl IntoResponse {
    match rail(&state) {
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "status": 0,
                "error": "spilman rail is not enabled"
            })),
        )
            .into_response(),
        Some(r) => Json(ParamsResponse {
            status: 1,
            mint_url: r.mint_url().map(str::to_string),
            in_bytes_per_millisat: r.in_bytes_per_millisat(),
            receiver_pubkey: r.receiver_pubkey().map(|key| key.to_hex()),
        })
        .into_response(),
    }
}

/// POST /spilman/payment — a signed balance update from the payer.
#[derive(Debug, Deserialize)]
pub struct PaymentRequest {
    pub channel_id: String,
    pub balance: u64,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct PaymentResponse {
    pub status: u8,
    /// What the ledger did with it: accepted, or refused as a replay.
    pub outcome: String,
}

pub async fn handle_payment(
    State(state): State<AppState>,
    Json(req): Json<PaymentRequest>,
) -> impl IntoResponse {
    let Some(r) = rail(&state) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "status": 0,
                "error": "spilman rail is not enabled"
            })),
        )
            .into_response();
    };

    // The rail decides. A refusal is a 409, not a 500: the request was well-formed
    // and the answer is "no", which is a different fact from "we broke".
    match r
        .record_payment(&req.channel_id, req.balance, &req.signature)
        .await
    {
        Ok(outcome) => Json(PaymentResponse {
            status: 1,
            outcome: format!("{outcome:?}"),
        })
        .into_response(),
        Err(e) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "status": 0,
                "error": e.to_string()
            })),
        )
            .into_response(),
    }
}

/// POST /spilman/channel — a payer registers an opened channel.
///
/// # Why this route exists
///
/// Without it a channel could only be registered **in-process**, so a channel
/// client talking to a *running* module could never make its channel known and
/// every payment for it was refused as `UnknownChannel`. This is the missing half
/// of the payee surface: `/payment` spends credit, `/channel` establishes what
/// credit will be checked against.
///
/// # What the handler does, and does not do
///
/// It translates. Every decision — whether the body is a coherent channel, whether
/// the id is already taken, and whether the store may be written — belongs to
/// `SpilmanRail::register_channel`. The body fields are the ledger's own names for
/// the same values (see [`crate::spilman::ledger::ChannelFundingRecord`]), so no
/// byte is renamed between the wire and the row.
///
/// # Security: registration is not a credit-forgery vector
///
/// Anyone may POST here; that is deliberate, because the payee cannot know who the
/// payer is before the payer tells it. It is safe because **registration grants no
/// credit**. Credit is granted only by [`handle_payment`] →
/// `SpilmanRail::record_payment`, which re-derives the channel from this record and
/// verifies a BIP-340 signature over `(channel_id, balance)` before the durable
/// compare-and-swap. A forged registration therefore buys the forger a channel that
/// refuses its own payments: wrong bytes make verification **fail**, and a failure
/// is a refusal, never a default-allow.
///
/// Two things follow, and both are intentional rather than oversights:
///
/// 1. Registration cannot *raise* a ceiling on an existing channel — a
///    conflicting record is refused and the stored one is left byte-identical (see
///    [`SpilmanError::ChannelAlreadyRegistered`]). An identical re-registration is
///    idempotent so a payer whose response was lost can retry.
/// 2. Registration does **not** authenticate the registrant. The funding record
///    names a mint and a keyset, and a payee with no trusted-(mint, keyset) policy
///    will happily store a self-consistent record for a channel the poster minted
///    for themselves. That is not a credit hole (the payee still verifies every
///    payment, so it never serves bytes it was not paid for) but it is an
///    unauthenticated-write surface, and it is documented in `REPORT.md` rather
///    than papered over with an invented policy.
///
/// # Why the body arrives as raw bytes
///
/// axum's `Json` extractor answers **422** for a syntactically valid body whose
/// shape is wrong (missing/wrong-typed field) while a registration that is merely
/// semantically impossible is a **400**. Same class of client error, two statuses,
/// decided by a dependency's internal split. Parsing here keeps one rule, in our
/// code: any body that cannot become a funding record is 400.
pub async fn handle_register_channel(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let Some(r) = rail(&state) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "status": 0,
                "error": "spilman rail is not enabled"
            })),
        )
            .into_response();
    };

    // The only parse in this handler. A body that is not a registration is a
    // client error (400), never a 500 and never an empty registration.
    let req: crate::spilman::ChannelRegistrationRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "status": 0,
                    "error": format!("malformed registration body: {e}")
                })),
            )
                .into_response()
        }
    };

    match r.register_channel(&req) {
        Ok(outcome) => Json(ChannelRegistrationResponse {
            status: 1,
            channel_id: req.channel_id,
            // "registered" vs "already_registered": both are 200, because in both
            // cases the record the payer asked for is the record that is durable.
            // A payer retrying after a lost response must not be told it failed.
            outcome: match outcome {
                crate::spilman::FundingRegistration::Registered => "registered".to_string(),
                crate::spilman::FundingRegistration::AlreadyRegistered => {
                    "already_registered".to_string()
                }
            },
        })
        .into_response(),
        // 409 for "this id exists with different funding data": the request was
        // well-formed and the answer is "no". Never a silent overwrite.
        Err(e @ SpilmanError::ChannelAlreadyRegistered { .. }) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "status": 0,
                "error": e.to_string()
            })),
        )
            .into_response(),
        // 400 for a body that cannot become a usable record. Malformed JSON is
        // rejected by axum's extractor before the handler runs (also 400).
        Err(e @ SpilmanError::InvalidRegistration { .. }) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "status": 0,
                "error": e.to_string()
            })),
        )
            .into_response(),
        // A store failure is ours, not the caller's, and it must not read as a
        // successful registration: 500 with the reason.
        Err(e) => {
            tracing::error!(channel_id = %req.channel_id, error = %e,
                "spilman channel registration failed to persist");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "status": 0,
                    "error": e.to_string()
                })),
            )
                .into_response()
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ChannelRegistrationResponse {
    pub status: u8,
    pub channel_id: String,
    /// `registered` (newly stored) or `already_registered` (identical record was
    /// already durable). Both mean "the record you sent is the record I hold".
    pub outcome: String,
}

/// GET /spilman/status?channel_id=... — the payee's view of one channel.
#[derive(Debug, Deserialize)]
pub struct StatusQuery {
    pub channel_id: String,
}

pub async fn handle_status(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<StatusQuery>,
) -> impl IntoResponse {
    let Some(r) = rail(&state) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "status": 0,
                "error": "spilman rail is not enabled"
            })),
        )
            .into_response();
    };

    // "Is this channel known?" is a question about the **funding record**, not the
    // balance. A channel that has been registered but not yet paid has no balance
    // row at all, and `authorize_bytes` reads a missing balance as `Deny` — which
    // is right for "may I serve these bytes" and wrong for "do I know this
    // channel". Answering 404 for a registered channel would tell a payer its
    // registration failed when it did not, so the two questions are asked
    // separately here.
    let known = match r.is_known_channel(&q.channel_id) {
        Ok(known) => known,
        Err(e) => {
            // An unreadable ledger must not be reported as "unknown": that would
            // tell a payer its funded channel does not exist.
            tracing::error!(channel_id = %q.channel_id, error = %e,
                "spilman funding read failed; refusing to answer /status");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "status": 0,
                    "error": "channel ledger unreadable"
                })),
            )
                .into_response();
        }
    };
    if !known {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "status": 0,
                "error": "unknown channel"
            })),
        )
            .into_response();
    }

    // Known: report the credit decision and the balance it is derived from.
    let decision = r.authorize_bytes(&q.channel_id, 0, 0).await;
    // A failed READ is not "no balance". `unwrap_or(None)` mapped a ledger error to
    // `balance: null`, which reads as "registered but never paid" -- the opposite
    // of what happened -- and contradicted the 500 the funding read above returns
    // for the same class of failure.
    let balance = match r.channel_balance(&q.channel_id) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(channel_id = %q.channel_id, error = %e,
                "spilman balance read failed; refusing to answer /status");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "status": 0,
                    "error": "channel ledger unreadable"
                })),
            )
                .into_response();
        }
    };
    Json(serde_json::json!({
        "status": 1,
        "channel_id": q.channel_id,
        "decision": format!("{decision:?}"),
        // Raw channel units (sats) currently credited. `null` when the channel is
        // registered but has never been paid — deliberately distinct from 0.
        "balance": balance,
    }))
    .into_response()
}

/// POST /spilman/close — only a durably completed close returns a receipt.
pub async fn handle_close(
    State(state): State<AppState>,
    Json(payment): Json<cdk_spilman::Payment>,
) -> axum::response::Response {
    let Some(r) = rail(&state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let refuse = |status, message: &str| {
        (status, Json(serde_json::json!({"error": message}))).into_response()
    };
    match r.authenticated_close_receipt(&payment) {
        Ok(Some(receipt)) => return Json(receipt).into_response(),
        Ok(None) => {}
        Err(_) => return refuse(StatusCode::CONFLICT, "close authorization refused"),
    }
    // Recovery uses the journal's exact outputs; never discover new keys for it.
    if r.close_status(&payment.channel_id).is_err() {
        use cdk_spilman::configurable_networking::{
            build_keyset_info_json, fetch_all_keysets_from_mint,
        };
        let Some(mint) = r.mint_url() else {
            return refuse(StatusCode::CONFLICT, "mint not configured");
        };
        let discovery = match fetch_all_keysets_from_mint(mint).await {
            Ok(v) => v,
            Err(_) => return refuse(StatusCode::BAD_GATEWAY, "mint keyset discovery failed"),
        };
        let now = crate::spilman::payer::now_seconds();
        let Some(keys) = discovery.keysets.iter().find(|k| {
            k.active
                && k.unit == cashu::nuts::CurrencyUnit::Sat
                && k.final_expiry.is_none_or(|expiry| expiry > now)
        }) else {
            return refuse(StatusCode::BAD_GATEWAY, "no usable mint keyset");
        };
        let info = build_keyset_info_json(
            &keys.id,
            &keys.unit,
            &keys.keys,
            keys.input_fee_ppk,
            keys.final_expiry,
        );
        if r.prepare_close(
            &payment.channel_id,
            payment.balance,
            &payment.signature,
            &info,
        )
        .is_err()
        {
            return refuse(StatusCode::CONFLICT, "close preparation refused");
        }
    }
    // The upstream synchronous adapter bridges into Tokio. Keep SQLite and
    // blocking network work off the HTTP task, including on current-thread tests.
    let execution_rail = r.clone();
    let id = payment.channel_id.clone();
    let result = tokio::task::spawn_blocking(move || {
        let network = cdk_spilman::configurable_networking::ReqwestClientNetworking::new(
            std::time::Duration::from_secs(15),
        )
        .map_err(|e| e.to_string())?;
        execution_rail
            .execute_close_with_network(&id, &network)
            .map_err(|e| e.to_string())
    })
    .await;
    if !matches!(result, Ok(Ok(_))) {
        return refuse(
            StatusCode::BAD_GATEWAY,
            "close incomplete; retry the same authorized payment",
        );
    }
    match r.authenticated_close_receipt(&payment) {
        Ok(Some(mut receipt)) => {
            receipt.already_closed = false;
            Json(receipt).into_response()
        }
        _ => refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "durable close receipt unavailable",
        ),
    }
}

/// Build the `/spilman` sub-router.
///
/// Mounted by `create_router` **only when the rail exists**, so a disabled rail
/// yields 404 on every path here with no handler ever running.
pub fn spilman_router() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/params", axum::routing::get(handle_params))
        .route("/channel", axum::routing::post(handle_register_channel))
        .route("/payment", axum::routing::post(handle_payment))
        .route("/close", axum::routing::post(handle_close))
        .route("/status", axum::routing::get(handle_status))
        // The ONE production writer of `CustomerSession.channel_id`. Without it the
        // access path is wired and unreachable.
        .route("/access", axum::routing::post(handle_bind_access))
}

// ── the ACCESS binding: MAC -> channel ────────────────────────────────────────
//
// WHY THIS ROUTE EXISTS
//
// A cold review found the feature unreachable: `channel_id` was set to `None` at
// `session/mod.rs:181` and **nothing in production ever assigned a non-None
// value**. The access-path unit tests set the field directly, so they passed
// while no real router could ever bind a client to a channel. `effective_allotment`
// therefore always returned at its first branch, and a channel bought a client
// nothing -- exactly the gap the access-path work was supposed to close, reopened
// one layer up.
//
// This route is the missing writer. It is the whole point of the surface: without
// it, `/spilman/channel` registers a channel nobody can spend and `/spilman/payment`
// records credit no session can draw on.

/// POST /spilman/access — bind a client MAC to a Spilman channel.
#[derive(Debug, Deserialize)]
pub struct AccessRequest {
    /// The client whose access this channel funds.
    pub mac: String,
    /// The channel that pays for it. Must already be registered.
    pub channel_id: String,
}

/// Bind (or unbind) a MAC's access to a channel.
///
/// # What this does NOT do
///
/// It does not grant access and does not open a gate. It records *which channel
/// pays for this client*; whether the client is served is decided by the sweep,
/// which recomputes the effective ceiling from the channel's **verified** balance
/// every tick. A binding to a channel with no verified credit buys nothing, which
/// is the correct outcome: the binding is a pointer, not a payment.
///
/// # Why the channel must already be registered
///
/// Binding to an unknown id would create a session that can never be credited and
/// whose refusal reason would be indistinguishable from a typo. Refusing here
/// names the problem at the point it is introduced.
pub async fn handle_bind_access(
    State(state): State<AppState>,
    Json(req): Json<AccessRequest>,
) -> impl IntoResponse {
    let Some(r) = rail(&state) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "status": 0,
                "error": "spilman rail is not enabled"
            })),
        )
            .into_response();
    };

    // An unreadable ledger must not be reported as "unknown channel": that would
    // blame the caller for our failure.
    match r.is_known_channel(&req.channel_id) {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "status": 0,
                    "error": "unknown channel",
                    "channel_id": req.channel_id
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(channel_id = %req.channel_id, error = %e,
                "spilman funding read failed; refusing to bind access");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "status": 0,
                    "error": "channel ledger unreadable"
                })),
            )
                .into_response();
        }
    }

    let mut sessions = state.sessions.lock().await;
    match sessions.bind_channel(&req.mac, &req.channel_id) {
        Ok(Some(effective)) => Json(serde_json::json!({
            "status": 1,
            "mac": req.mac,
            "channel_id": req.channel_id,
            // The ceiling the sweep will honour until it next recomputes from the
            // channel's verified balance. Stated so the caller can see that
            // binding alone grants no bytes.
            "effective_allotment": effective,
        }))
        .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "status": 0,
                "error": "no live session for this mac; a binding attaches to an \
                          existing session and does not create access"
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "status": 0,
                "error": e.to_string()
            })),
        )
            .into_response(),
    }
}
