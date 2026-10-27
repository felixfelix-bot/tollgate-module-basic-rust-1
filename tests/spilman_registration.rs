//! Channel protocol end to end, over **real HTTP** against a **running router**.
//!
//! `src/http/spilman_mount_test.rs` proves the registration surface's status codes
//! with bodies built by a test fixture. That is necessary and not sufficient: it
//! never sends a *real* channel. This suite is the honest version — it opens a
//! channel against an in-process `cdk-spilman-test-mint`, funds it through a real
//! mint swap, registers it with a router listening on a real TCP port, signs a
//! payment with the payer's own bridge, and requires the running payee to credit it.
//!
//! ```text
//! cargo test --test spilman_registration -- --ignored --nocapture
//! ```
//!
//! # Why `#[ignore]`
//!
//! Same reason as `tests/spilman_payer_lifecycle.rs` and
//! `tests/spilman_payee_verification.rs`: it needs the in-process mint harness, so
//! the default suite (and CI) stays fast. Nothing here is weakened to make that
//! work — the gate is on *cost*, not on assertion strength.
//!
//! # What only this test can prove
//!
//! 1. **The registration endpoint is reachable at all** — over a socket, through the
//!    real axum stack with its middleware, not through `oneshot`.
//! 2. **A funding record written by HTTP verifies payments.** The in-process suites
//!    write the record directly; here it arrives as JSON over the wire, exactly as a
//!    payer driver would send it, and then a real signature is checked against it.
//! 3. **The credit is durable and spendable** — `/status` reports the balance and
//!    `authorize_bytes` allows exactly the bytes that balance buys.
//!
//! # The payee's identity is real, not implied
//!
//! The payee is configured with the **test mint's actual URL** and holds a **receiver
//! key** that the channel is addressed to. Both are load-bearing since registration
//! started enforcing them: a body addressed to another key, or funded at another mint,
//! is refused before anything is stored — because such a channel could be funded and
//! then never settled. A placeholder mint here would only prove the refusal path.

use std::sync::Arc;
use std::time::Duration;

use cashu::nuts::{CurrencyUnit, SecretKey};
use cdk_spilman::{
    build_cashu_b_token, parse_keyset_info_from_json, ConfigurableClientHost, SpilmanClientBridge,
    SqliteClientStorage,
};
use cdk_spilman_test_mint::{serve_existing_mint_with_shutdown, TestMintConfig, TestMintHelper};
use tollgate_module_basic_rust::config::schema::{Config, SpilmanConfig};
use tollgate_module_basic_rust::http::{create_router, AppState};
use tollgate_module_basic_rust::spilman::payer::{
    self, ChannelOpening, DEFAULT_CHANNEL_LIFETIME_SECS,
};
use tollgate_module_basic_rust::spilman::payer_driver::PayeeClient;
use tollgate_module_basic_rust::spilman::rail::SpilmanRail;
use tollgate_module_basic_rust::spilman::registration::ChannelRegistrationRequest;
use tollgate_module_basic_rust::spilman::{PaymentRail, RailDecision};

/// A spawned server task that is aborted when this value is dropped.
///
/// Holding a `JoinHandle` and dropping it does **not** stop the task — dropping a
/// handle detaches it. A test that leaks its payee would hold the port and the ledger
/// for the rest of the run, so the abort is explicit and tied to ownership.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl AbortOnDrop {
    /// Take ownership of a task, discarding its (differing) output type.
    fn new<T: Send + 'static>(handle: tokio::task::JoinHandle<T>) -> Self {
        Self(tokio::spawn(async move {
            // The task's own result is irrelevant here: if it failed, the `wait_until_up`
            // that follows will say so with a better message than a join error would.
            let _ = handle.await;
        }))
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Capacity of the channel these tests open, in sats.
const CHANNEL_CAPACITY: u64 = 64;

/// What a running payee + funded payer looks like.
struct LivePayee {
    /// Kept alive so the ledger and payer files survive the test.
    _dir: tempfile::TempDir,
    /// Kept alive because the served mint borrows the `Arc`.
    _helper: TestMintHelper,
    /// Aborts the payee's axum server on drop. Generic over the task's output:
    /// axum returns `Result<(), io::Error>` and the mint helper returns
    /// `Result<(), anyhow::Error>`, and neither is worth flattening just to store.
    _payee_server: AbortOnDrop,
    /// Aborts the test mint's server on drop.
    _mint_server: AbortOnDrop,
    client: PayeeClient,
    rail: Arc<SpilmanRail>,
    bridge: SpilmanClientBridge<
        ConfigurableClientHost<SqliteClientStorage>,
        cdk_spilman::ReqwestClientNetworking,
    >,
    channel_id: String,
    registration: ChannelRegistrationRequest,
}

/// Bind an ephemeral port, hand back the address, and drop the probe listener.
///
/// Racing for a free port is unavoidable without a socket-activation dance; a probe
/// bind at least fails loudly instead of silently colliding on a fixed port.
async fn ephemeral_port() -> u16 {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind an ephemeral port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

/// Wait until `url` answers, or give up. Never a bare `sleep`.
async fn wait_until_up(url: &str) {
    for _ in 0..100 {
        if let Ok(resp) = reqwest::get(url).await {
            if resp.status().is_success() || resp.status().is_client_error() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{url} never answered");
}

fn enabled_config(db_path: &str, mint_url: &str) -> SpilmanConfig {
    SpilmanConfig {
        enabled: true,
        // The mint this payee will actually redeem against. Registration refuses a
        // channel funded anywhere else, so a placeholder would only test the refusal.
        mint_url: Some(mint_url.to_string()),
        in_bytes_per_millisat: 22_021,
        channel_db_path: Some(db_path.to_string()),
    }
}

fn app_state(cfg: Config, rail: Arc<SpilmanRail>) -> AppState {
    let secp = secp256k1::Secp256k1::new();
    let (sk, _) = secp.generate_keypair(&mut rand::thread_rng());
    AppState {
        config: Arc::new(cfg),
        identity: Arc::new(tollgate_module_basic_rust::identity::MerchantIdentity {
            name: "spilman-registration-e2e".into(),
            secret_key: sk,
        }),
        wallet: Arc::new(tokio::sync::Mutex::new(None)),
        sessions: Arc::new(tokio::sync::Mutex::new(
            tollgate_module_basic_rust::session::SessionManager::new(),
        )),
        quotes: Arc::new(std::sync::Mutex::new(
            tollgate_module_basic_rust::http::routes::quote::MintQuoteRegistry::new(),
        )),
        spilman: Some(rail),
    }
}

/// Start a real payee on a real port, open and fund a real channel, and build the
/// registration body from upstream's own `Payment`.
async fn live_payee() -> LivePayee {
    let helper = TestMintHelper::new().await.expect("test mint");
    let keyset_info_json = helper.keyset_info_json().expect("keyset info");

    // ── the test mint, listening over HTTP ──────────────────────────────────
    let mint_port = ephemeral_port().await;
    let mint_url = format!("http://127.0.0.1:{mint_port}");
    let mint_arc = helper.mint();
    let mint_server = AbortOnDrop::new(tokio::spawn(async move {
        let _ = serve_existing_mint_with_shutdown(
            mint_arc,
            TestMintConfig::for_port(mint_port),
            async {
                // Never fires in a test; the handle is aborted on drop instead.
                std::future::pending::<()>().await;
            },
        )
        .await;
    }));
    wait_until_up(&format!("{mint_url}/v1/info")).await;

    // ── the payee, listening over HTTP ──────────────────────────────────────
    let dir = tempfile::tempdir().expect("tempdir");
    // The key the channel will be addressed to — the same key the rail holds and
    // `/spilman/params` advertises. Registration refuses any other.
    let receiver_secret = SecretKey::generate();
    let cfg = Config {
        spilman: enabled_config(
            &dir.path().join("spilman.db").to_string_lossy(),
            &mint_url,
        ),
        ..Config::default()
    };
    let rail = Arc::new(
        SpilmanRail::from_config(&cfg.spilman)
            .expect("enabled config is not an error")
            .expect("enabled config builds a rail")
            .with_receiver_key(receiver_secret.clone()),
    );
    let router = create_router(app_state(cfg, Arc::clone(&rail)));
    let payee_port = ephemeral_port().await;
    let payee_server = AbortOnDrop::new(tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(("127.0.0.1", payee_port)).await {
            Ok(listener) => listener,
            // A test helper may panic; the waiter this feeds reports the failure with
            // a far more useful message than a detached task's join error would.
            Err(_) => return,
        };
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    }));
    let client = PayeeClient::new(&format!("http://127.0.0.1:{payee_port}")).expect("payee client");
    wait_until_up(&format!("{}/spilman/params", client.base_url())).await;

    // ── open + fund a real channel ──────────────────────────────────────────
    let sender_secret = SecretKey::generate();

    let mut client_host =
        ConfigurableClientHost::open_sqlite(&dir.path().join("payer.sqlite").to_string_lossy())
            .expect("payer store");
    client_host.add_key(sender_secret.clone());

    // Separate clients per leg: the bridge consumes its networking by value.
    let bridge_networking =
        cdk_spilman::ReqwestClientNetworking::new(Duration::from_secs(20)).expect("networking");
    let swap_networking =
        cdk_spilman::ReqwestClientNetworking::new(Duration::from_secs(20)).expect("networking");
    let bridge = SpilmanClientBridge::new(client_host, bridge_networking);

    let proofs = helper
        .mint_proofs(CHANNEL_CAPACITY * 2)
        .await
        .expect("mint proofs");
    let token = build_cashu_b_token(
        &mint_url,
        "sat",
        &serde_json::to_string(&proofs).expect("proofs json"),
    )
    .expect("token");

    let expiry = payer::now_seconds() + DEFAULT_CHANNEL_LIFETIME_SECS;
    let mut opening = ChannelOpening::prepare(
        &bridge,
        &token,
        &receiver_secret.public_key().to_hex(),
        &sender_secret.public_key().to_hex(),
        expiry,
        &keyset_info_json,
        64,
    )
    .expect("prepare open");
    let channel_id = opening.channel_id().to_string();

    opening.save_opening(&bridge).expect("persist opening");
    opening
        .submit_funding_swap(&swap_networking)
        .expect("funding swap");
    let completed = opening.finish_open(&bridge).expect("finish open");
    assert_eq!(
        completed.channel_id, channel_id,
        "the mint must complete the channel the payer prepared"
    );

    // Upstream's own `Payment` -> the payee's wire body. No hand-built JSON.
    let registration_payment = bridge
        .sign_channel_registration(&channel_id)
        .expect("sign registration");
    let registration = ChannelRegistrationRequest::from_registration(&registration_payment)
        .expect("registration carries funding")
        .with_channel_secret(&sender_secret, &receiver_secret.public_key().to_hex())
        .expect("attach channel secret")
        .with_keyset_info_json(keyset_info_json.clone());

    LivePayee {
        _dir: dir,
        _helper: helper,
        _payee_server: payee_server,
        _mint_server: mint_server,
        client,
        rail,
        bridge,
        channel_id,
        registration,
    }
}

/// THE LOAD-BEARING TEST: a channel registered **over HTTP** accepts a real payment.
///
/// Every step here would fail if the registration endpoint were absent, refused the
/// body, or stored it unfaithfully: without the record, `record_payment` answers
/// `UnknownChannel`; with a wrong record, verification fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the in-process mint harness; run with --ignored"]
async fn a_channel_registered_over_http_accepts_a_real_payment() {
    let live = live_payee().await;

    // Before registration the running payee does not know this channel.
    let before = live.client.status(&live.channel_id).await.expect("status");
    assert_eq!(
        before.get("status").and_then(serde_json::Value::as_u64),
        Some(0),
        "an unregistered channel must be unknown to the live payee: {before}"
    );

    let outcome = live
        .client
        .register_channel(&live.registration)
        .await
        .expect("the live payee must accept a real funding record");
    assert_eq!(outcome, "registered");

    // Now it is known — without any payment having been made yet. `balance` is null
    // rather than 0, because "registered, never paid" is not "paid zero".
    let after = live.client.status(&live.channel_id).await.expect("status");
    assert_eq!(
        after.get("status").and_then(serde_json::Value::as_u64),
        Some(1),
        "a registered channel must be known to the live payee: {after}"
    );
    assert_eq!(
        after.get("balance"),
        Some(&serde_json::Value::Null),
        "a registered-but-unpaid channel must report no balance, not zero: {after}"
    );

    // Sign with the payer's own bridge and pay over HTTP.
    let payment = payer::step_payment(&live.bridge, &live.channel_id, 1).expect("sign payment");
    let paid = live
        .client
        .submit_payment(&live.channel_id, payment.balance, &payment.signature)
        .await
        .expect("the live payee must accept a genuinely signed payment");
    assert_eq!(
        paid, "Accepted",
        "the payee must report the ledger outcome, not just 200"
    );

    // The bytes the registration stored are the bytes the verifier used, so the
    // credit must be both durable and spendable.
    let status = live.client.status(&live.channel_id).await.expect("status");
    assert_eq!(
        status.get("balance").and_then(serde_json::Value::as_u64),
        Some(1),
        "the payee's durable balance must be exactly what was signed: {status}"
    );
    assert_eq!(
        live.rail
            .authorize_bytes(&live.channel_id, 22_021_000, 0)
            .await,
        RailDecision::Allow,
        "1 sat must buy exactly 22_021_000 bytes at the parity rate"
    );
    assert_eq!(
        live.rail
            .authorize_bytes(&live.channel_id, 22_021_001, 0)
            .await,
        RailDecision::Deny,
        "one byte past the paid-for credit must not be served"
    );
}

/// Re-registering the same channel over HTTP is idempotent, and the payee keeps the
/// balance it had already credited.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the in-process mint harness; run with --ignored"]
async fn a_retried_registration_over_http_is_idempotent() {
    let live = live_payee().await;

    let first = live
        .client
        .register_channel(&live.registration)
        .await
        .expect("first registration");
    assert_eq!(first, "registered");

    let payment = payer::step_payment(&live.bridge, &live.channel_id, 1).expect("sign payment");
    live.client
        .submit_payment(&live.channel_id, payment.balance, &payment.signature)
        .await
        .expect("payment");

    // A real retry: the first response was "lost", so the payer sends the same body.
    let second = live
        .client
        .register_channel(&live.registration)
        .await
        .expect("an identical re-registration must not be an error");
    assert_eq!(
        second, "already_registered",
        "the payee must distinguish a retry from a fresh write"
    );

    // Crucially, the retry did not reset anything: the credit survives it.
    let status = live.client.status(&live.channel_id).await.expect("status");
    assert_eq!(
        status.get("balance").and_then(serde_json::Value::as_u64),
        Some(1),
        "re-registering must not disturb the credited balance: {status}"
    );
}

/// A conflicting registration over HTTP is refused, and the live payee keeps serving
/// against the record it already had.
///
/// The conflict here is the funding-proofs substitution: the channel id is a hash
/// over every params field, so under a fixed id the proof set is the only field a
/// poster can swap — and swapping it is precisely what would let a forger redirect
/// whose signature counts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the in-process mint harness; run with --ignored"]
async fn a_conflicting_registration_over_http_is_refused() {
    let live = live_payee().await;

    live.client
        .register_channel(&live.registration)
        .await
        .expect("first registration");

    let mut forged = live.registration.clone();
    forged.funding_proofs_json = r#"[{"amount":1,"id":"00","secret":"x","C":"00"}]"#.to_string();

    let err = live
        .client
        .register_channel(&forged)
        .await
        .expect_err("a conflicting registration must be refused");
    let message = err.to_string();
    assert!(
        message.contains("409") && message.contains("already registered"),
        "the refusal must be the payee's conflict, not a generic failure: {message}"
    );

    // And the original is still the one in force: a real payment still verifies.
    let payment = payer::step_payment(&live.bridge, &live.channel_id, 1).expect("sign payment");
    live.client
        .submit_payment(&live.channel_id, payment.balance, &payment.signature)
        .await
        .expect("the untouched record must still verify the payer's signature");
}

/// A registration for a channel this payee cannot price must be refused at the door
/// — over HTTP, with the payee's own explanation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the in-process mint harness; run with --ignored"]
async fn a_non_sat_channel_is_refused_over_http() {
    let live = live_payee().await;

    let mut req = live.registration.clone();
    // A coherent `usd` channel cannot be built by mutating this one (the id binds the
    // unit), so the body is expected to fail on the id or on the unit — either way it
    // is a 400 and not a stored record.
    req.params_json = req
        .params_json
        .replace("\"unit\":\"sat\"", "\"unit\":\"usd\"");
    req.keyset_info_json = req
        .keyset_info_json
        .replace("\"unit\":\"sat\"", "\"unit\":\"usd\"");

    let err = live
        .client
        .register_channel(&req)
        .await
        .expect_err("a non-sat channel must be refused");
    let message = err.to_string();
    assert!(
        message.contains("400"),
        "a body the payee cannot use must be a 400 over HTTP: {message}"
    );

    // Nothing was written: the channel is still unknown.
    let status = live.client.status(&live.channel_id).await.expect("status");
    assert_eq!(
        status.get("status").and_then(serde_json::Value::as_u64),
        Some(0),
        "a refused registration must leave no record: {status}"
    );
}

/// The unit of the registered channel is the rail's own, so `authorize_bytes`'
/// `raw_units_to_msats(RAIL_UNIT, ..)` conversion is the one that was priced.
///
/// Cheap, and it is the invariant the `usd` refusal exists to protect.
#[test]
fn the_registered_channel_unit_is_the_rail_unit() {
    let parsed: CurrencyUnit = "sat".parse().expect("sat parses");
    assert_eq!(parsed, CurrencyUnit::Sat);
    assert_eq!(
        tollgate_module_basic_rust::spilman::rail::RAIL_UNIT,
        CurrencyUnit::Sat.to_string()
    );
}

/// `parse_keyset_info_from_json` is what registration validates the keyset blob with;
/// asserting it round-trips keeps that from silently becoming a no-op.
#[tokio::test]
#[ignore = "needs the in-process mint harness; run with --ignored"]
async fn the_test_mints_keyset_info_parses_with_the_validators_own_parser() {
    let helper = TestMintHelper::new().await.expect("test mint");
    let json = helper.keyset_info_json().expect("keyset info");
    let parsed = parse_keyset_info_from_json(&json).expect("the validator's parser accepts it");
    assert_eq!(parsed.keyset_id, helper.keyset_id());
}
