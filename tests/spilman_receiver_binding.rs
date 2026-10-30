//! The receiver-key binding, end to end over **real sockets**.
//!
//! # The bug this file exists for
//!
//! Measured on real hardware: `POST /spilman/close` answered **HTTP 409** for a
//! channel a real payer had opened and paid. The cause was not the close path — it
//! was that the two ends never agreed on who the receiver *is*:
//!
//! | where | what it said |
//! |---|---|
//! | `GET /spilman/params` | nothing — no receiver key was advertised at all |
//! | `examples/spilman_payer.rs` | `SecretKey::generate()` — a fresh random receiver key per run |
//! | `LedgerPayeeHost::receiver_key_is_acceptable` | `false`, hardcoded |
//!
//! So a payer could only ever open a channel against a key of its own choosing, the
//! payee could never sign a close for it, and every close was refused. 300+ unit
//! tests stayed green because no test traversed the policy: there was exactly one
//! implementation and it returned `false`.
//!
//! # What this file proves
//!
//! 1. A payer that reads `receiver_pubkey` from `/spilman/params` and opens against
//!    **that** key is accepted, paid, and **settled** — the payee's close swap runs
//!    against the mint and the payer verifies the receipt.
//! 2. A payer that opens against some **other** key is refused at registration, before
//!    any money is stranded in a channel the payee cannot close.
//!
//! Both assertions are the regression: reverting `receiver_key_is_acceptable` to
//! `false`, dropping `receiver_pubkey` from `/spilman/params`, or going back to a
//! random channel receiver in the driver all make this file fail.
//!
//! ```text
//! cargo test --test spilman_receiver_binding --features test-support,payer-driver -- --include-ignored
//! ```

use std::sync::Arc;
use std::time::Duration;

use cashu::nuts::SecretKey;
use cdk_spilman::{
    build_cashu_b_token, ConfigurableClientHost, SpilmanClientBridge, SqliteClientStorage,
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

/// A spawned server task that is aborted when this value is dropped.
struct AbortOnDrop(tokio::task::AbortHandle);

impl AbortOnDrop {
    fn new<T: Send + 'static>(handle: tokio::task::JoinHandle<T>) -> Self {
        Self(handle.abort_handle())
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Capacity of the channel these tests open, in sats.
const CHANNEL_CAPACITY: u64 = 64;

/// A running payee (holding a receiver key), a real mint, and a funded payer.
struct Live {
    _dir: tempfile::TempDir,
    _helper: TestMintHelper,
    _payee_server: AbortOnDrop,
    _mint_server: AbortOnDrop,
    client: PayeeClient,
    bridge: SpilmanClientBridge<
        ConfigurableClientHost<SqliteClientStorage>,
        cdk_spilman::ReqwestClientNetworking,
    >,
    rail: Arc<SpilmanRail>,
    /// The mint the payee is configured for. Named in the settlement log line.
    mint_url: String,
    /// The channel the payer opened, named by the mint's own completion.
    channel_id: String,
    /// The registration body built from the payer's own signed `Payment`.
    registration: ChannelRegistrationRequest,
}

async fn ephemeral_port() -> u16 {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind an ephemeral port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

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

fn app_state(cfg: Config, rail: Arc<SpilmanRail>, receiver: &SecretKey) -> AppState {
    AppState {
        config: Arc::new(cfg),
        identity: Arc::new(tollgate_module_basic_rust::identity::MerchantIdentity {
            name: "spilman-receiver-binding".into(),
            secret_key: secp256k1::SecretKey::from_slice(&receiver.secret_bytes())
                .expect("receiver key is a valid secp256k1 scalar"),
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

/// Stand up a mint and a payee that **holds a receiver key**, and fund a payer whose
/// opening key is chosen by the caller.
///
/// `receiver_for_channel` is deliberately a parameter: the whole point of this file is
/// to compare "the key the payee advertises" with "the key the payer used", so the
/// caller must be able to make them differ.
async fn live(receiver_for_channel: Option<SecretKey>) -> Live {
    let helper = TestMintHelper::new().await.expect("test mint");
    let keyset_info_json = helper.keyset_info_json().expect("keyset info");

    let mint_port = ephemeral_port().await;
    let mint_url = format!("http://127.0.0.1:{mint_port}");
    let mint_arc = helper.mint();
    let mint_server = AbortOnDrop::new(tokio::spawn(async move {
        let _ = serve_existing_mint_with_shutdown(
            mint_arc,
            TestMintConfig::for_port(mint_port),
            async { std::future::pending::<()>().await },
        )
        .await;
    }));
    wait_until_up(&format!("{mint_url}/v1/info")).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let receiver_secret = SecretKey::generate();
    let mut cfg = Config {
        spilman: SpilmanConfig {
            enabled: true,
            mint_url: Some(mint_url.clone()),
            in_bytes_per_millisat: 22_021,
            channel_db_path: Some(dir.path().join("spilman.db").to_string_lossy().to_string()),
        },
        ..Config::default()
    };
    cfg.spilman.mint_url = Some(mint_url.clone());
    let rail = Arc::new(
        SpilmanRail::from_config(&cfg.spilman)
            .expect("enabled config is not an error")
            .expect("enabled config builds a rail")
            .with_receiver_key(receiver_secret.clone()),
    );
    let router = create_router(app_state(cfg, Arc::clone(&rail), &receiver_secret));
    let payee_port = ephemeral_port().await;
    let payee_server = AbortOnDrop::new(tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(("127.0.0.1", payee_port)).await {
            Ok(listener) => listener,
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

    // ── what does the payee say it is? ───────────────────────────────────────
    //
    // This is the read the payer driver performs. It is asserted here too, so a
    // `params` that stops advertising the key fails in this file rather than only in
    // the driver.
    let params = client.params().await.expect("GET /spilman/params");
    let advertised = params
        .get("receiver_pubkey")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("params must advertise receiver_pubkey: {params}"));
    assert_eq!(
        advertised,
        receiver_secret.public_key().to_hex(),
        "params must advertise the key this payee actually holds: {params}"
    );

    // ── fund a payer, then open a channel for `receiver_for_channel` ─────────
    let sender_secret = SecretKey::generate();
    let mut client_host =
        ConfigurableClientHost::open_sqlite(&dir.path().join("payer.sqlite").to_string_lossy())
            .expect("payer store");
    client_host.add_key(sender_secret.clone());

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

    let channel_receiver = receiver_for_channel.unwrap_or_else(|| receiver_secret.clone());
    let expiry = payer::now_seconds() + DEFAULT_CHANNEL_LIFETIME_SECS;
    let mut opening = ChannelOpening::prepare(
        &bridge,
        &token,
        &channel_receiver.public_key().to_hex(),
        &sender_secret.public_key().to_hex(),
        expiry,
        &keyset_info_json,
        64,
    )
    .expect("prepare open");
    opening.save_opening(&bridge).expect("persist opening");
    opening
        .submit_funding_swap(&swap_networking)
        .expect("funding swap");
    let channel_id = opening.channel_id().to_string();
    opening.finish_open(&bridge).expect("finish open");

    // Upstream's own `Payment` -> the payee's wire body. No hand-built JSON: the bytes
    // that reach the payee are the bytes cdk-spilman produced.
    let registration_payment = bridge
        .sign_channel_registration(&channel_id)
        .expect("sign registration");
    let registration = ChannelRegistrationRequest::from_registration(&registration_payment)
        .expect("registration carries funding")
        .with_channel_secret(&sender_secret, &channel_receiver.public_key().to_hex())
        .expect("attach channel secret")
        .with_keyset_info_json(keyset_info_json.clone());

    Live {
        _dir: dir,
        _helper: helper,
        _payee_server: payee_server,
        _mint_server: mint_server,
        client,
        bridge,
        rail,
        mint_url,
        channel_id,
        registration,
    }
}

/// **The regression this whole change exists for.**
///
/// A payer that uses the key `/spilman/params` advertises opens a channel the payee
/// accepts, pays it, and **settles** it: `POST /spilman/close` succeeds, the close swap
/// runs against the mint, and the payer's own `CooperativeSettlement` verifies the
/// receipt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the in-process mint harness; run with --ignored"]
async fn a_channel_opened_against_the_advertised_key_settles_over_http() {
    let live = live(None).await;
    let channel_id = live.channel_id.clone();
    let registration = live.registration.clone();

    // A channel addressed to the payee's own key must be accepted.
    let outcome = live
        .client
        .register_channel(&registration)
        .await
        .expect("a channel addressed to the advertised key must be accepted");
    assert_eq!(outcome, "registered");

    let payment = payer::step_payment(&live.bridge, &channel_id, 3).expect("sign payment");
    live.client
        .submit_payment(&channel_id, payment.balance, &payment.signature)
        .await
        .expect("the payee must credit a genuinely signed payment");
    let status = live.client.status(&channel_id).await.expect("status");
    assert_eq!(
        status.get("balance").and_then(serde_json::Value::as_u64),
        Some(3),
        "the payee must hold exactly the signed balance: {status}"
    );

    // ── settle ───────────────────────────────────────────────────────────────
    let settlement =
        payer::CooperativeSettlement::from_accepted_payment(&live.bridge, &payment).expect("close");
    let response = reqwest::Client::new()
        .post(format!("{}/spilman/close", live.client.base_url()))
        .json(settlement.payment())
        .send()
        .await
        .expect("POST /spilman/close");
    let status = response.status();
    let body = response.text().await.expect("body");
    assert!(
        status.is_success(),
        "POST /spilman/close must settle, not 409: {status}: {body}"
    );

    // The payer's own verification: it unblinds the receipt against the proofs it
    // funded, so this cannot pass on a fabricated body.
    // Fee-aware: the receipt carries the NOMINAL receiver sum, so the payer checks it
    // against the channel's own keyset rule rather than against the net balance.
    let accounting = payer::CloseAccounting::from_params_json(
        &live.registration.keyset_info_json,
        &live.registration.params_json,
    )
    .expect("channel accounting");
    let receipt = settlement
        .complete(&live.bridge, &body, &accounting)
        .expect("the payer must be able to verify the close receipt");
    assert_eq!(
        receipt.receiver_sum + receipt.sender_sum,
        receipt.total_value,
        "the mint's own value split must add up: {body}"
    );
    assert!(
        receipt.receiver_sum > 0,
        "the payee must have received a share of the channel: {body}"
    );
    println!(
        "SETTLED channel={channel_id} mint={} receiver_sum={} sender_sum={}",
        live.mint_url, receipt.receiver_sum, receipt.sender_sum
    );
    assert_eq!(
        live.rail.close_status(&channel_id).expect("status").state,
        "closed"
    );
}

/// A channel addressed to a key the payee does **not** hold is refused at
/// registration — before the payee is asked to serve a byte of it, and with a message
/// that names the key the payee would have needed.
///
/// This is the other half of the binding: without it the payee would accept a channel
/// it can never close, which is exactly how the payer's money got stranded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the in-process mint harness; run with --ignored"]
async fn a_channel_for_a_foreign_receiver_key_is_refused_at_registration() {
    let foreign = SecretKey::generate();
    let live = live(Some(foreign.clone())).await;
    let channel_id = live.channel_id.clone();
    let registration = live.registration.clone();

    let error = live
        .client
        .register_channel(&registration)
        .await
        .expect_err("a channel for another key must be refused");
    let message = error.to_string();
    assert!(
        message.contains("400"),
        "a body the payee cannot use must be a 400 over HTTP: {message}"
    );
    assert!(
        message.contains("receiver_pubkey"),
        "the refusal must name the field that is wrong: {message}"
    );

    // Nothing was written: `/status` still reports the channel as unknown.
    let status = live.client.status(&channel_id).await.expect("status");
    assert_eq!(
        status.get("status").and_then(serde_json::Value::as_u64),
        Some(0),
        "a refused registration must leave no record: {status}"
    );
    assert!(live
        .rail
        .channel_funding(&channel_id)
        .expect("read funding")
        .is_none());
}
