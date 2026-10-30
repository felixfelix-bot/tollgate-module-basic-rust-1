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
///
/// Holding a `JoinHandle` and dropping it does **not** stop the task — dropping a
/// handle detaches it. A test that leaks its payee would hold the port and the ledger
/// for the rest of the run, so the abort is explicit and tied to ownership.
struct AbortOnDrop(tokio::task::AbortHandle);

impl AbortOnDrop {
    /// Take ownership of a task, discarding its (differing) output type.
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

fn enabled_config(db_path: &str) -> SpilmanConfig {
    SpilmanConfig {
        enabled: true,
        // Replaced with the live mint URL before constructing the rail.
        mint_url: Some("https://mint.example".to_string()),
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
    let receiver_secret = SecretKey::generate();
    let mut cfg = Config {
        spilman: enabled_config(&dir.path().join("spilman.db").to_string_lossy()),
        ..Config::default()
    };
    cfg.spilman.mint_url = Some(mint_url.clone());
    let rail = Arc::new(
        SpilmanRail::from_config(&cfg.spilman)
            .expect("enabled config is not an error")
            .expect("enabled config builds a rail")
            .with_receiver_key(receiver_secret.clone()),
    );
    let mut state = app_state(cfg, Arc::clone(&rail));
    state.identity = Arc::new(tollgate_module_basic_rust::identity::MerchantIdentity {
        name: "close-http".into(),
        secret_key: secp256k1::SecretKey::from_slice(&receiver_secret.secret_bytes()).unwrap(),
    });
    let router = create_router(state);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn close_http_settles_and_replays_only_authenticated_sender_receipt() {
    let live = live_payee().await;
    live.client
        .register_channel(&live.registration)
        .await
        .unwrap();
    let payment = payer::step_payment(&live.bridge, &live.channel_id, 3).unwrap();
    live.client
        .submit_payment(&live.channel_id, 3, &payment.signature)
        .await
        .unwrap();
    let http = reqwest::Client::new();
    let url = format!("{}/spilman/close", live.client.base_url());
    let mut forged = serde_json::to_value(&payment).unwrap();
    forged["signature"] = "00".into();
    assert_eq!(
        http.post(&url).json(&forged).send().await.unwrap().status(),
        409
    );
    assert!(live.rail.close_status(&live.channel_id).is_err());
    let settlement =
        payer::CooperativeSettlement::from_accepted_payment(&live.bridge, &payment).unwrap();
    let response = http
        .post(&url)
        .json(settlement.payment())
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert!(status.is_success(), "{status}: {body}");
    assert!(
        !body.contains("receiver_proofs"),
        "receiver bearer proofs leaked"
    );
    // Recompute the nominal receiver sum from the channel's own keyset rule, so the
    // receipt is checked against what the seller actually had to commit to.
    let accounting = payer::CloseAccounting::from_params_json(
        &live.registration.keyset_info_json,
        &live.registration.params_json,
    )
    .expect("channel accounting");
    settlement
        .complete(&live.bridge, &body, &accounting)
        .expect("payer settled");
    println!("BEFORE: open balance=3; AFTER: seller closed receiver_sum=3, payer closed");
    let receipt: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(receipt["receiver_sum"], 3);
    assert!(receipt["already_closed"] == false);
    assert_eq!(
        live.rail.close_status(&live.channel_id).unwrap().state,
        "closed"
    );
    assert_eq!(
        http.post(&url).json(&forged).send().await.unwrap().status(),
        409
    );
    let retry = http.post(&url).json(&payment).send().await.unwrap();
    assert!(retry.status().is_success());
    let repeated: serde_json::Value = retry.json().await.unwrap();
    let restarted = SpilmanRail::open(
        &live._dir.path().join("spilman.db"),
        22_021,
        live.rail.mint_url().map(str::to_string),
    )
    .unwrap();
    let durable = restarted
        .authenticated_close_receipt(&payment)
        .unwrap()
        .unwrap();
    assert_eq!(serde_json::to_value(durable).unwrap(), repeated);
    assert!(repeated["already_closed"] == true);
    assert_eq!(repeated["sender_proofs"], receipt["sender_proofs"]);
    let proofs: Vec<cashu::nuts::Proof> =
        serde_json::from_str(receipt["sender_proofs"].as_str().unwrap()).unwrap();
    assert_eq!(
        proofs.iter().map(|p| u64::from(p.amount)).sum::<u64>(),
        receipt["sender_sum"].as_u64().unwrap()
    );
}
