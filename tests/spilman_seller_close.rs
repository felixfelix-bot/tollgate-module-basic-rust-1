use std::sync::Arc;

use cashu::nuts::{CurrencyUnit, SecretKey};
use cdk_spilman::configurable_host::{
    ConfigurableHost, ConfigurableHostConfig, KeysetCacheEntry, StorageConfig, UnitPricingConfig,
};
use cdk_spilman::{
    build_cashu_b_token, parse_keyset_info_from_json, ConfigurableClientHost, SpilmanBridge,
    SpilmanClientBridge, SqliteClientStorage,
};
use cdk_spilman_test_mint::{InMemoryMintNetworking, TestMintHelper};
use tollgate_module_basic_rust::spilman::ledger::{ChannelFundingRecord, ChannelLedger};
use tollgate_module_basic_rust::spilman::payer::{
    self, ChannelOpening, DEFAULT_CHANNEL_LIFETIME_SECS,
};
use tollgate_module_basic_rust::spilman::rail::SpilmanRail;
use tollgate_module_basic_rust::spilman::{
    PaymentRail, TOLLGATE_PARITY_IN_BYTES_PER_MILLISAT, TOLLGATE_STEP_SIZE_BYTES,
};

/// The URL the in-memory harness advertises for its mint.
const MINT_URL: &str = "https://test-mint";

/// One 21 MiB step — also the payee's `pricing_scale`, so one step costs 1 sat.
const STEP: u64 = TOLLGATE_STEP_SIZE_BYTES;

/// Hex of a secret key's raw scalar — used to seed the reference payee host.
fn secret_hex(secret: &SecretKey) -> String {
    secret
        .secret_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Hex of a key's *public* half — what the protocol takes as `sender_pubkey_hex`.
fn pubkey_hex(secret: &SecretKey) -> String {
    secret.public_key().to_hex()
}

/// Payee host config in the shape the live router advertises (same as the payer
/// lifecycle suite): the payee prices bytes, one 21 MiB step per sat.
fn reference_payee_config(path: &std::path::Path) -> ConfigurableHostConfig {
    ConfigurableHostConfig {
        mints: [(MINT_URL.to_string(), vec!["sat".to_string()])].into(),
        min_expiry_seconds: 60,
        pricing_scale: STEP,
        storage: StorageConfig::Sqlite {
            path: path.to_str().expect("utf8 path").to_string(),
        },
        pricing: [(
            "sat".to_string(),
            UnitPricingConfig {
                min_capacity: 1,
                max_amount_per_output: None,
                variables: [("bytes".to_string(), 1u64)].into(),
            },
        )]
        .into(),
    }
}

/// A funded channel, with the payee rail under test wired to its funding record.
struct FundedPayee {
    /// Kept alive so the ledger/payer files survive the test.
    _dir: tempfile::TempDir,
    /// Kept alive because the mint client borrows nothing but the Arc.
    _helper: TestMintHelper,
    rail: SpilmanRail,
    ledger: ChannelLedger,
    channel_id: String,
    receiver_secret: SecretKey,
    keyset_info_json: String,
    client:
        SpilmanClientBridge<ConfigurableClientHost<SqliteClientStorage>, InMemoryMintNetworking>,
}

impl FundedPayee {
    /// Sign `balance` with the payer's real bridge — a genuine Schnorr signature
    /// over `(channel_id, balance)`.
    fn sign(&self, balance: u64) -> String {
        payer::step_payment(&self.client, &self.channel_id, balance)
            .expect("the payer signs a balance update")
            .signature
    }
}

/// Open a real channel against the in-process mint, register it with a reference
/// cdk-spilman payee host, and persist the resulting funding record into the rail's
/// ledger.
async fn open_funded_payee() -> FundedPayee {
    let helper = TestMintHelper::new().await.expect("test mint");
    let mint = helper.mint();
    let keyset_info_json = helper.keyset_info_json().expect("keyset info");

    let dir = tempfile::tempdir().expect("tempdir");
    let payer_db = dir.path().join("payer.sqlite");
    let reference_db = dir.path().join("reference-payee.sqlite");
    let ledger_path = dir.path().join("spilman.db");

    let receiver_secret = SecretKey::generate();
    let sender_secret = SecretKey::generate();

    // ── payer side ──────────────────────────────────────────────────────────
    let mut client_host =
        ConfigurableClientHost::open_sqlite(payer_db.to_str().expect("utf8 path"))
            .expect("payer store");
    client_host.add_key(sender_secret.clone());
    let client =
        SpilmanClientBridge::new(client_host, InMemoryMintNetworking::new(Arc::clone(&mint)));

    let proofs = helper.mint_proofs(100).await.expect("mint proofs");
    let token = build_cashu_b_token(
        MINT_URL,
        "sat",
        &serde_json::to_string(&proofs).expect("proofs json"),
    )
    .expect("token");

    let expiry = payer::now_seconds() + DEFAULT_CHANNEL_LIFETIME_SECS;
    let mut opening = ChannelOpening::prepare(
        &client,
        &token,
        &receiver_secret.public_key().to_hex(),
        &pubkey_hex(&sender_secret),
        expiry,
        &keyset_info_json,
        64,
    )
    .expect("prepare open");
    let channel_id = opening.channel_id().to_string();

    opening.save_opening(&client).expect("persist opening");
    let funding_networking = InMemoryMintNetworking::new(Arc::clone(&mint));
    opening
        .submit_funding_swap(&funding_networking)
        .expect("funding swap");
    opening.finish_open(&client).expect("finish open");

    // ── the reference payee: upstream's own host derives the funding record ──
    let reference = ConfigurableHost::new(
        reference_payee_config(&reference_db),
        &secret_hex(&receiver_secret),
    )
    .expect("reference payee host");
    reference
        .set_keyset(
            MINT_URL,
            parse_keyset_info_from_json(&keyset_info_json)
                .expect("parse keyset info")
                .keyset_id,
            KeysetCacheEntry {
                info_json: keyset_info_json.clone(),
                active: true,
                unit: CurrencyUnit::Sat,
            },
        )
        .expect("reference keyset");

    let registration = client
        .sign_channel_registration(&channel_id)
        .expect("sign registration");
    assert!(
        registration.has_funding(),
        "the registration must carry the funding proofs, or there is nothing to verify against"
    );
    SpilmanBridge::new(reference.clone())
        .process_payment(
            &registration.channel_id,
            registration.balance,
            &registration.signature,
            registration.params.as_ref(),
            registration.funding_proofs.as_deref(),
            &String::new(),
        )
        .expect("the reference payee registers the channel");

    // Copied out of upstream's own store — not hand-built here.
    let funding = reference
        .get_funding_data(&channel_id)
        .expect("the reference payee must hold a funding record after registration");
    let capacity = serde_json::from_str::<serde_json::Value>(&funding.params_json)
        .expect("params json")
        .get("capacity")
        .and_then(serde_json::Value::as_u64)
        .expect("params must carry the capacity");

    let ledger = ChannelLedger::open(&ledger_path).expect("ledger");
    ledger
        .save_channel_funding(&ChannelFundingRecord {
            channel_id: channel_id.clone(),
            params_json: funding.params_json.clone(),
            funding_proofs_json: funding.funding_proofs_json.clone(),
            channel_secret_hex: funding.channel_secret_hex.clone(),
            keyset_info_json: funding.keyset_info_json.clone(),
            capacity,
            created_at: payer::now_seconds(),
        })
        .expect("persist the funding record");

    let rail = SpilmanRail::open(
        &ledger_path,
        TOLLGATE_PARITY_IN_BYTES_PER_MILLISAT,
        Some(MINT_URL.to_string()),
    )
    .expect("rail")
    .with_receiver_key(receiver_secret.clone());

    FundedPayee {
        _dir: dir,
        _helper: helper,
        rail,
        ledger,
        channel_id,
        receiver_secret,
        keyset_info_json,
        client,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn seller_close_exact_settlement_and_restart() {
    let f = open_funded_payee().await;
    let id = &f.channel_id;
    for balance in [1, 2, 3] {
        f.rail
            .record_payment(id, balance, &f.sign(balance))
            .await
            .unwrap();
    }
    assert!(f
        .rail
        .prepare_close(id, 2, &f.sign(2), &f.keyset_info_json)
        .is_err());
    assert!(f
        .rail
        .prepare_close(id, 3, "00", &f.keyset_info_json)
        .is_err());
    let accepted = f.ledger.get_latest_payment(id).unwrap().unwrap();
    f.rail
        .prepare_close(id, 3, &accepted.signature, &f.keyset_info_json)
        .unwrap();
    assert!(f.rail.record_payment(id, 4, &f.sign(4)).await.is_err());
    let network = InMemoryMintNetworking::new(f._helper.mint());
    let result = f.rail.execute_close_with_network(id, &network).unwrap();
    assert_eq!(result.state, "closed");
    assert_eq!(result.receiver_sum, Some(3));
    let restarted = SpilmanRail::open(&f._dir.path().join("spilman.db"), 1, Some(MINT_URL.into()))
        .unwrap()
        .with_receiver_key(f.receiver_secret.clone());
    let retry = restarted.execute_close_with_network(id, &network).unwrap();
    assert_eq!(retry.receiver_sum, Some(3));
    assert!(restarted
        .prepare_close("missing", 1, "00", &f.keyset_info_json)
        .is_err());
}
/// The real mint processes the swap, but the response never reaches the seller.
struct LostResponse {
    inner: InMemoryMintNetworking,
    swaps: std::sync::atomic::AtomicUsize,
    submit: bool,
}
impl cdk_spilman::SpilmanClientNetworking for LostResponse {
    fn call_mint_swap(&self, mint: &str, request: &str) -> Result<String, String> {
        self.swaps.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.submit {
            self.inner.call_mint_swap(mint, request)?;
        }
        Err("connection lost".into())
    }
    fn call_mint_restore(&self, m: &str, r: &str) -> Result<String, String> {
        self.inner.call_mint_restore(m, r)
    }
    fn call_mint_keysets(&self, m: &str) -> Result<String, String> {
        self.inner.call_mint_keysets(m)
    }
    fn call_mint_keys(&self, m: &str, k: &str) -> Result<String, String> {
        self.inner.call_mint_keys(m, k)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_swap_response_recovers_without_resubmission() {
    use std::sync::atomic::Ordering;
    let f = open_funded_payee().await;
    let signature = f.sign(7);
    f.rail
        .record_payment(&f.channel_id, 7, &signature)
        .await
        .unwrap();
    f.rail
        .prepare_close(&f.channel_id, 7, &signature, &f.keyset_info_json)
        .unwrap();
    let network = LostResponse {
        inner: InMemoryMintNetworking::new(f._helper.mint()),
        swaps: 0.into(),
        submit: true,
    };
    assert!(f
        .rail
        .execute_close_with_network(&f.channel_id, &network)
        .is_err());
    assert_eq!(
        f.rail.close_status(&f.channel_id).unwrap().state,
        "uncertain"
    );
    let restarted = SpilmanRail::open(&f._dir.path().join("spilman.db"), 1, Some(MINT_URL.into()))
        .unwrap()
        .with_receiver_key(f.receiver_secret.clone());
    let closed = restarted
        .execute_close_with_network(&f.channel_id, &network)
        .unwrap();
    assert_eq!(closed.receiver_sum, Some(7));
    assert_eq!(closed.state, "closed");
    assert_eq!(network.swaps.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_restore_never_replays_ambiguous_swap() {
    use std::sync::atomic::Ordering;
    let f = open_funded_payee().await;
    let signature = f.sign(5);
    f.rail
        .record_payment(&f.channel_id, 5, &signature)
        .await
        .unwrap();
    f.rail
        .prepare_close(&f.channel_id, 5, &signature, &f.keyset_info_json)
        .unwrap();
    let network = LostResponse {
        inner: InMemoryMintNetworking::new(f._helper.mint()),
        swaps: 0.into(),
        submit: false,
    };
    for _ in 0..3 {
        assert!(f
            .rail
            .execute_close_with_network(&f.channel_id, &network)
            .is_err());
    }
    assert_eq!(
        f.rail.close_status(&f.channel_id).unwrap().state,
        "uncertain"
    );
    assert_eq!(network.swaps.load(Ordering::SeqCst), 1);
}
