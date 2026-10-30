//! Real-mint cooperative close receipt validation and sender ownership checks.
use cashu::nuts::{CurrencyUnit, SecretKey};
use cdk_spilman::configurable_host::{ConfigurableHost, StorageConfig, UnitPricingConfig};
use cdk_spilman::{
    build_cashu_b_token, ClientChannelState, ConfigurableClientHost, SpilmanBridge,
    SpilmanClientBridge, SpilmanClientHost, SqliteClientStorage,
};
use cdk_spilman_test_mint::{InMemoryMintNetworking, TestMintHelper};
use tollgate_module_basic_rust::spilman::payer::{
    self, ChannelOpening, DEFAULT_CHANNEL_LIFETIME_SECS,
};
use tollgate_module_basic_rust::spilman::{
    ChannelLedger, SessionPricing, TOLLGATE_PARITY_IN_BYTES_PER_MILLISAT, TOLLGATE_STEP_SIZE_BYTES,
};

/// One 21 MiB step.
const STEP: u64 = TOLLGATE_STEP_SIZE_BYTES;

/// The URL the in-memory harness advertises for its mint.
const MINT_URL: &str = "https://test-mint";

/// How many 21 MiB steps the happy path signs.
const STEPS: u64 = 10;

/// Hex of a secret key's raw scalar — used to seed a payer host.
fn secret_hex(secret: &SecretKey) -> String {
    secret
        .secret_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Hex of a key's *public* half — this is what the protocol takes as `sender_pubkey_hex`.
fn pubkey_hex(secret: &SecretKey) -> String {
    secret.public_key().to_hex()
}

/// Payee host config, in the shape the live TollGate router advertises.
///
/// The payee prices *bytes*: `amount_due = ceil(accumulated_bytes / pricing_scale)`.
/// Setting the scale to one 21 MiB step makes one step cost exactly 1 sat, which is the
/// §4 billing rule. The scale is the only place this number lives on the payee side; the
/// payer derives the same figure from `in_bytes_per_millisat`.
fn payee_config(path: &std::path::Path) -> cdk_spilman::configurable_host::ConfigurableHostConfig {
    cdk_spilman::configurable_host::ConfigurableHostConfig {
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

fn payee_host(
    path: &std::path::Path,
    receiver: &SecretKey,
    keyset_info_json: &str,
) -> ConfigurableHost {
    let host =
        ConfigurableHost::new(payee_config(path), &secret_hex(receiver)).expect("payee host");
    host.set_keyset(
        MINT_URL,
        cdk_spilman::parse_keyset_info_from_json(keyset_info_json)
            .expect("parse keyset info")
            .keyset_id,
        cdk_spilman::configurable_host::KeysetCacheEntry {
            info_json: keyset_info_json.to_string(),
            active: true,
            unit: CurrencyUnit::Sat,
        },
    )
    .expect("payee keyset");
    host
}

fn payer_bridge(
    db: &std::path::Path,
    sender: &SecretKey,
    mint: std::sync::Arc<cdk::Mint>,
) -> SpilmanClientBridge<ConfigurableClientHost<SqliteClientStorage>, InMemoryMintNetworking> {
    let mut host =
        ConfigurableClientHost::open_sqlite(db.to_str().expect("utf8 path")).expect("payer store");
    host.add_key(sender.clone());
    SpilmanClientBridge::new(host, InMemoryMintNetworking::new(mint))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn payer_cooperative_settle_validates_receipt_and_ownership() {
    let helper = TestMintHelper::new().await.expect("test mint");
    let mint = helper.mint();
    let keyset_info_json = helper.keyset_info_json().expect("keyset info");

    let dir = tempfile::tempdir().expect("tempdir");
    let payee_db = dir.path().join("payee.sqlite");
    let payer_db = dir.path().join("payer.sqlite");

    // ── payee side: the upstream router's real SpilmanHost ──────────────────
    let receiver_secret = SecretKey::generate();
    let payee_bridge =
        SpilmanBridge::new(payee_host(&payee_db, &receiver_secret, &keyset_info_json));

    // ── payer side ───────────────────────────────────────────────────────────
    let sender_secret = SecretKey::generate();
    let client_bridge = payer_bridge(&payer_db, &sender_secret, std::sync::Arc::clone(&mint));

    let proofs = helper.mint_proofs(100).await.expect("mint proofs");
    let token = build_cashu_b_token(
        MINT_URL,
        "sat",
        &serde_json::to_string(&proofs).expect("proofs json"),
    )
    .expect("token");

    let expiry = payer::now_seconds() + DEFAULT_CHANNEL_LIFETIME_SECS;

    // ── phases 1 & 2: prepare (pure), then persist BEFORE the swap ──────────
    let mut opening = ChannelOpening::prepare(
        &client_bridge,
        &token,
        &receiver_secret.public_key().to_hex(),
        &pubkey_hex(&sender_secret),
        expiry,
        &keyset_info_json,
        64,
    )
    .expect("prepare open");
    let channel_id = opening.channel_id().to_string();
    assert!(!opening.is_persisted(), "prepare must not touch storage");
    assert!(
        opening.capacity() > STEPS,
        "the funding token must buy more than {STEPS} sat: got {}",
        opening.capacity()
    );

    opening
        .save_opening(&client_bridge)
        .expect("persist opening");
    assert!(opening.is_persisted());

    // Durability, proven from a *separate read-only connection* to the same file.
    {
        let inspector =
            ConfigurableClientHost::open_sqlite_read_only(payer_db.to_str().expect("utf8 path"))
                .expect("read-only inspector");
        let persisted = inspector
            .get_channel_opening_from_swap(&channel_id)
            .expect("read opening")
            .expect("opening must be durable before the swap");
        assert!(
            !persisted.input_token.is_empty(),
            "the original funding input is the NUT-09 restore material and must be persisted"
        );
        assert!(
            !persisted.channel_secret_hex.is_empty(),
            "the ECDH channel secret must be persisted"
        );
        assert_eq!(
            inspector.get_channel_state(&channel_id),
            Some(ClientChannelState::OpeningFromSwap),
            "the record exists, so the state is exactly this"
        );
        assert!(
            inspector.get_channel_funding(&channel_id).is_none(),
            "no funding yet: the swap has not been submitted"
        );
    }

    // ── phase 3: the point of no return ─────────────────────────────────────
    // A mint client is stateless configuration, so a second one is equivalent to the
    // bridge's own; the swap is the only place the payer touches the mint.
    let funding_networking = InMemoryMintNetworking::new(std::sync::Arc::clone(&mint));
    opening
        .submit_funding_swap(&funding_networking)
        .expect("funding swap");

    // ── phases 4-5: unblind + verify + mark open ────────────────────────────
    let opened = opening.finish_open(&client_bridge).expect("finish open");
    assert_eq!(opened.channel_id, channel_id);

    // Register with the payee: the registration carries params + funding proofs.
    let registration = client_bridge
        .sign_channel_registration(&channel_id)
        .expect("sign registration");
    assert_eq!(registration.balance, 0);
    assert!(
        registration.has_funding(),
        "the registration must carry the funding proofs so the payee can verify them"
    );
    payee_bridge
        .process_payment(
            &registration.channel_id,
            registration.balance,
            &registration.signature,
            registration.params.as_ref(),
            registration.funding_proofs.as_deref(),
            &String::new(),
        )
        .expect("payee registers channel");

    // ── the payee's durable ledger ──────────────────────────────────────────
    let ledger = ChannelLedger::open(&dir.path().join("spilman.db")).expect("ledger");
    assert_eq!(
        ledger.get_balance(&channel_id).expect("balance"),
        None,
        "a zero-balance registration is not a payment"
    );

    // ── one signed balance update per 21 MiB, sat-denominated ───────────────
    let pricing =
        SessionPricing::tollgate_parity(TOLLGATE_PARITY_IN_BYTES_PER_MILLISAT).expect("pricing");
    let mut cumulative_bytes = 0u64;
    for step in 1..=STEPS {
        cumulative_bytes += STEP;
        let balance = pricing
            .raw_balance_due("sat", cumulative_bytes, 0)
            .expect("raw balance");
        assert_eq!(
            balance, step,
            "step {step} must bill exactly {step} sat at the parity rate"
        );

        // No networking argument: the hot path cannot reach a mint.
        let payment =
            payer::step_payment(&client_bridge, &channel_id, balance).expect("sign payment");
        assert_eq!(payment.channel_id, channel_id);
        assert_eq!(payment.balance, balance);
        assert!(
            !payment.has_funding(),
            "only the registration carries funding; later updates are balance-only"
        );

        // The payee validates the signature, records the balance, AND applies the
        // usage increment carried in the context. The context is the byte counter:
        // it is what makes the payee's own `amount_due` agree with the balance the
        // payer signed, which the cooperative close later re-checks.
        let context = serde_json::json!({ "bytes": STEP }).to_string();
        let accepted = payee_bridge
            .process_payment(
                &payment.channel_id,
                payment.balance,
                &payment.signature,
                payment.params.as_ref(),
                payment.funding_proofs.as_deref(),
                &context,
            )
            .expect("payee accepts payment");
        assert_eq!(accepted.balance, balance);
        assert_eq!(
            accepted.amount_due, balance,
            "the payee's own byte accounting must land on the same figure the payer signed"
        );

        // ...and records it durably BEFORE serving any byte.
        ledger
            .record_payment_unverified(&channel_id, payment.balance, &payment.signature)
            .expect("durable ledger write");
        assert_eq!(
            ledger.get_balance(&channel_id).expect("balance"),
            Some(balance)
        );
        assert_eq!(ledger.get_amount_due(&channel_id).expect("due"), balance);
    }

    // ── settle: the payee gets exactly the balance it holds a signature for ──
    let latest = ledger
        .get_latest_payment(&channel_id)
        .expect("query")
        .expect("present");
    assert_eq!(latest.balance, STEPS);
    assert_eq!(latest.payment_count, STEPS);

    let attacker = payer_bridge(
        &payer_db,
        &SecretKey::generate(),
        std::sync::Arc::clone(&mint),
    );
    assert!(
        payer::CooperativeSettlement::prepare(&attacker, &channel_id, latest.balance).is_err(),
        "a stored channel without its sender key must not authorize close"
    );
    // The channel's own accounting rule, so the payer can recompute the nominal
    // receiver sum the seller had to commit to (64 matches the `prepare` call above).
    let close_accounting = payer::CloseAccounting::new(&keyset_info_json, 64);
    let settlement =
        payer::CooperativeSettlement::prepare(&client_bridge, &channel_id, latest.balance)
            .expect("prepare settlement");
    let close_json = serde_json::to_string(settlement.payment()).expect("close json");
    assert_eq!(
        client_bridge.get_channel_info(&channel_id).unwrap().state,
        ClientChannelState::Open
    );
    assert!(settlement
        .complete(
            &client_bridge,
            r#"{"channel_id":"other"}"#,
            &close_accounting
        )
        .is_err());
    assert!(settlement
        .complete(
            &client_bridge,
            &serde_json::json!({"channel_id":channel_id}).to_string(),
            &close_accounting,
        )
        .is_err());
    assert_eq!(
        client_bridge.get_channel_info(&channel_id).unwrap().state,
        ClientChannelState::Open
    );

    // Reopen the payee store to prove the balance and signature survived a restart
    // before settling — that pair is the only thing settlement depends on.
    let payee2 = payee_host(&payee_db, &receiver_secret, &keyset_info_json);
    let restored = payee2
        .get_balance(&channel_id)
        .expect("balance must survive a restart");
    assert_eq!(restored.balance, latest.balance);
    assert_eq!(restored.signature, latest.signature);

    let settle_networking = InMemoryMintNetworking::new(std::sync::Arc::clone(&mint));
    let closed = SpilmanBridge::new(payee2)
        .execute_cooperative_close(&close_json, &settle_networking, &settle_networking)
        .expect("cooperative close");

    assert_eq!(
        closed.receiver_sum, latest.balance,
        "the payee must receive exactly the signed balance"
    );
    assert!(!closed.already_closed, "this is the first close");

    let receipt = serde_json::to_string(&closed).unwrap();
    let mut wrong: serde_json::Value = serde_json::from_str(&receipt).unwrap();
    wrong["channel_id"] = "other".into();
    assert!(settlement
        .complete(&client_bridge, &wrong.to_string(), &close_accounting)
        .is_err());
    wrong = serde_json::from_str(&receipt).unwrap();
    wrong["sender_sum"] = 9999.into();
    assert!(settlement
        .complete(&client_bridge, &wrong.to_string(), &close_accounting)
        .is_err());
    assert_eq!(
        client_bridge.get_channel_info(&channel_id).unwrap().state,
        ClientChannelState::Open
    );
    let verified = settlement
        .complete(&client_bridge, &receipt, &close_accounting)
        .expect("complete actual close");
    assert_eq!(verified.receiver_sum, STEPS);
    assert_eq!(
        client_bridge.get_channel_info(&channel_id).unwrap().state,
        ClientChannelState::Closed
    );
    assert!(payer::step_payment(&client_bridge, &channel_id, STEPS + 1).is_err());
}
