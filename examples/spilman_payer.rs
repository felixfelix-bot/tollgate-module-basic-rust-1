//! External-mint physical-router test driver. Uses the seller-advertised mint
//! via NUT-04 HTTP quote/mint and real blinded proofs, then funds a Spilman channel.
//! Test mint FakeWallet auto-pays quotes; other mints need the printed invoice paid.
//! No local mint, fabricated proofs, or URL substitution. Never use real funds:
//! payer state (including returned change proofs) is temporary.
//! With --phase-dir DIR, pre-create DIR but NOT funded.continue / paid.continue.
//! Wait for PAYER_PHASE_READY phase=funded, start measurement, create funded.continue.
//! Wait for phase=paid, stop measurement, create paid.continue. Gates time out at 300s.
//! PAYER_PAYMENT_OK proves seller credit, NOT mint settlement.

use cashu::nuts::SecretKey;
use cdk_spilman::{
    build_cashu_b_token, parse_keyset_info_from_json, ConfigurableClientHost, SpilmanClientBridge,
};
use std::io::Write;
use tollgate_module_basic_rust::spilman::payer::{
    self, ChannelOpening, DEFAULT_CHANNEL_LIFETIME_SECS,
};
use tollgate_module_basic_rust::spilman::payer_driver::PayeeClient;
use tollgate_module_basic_rust::spilman::registration::ChannelRegistrationRequest;
use tollgate_module_basic_rust::spilman::SpilmanError;

/// Capacity, in sats, of the channel this driver opens.
///
/// One sat is 22_021_000 bytes at the parity rate, so this is far more than the
/// driver spends; the interesting number is the *balance it signs*, not the ceiling.
const CHANNEL_CAPACITY: u64 = 64;

/// How much of the channel the driver actually spends, in raw channel units.
const PAYMENT_RAW_UNITS: u64 = 1;

/// One request's timeout against the payee — see `PayableClient`'s own default.
const EXAMPLE_PAYEE_URL: &str = "http://127.0.0.1:8080";

/// Print a step's outcome in a shape a log can be grepped for.
fn step(n: u8, what: &str, outcome: &str) {
    println!("[{n}/5] {what}: {outcome}");
}

/// Emit a MACHINE-readable marker line.
///
/// The human `step()` lines above are for a person reading a log; these are the
/// contract the physical-router lane parses
/// (`PAYER_OPEN_OK`, `PAYER_PAYMENT_OK`, and `PAYER_EXIT`).
/// Both are printed: a marker that replaced the human line would make the lane
/// pass while making the failure harder for a person to read, and the lane's own
/// rule is that a driver which exists but does not emit these is a FAIL, not a
/// SKIP — so the two halves have to agree on an exact shape.
///
/// The shapes are fixed by the lane's regexes:
///   PAYER_OPEN_OK channel_id=<hex>
///   PAYER_PAYMENT_OK channel_id=<hex> balance=<n> payee_credited=<n>
///   PAYER_EXIT=<n>
fn marker(line: &str) {
    println!("{line}");
    std::io::stdout().flush().expect("flush marker");
}

/// The exit code the driver ends with, mirrored as a marker line.
///
/// The lane reads the log text over a serial console, where the process's real
/// exit status is not visible; `PAYER_EXIT=<n>` is how it learns the outcome.
/// Printing it on every path — including the failure paths — is what keeps a
/// failed run from looking like a truncated one.
fn exit_with(code: i32) -> ! {
    marker(&format!("PAYER_EXIT={code}"));
    std::process::exit(code);
}

/// Fail the run: print why and exit non-zero.
///
/// `panic = "abort"` is set for release, so a panic in this driver would abort
/// without unwinding — no destructors, and (depending on the harness) an exit code
/// that does not distinguish "the payee refused me" from "the driver crashed". An
/// explicit non-zero exit is the honest signal.
fn fail(what: &str, err: &SpilmanError) -> ! {
    eprintln!("FAILED at {what}: {err}");
    marker(&format!("PAYER_FAILED={what}"));
    exit_with(1);
}

/// A mint networking client for one leg of the protocol.
///
/// `ReqwestClientNetworking` bridges the sync trait to async reqwest with
/// `block_in_place`, so it needs a multi-threaded runtime — which `main` provides.
fn mint_networking() -> Result<cdk_spilman::ReqwestClientNetworking, SpilmanError> {
    cdk_spilman::ReqwestClientNetworking::new(std::time::Duration::from_secs(20))
        .map_err(|e| SpilmanError::Config(format!("build the mint networking client: {e}")))
}

/// Parse seller URL and optional file-based phase gates.
fn parse_args() -> (String, Option<std::path::PathBuf>) {
    let mut args = std::env::args().skip(1);
    let mut payee: Option<String> = None;
    let mut phase_dir = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--payee" => payee = args.next(),
            "--external-mint" => {} // explicit alias; external is now the default
            "--phase-dir" => {
                phase_dir = Some(std::path::PathBuf::from(
                    args.next().unwrap_or_else(|| exit_with(2)),
                ))
            }
            "--help" | "-h" => {
                println!(
                    "usage: spilman-payer --payee <base-url> [--external-mint] [--phase-dir <dir>]"
                );
                println!();
                println!(
                    "  --payee <url>   the running module's base URL, e.g. {EXAMPLE_PAYEE_URL}"
                );
                exit_with(0);
            }
            other => {
                eprintln!("unexpected argument: {other}");
                eprintln!(
                    "usage: spilman-payer --payee <base-url> [--external-mint] [--phase-dir <dir>]"
                );
                exit_with(2);
            }
        }
    }
    match payee {
        Some(url) if !url.trim().is_empty() => (url, phase_dir),
        _ => {
            eprintln!(
                "usage: spilman-payer --payee <base-url> [--external-mint] [--phase-dir <dir>]"
            );
            exit_with(2);
        }
    }
}

async fn phase_gate(dir: Option<&std::path::Path>, phase: &str) {
    marker(&format!("PAYER_PHASE_READY phase={phase}"));
    if let Some(dir) = dir {
        let gate = dir.join(format!("{phase}.continue"));
        for _ in 0..3000 {
            if gate.is_file() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        eprintln!("FAILED waiting for {}", gate.display());
        exit_with(1);
    }
}

async fn submit_close(
    payee_url: &str,
    payment: &cdk_spilman::Payment,
) -> Result<String, SpilmanError> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| SpilmanError::Bridge(e.to_string()))?;
    http.post(format!("{}/spilman/close", payee_url.trim_end_matches('/')))
        .json(payment)
        .send()
        .await
        .map_err(|e| SpilmanError::Bridge(e.to_string()))?
        .error_for_status()
        .map_err(|e| SpilmanError::Bridge(e.to_string()))?
        .text()
        .await
        .map_err(|e| SpilmanError::Bridge(e.to_string()))
}

async fn fund_external(
    url: &str,
) -> Result<(String, Vec<cashu::nuts::Proof>), Box<dyn std::error::Error>> {
    use cashu::amount::SplitTarget;
    use cashu::nuts::{Id, Keys, MintResponse, PreMintSecrets};
    use serde_json::{json, Value};
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()?;
    let sets: Value = http
        .get(format!("{url}/v1/keysets"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let set = sets["keysets"]
        .as_array()
        .ok_or("missing keysets")?
        .iter()
        .find(|s| s["active"] == true && s["unit"] == "sat")
        .ok_or("no active sat keyset")?;
    let id_text = set["id"].as_str().ok_or("missing keyset id")?;
    let id: Id = id_text.parse()?;
    let response: Value = http
        .get(format!("{url}/v1/keys/{id_text}"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let keyset = response["keysets"]
        .as_array()
        .ok_or("missing keys")?
        .iter()
        .find(|s| s["id"] == id_text)
        .ok_or("keyset mismatch")?;
    let keys: Keys = serde_json::from_value(keyset["keys"].clone())?;
    let info = json!({"keysetId": id_text, "unit":"sat", "keys":keyset["keys"],
        "inputFeePpk":set["input_fee_ppk"].as_u64().unwrap_or(0)})
    .to_string();
    let quote: Value = http
        .post(format!("{url}/v1/mint/quote/bolt11"))
        .json(&json!({"amount":CHANNEL_CAPACITY*2,"unit":"sat"}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let quote_id = quote["quote"].as_str().ok_or("missing quote")?;
    println!(
        "PAYER_FUNDING_INVOICE {}",
        quote["request"].as_str().ok_or("missing invoice")?
    );
    let mut paid = false;
    for _ in 0..120 {
        let q: Value = http
            .get(format!("{url}/v1/mint/quote/bolt11/{quote_id}"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if q["state"] == "PAID" {
            paid = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    if !paid {
        return Err("funding invoice not paid within 120s".into());
    }
    let fees: (u64, Vec<u64>) = (0, keys.iter().map(|a| a.0.to_u64()).collect());
    let secrets = PreMintSecrets::random(
        id,
        (CHANNEL_CAPACITY * 2).into(),
        &SplitTarget::None,
        &fees.into(),
    )?;
    let minted: MintResponse = http
        .post(format!("{url}/v1/mint/bolt11"))
        .json(&json!({"quote":quote_id,"outputs":secrets.blinded_messages()}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let proofs =
        cashu::dhke::construct_proofs(minted.signatures, secrets.rs(), secrets.secrets(), &keys)?;
    Ok((info, proofs))
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    // `ReqwestClientNetworking` bridges sync->async with `block_in_place`, so a
    // multi-thread runtime is required; `multi_thread` above is not decoration.
    let (payee_url, phase_dir) = parse_args();

    let tempdir = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("FAILED to create a working directory: {e}");
            exit_with(1);
        }
    };

    // ── STEP 1: what does the payee want? ───────────────────────────────────
    let payee = match PayeeClient::new(&payee_url) {
        Ok(client) => client,
        Err(e) => fail("build the payee client", &e),
    };
    let params = match payee.params().await {
        Ok(params) => params,
        Err(e) => fail("GET /spilman/params", &e),
    };
    let advertised_mint = params
        .get("mint_url")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<none>")
        .to_string();
    step(
        1,
        "GET /spilman/params",
        &format!(
            "mint_url={advertised_mint} in_bytes_per_millisat={}",
            params
                .get("in_bytes_per_millisat")
                .map(|v| v.to_string())
                .unwrap_or_else(|| "<none>".to_string())
        ),
    );

    // External mode never creates a local mint or substitutes its URL.
    let mint_url = advertised_mint.trim_end_matches('/').to_string();
    let (keyset_info_json, proofs) = match fund_external(&mint_url).await {
        Ok(result) => result,
        Err(e) => {
            eprintln!("FAILED external funding: {e}");
            exit_with(1);
        }
    };
    marker(&format!("PAYER_MINT_EXTERNAL url={mint_url}"));
    let sender_secret = SecretKey::generate();
    let receiver_secret = SecretKey::generate();

    let payer_db = tempdir.path().join("payer.sqlite");
    let mut client_host =
        match ConfigurableClientHost::open_sqlite(payer_db.to_str().unwrap_or("payer.sqlite")) {
            Ok(host) => host,
            Err(e) => {
                eprintln!("FAILED to open the payer store: {e}");
                exit_with(1);
            }
        };
    client_host.add_key(sender_secret.clone());

    // Two mint clients, on purpose. `SpilmanClientBridge` consumes its networking by
    // value and exposes no accessor (see `spilman::payer`'s module docs), and a mint
    // client is stateless configuration — so step 3 gets its own rather than the
    // driver pretending one object can be shared.
    let bridge_networking = match mint_networking() {
        Ok(networking) => networking,
        Err(e) => {
            eprintln!("FAILED to build the mint networking client: {e}");
            exit_with(1);
        }
    };
    let swap_networking = match mint_networking() {
        Ok(networking) => networking,
        Err(e) => {
            eprintln!("FAILED to build the mint networking client: {e}");
            exit_with(1);
        }
    };
    let client = SpilmanClientBridge::new(client_host, bridge_networking);

    let proofs_json = match serde_json::to_string(&proofs) {
        Ok(json) => json,
        Err(e) => {
            eprintln!("FAILED to serialize test proofs: {e}");
            exit_with(1);
        }
    };
    let token = match build_cashu_b_token(&mint_url, "sat", &proofs_json) {
        Ok(token) => token,
        Err(e) => {
            eprintln!("FAILED to build the funding token: {e}");
            exit_with(1);
        }
    };

    let expiry = payer::now_seconds() + DEFAULT_CHANNEL_LIFETIME_SECS;
    let mut opening = match ChannelOpening::prepare(
        &client,
        &token,
        &receiver_secret.public_key().to_hex(),
        &sender_secret.public_key().to_hex(),
        expiry,
        &keyset_info_json,
        64,
    ) {
        Ok(opening) => opening,
        Err(e) => fail("prepare the channel open", &e),
    };
    let channel_id = opening.channel_id().to_string();
    let capacity = opening.capacity();

    // The two-phase open, in the only order that protects money: persist the
    // restore material, THEN swap.
    if let Err(e) = opening.save_opening(&client) {
        fail("persist the opening record", &e);
    }
    if let Err(e) = opening.submit_funding_swap(&swap_networking) {
        fail("submit the funding swap", &e);
    }
    let completed = match opening.finish_open(&client) {
        Ok(completed) => completed,
        Err(e) => fail("complete the channel open", &e),
    };

    // The registration payload is built from upstream's own `Payment`, so the bytes
    // the payee receives are the bytes cdk-spilman produced.
    let registration_payment = match client.sign_channel_registration(&channel_id) {
        Ok(payment) => payment,
        Err(e) => {
            eprintln!("FAILED to sign the channel registration: {e}");
            exit_with(1);
        }
    };
    let keyset_id = match parse_keyset_info_from_json(&keyset_info_json) {
        Ok(info) => info.keyset_id,
        Err(e) => {
            eprintln!("FAILED to parse the keyset info this driver just fetched: {e}");
            exit_with(1);
        }
    };
    // `ChannelRegistrationRequest::from_registration` is the only translation from
    // upstream's `Payment` to the payee's wire body, so the params and funding proofs
    // the payee receives are the exact bytes cdk-spilman produced — no re-serialisation.
    //
    // `Payment` carries neither the ECDH channel secret nor the keyset blob, so the
    // payer adds both here: it derived the secret at open time, and the payee has no
    // way to recover it from the channel id alone.
    let registration = match ChannelRegistrationRequest::from_registration(&registration_payment)
        .and_then(|req| {
            req.with_channel_secret(&sender_secret, &receiver_secret.public_key().to_hex())
        }) {
        Ok(req) => req.with_keyset_info_json(keyset_info_json.clone()),
        Err(e) => fail("build the registration payload", &e),
    };

    // `finish_open` returns the mint's own view of the channel; the funding proofs
    // live on the opening (they are the restore material), so both are reported.
    let funding_proofs_len = opening.funding_proofs_json().map(str::len).unwrap_or(0);
    step(
        2,
        "open + fund a channel",
        &format!(
            "channel_id={channel_id} capacity={capacity} mint={} unit={} keyset={} \
             funding_proofs={funding_proofs_len}B mint_channel_id={}",
            completed.mint_url, completed.unit, completed.keyset_id, completed.channel_id
        ),
    );
    if completed.channel_id != channel_id {
        eprintln!(
            "FAILED: the mint completed a channel named {}, but the payer prepared {channel_id}",
            completed.channel_id
        );
        marker(&format!(
            "PAYER_FAILED=mint-channel-id-mismatch channel_id={channel_id}"
        ));
        exit_with(1);
    }

    // The lane's E assertion: the channel is open and funded. Emitted only after the
    // id-mismatch check above, so a marker means "open AND agrees with the mint".
    marker(&format!(
        "PAYER_OPEN_OK channel_id={channel_id} capacity={capacity}"
    ));

    // ── STEP 3: register it with the running payee ──────────────────────────
    let outcome = match payee.register_channel(&registration).await {
        Ok(outcome) => outcome,
        Err(e) => fail("POST /spilman/channel", &e),
    };
    step(
        3,
        "POST /spilman/channel",
        &format!("outcome={outcome} channel_id={channel_id} keyset={keyset_id}"),
    );

    phase_gate(phase_dir.as_deref(), "funded").await;

    // ── STEP 4: sign and submit a payment ───────────────────────────────────
    let payment = match payer::step_payment(&client, &channel_id, PAYMENT_RAW_UNITS) {
        Ok(payment) => payment,
        Err(e) => fail("sign a balance update", &e),
    };
    let paid = match payee
        .submit_payment(&channel_id, payment.balance, &payment.signature)
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => fail("POST /spilman/payment", &e),
    };
    step(
        4,
        "POST /spilman/payment",
        &format!("outcome={paid} balance={}", payment.balance),
    );

    // ── STEP 5: what did the payee actually credit? ─────────────────────────
    //
    // The assertion that makes this a test rather than a demo: the payee must report
    // the balance the payer signed. A 200 on step 4 is the payee saying it accepted;
    // this is the payee saying what it *holds*.
    let status = match payee.status(&channel_id).await {
        Ok(status) => status,
        Err(e) => fail("GET /spilman/status", &e),
    };
    let credited = status.get("balance").and_then(serde_json::Value::as_u64);
    step(
        5,
        "GET /spilman/status",
        &format!(
            "balance={} decision={}",
            credited
                .map(|b| b.to_string())
                .unwrap_or_else(|| "<null>".to_string()),
            status
                .get("decision")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("<none>")
        ),
    );

    if credited != Some(PAYMENT_RAW_UNITS) {
        eprintln!(
            "FAILED: the payee reports balance {credited:?}, but the payer signed \
             {PAYMENT_RAW_UNITS}. The channel protocol did not complete."
        );
        marker(&format!(
            "PAYER_FAILED=payee-held-a-different-balance channel_id={channel_id} signed={PAYMENT_RAW_UNITS} payee_credited={}",
            credited.map(|b| b.to_string()).unwrap_or_else(|| "<null>".to_string())
        ));
        exit_with(1);
    }

    // The lane's F/G assertions: the payment completed AND the payee holds exactly the
    // balance the payer signed. `payee_credited` is the payee's own read-back, not the
    // driver's assumption — a 200 on step 4 would only mean "accepted".
    marker(&format!(
        "PAYER_PAYMENT_OK channel_id={channel_id} balance={PAYMENT_RAW_UNITS} payee_credited={}",
        credited.unwrap_or(0)
    ));

    phase_gate(phase_dir.as_deref(), "paid").await;
    let settlement =
        match payer::CooperativeSettlement::from_accepted_payment(&client, &payment) {
            Ok(settlement) => settlement,
            Err(e) => fail("sign cooperative close", &e),
        };
    let response = match submit_close(&payee_url, settlement.payment()).await {
        Ok(response) => response,
        Err(e) => fail("POST /spilman/close", &e),
    };
    let receipt = match settlement.complete(&client, &response) {
        Ok(receipt) => receipt,
        Err(e) => fail("verify cooperative close", &e),
    };
    marker(&format!(
        "PAYER_SETTLED channel_id={channel_id} receiver_sum={} sender_sum={} total_value={}",
        receipt.receiver_sum, receipt.sender_sum, receipt.total_value
    ));
    println!();
    println!(
        "OK: channel {channel_id} registered, paid {PAYMENT_RAW_UNITS} raw unit(s), and the \
         payee holds exactly that balance."
    );
    exit_with(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn close_transport_rejects_http_failure() {
        let app = axum::Router::new().route(
            "/spilman/close",
            axum::routing::post(|| async {
                (axum::http::StatusCode::CONFLICT, "mint rejected close")
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let payment = cdk_spilman::Payment::new("test".into(), 1, "invalid".into());
        assert!(submit_close(&url, &payment).await.is_err());
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn external_http_funding_opens_real_channel() {
        use cdk_spilman_test_mint::{
            serve_existing_mint_with_shutdown, TestMintConfig, TestMintHelper,
        };
        let helper = TestMintHelper::new().await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let config = TestMintConfig::for_port(port);
        let url = config.base_url.clone();
        let server = tokio::spawn(serve_existing_mint_with_shutdown(
            helper.mint(),
            config,
            std::future::pending::<()>(),
        ));
        let http = reqwest::Client::new();
        let mut ready = false;
        for _ in 0..100 {
            if http.get(format!("{url}/v1/info")).send().await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(ready);
        let (info, proofs) = fund_external(&url).await.unwrap();
        assert!(!proofs.is_empty());
        let token =
            build_cashu_b_token(&url, "sat", &serde_json::to_string(&proofs).unwrap()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let sender = SecretKey::generate();
        let receiver = SecretKey::generate();
        let mut host =
            ConfigurableClientHost::open_sqlite(dir.path().join("test.sqlite").to_str().unwrap())
                .unwrap();
        host.add_key(sender.clone());
        let client = SpilmanClientBridge::new(host, mint_networking().unwrap());
        let mut opening = ChannelOpening::prepare(
            &client,
            &token,
            &receiver.public_key().to_hex(),
            &sender.public_key().to_hex(),
            payer::now_seconds() + DEFAULT_CHANNEL_LIFETIME_SECS,
            &info,
            64,
        )
        .unwrap();
        opening.save_opening(&client).unwrap();
        opening
            .submit_funding_swap(&mint_networking().unwrap())
            .unwrap();
        let completed = opening.finish_open(&client).unwrap();
        assert_eq!(completed.mint_url, url);
        assert_eq!(completed.channel_id, opening.channel_id());
        server.abort();
    }
}
