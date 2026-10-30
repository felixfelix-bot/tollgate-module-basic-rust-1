//! `spilman-payer` — **a TEST DRIVER**, not a product feature.
//!
//! It performs the full payer half of the channel protocol against a *running*
//! payee, so the physical-router E2E can exercise the protocol over HTTP instead of
//! only in-process:
//!
//! ```text
//! 1. GET  /spilman/params    read the payee's mint, rate AND receiver pubkey
//! 2. (mint, over HTTP)       open a channel against that mint, fund it
//! 3. POST /spilman/channel   register the funding record with the payee
//! 4. POST /spilman/payment   sign a balance update and pay
//! 5. GET  /spilman/status    read back what the payee credited
//! ```
//!
//! # The CLI is a contract with the bench lane
//!
//! `spilman_router_lane.py` (the PRTA router lane) launches this binary as
//!
//! ```text
//! ./spilman-payer --mint-url <mint> --module-url <base> --flow open-settle
//! ```
//!
//! so those are the flags, spelled exactly: `--mint-url`, `--mint-file` (read the
//! URL from a file instead), `--module-url`, and `--flow`. `--payee` is kept as an
//! alias for `--module-url` because earlier runs and the docs used it. Anything
//! else is a usage error and exits **2**, which the lane reports as "the two
//! halves disagree on the interface" rather than as a protocol failure.
//!
//! # Funding is real HTTP, at the seller-advertised URL
//!
//! The mint leg lives in the library (`spilman::mint_http`, behind the same
//! non-default `payer-driver` feature as this example) and talks NUT-04 over the
//! wire to the seller-advertised mint; CLI mint flags must match it. It does **not** spawn an in-process test
//! mint. Two reasons, and the second is the load-bearing one:
//!
//! - the driver should be the protocol orchestration, not a second mint
//!   implementation with its own test-only behaviour;
//! - the lane measures "ZERO mint calls between open and settle" with a
//!   **counting proxy** in front of the mint, and advertises *the proxy's* URL
//!   through the payee's `/spilman/params`. A driver minting at an ephemeral
//!   loopback port bypasses that proxy entirely, so the proxy would count zero
//!   no matter what the payer did — the assertion could not fail, which means it
//!   was measuring nothing. Funding at the URL passed in is what makes it a
//!   measurement.
//!
//! # Why it is an example, not a `[[bin]]`
//!
//! It is behind `required-features = ["payer-driver"]`, so a plain `cargo build`,
//! `cargo test`, or release image neither builds nor installs it. That matters
//! more now than when this was written: the funding leg asks a mint for ecash,
//! and a router binary carrying a "fund me" routine is exactly the kind of thing
//! that later gets switched on by accident. The in-process test mint remains a
//! **dev-dependency only**, for the `#[ignore]`-gated integration tests; this
//! example no longer references it.
//!
//! # Running it
//!
//! ```text
//! # terminal 1 — the payee, with the rail on (see docs/spilman-channel-rail.md)
//! # terminal 2 — a mint that will actually pay its own quotes, e.g. the bench one
//! # terminal 3 — the driver
//! cargo run --example spilman-payer --features payer-driver -- \
//!     --mint-url http://127.0.0.1:3499 --module-url http://127.0.0.1:8080
//! ```
//!
//! # The exit contract
//!
//! Every exit path — success, failure, usage error — prints `PAYER_EXIT=<n>`,
//! because the lane reads the log over a serial console where the process's real
//! status is invisible. It also prints two machine markers it greps for, whose
//! shapes its regexes fix:
//!
//! ```text
//! PAYER_OPEN_OK channel_id=<hex>
//! PAYER_PAYMENT_OK channel_id=<hex> balance=<n> payee_credited=<n>
//! ```
//!
//! The human `[n/5] ...` lines are printed as well: a marker that replaced the
//! human line would make the lane pass while making a failure harder to read.
//!
//! # What it deliberately does not do
//!
//! No retries, no fallbacks, no partial success. Each step is a precondition for the
//! next (a channel that did not open cannot be registered; a payment the payee
//! refused must not be followed by a "settled" line), so continuing past a failure
//! would produce a log that reads like a run and isn't one.
//! Never use real funds: payer state (including returned change proofs) is temporary.

use cashu::nuts::SecretKey;
use cdk_spilman::{parse_keyset_info_from_json, ConfigurableClientHost, SpilmanClientBridge};
use std::io::Write;
use tollgate_module_basic_rust::spilman::mint_http::{
    funding_token, RemoteMint, DEFAULT_QUOTE_TIMEOUT,
};
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

/// The one flow this driver implements.
///
/// Named in the CLI rather than implied, because the lane passes it: a driver that
/// silently accepted `--flow anything` would report success for a flow it never ran.
const FLOW_OPEN_SETTLE: &str = "open-settle";

const USAGE: &str =
    "usage: spilman-payer --mint-url <url> --module-url <base-url> [--flow open-settle]
       spilman-payer --mint-file <path> --module-url <base-url> [--flow open-settle]

  --mint-url <url>    the mint to fund the channel at (a remote mint over HTTP)
  --mint-file <path>  read that mint URL from a file instead (whitespace trimmed)
  --module-url <url>  the running module's base URL, e.g. http://127.0.0.1:8080
  --payee <url>       alias for --module-url
  --flow <name>       the flow to run; only 'open-settle' is implemented
  --external-mint    explicit alias for the default external funding mode
  --phase-dir <dir>   wait for funded.continue / paid.continue (300s timeout)
  --help, -h          this text";

/// Everything the driver needs from its command line.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Args {
    /// Where to fund. Either given directly or read from a file.
    mint: MintSource,
    /// The payee's base URL.
    module_url: String,
    /// The flow, validated against the one value this driver implements.
    flow: String,
    phase_dir: Option<std::path::PathBuf>,
}

/// `--mint-url <url>` or `--mint-file <path>`; exactly one is required.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MintSource {
    Url(String),
    File(std::path::PathBuf),
}

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

/// A usage error: say what was wrong, show the usage, exit 2.
///
/// Exit 2 (not 1) so the lane can tell "this binary does not implement my CLI"
/// from "this run failed", which is the difference between a build/deploy bug and
/// a protocol bug.
fn usage_error(why: &str) -> ! {
    eprintln!("{why}");
    eprintln!("{USAGE}");
    exit_with(2);
}

/// Parse the command line, or exit 2 with the usage.
fn parse_args() -> Args {
    let mut args = std::env::args().skip(1);
    let mut mint_url: Option<String> = None;
    let mut mint_file: Option<String> = None;
    let mut module_url: Option<String> = None;
    let mut flow: Option<String> = None;
    let mut phase_dir = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mint-url" => mint_url = args.next(),
            "--mint-file" => mint_file = args.next(),
            // `--payee` is the pre-lane spelling of the same value; it is an alias,
            // not a separate concept, so it must not be able to disagree with
            // `--module-url`. Whichever appears last wins, exactly as a repeated
            // flag would.
            "--payee" | "--module-url" => module_url = args.next(),
            "--flow" => flow = args.next(),
            "--external-mint" => {}
            "--phase-dir" => {
                phase_dir =
                    Some(std::path::PathBuf::from(args.next().unwrap_or_else(|| {
                        usage_error("--phase-dir requires a path")
                    })));
            }
            "--help" | "-h" => {
                println!("{USAGE}");
                exit_with(0);
            }
            other => usage_error(&format!("unexpected argument: {other}")),
        }
    }

    let mint = match (mint_url, mint_file) {
        (Some(url), None) => {
            let url = url.trim().to_string();
            if url.is_empty() {
                usage_error("--mint-url was given an empty value");
            }
            MintSource::Url(url)
        }
        (None, Some(path)) => {
            let path = path.trim().to_string();
            if path.is_empty() {
                usage_error("--mint-file was given an empty path");
            }
            MintSource::File(std::path::PathBuf::from(path))
        }
        // Two sources of truth for where the money goes is a bug waiting to be
        // silent: refuse rather than pick one.
        (Some(_), Some(_)) => usage_error("give either --mint-url or --mint-file, not both"),
        (None, None) => usage_error("no mint given: --mint-url or --mint-file is required"),
    };

    let module_url = match module_url {
        Some(url) if !url.trim().is_empty() => url.trim().to_string(),
        _ => usage_error("no module URL given: --module-url is required"),
    };

    let flow = flow.unwrap_or_else(|| FLOW_OPEN_SETTLE.to_string());
    if flow != FLOW_OPEN_SETTLE {
        usage_error(&format!(
            "unsupported --flow {flow:?}; this driver implements only {FLOW_OPEN_SETTLE:?}"
        ));
    }

    Args {
        mint,
        module_url,
        flow,
        phase_dir,
    }
}

/// Resolve [`MintSource`] to a URL, reading the file when that is what was asked.
///
/// An empty file is an error rather than a fallback: a driver that quietly funded
/// at some default mint because a path was empty would be showing green for a
/// configuration nobody wrote.
fn resolve_mint(source: &MintSource) -> Result<String, String> {
    match source {
        MintSource::Url(url) => Ok(url.clone()),
        MintSource::File(path) => {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| format!("read --mint-file {}: {e}", path.display()))?;
            let url = raw.trim().to_string();
            if url.is_empty() {
                return Err(format!(
                    "--mint-file {} is empty: it must contain a mint URL, and funding at a \
                     guessed mint would be a green run for a configuration nobody wrote",
                    path.display()
                ));
            }
            Ok(url)
        }
    }
}

/// A mint networking client for one leg of the protocol.
///
/// `ReqwestClientNetworking` bridges the sync trait to async reqwest with
/// `block_in_place`, so it needs a multi-threaded runtime — which `main` provides.
fn mint_networking() -> Result<cdk_spilman::ReqwestClientNetworking, SpilmanError> {
    cdk_spilman::ReqwestClientNetworking::new(std::time::Duration::from_secs(20))
        .map_err(|e| SpilmanError::Config(format!("build the mint networking client: {e}")))
}

fn seller_mint(advertised: &str, requested: &str) -> Result<String, SpilmanError> {
    let advertised = advertised.trim_end_matches('/');
    let requested = requested.trim_end_matches('/');
    if advertised.is_empty() || advertised == "<none>" || advertised != requested {
        return Err(SpilmanError::Config(format!(
            "seller mint {advertised:?} does not match requested mint {requested:?}; refusing funding"
        )));
    }
    Ok(advertised.to_string())
}

/// The seller's receiver (payee) pubkey, from `/spilman/params`.
///
/// # Why this is read and not generated
///
/// The channel's `receiver_pubkey` is the key the **payee** signs the close with.
/// This driver used to generate a throwaway key here, which meant every channel it
/// opened was addressed to a key no payee held: the open funded at the mint, the
/// payment verified (that only needs the *sender* key), and then `POST /spilman/close`
/// failed — measured as HTTP 409 on real hardware — because the payee could not sign a
/// close for somebody else's key. The advertised key is the only correct answer.
///
/// Returns the canonical 33-byte compressed hex, so the value used to open the channel
/// and the value used to derive the ECDH channel secret for registration are the same
/// bytes.
fn seller_receiver_pubkey(params: &serde_json::Value) -> Result<String, SpilmanError> {
    let advertised = params
        .get("receiver_pubkey")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            SpilmanError::Config(
                "seller receiver_pubkey is missing or not a string; refusing funding".into(),
            )
        })?;
    let key = cashu::nuts::PublicKey::from_hex(advertised).map_err(|e| {
        SpilmanError::Config(format!(
            "invalid seller receiver_pubkey: {e}; refusing funding"
        ))
    })?;
    Ok(key.to_hex())
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

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    // `ReqwestClientNetworking` bridges sync->async with `block_in_place`, so a
    // multi-thread runtime is required; `multi_thread` above is not decoration.
    let args = parse_args();
    let mint_url = match resolve_mint(&args.mint) {
        Ok(url) => url,
        Err(e) => {
            eprintln!("FAILED: {e}");
            marker("PAYER_FAILED=resolve-mint-url");
            exit_with(1);
        }
    };
    let payee_url = args.module_url;
    let phase_dir = args.phase_dir;

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
            "mint_url={advertised_mint} in_bytes_per_millisat={} receiver_pubkey={}",
            params
                .get("in_bytes_per_millisat")
                .map(|v| v.to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            params
                .get("receiver_pubkey")
                .map(|v| v.to_string())
                .unwrap_or_else(|| "<none>".to_string()),
        ),
    );

    // The seller's advertisement is authoritative. CLI mint flags are assertions,
    // never an override that can bypass the measurement proxy or fund another mint.
    let mint_url = match seller_mint(&advertised_mint, &mint_url) {
        Ok(url) => url,
        Err(e) => fail("validate seller-advertised mint", &e),
    };
    // Before any funding: the key every open and registration below is addressed to.
    let receiver_pubkey = match seller_receiver_pubkey(&params) {
        Ok(key) => key,
        Err(e) => fail("validate seller-advertised receiver key", &e),
    };
    marker(&format!("PAYER_MINT_EXTERNAL url={mint_url}"));

    // ── STEP 2: fund a real channel at a real, remote mint over HTTP ────────
    //
    // Everything below goes over the wire to `mint_url`. There is no in-process
    // mint: the payee names the mint it will verify against, and the lane counts
    // the calls this leg makes through a proxy in front of it.
    //
    // Step 2 prints twice — the mint leg, then the channel open — because they are
    // the two halves of funding and a failure in either is worth seeing in the log.
    let remote = match RemoteMint::new(&mint_url) {
        Ok(mint) => mint,
        Err(e) => fail("build the mint client", &e),
    };
    if let Err(e) = remote.info().await {
        fail("GET /v1/info on the mint", &e);
    }

    let funded = match remote
        .mint(CHANNEL_CAPACITY * 2, DEFAULT_QUOTE_TIMEOUT)
        .await
    {
        Ok(funded) => funded,
        Err(e) => fail("mint proofs at the remote mint", &e),
    };
    step(
        2,
        "mint proofs (NUT-04 over HTTP)",
        &format!(
            "mint={} amount={} keyset={} proofs={}",
            remote.url(),
            funded.amount,
            funded.keyset_id,
            funded.proofs.len()
        ),
    );

    // The token must name the mint that signed the proofs; `funding_token` takes
    // the URL for exactly that reason.
    let token = match funding_token(remote.url(), &funded.proofs_json) {
        Ok(token) => token,
        Err(e) => fail("build the funding token", &e),
    };
    let keyset_info_json = funded.keyset_info_json.clone();

    let sender_secret = SecretKey::generate();

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
    // client is stateless configuration — so the funding swap gets its own rather
    // than the driver pretending one object can be shared.
    let bridge_networking = match mint_networking() {
        Ok(networking) => networking,
        Err(e) => fail("build the mint networking client", &e),
    };
    let swap_networking = match mint_networking() {
        Ok(networking) => networking,
        Err(e) => fail("build the mint networking client", &e),
    };
    let client = SpilmanClientBridge::new(client_host, bridge_networking);

    let expiry = payer::now_seconds() + DEFAULT_CHANNEL_LIFETIME_SECS;
    let mut opening = match ChannelOpening::prepare(
        &client,
        &token,
        &receiver_pubkey,
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
        .and_then(|req| req.with_channel_secret(&sender_secret, &receiver_pubkey))
    {
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
    //
    // Nothing between this line and `PAYER_PAYMENT_OK` touches the mint: registration,
    // signing and payment are all local or payee-side. That is the claim the lane's
    // counting proxy measures, and it is why this marker is emitted here rather than
    // after the registration.
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
    let settlement = match payer::CooperativeSettlement::from_accepted_payment(&client, &payment) {
        Ok(settlement) => settlement,
        Err(e) => fail("sign cooperative close", &e),
    };
    let response = match submit_close(&payee_url, settlement.payment()).await {
        Ok(response) => response,
        Err(e) => fail("POST /spilman/close", &e),
    };
    // The channel's own keyset rule (the same 64 passed to `ChannelOpening::prepare`).
    let accounting = payer::CloseAccounting::new(&keyset_info_json, 64);
    let receipt = match settlement.complete(&client, &response, &accounting) {
        Ok(receipt) => receipt,
        Err(e) => fail("verify cooperative close", &e),
    };
    marker(&format!(
        "PAYER_SETTLED channel_id={channel_id} receiver_sum={} sender_sum={} total_value={}",
        receipt.receiver_sum, receipt.sender_sum, receipt.total_value
    ));
    println!();
    println!(
        "OK: channel {channel_id} opened at {}, registered, paid {PAYMENT_RAW_UNITS} raw unit(s), \
         and the payee holds exactly that balance (flow={}).",
        remote.url(),
        args.flow
    );
    exit_with(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receiver_key_is_selected_from_seller_advertisement() {
        let seller = SecretKey::generate().public_key().to_hex();
        let params = serde_json::json!({"receiver_pubkey": seller});
        assert_eq!(seller_receiver_pubkey(&params).unwrap(), seller);
    }

    #[test]
    fn receiver_key_refuses_missing_or_invalid_advertisements() {
        for params in [
            serde_json::json!({}),
            serde_json::json!({"receiver_pubkey": null}),
            serde_json::json!({"receiver_pubkey": 42}),
            serde_json::json!({"receiver_pubkey": ""}),
            serde_json::json!({"receiver_pubkey": "not-a-key"}),
            serde_json::json!({"receiver_pubkey": format!("02{}", "ff".repeat(32))}),
        ] {
            let error = seller_receiver_pubkey(&params).expect_err("must refuse funding");
            assert!(error.to_string().contains("receiver_pubkey"), "{error}");
        }
    }

    /// The production path must not mint its own channel receiver key.
    ///
    /// This is the regression the random key caused: `SecretKey::generate()` for the
    /// *receiver* made every channel uncloseable, and no amount of protocol testing
    /// caught it because the payer half was internally consistent. The driver's only
    /// permitted ephemeral key is the sender's; the receiver must come from
    /// `/spilman/params`.
    ///
    /// A source-level assertion is deliberate: the failure mode is a *deleted call
    /// site*, which no behavioural test in this file can observe without a live payee.
    #[test]
    fn the_production_path_generates_no_receiver_key() {
        let source = include_str!("spilman_payer.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("the file has a production half");

        assert_eq!(
            production.matches("SecretKey::generate()").count(),
            1,
            "the driver may generate exactly one ephemeral key (the sender); a \
             receiver key must come from /spilman/params"
        );
        assert!(
            production.contains("let sender_secret = SecretKey::generate();"),
            "the single ephemeral key must be the sender's"
        );
        for site in [
            "&receiver_pubkey,",
            "with_channel_secret(&sender_secret, &receiver_pubkey)",
        ] {
            assert!(
                production.contains(site),
                "the open and the registration must both use the advertised key ({site} \
                 missing)"
            );
        }
    }

    #[test]
    fn the_usage_names_every_flag_the_lane_passes() {
        // The lane launches this binary with exactly these three flags plus --flow.
        // If the usage text stops naming one, the next person to read a rejected run
        // is reading a document that does not describe the interface.
        for flag in ["--mint-url", "--mint-file", "--module-url", "--flow"] {
            assert!(USAGE.contains(flag), "usage omits {flag}:\n{USAGE}");
        }
        assert!(USAGE.contains("--payee"), "usage omits the --payee alias");
        assert!(USAGE.contains(FLOW_OPEN_SETTLE));
    }

    #[test]
    fn an_empty_mint_file_is_an_error_not_a_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("mint.txt");
        std::fs::write(&path, "  \n\t\n").expect("write");
        let err = resolve_mint(&MintSource::File(path)).expect_err("must refuse");
        assert!(err.contains("empty"), "{err}");
    }

    #[test]
    fn a_mint_file_is_trimmed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("mint.txt");
        std::fs::write(&path, "  http://127.0.0.1:3499\n").expect("write");
        let url = resolve_mint(&MintSource::File(path)).expect("url");
        assert_eq!(url, "http://127.0.0.1:3499");
    }

    #[test]
    fn a_missing_mint_file_names_the_path_it_tried() {
        let err = resolve_mint(&MintSource::File("/nonexistent/mint.txt".into()))
            .expect_err("must refuse");
        assert!(err.contains("/nonexistent/mint.txt"), "{err}");
    }
    #[test]
    fn seller_advertisement_is_authoritative() {
        assert!(seller_mint("https://seller-mint", "http://127.0.0.1:3499").is_err());
        assert!(seller_mint("<none>", "https://payer-mint").is_err());
        assert!(seller_mint("", "").is_err());
        assert_eq!(
            seller_mint("https://seller-mint/", "https://seller-mint").unwrap(),
            "https://seller-mint"
        );
    }

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
        let advertised = seller_mint(&url, &url).unwrap();
        let remote = RemoteMint::new(&advertised).unwrap();
        let funded = remote
            .mint(CHANNEL_CAPACITY * 2, DEFAULT_QUOTE_TIMEOUT)
            .await
            .unwrap();
        assert!(!funded.proofs.is_empty());
        let info = funded.keyset_info_json;
        let token = funding_token(remote.url(), &funded.proofs_json).unwrap();
        let dir = tempfile::tempdir().unwrap();
        // EPHEMERAL ON PURPOSE, and only here: this test opens a channel against an
        // in-process mint with no payee on the other end, so there is no advertised key
        // to honour. The production path (`main`, above) must NEVER generate this key —
        // see `seller_receiver_pubkey`.
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
