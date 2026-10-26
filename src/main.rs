//! tollgate-module-basic-rust — main entry point.

use std::path::PathBuf;
use std::sync::Arc;
use tollgate_module_basic_rust::{
    cli, config, http, identity, session, spilman, tracing_setup, wallet,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() {
    // Initialize tracing — must happen before anything else
    tracing_setup::init();

    tracing::info!("RunInitialProbe: tollgate-module-basic-rust v{VERSION} starting");

    // Load config
    let config_obj = config::load_config().unwrap_or(None).unwrap_or_default();
    tracing::info!(
        metric = %config_obj.metric,
        mints = config_obj.accepted_mints.len(),
        "config loaded"
    );

    // Load or generate merchant identity
    let identity = identity::MerchantIdentity::load_or_generate()
        .expect("failed to load/generate merchant identity");
    tracing::info!(pubkey = %identity.pubkey_hex(), "merchant identity loaded");

    // Load or generate wallet seed
    let db_dir = PathBuf::from("/etc/tollgate");
    let seed_path = db_dir.join("wallet_seed.bin");
    if let Some(parent) = seed_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // First-boot auto-migration: if gonuts bbolt wallet.db exists AND CDK
    // wallet.sqlite does NOT exist AND migration marker is absent:
    // 1. Run gonuts-export → tokens.jsonl
    // 2. Import tokens via wallet.receive()
    // 3. Write .migration_complete marker
    // 4. Rename wallet.db → wallet.db.pre-migration
    let old_db = db_dir.join("wallet.db");
    let new_db = db_dir.join("wallet.sqlite");
    let migration_marker = db_dir.join(".migration_complete");

    if old_db.exists() && !new_db.exists() && !migration_marker.exists() {
        tracing::info!("detected gonuts bbolt wallet, attempting auto-migration");
        let export_tool = std::env::var("GONUTS_EXPORT_PATH")
            .unwrap_or_else(|_| "/usr/bin/gonuts-export".to_string());
        let tokens_file = db_dir.join("tokens.jsonl");

        let export_result = tokio::process::Command::new(&export_tool)
            .arg(&old_db)
            .arg(&tokens_file)
            .output()
            .await;

        match export_result {
            Ok(output) if output.status.success() => {
                tracing::info!("gonuts-export completed, importing tokens");
                // Tokens will be imported on next CLI `migrate` command
                // or when mint connectivity allows wallet.receive()
                tracing::info!(tokens_file = %tokens_file.display(), "tokens exported, run 'migrate <path>' via CLI to import");
            }
            Ok(output) => {
                tracing::warn!(
                    stderr = String::from_utf8_lossy(&output.stderr).to_string(),
                    "gonuts-export failed, starting with empty wallet"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    export_tool = %export_tool,
                    "gonuts-export not found or failed, starting with empty wallet. \
                     Operator can run migration manually: gonuts-export wallet.db tokens.jsonl && \
                     echo 'migrate /etc/tollgate/tokens.jsonl' | nc -U /var/run/tollgate.sock"
                );
            }
        }
    }

    let seed = wallet::TollWallet::load_or_create_seed(&seed_path)
        .await
        .expect("failed to load/create wallet seed");

    // Build wallet with accepted mints from config
    let mint_urls: Vec<String> = config_obj
        .accepted_mints
        .iter()
        .map(|m| m.url.clone())
        .collect();
    let mut toll_wallet = wallet::TollWallet::new(seed, mint_urls, db_dir.clone());
    for mint in &config_obj.accepted_mints {
        match toll_wallet.ensure_mint(&mint.url).await {
            Ok(()) => tracing::info!(mint = %mint.url, "wallet registered for mint"),
            Err(e) => tracing::warn!(mint = %mint.url, error = %e, "failed to register mint"),
        }
    }

    // P1: durable session/quote store. Same directory as the wallet database so a
    // single backup (or a single drained volume) covers both.
    let state_db_path = {
        let p = std::env::var("TOLLGATE_STATE_DB")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| db_dir.join("tollgate.db"));
        tracing::info!(path = %p.display(), "durable session store");
        p
    };

    // Wholesale Spilman rail. `None` unless config.json says `spilman.enabled`.
    //
    // A config error here is fatal on purpose (EX_CONFIG): an operator who opted
    // into the wholesale rail and got the config wrong must not silently fall back
    // to "channel payments are refused" or, worse, to a ledger that forgets.
    let spilman_rail = match spilman::SpilmanRail::from_config(&config_obj.spilman) {
        Ok(rail) => rail.map(|rail| {
            let receiver_key =
                cashu::nuts::SecretKey::from_slice(&identity.secret_key.secret_bytes())
                    .expect("merchant identity is a valid secp256k1 scalar");
            Arc::new(rail.with_receiver_key(receiver_key))
        }),
        Err(e) => {
            eprintln!("FATAL: spilman config: {e}");
            std::process::exit(78); // EX_CONFIG
        }
    };
    if let Some(rail) = &spilman_rail {
        tracing::info!(
            in_bytes_per_millisat = rail.in_bytes_per_millisat(),
            mint = rail.mint_url().unwrap_or("<none>"),
            "spilman wholesale rail ENABLED"
        );
    } else {
        tracing::debug!("spilman wholesale rail disabled");
    }

    // Build app state
    let state = Arc::new(http::AppState {
        config: Arc::new(config_obj),
        identity: Arc::new(identity),
        wallet: Arc::new(tokio::sync::Mutex::new(Some(toll_wallet))),
        sessions: Arc::new(tokio::sync::Mutex::new(
            session::SessionManager::open(&state_db_path).unwrap_or_else(|e| {
                // FAIL CLOSED: an unreadable store must never be read as "no
                // sessions" — starting empty would grant fresh access to every
                // client. Refusing to start is strictly safer than that.
                eprintln!("FATAL: cannot open session store: {e}");
                std::process::exit(78); // EX_CONFIG
            }),
        )),
        quotes: Arc::new(std::sync::Mutex::new(
            http::routes::quote::MintQuoteRegistry::new(),
        )),
        spilman: spilman_rail,
    });

    // Start HTTP server + CLI socket
    let http_state = state.clone();
    let http_handle = tokio::spawn(async move {
        let app = http::create_router((*http_state).clone());
        // A8: the bind address is overridable so a conformance runner can drive
        // the real binary on an ephemeral port. The default remains the
        // protocol's :2121 on every interface, because a captive portal bound to
        // loopback cannot be reached by any LAN client.
        let bind = std::env::var("TOLLGATE_BIND").unwrap_or_else(|_| "0.0.0.0:2121".to_string());
        let listener = tokio::net::TcpListener::bind(&bind)
            .await
            .unwrap_or_else(|e| panic!("failed to bind {bind}: {e}"));
        tracing::info!(bind = %bind, "HTTP server listening");
        // ADR-0007: ConnectInfo must reach the handlers, so the app is wrapped here.
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .expect("HTTP server error");
    });

    // ADR-0006 §5 (continuity): a module restart is our fault, not the customer's.
    // Restore the gate for every still-valid session: deauth first to clear any state
    // that a module-only restart left behind, then auth to re-open it. Sessions that
    // expired or exhausted while down are closed by close_expired() at open() time and
    // are deliberately NOT re-authed.
    {
        let sessions = state.sessions.lock().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let valid: Vec<String> = sessions
            .snapshot()
            .into_iter()
            .filter(|s| s.expiry > now && s.used < s.allotment)
            .map(|s| s.mac)
            .collect();
        drop(sessions);
        for mac in &valid {
            let _ = tollgate_module_basic_rust::metering::close_gate(mac).await; // clear stale state
            match tollgate_module_basic_rust::metering::open_gate(mac).await {
                tollgate_module_basic_rust::metering::GateOutcome::Opened => {
                    tracing::info!(mac = %mac, "restored gate for valid session at boot")
                }
                other => tracing::warn!(
                    mac = %mac,
                    outcome = ?other,
                    "could not restore gate at boot; client will re-trigger the portal"
                ),
            }
        }
        if !valid.is_empty() {
            tracing::info!(count = valid.len(), "boot continuity: gates re-opened");
        }
    }

    // ADR-0006 §1/§3/§4: periodic gate-close sweep. Before this, close_expired ran
    // ONLY at startup, so a session could expire or exhaust while the daemon ran and
    // the client kept the access it paid for. The sweep closes terminal sessions and
    // their gates every 30s (operator-accepted interval).
    let sweep_state = state.clone();
    // Underscore-prefixed only to say "held, not read": the handle is kept alive so
    // the sweep task is not detached-and-forgotten. Pre-existing site.
    let _sweep_handle = tokio::spawn(async move {
        let mut tick =
            tokio::time::interval(std::time::Duration::from_secs(session::SWEEP_INTERVAL_SECS));
        // The first tick fires immediately; that is fine — it is a no-op when nothing
        // is terminal, and it closes anything that slipped in during startup.
        loop {
            tick.tick().await;
            // STEP 1: snapshot the active sessions WITHOUT live counters. The
            // in-memory `used` is only ever a fallback — the truth lives in
            // nodogsplash — so exhaustion can ONLY be detected after syncing the
            // live counters in. Without this sync the sweep never saw exhaustion:
            // `used` stayed 0 in memory while the client had transferred bytes.
            // (Same silent-zero class as #40/#42/#43; found by measuring on A04E.)
            let (active, now) = {
                let sessions = sweep_state.sessions.lock().await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let active: Vec<(String, u64, u64, u64)> = sessions
                    .map_ref()
                    .iter()
                    .filter(|(_, s)| s.expiry > now && s.used < s.allotment)
                    .map(|(mac, s)| (mac.clone(), s.allotment, s.used, s.expiry))
                    .collect();
                (active, now)
            };

            // STEP 2: poll live usage per active session, OUTSIDE the lock. One
            // ndsctl exec per active session per tick — cheap, and the exec is
            // already the metering mechanism.
            let mut live_readings: Vec<(String, u64)> = Vec::with_capacity(active.len());
            for (mac, _allotment, _used, _expiry) in &active {
                match tollgate_module_basic_rust::metering::poll_usage_reading(mac).await {
                    Ok(r) => live_readings.push((mac.clone(), r.used)),
                    Err(e) => {
                        // Absence is NOT zero: if ndsctl has no record we keep the
                        // stored counter rather than pretending the client
                        // transferred nothing (or something it did not).
                        tracing::debug!(mac = %mac, error = %e, "sweep: no live reading, keeping stored counter");
                    }
                }
            }

            // STEP 3: write the live counters back, THEN decide terminal. Only now
            // can `used >= allotment` be true from real traffic.
            //
            // The decision goes through `sweep_with_channel_credit`: for a
            // channel-bound session it first recomputes `allotment` from the
            // channel's latest VERIFIED balance, so an increment that landed since
            // the last tick extends access without a new gate-open, and an exhausted
            // channel stops granting. With no rail the recomputation is the identity
            // (`channel_id` is always None, effective == retail), which is what keeps
            // the rail-off path bit-identical rather than merely similar.
            let terminal = {
                let mut sessions = sweep_state.sessions.lock().await;
                for (mac, used) in &live_readings {
                    sessions.update_usage(mac, *used);
                }
                let terminal = session::channel_credit::sweep_with_channel_credit(
                    &mut sessions,
                    sweep_state.spilman.as_deref(),
                    now,
                );
                for mac in &terminal {
                    // Flush the exact final usage BEFORE removing the row: the
                    // terminal value is what a dispute would be settled against
                    // (ADR-0002).
                    sessions.flush_for_sweep(mac);
                    sessions.revoke_session(mac);
                }
                terminal
            };
            if terminal.is_empty() {
                continue;
            }
            // Close the gates AFTER releasing the lock: ndsctl exec must never hold
            // the session mutex, or a slow deauth stalls every HTTP handler.
            for mac in &terminal {
                match tollgate_module_basic_rust::metering::close_gate(mac).await {
                    tollgate_module_basic_rust::metering::GateOutcome::Closed => {
                        tracing::info!(mac = %mac, "gate closed for terminal session")
                    }
                    tollgate_module_basic_rust::metering::GateOutcome::UnknownClient => {
                        // SUCCESS for a close: nodogsplash already forgot this client.
                        tracing::debug!(mac = %mac, "gate already closed (client unknown)")
                    }
                    other => {
                        // §2: never propagate. Log with the tool's own words; the next
                        // sweep retries. A quiet leak gets a counter, not a failure.
                        tracing::warn!(mac = %mac, outcome = ?other, "gate close failed; will retry next sweep");
                    }
                }
            }
        }
    });

    let cli_state = state.clone();
    let cli_handle = tokio::spawn(async move {
        if let Err(e) = cli::serve(cli_state).await {
            tracing::error!(error = %e, "CLI socket server error");
        }
    });

    // Wait for shutdown signal
    let shutdown_int = tokio::signal::ctrl_c();

    tokio::pin!(shutdown_int);

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM handler");

    tokio::select! {
        _ = shutdown_int => {
            tracing::info!("SIGINT received, shutting down");
        }
        _ = sigterm.recv() => {
            tracing::info!("SIGTERM received, shutting down");
        }
    }

    // Cleanup
    let socket_path = cli::socket_path();
    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }

    http_handle.abort();
    cli_handle.abort();
    tracing::info!("shutdown complete");
}
