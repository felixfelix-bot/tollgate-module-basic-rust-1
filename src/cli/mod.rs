//! Unix socket CLI server.
//!
//! Listens on /var/run/tollgate.sock (or TOLLGATE_TEST_CONFIG_DIR/tollgate.sock).
//! Mode 0660. Line-delimited JSON request/response.
//!
/// Commands: version, status, "wallet info", "wallet balance", "migrate <path>"
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use crate::http::AppState;

/// Socket path — honors TOLLGATE_TEST_CONFIG_DIR for tests.
pub fn socket_path() -> PathBuf {
    std::env::var("TOLLGATE_TEST_CONFIG_DIR")
        .map(|d| PathBuf::from(d).join("tollgate.sock"))
        .unwrap_or_else(|_| PathBuf::from("/var/run/tollgate.sock"))
}

/// Version info returned by the `version` command.
pub fn version_string() -> String {
    let version = env!("CARGO_PKG_VERSION");
    let commit = option_env!("GIT_COMMIT").unwrap_or("0000000");
    let build_time = option_env!("BUILD_TIME").unwrap_or("unknown");
    let rust_version = option_env!("RUSTC_VERSION").unwrap_or("unknown");

    format!(
        "version: {version}\n\
         commit: {commit}\n\
         build_time: {build_time}\n\
         rust_version: {rust_version}\n\
         openwrt: target={arch}\n",
        arch = std::env::consts::ARCH
    )
}

/// Start the Unix socket CLI server with shared AppState.
pub async fn serve(state: Arc<AppState>) -> std::io::Result<()> {
    let path = socket_path();

    // Remove stale socket
    if path.exists() {
        std::fs::remove_file(&path)?;
    }

    // Create parent dir if needed
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(&path)?;

    // Set mode 0660
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))?;
    }

    tracing::info!(socket = %path.display(), "CLI Unix socket listening");

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let state = state.clone();
                tokio::spawn(handle_connection(stream, state));
            }
            Err(e) => {
                tracing::error!(error = %e, "accept failed on CLI socket");
            }
        }
    }
}

async fn handle_connection(stream: tokio::net::UnixStream, state: Arc<AppState>) {
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        match buf_reader.read_line(&mut line).await {
            Ok(0) => break, // EOF
            Ok(_) => {
                let cmd = line.trim();
                let response = handle_command(cmd, &state).await;
                if let Err(e) = writer.write_all(response.as_bytes()).await {
                    tracing::warn!(error = %e, "write failed on CLI socket");
                    break;
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "read failed on CLI socket");
                break;
            }
        }
    }
}

async fn handle_command(cmd: &str, state: &AppState) -> String {
    match cmd {
        "version" => version_string(),
        "status" => {
            serde_json::json!({
                "success": true,
                "message": "running"
            })
            .to_string()
                + "\n"
        }
        "wallet info" => {
            let wallet_guard = state.wallet.lock().await;
            if let Some(ref wallet) = *wallet_guard {
                let balances = wallet.get_balance_by_mint().await.unwrap_or_default();
                let mints: Vec<serde_json::Value> = balances
                    .iter()
                    .map(|(url, bal)| serde_json::json!({"url": url, "balance": bal}))
                    .collect();
                drop(wallet_guard);
                serde_json::json!({
                    "success": true,
                    "message": serde_json::to_string(&mints).unwrap_or_default()
                })
                .to_string()
                    + "\n"
            } else {
                serde_json::json!({
                    "success": true,
                    "message": "no wallet configured"
                })
                .to_string()
                    + "\n"
            }
        }
        "wallet balance" => {
            let wallet_guard = state.wallet.lock().await;
            if let Some(ref wallet) = *wallet_guard {
                match wallet.get_balance().await {
                    Ok(balance) => {
                        drop(wallet_guard);
                        serde_json::json!({
                            "success": true,
                            "message": balance.to_string()
                        })
                        .to_string()
                            + "\n"
                    }
                    Err(e) => {
                        drop(wallet_guard);
                        serde_json::json!({
                            "success": false,
                            "error": format!("wallet error: {e}")
                        })
                        .to_string()
                            + "\n"
                    }
                }
            } else {
                serde_json::json!({
                    "success": true,
                    "message": "0"
                })
                .to_string()
                    + "\n"
            }
        }
        cmd if cmd.starts_with("migrate ") => {
            let tokens_path = cmd.strip_prefix("migrate ").unwrap().trim();
            match run_migration(tokens_path, state).await {
                Ok(report) => {
                    serde_json::json!({
                        "success": true,
                        "message": report
                    })
                    .to_string()
                        + "\n"
                }
                Err(e) => {
                    serde_json::json!({
                        "success": false,
                        "error": format!("migration failed: {e}")
                    })
                    .to_string()
                        + "\n"
                }
            }
        }
        _ => {
            serde_json::json!({
                "success": false,
                "error": format!("unknown command: {cmd}")
            })
            .to_string()
                + "\n"
        }
    }
}

/// Run wallet migration from a tokens.jsonl file.
///
/// Each line is a Cashu V3/V4 token string. For each token, calls
/// `wallet.receive()`. Requires mint connectivity. After all receives,
/// optionally advances keyset counters using keyset_counters.json.
///
/// Returns a JSON report string with imported/failed counts.
async fn run_migration(tokens_path: &str, state: &AppState) -> Result<String, String> {
    let content = tokio::fs::read_to_string(tokens_path)
        .await
        .map_err(|e| format!("failed to read {tokens_path}: {e}"))?;

    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    let total = lines.len();

    let wallet_guard = state.wallet.lock().await;
    let wallet = wallet_guard
        .as_ref()
        .ok_or_else(|| "no wallet configured".to_string())?;

    let mut imported: u64 = 0;
    let mut failed: u64 = 0;
    let mut errors: Vec<String> = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        let token = line.trim();
        match wallet.receive(token).await {
            Ok(amount) => {
                imported += 1;
                tracing::info!(token_idx = i, amount, "migrated token");
            }
            Err(e) => {
                failed += 1;
                let err = format!("token {i}: {e}");
                tracing::warn!(error = %err, "migration token failed");
                errors.push(err);
            }
        }
    }

    drop(wallet_guard);

    let report = serde_json::json!({
        "total": total,
        "imported": imported,
        "failed": failed,
        "errors": errors.iter().take(10).collect::<Vec<_>>(),
    });

    Ok(serde_json::to_string(&report).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::identity::MerchantIdentity;
    use crate::session::SessionManager;
    use crate::wallet::TollWallet;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn make_test_state() -> Arc<AppState> {
        INIT.call_once(|| {
            // Redirect config/identity paths to a temp dir so tests
            // don't try to write to /etc/tollgate (fails on CI runners).
            //
            // The env var is process-global, and other tests assert on it
            // (`config::tests::config_dir_reports_correct_directory` removes it and
            // expects the default). Setting it *outside* the shared guard let it land
            // between that test's `remove_var` and its assertion — a flake that only
            // appeared once a third suite also touched the variable. Take the same
            // guard every other env-var test uses.
            let _g = crate::config::tests::env_guard();
            let dir = std::env::temp_dir().join("tollgate-cli-tests");
            std::fs::create_dir_all(&dir).ok();
            std::env::set_var("TOLLGATE_TEST_CONFIG_DIR", &dir);
        });
        let config = Arc::new(Config::new_default());

        // Generate a test identity in-memory (don't hit disk — CI runners
        // fail on MerchantIdentity::load_or_generate() write).
        let secp = secp256k1::Secp256k1::new();
        let (secret_key, _) = secp.generate_keypair(&mut rand::thread_rng());
        let identity = Arc::new(MerchantIdentity {
            name: "merchant".to_string(),
            secret_key,
        });

        let wallet = Arc::new(tokio::sync::Mutex::new(Some(TollWallet::new(
            [0u8; 64],
            vec![],
            std::path::PathBuf::from("/tmp"),
        ))));
        // P1: durable. Same fail-closed rule as main.rs — an unreadable store
        // must not be read as "no sessions".
        let state_db = std::env::var("TOLLGATE_STATE_DB")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("/etc/tollgate/tollgate.db"));
        let sessions = Arc::new(tokio::sync::Mutex::new(
            SessionManager::open(&state_db).unwrap_or_else(|e| {
                eprintln!(
                    "FATAL: cannot open session store at {}: {e}",
                    state_db.display()
                );
                std::process::exit(78);
            }),
        ));
        Arc::new(AppState {
            config,
            identity,
            wallet,
            sessions,
            quotes: Arc::new(std::sync::Mutex::new(
                crate::http::routes::quote::MintQuoteRegistry::new(),
            )),
            spilman: None,
        })
    }

    #[tokio::test]
    async fn version_contains_required_fields() {
        let v = version_string();
        assert!(v.contains("version:"));
        assert!(v.contains("commit:"));
        assert!(v.contains("build_time:"));
        assert!(v.contains("rust_version:"));
        assert!(v.contains("openwrt"));
    }

    #[tokio::test]
    async fn status_returns_running() {
        let state = make_test_state();
        let resp = handle_command("status", &state).await;
        let json: serde_json::Value = serde_json::from_str(resp.trim()).unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["message"], "running");
    }

    #[tokio::test]
    async fn wallet_balance_returns_zero_for_empty_wallet() {
        let state = make_test_state();
        let resp = handle_command("wallet balance", &state).await;
        let json: serde_json::Value = serde_json::from_str(resp.trim()).unwrap();
        assert_eq!(json["success"], true);
        // Balance will be "0" since the wallet has no mints registered
        assert_eq!(json["message"], "0");
    }

    #[tokio::test]
    async fn wallet_info_returns_json() {
        let state = make_test_state();
        let resp = handle_command("wallet info", &state).await;
        let json: serde_json::Value = serde_json::from_str(resp.trim()).unwrap();
        assert_eq!(json["success"], true);
        assert!(json["message"].is_string());
    }

    #[tokio::test]
    async fn unknown_command_returns_error() {
        let state = make_test_state();
        let resp = handle_command("foobar", &state).await;
        let json: serde_json::Value = serde_json::from_str(resp.trim()).unwrap();
        assert_eq!(json["success"], false);
        assert!(json["error"].as_str().unwrap().contains("unknown command"));
    }

    #[tokio::test]
    async fn migrate_nonexistent_file_returns_error() {
        let state = make_test_state();
        let resp = handle_command("migrate /nonexistent/tokens.jsonl", &state).await;
        let json: serde_json::Value = serde_json::from_str(resp.trim()).unwrap();
        assert_eq!(json["success"], false);
        assert!(json["error"].as_str().unwrap().contains("failed to read"));
    }

    #[tokio::test]
    async fn migrate_empty_file_returns_zero_totals() {
        let tmp = tempfile::TempDir::new().unwrap();
        let tokens_path = tmp.path().join("tokens.jsonl");
        std::fs::write(&tokens_path, "").unwrap();

        let state = make_test_state();
        let path_str = tokens_path.to_str().unwrap();
        let resp = handle_command(&format!("migrate {path_str}"), &state).await;
        let json: serde_json::Value = serde_json::from_str(resp.trim()).unwrap();
        assert_eq!(json["success"], true);
        let report: serde_json::Value =
            serde_json::from_str(json["message"].as_str().unwrap()).unwrap();
        assert_eq!(report["total"], 0);
        assert_eq!(report["imported"], 0);
        assert_eq!(report["failed"], 0);
    }

    #[tokio::test]
    async fn migrate_invalid_tokens_counted_as_failed() {
        let tmp = tempfile::TempDir::new().unwrap();
        let tokens_path = tmp.path().join("tokens.jsonl");
        // Two invalid token strings — wallet has no mints registered so receive will fail
        std::fs::write(&tokens_path, "not-a-token\ndefinitely-not-a-token\n").unwrap();

        let state = make_test_state();
        let path_str = tokens_path.to_str().unwrap();
        let resp = handle_command(&format!("migrate {path_str}"), &state).await;
        let json: serde_json::Value = serde_json::from_str(resp.trim()).unwrap();
        assert_eq!(json["success"], true);
        let report: serde_json::Value =
            serde_json::from_str(json["message"].as_str().unwrap()).unwrap();
        assert_eq!(report["total"], 2);
        assert_eq!(report["failed"], 2);
    }
}
