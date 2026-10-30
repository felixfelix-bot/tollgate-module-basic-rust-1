//! The real-process end-to-end, run from `cargo test`.
//!
//! # Why a test that runs a script
//!
//! `scripts/spilman_receiver_binding_e2e.sh` proves the things an in-process test cannot:
//! a key that survives a **real process restart**, a key file that lands `0600` on a real
//! filesystem, `EX_CONFIG` on an unusable config dir, and a channel opened, paid and
//! **settled by the real `spilman-payer` binary as a separate OS process**. Items 2–5 of
//! the review listed exactly those as unproven.
//!
//! The first version of that evidence was a script nobody's test run would execute, which
//! is the same failure mode as the original bug: a check that exists but is never
//! traversed. So the script is invoked from here, which puts it behind
//! `cargo test --include-ignored` — the same command the quality gates run.
//!
//! It is `#[ignore]`d because it builds a release-of-sorts tree in its own target dir and
//! spawns three processes; it is not something to run on every `cargo test`.
//!
//! ```text
//! cargo test --features payer-driver --test spilman_process_e2e -- --include-ignored
//! ```

#![cfg(feature = "payer-driver")]

use std::path::Path;
use std::process::Command;

/// Resolve the repository root (the crate manifest directory).
fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

#[test]
#[ignore = "spawns real binaries and a mint daemon; run with --include-ignored"]
fn the_real_process_receiver_key_e2e_passes() {
    let script = repo_root().join("scripts/spilman_receiver_binding_e2e.sh");
    assert!(
        script.is_file(),
        "the E2E script is missing: {} — the process-level claims (restart, 0600, \
         EX_CONFIG, real payer settle) have no evidence without it",
        script.display()
    );

    // The mint's own default fee (400 ppk). A fee-free mint is the unrepresentative case
    // and is exactly what hid the fee-bearing receipt defect.
    let output = Command::new("bash")
        .arg(&script)
        .env("MINT_FEE_PPK", "400")
        .output()
        .expect("run the E2E script");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let log = format!("--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}\n--- end ---",);

    assert!(
        output.status.success(),
        "the real-process E2E failed ({:?}):\n{log}",
        output.status.code()
    );
    assert!(
        stdout.contains("RESULT: PASS"),
        "the script exited 0 without claiming PASS — read it, do not trust it:\n{log}"
    );
    // The two claims that matter most: the payer verified a close against a fee-bearing
    // mint, and the key the payee advertised is the key it signs with.
    assert!(
        stdout.contains("PAYER_SETTLED"),
        "no settlement marker from the real payer process:\n{log}"
    );
    assert!(
        stdout.contains("receiver_pubkey identical across the restart"),
        "the key did not survive a real restart:\n{log}"
    );
}
