# External-mint physical run

Build example `spilman-payer` with feature `payer-driver`. External HTTP funding is now the only mode (optional `--external-mint` is an explicit alias). The mint URL comes exclusively from seller `/spilman/params`; no embedded mint or URL override is used. This is test tooling, not a recoverable wallet: temporary payer storage and missing seller settlement make real-money use unsafe.

```
spilman-payer --payee http://SELLER:8080 --external-mint --phase-dir /tmp/run-unique
```

Harness creates an empty, unique phase directory beforehand. Do not reuse one containing gate files.

1. Driver requests mint SAT keys and a NUT-04 quote, prints the invoice, waits up to 120 seconds for PAID, requests blinded signatures, unblinds real proofs, then performs the real Spilman funding swap.
2. After funding and seller registration, driver prints `PAYER_PHASE_READY phase=funded`. Start proxy counting here, then create `funded.continue` in the phase directory.
3. Driver submits a real signed balance update and checks the seller's credited balance. `PAYER_PAYMENT_OK` reports this result. At `PAYER_PHASE_READY phase=paid`, stop proxy counting and create `paid.continue`.
4. Each gate has a 300-second timeout. Driver prints `PAYER_SETTLEMENT_NOT_IMPLEMENTED` and exits 0 only after successful payment verification. There is deliberately NO `PAYER_SETTLE_OK`: the previous marker falsely called a seller balance read-back settlement.

The standalone CDK test mint's FakeWallet auto-pays the funding invoice; crypto proofs and swaps remain real. A non-test mint requires payment of the printed invoice externally. This is not a simulated mint HTTP response.

## Remaining blocker

The seller's `payee_host.rs` explicitly does not implement channel-close lifecycle; there is no settlement endpoint in this worktree. Consequently this driver proves funding + signed payment + seller credit, NOT completed mint settlement. The harness must not claim settlement success. Seller close integration is separate work.

## Verification

`cargo test --release --example spilman-payer --features payer-driver -- --nocapture` executes `external_http_funding_opens_real_channel`: a real CDK test mint is served on HTTP, the exact external funding function fetches keys/quotes/proofs over HTTP, the funding swap completes, and mint URL/channel ID match. No board or network configuration is touched.

Cross compile with the actual musl toolchain (GNU/glibc cross GCC cannot link bundled SQLite correctly):

```
CC_aarch64_unknown_linux_musl=$HOME/toolchains/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc \
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=$HOME/toolchains/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc \
cargo build --release --target aarch64-unknown-linux-musl --example spilman-payer --features payer-driver
```
