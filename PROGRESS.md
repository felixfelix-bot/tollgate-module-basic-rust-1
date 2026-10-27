

## Phase 3 — payer-side channel lifecycle + crash recovery (GREEN)

**Finding (the seam is usage-context, not the payment balance).** The payee's
`get_amount_due` is computed from its own **accumulated usage variables**, fed by the
`context` JSON passed to `process_payment` — *not* from the balance the payer signed. The
cooperative close then hard-checks `balance == host.get_amount_due(channel_id, None)` and
rejects with `ValidationFailed { expected: 0, got: N }` when the two disagree. So the byte
counter must be driven into the payee on every payment, and the payee's `pricing_scale`
must be the byte price of one step. In this rail that is `pricing_scale = STEP`
(22,020,096), i.e. one 21 MiB step costs exactly 1 sat. This is the concrete form of the
"compute amount_due once from cumulative bytes" rule in §4, and it is now asserted in the
integration test (`accepted.amount_due == balance`).

**Second finding (a bug this phase caught).** The protocol's `sender_pubkey_hex` argument
is a **public** key; passing the secret's raw scalar fails deep inside the bridge with
`No key found for pubkey: ...`. The test now has separate `secret_hex()` / `pubkey_hex()`
helpers so the two can never be confused again.

**Third finding (no accessors).** cdk-spilman implements `SpilmanClientHost` on the
concrete `ConfigurableClientHost<S>` only — no blanket `Arc<H>` impl — and
`SpilmanClientBridge` owns its host with no accessor and consumes its networking by value.
Rather than build a ~20-method forwarding wrapper for no benefit, the rail:
- passes the `SpilmanClientNetworking` **into** `submit_funding_swap` (a mint client is
  stateless config, so a second instance is equivalent), and
- proves durability by opening a **separate read-only SQLite connection**
  (`ConfigurableClientHost::open_sqlite_read_only`) to the same file. That is a stronger
  proof than reading back through the writing handle, and it is why
  `payer::open_read_only_host` exists.
- `step_payment` deliberately takes **no** networking argument, so the hot path is
  structurally incapable of a mint round trip.

**Tests.** `tests/spilman_payer_lifecycle.rs`, all `#[ignore]`-gated (they need a mint),
run with `cargo test --test spilman_payer_lifecycle -- --ignored` against the in-process
`cdk-spilman-test-mint` harness. **3/3 pass**:
1. `payer_opens_signs_and_settles_a_channel` — two-phase open, 10 signed updates at
   exactly 1 sat/step, zero mint calls between open and settle, payee settles for exactly
   the signed balance after a restart, and the quantised retail model bills the same line.
2. `killed_process_between_persist_and_swap_recovers_the_channel` — crash before the
   swap: state survives as `OpeningFromSwap`, the re-prepared instance refuses to swap,
   and a failed restore never promotes the channel to `Open`.
3. `killed_after_swap_but_before_mark_open_recovers_the_channel` — crash *after* the
   swap, before `mark_open`: NUT-09 restore from the store alone recovers the funding
   proofs, and the recovered channel is immediately payable with no second mint spend.

Plus 3 unit tests in `payer.rs` pinning the fund-safety gate, clock sanity, and the
expiry margin (§6 hazard 5).

**Counts.** `cargo test --all-targets`: 216 lib + 14 billing, 0 failed. The 3 integration
tests are `ignored` by default, so the default run is unchanged for CI.

**Files touched.** `src/spilman/payer.rs` (new: `ChannelOpening` two-phase +
`step_payment` + `recover_open_channel` + `open_read_only_host` + `ensure_persisted`),
`src/spilman/mod.rs` (`pub mod payer`), `tests/spilman_payer_lifecycle.rs` (new),
`Cargo.toml` (dev-dependency `cdk-spilman-test-mint`).

## Phase 4 — payee-side payment verification (GREEN)

**What was broken.** `record_payment` refused every payment, because the payee held no
per-channel funding record to verify a signature against. Refusing is safe but it also
means no real payment can ever be accepted, so the rail was unusable — and the host E2E
(`~/reports/spilman-tollgate/host-e2e-spilman.sh`) could not justify a pass at assertion D.

**The fix, in three parts.**

1. **The funding record is durable** (`src/spilman/ledger.rs`). `spilman_channel_funding`
   lives in the same SQLite file as `spilman_channel_balance` — one file, one durability
   story, one `synchronous = FULL` + WAL setting. It stores exactly the five values
   upstream's `verify_signature` runs on (`params_json`, `funding_proofs_json`,
   `channel_secret_hex`, `keyset_info_json`, plus the `capacity` ceiling read out of the
   params) and reads them back **verbatim** — no re-serialisation in either direction.
   `save_channel_funding` is `INSERT OR IGNORE`: first write wins, because the params carry
   both the capacity ceiling and the secret the signature is checked against, so letting a
   second registration replace them would let anyone raise the ceiling on an open channel.
2. **A real payee host** (`src/spilman/payee_host.rs`). `LedgerPayeeHost` implements
   cdk-spilman's `SpilmanHost` directly over the ledger, mirroring MONAD's shape
   (`monad-relay/src/payments.rs:961`) rather than building the ~20-method
   `SpilmanStorage` backend `configurable_host` wants — one host, one store, no second
   copy of the balances. `validate_payment` only reads three host values, and all three
   are genuine ledger reads that fail closed: `get_channel_state` → `Open` **iff a funding
   record exists** (not iff a *balance* row exists — that is the state a forgery creates),
   `get_funding` → the five values, `get_amount_due` → the stored balance. Every other hook
   is a channel funding/close concern this rail does not implement, so it is an explicit
   refusal or an empty answer, each labelled `NOT ON THE VERIFICATION PATH` with the
   reason. `record_payment` is deliberately **inert**: credit is granted only by the CAS
   ledger write, and a second monotonic balance writer is the exact shape of the
   original bug.
3. **Verify, then write** (`src/spilman/rail.rs`). `record_payment` now: loads the funding
   record (absent → `UnknownChannel`, unchanged) → calls **upstream's own**
   `SpilmanBridge::validate_payment` and refuses on any error → and only then writes the
   CAS row. Not a re-implementation: the channel is re-derived by upstream from the
   persisted bytes, so this rail cannot drift from the protocol's own definition of a
   valid signature. Refusals carry upstream's reason in
   `SpilmanError::PaymentNotVerified { detail }`, so a 409 explains itself.

**Tests.** `tests/spilman_payee_verification.rs`, `#[ignore]`-gated (they need the mint,
matching the phase-3 convention) — run with
`cargo test --test spilman_payee_verification -- --ignored`. **7/7 pass.** The funding
record is not hand-built in the tests: a reference `ConfigurableHost` — cdk-spilman's own
payee host — processes the registration, and the five values are copied out with
`get_funding_data`, so the bytes under test are the bytes upstream derived.
1. `a_real_signed_payment_is_accepted` — **the load-bearing one.** A real Schnorr
   signature over a real funded channel is accepted, becomes durable, and the resulting
   credit serves exactly 22,021,000 bytes and denies 22,021,001. Without it, "refuse
   everything" would pass every other test — exactly the state the hotfix left.
2. `a_garbage_signature_on_a_funded_channel_is_refused` — the exact `"00"` forgery, now
   on a channel that *is* funded; i.e. the case that was accepted before the hotfix.
3. `a_correctly_shaped_but_wrong_signature_is_refused` — 128 hex chars of nonsense, **and**
   a genuine signature for balance 1 presented as balance 2 (everything valid except the
   signed message).
4. `a_balance_above_capacity_is_refused` — capacity + 1, refused before the signature
   check, with the detail naming the capacity.
5. `a_replay_of_the_exact_previous_balance_is_refused` — the case authenticity *cannot*
   catch: the signature verifies perfectly because it is valid, and the CAS is what
   refuses. A pre-existing guarantee, now asserted on verified payments too.
6. `a_refused_payment_leaves_no_balance_row` — and the baseline stays "nothing recorded",
   proven by a genuine payment still being accepted afterwards.
7. `an_unfunded_channel_still_reports_unknown` — the pre-existing contract is unchanged.

**Mutation check (the tests have teeth).** Deleting only the `validate_payment` block
from `record_payment` makes **4 of 7 fail** (`garbage`, `shaped-but-wrong`,
`above-capacity`, `leaves-no-row`) while `a_real_signed_payment_is_accepted` still
passes — which is exactly why the positive case and the refusals are both required.

**`tests/spilman_payment_authenticity.rs` is untouched and still 3/3 green.**

**Counts.** Default suite: 226 lib + 3 + 2 + 14 = **245 pass, 0 fail**, 13 ignored
(7 new + 3 pre-existing + 3 more). `--features test-support`: all 7 result groups ok
(incl. `rail_credits_exactly_what_was_recorded`). `-- --ignored`: 7 new + 3 pre-existing
mint suites, 0 fail.

**Files touched.** `src/spilman/ledger.rs` (`ChannelFundingRecord`,
`save_channel_funding`, `get_channel_funding`, schema), `src/spilman/payee_host.rs` (new),
`src/spilman/rail.rs` (verify-then-write), `src/spilman/mod.rs`
(`SpilmanError::PaymentNotVerified`, exports), `tests/spilman_payee_verification.rs` (new).

**Known, pre-existing, not fixed here.**
- `cargo clippy --all-targets -- -D warnings` fails on two `field_reassign_with_default`
  lints in `src/http/spilman_mount_test.rs`. Verified identical at `a7eca5d` with these
  changes stashed, so it is not a regression from this work.
- `cargo fmt` also wants to reflow `src/http/**`. Reverted rather than swept into these
  commits.

**Remaining for the physical-router E2E.** The rail verifies against a funding record that
must be *written*. Nothing on the live router writes one yet: a payer's registration must
reach the payee over HTTP and be turned into a `ChannelFundingRecord`. Next step is that
registration route — accept params + funding proofs, validate them against the channel id
(`validate_new_channel_funding`), persist via `save_channel_funding` — in front of the now
working `record_payment`.

## Phase 5 — receiver-key binding (GREEN, `pr/spilman-receiver-binding`)

- `receiver_pubkey` advertised on `GET /spilman/params`; `SpilmanRail::receiver_pubkey()`
  exposes the rail's key. `null` when the rail holds none. — done.
- New persisted key at `<config dir>/spilman-receiver.key` (`src/spilman/receiver_key.rs`):
  hex, `0600`, `create_new` (race-loser re-reads the winner), refuses corrupt files,
  reloaded on every boot; `main.rs` exits `EX_CONFIG` if it cannot load. Replaces the
  merchant-identity derivation, which would have linked the public params endpoint to the
  Nostr pubkey. — done, 4 unit tests + restart test.
- `receiver_key_is_acceptable` now compares against our own key (`None` → `false`).
  `mint_and_keyset_is_acceptable` now compares against the `(mint_url, keyset_json)` the
  close path was given; `false` when the host was built without them. — done.
- `SpilmanRail::register_channel` refuses a channel addressed to a foreign receiver key
  (`enforce_receiver_binding`), so the failure is at the door, not at settlement. — done.
- Payer `examples/spilman_payer.rs` uses the advertised key; single ephemeral key is the
  sender's; mint mismatch still fails before funding. — done.
- RED observed for every layer (see REPORT.md "Evidence"). — done.
- Full gates green: 327/0 with `test-support,payer-driver`, 306/0 default, clippy 0 both,
  x86_64-musl build 0. — done.
- Item 7 fixed as a money bug: keyless rail now REFUSES registration (400) instead of
  accepting a channel it can never settle; `LedgerPayeeHost::new` still answers false on
  the verification path. — done, mutation-verified.
- Item 6: `enforce_mint_binding` calls `mint_and_keyset_is_acceptable` with the trusted
  configured mint; honest about the keyset half being self-consistency only. — done,
  mutation-verified.
- Items 2-5: `scripts/spilman_receiver_binding_e2e.sh` + `~/reports/spilman_receiver_e2e.log`
  — real module process, real restart (same key), mode 600 on ext4, exit 78 on a
  read-only config dir, and a real `spilman-payer` process settling (close 200, not 409).
  18/18 checks. — done.
- Defect found, not fixed: fee-bearing close receipt (payer aborts after the mint already
  moved the proofs; payer.rs:285 compares nominal receiver_sum to net balance). — reported.
- Test-isolation flake in `src/cli/mod.rs` (env var set outside `env_guard`) fixed. — done.
- Survivors: no physical router/aarch64, no real sats, E2E not in `cargo test`, key
  rotation undocumented.
