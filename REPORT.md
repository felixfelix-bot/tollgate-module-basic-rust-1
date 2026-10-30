# REPORT — receiver-key binding in the Spilman rail

Branch `pr/spilman-receiver-binding`, base `origin/pr/spilman-channel-rail` @ `cc02326`.
The older report below ("Path A") is a different phase of this branch's lineage and is
kept verbatim for its own evidence; nothing in it is superseded by this section.

## The gap, precisely

A Spilman channel names a `receiver_pubkey` in its params. The payee signs every close
with *its own* receiver key (`LedgerPayeeHost::sign_with_tweaked_key`). Nothing on the
wire told a payer which key that was, and `examples/spilman_payer.rs` generated a random
one per run. Measured on real hardware: the channel funded at the mint, then every
`POST /spilman/close` answered **HTTP 409**, forever — the money sat in a channel the
payee could never close. The suite was green throughout because both halves were
internally consistent and neither half ever asked the other what key it held.

## What changed

1. **A persisted receiver key.** New `src/spilman/receiver_key.rs`. `main.rs` loads
   `<config dir>/spilman-receiver.key` (production `/etc/tollgate/spilman-receiver.key`)
   via `receiver_key::default_path()`, which resolves through the existing
   `config::config_dir()` so `TOLLGATE_TEST_CONFIG_DIR` moves it in tests. Tested
   properties:
   - created once with `0600` **at creation** (`OpenOptionsExt::mode`), hex + newline;
   - reloaded on every boot — same file, same key (restart test);
   - corrupt/empty/short/zero file is a **refusal**, never a quiet regeneration
     (regenerating would orphan every open channel);
   - `create_new` + re-read on `AlreadyExists`, so two simultaneous boots converge on one
     key instead of one overwriting the other.
   `main.rs` exits `78` (EX_CONFIG) if it cannot load the key: a rail that cannot settle
   must not start pretending it can.

   Deliberately **not** the merchant (Nostr) identity that `main.rs` used before: a
   compressed secp256k1 key shares its x-coordinate with the x-only Nostr pubkey, so
   advertising it on a public endpoint would link the router's identity to its payment
   rail. One extra file buys unlinkability.

2. **`GET /spilman/params` advertises `receiver_pubkey`.** Additive field on
   `ParamsResponse`; `Some(<33-byte compressed hex>)`, or `null` when the rail holds no
   key. Encoding matches `registration.rs` / `PublicKey::from_hex` (`02…`/`03…`). Docs:
   `docs/spilman-channel-rail.md` §2.3.

3. **The policy is honest.** `receiver_key_is_acceptable` compares the offered key with
   `self.receiver.public_key()`; `false` only when the host holds no key (the read-only
   `LedgerPayeeHost::new` shape). `mint_and_keyset_is_acceptable` was made honest where
   it can be: `for_close` is constructed with the rail's own configured `mint_url` and
   the keyset JSON fetched *from that mint*, so the comparison is against trusted bytes.
   It stays `false` for a host with neither — there is no cached keyset to validate
   against and inventing one would be a lie.

   `SpilmanRail::register_channel` additionally refuses a channel whose params name a
   foreign `receiver_pubkey` (`enforce_receiver_binding`) **before** persisting, using
   that same trait method: one implementation of the rule, at the door rather than at
   settlement. A keyless rail is the documented read-only carve-out.

4. **The payer opens against the advertised key.** `examples/spilman_payer.rs` fetches
   `/spilman/params`, requires `receiver_pubkey` (refusing missing/null/non-string/empty/
   unparseable), and uses it for both the open and the registration. The only ephemeral
   key left in the production path is the **sender's**, named as such. The one remaining
   `SecretKey::generate()` for a receiver lives inside `#[cfg(test)]`, in the in-process
   funding self-test that talks to a test mint and no payee — a throwaway by
   construction. The seller-advertised mint still wins; a `--mint-url` mismatch still
   fails before funding.

## Evidence — RED first, then GREEN

| Test | Mutation that makes it fail | Observed |
|---|---|---|
| `tests/spilman_receiver_binding.rs::a_channel_opened_against_the_advertised_key_settles_over_http` | `receiver_key_is_acceptable` → `false` | FAILED at registration, GREEN settles |
| same | params `receiver_pubkey` → `None` | FAILED at the params assertion |
| `…::a_channel_for_a_foreign_receiver_key_is_refused_at_registration` | params field removed | FAILED |
| `spilman_mount_test::params_advertises_the_receiver_key_the_payee_accepts` | field removed / policy `false` | RED before impl, GREEN after |
| `payee_host::tests::a_host_accepts_only_its_own_receiver_key` | policy → `false` | RED→GREEN |
| `examples/spilman_payer.rs::the_production_path_generates_no_receiver_key` | re-add `let receiver_secret = SecretKey::generate();` | FAILED (2 generates, 1 allowed) |
| `receiver_key::tests::{the_same_key_is_reloaded_after_a_restart, a_new_key_is_persisted_with_owner_only_permissions, a_corrupt_file_is_refused_and_left_untouched}` | regenerate per call / mode 0644 / silent replacement | RED→GREEN |

First RED run of the in-crate tests: `cargo test --lib spilman` → **2 failed** (params
advertisement + host policy) before any production change.

The settlement test is end-to-end over real sockets: an in-process `cdk-spilman-test-mint`
HTTP server, the payee on an `axum` router, a real `SpilmanPayerDriver` opening and funding
the channel with the advertised key, `POST /spilman/payment`, then `POST /spilman/close`;
it asserts the payee's receipt and that the payer's `CooperativeSettlement` unblinds the
returned proofs (`receiver_sum=3, sender_sum=125, total=128`). The swap against the mint
really executed: proofs were signed, swapped, and unblinded.

## Gates (all observed, exit 0)

- `cargo test --all-targets --features test-support,payer-driver -- --include-ignored`
  → **327 passed, 0 failed**.
- `cargo test --all-targets -- --include-ignored` → **306 passed, 0 failed**.
- `cargo clippy --all-targets -- -D warnings` → 0.
- `cargo clippy --all-targets --features test-support,payer-driver -- -D warnings` → 0.
- `cargo build --release --target x86_64-unknown-linux-musl --bin tollgate-module-basic-rust --features payer-driver --example spilman-payer`
  → 0; both artefacts `ELF 64-bit LSB pie executable, x86-64, static-pie linked`.
  aarch64 not attempted (another agent owns that toolchain).

No existing assertion was weakened; edits to existing tests are fixtures that now
install a receiver key (which production always did) plus the new params assertion.

## What is NOT proven

1. **No public mint, no real sats.** Every settlement used `cdk-spilman-test-mint` over
   loopback HTTP. Real code over a real socket, but a test mint with a fake wallet: no
   Lightning, no mainnet, no money.
2. **No physical-router run.** Builds and the suite are x86_64; this branch was not
   deployed to `tollgate-0195` (aarch64, blocked on the toolchain another agent owns). The
   409 was measured on hardware; its fix is measured in-process here.
3. **The payer's `main()` is not executed by the suite.**
   `the_production_path_generates_no_receiver_key` is a source-level guard: no behavioural
   test can observe which key a separate binary chose without a live payee and mint. It
   catches the specific regression (a random receiver key reappearing), not e.g. a caller
   that ignores the helper's return value.
4. **Restart durability is tested at the file and rail level, not across a real process
   restart** — `load_or_create` twice in one process plus a rail rebuild. The mechanism is
   a plain file read, but "process A wrote it, process B read it after exec" is not
   literally asserted.
5. **Key-file permissions on the deployed filesystem** (overlay/read-only rootfs) are
   untested; `0600` is asserted on tmpfs only. A read-only config dir makes `main.rs` exit
   `78` — loud, but unverified on the device.
6. **`mint_and_keyset_is_acceptable` is honest but not load-bearing on the live close
   path**: upstream's close preparation does not consult it (verified by reading
   `bridge.rs`), so it is unit-tested only. It is what a funding-time policy call would
   use, but nothing in this module calls it today.
7. **A payee with no receiver key still accepts registrations** (documented carve-out).
   It cannot settle anything, so it cannot lose money, but it can accumulate uncloseable
   records. Production always installs a key via `main.rs`.

---

# Appendix — earlier report (Path A phase, unchanged)

# REPORT — Path A (tollgate-module-basic-rust)

Reference: issue #12. Branch: stacked on `fix/tip-conformance-and-cdk-018` (#11).

Consumers must not be added to `corpus kg_state.green_consumers` on the strength
of this report. See "What is NOT verified" at the end.

## Summary

| Item | Status | Tests |
|---|---|---|
| A1 sign 1022, allotment = steps x step_size | DONE | 70 (was 62) |
| A2 real 21023 with level + code | DONE | 74 |
| A4 absent Content-Type, 1 MiB cap | DONE | 79 |
| A3 MAC resolution, sessions keyed on it | DONE | 86 |
| A7 wire the dead metering module | DONE | 92 |
| A5 mint quote state + NUT-09 restore | DONE (state machine only, see below) | 101 |
| A6 multi-mint selection | DONE (selection only, single wallet remains) | 107 |
| A9 remove the tautological tests | DONE | 108 |
| A8 conformance runner + committed verdict set | DONE | runner exit 0 |

`cargo test`: **108 passed, 0 failed**. `cargo fmt --check`: clean. `cargo build`: clean.

## The two findings that mattered most

### A3 — the reason nothing worked end to end

The payment handler created every session under the literal
`00:00:00:00:00:00`, and `/usage` keyed on `X-Forwarded-For` (an address). The
two could never agree, so `/usage` answered `-1/-1` for every caller and metering
did nothing — no matter how correct the wire format was. A1/A2/A4 alone would have
produced a conformant gateway that did not work.

### A6 — a bug that only exists with 2+ mints

`accepted_mints.first()` was used both to price a payment and to decide whether a
mint is acceptable. A token from the second configured mint was priced with the
first mint's table. With one mint configured the bug is invisible, which is how
Phase 4 came to be called "complete".

## Evidence per item

Every item was test-first: the test was written, observed failing for the right
reason, then the implementation added.

* **A1.** RED: `cannot find function calculate_allotment`. GREEN: 8 tests.
  Mutation-checked both ways — reverting the formula fails 4 tests
  (`left: 5000, right: 110100480`); reverting the signing fails the signature
  test (`sig len 0 != 128`).
* **A2.** RED: `cannot find function build_notice_event`. GREEN: 4 tests.
  `grep '"kind": 21023"' src/` returns nothing — all five bare sites routed
  through one builder.
* **A4.** RED: 2 of 5 failed (`absent CT` → 415; `>1 MiB` accepted). GREEN: 5.
  The other 3 passed before the change and act as regression guards.
* **A3.** GREEN: 7 tests against fixture lease/ARP files.
* **A7.** GREEN: 6 tests against a fake `ndsctl` shell script.
* **A5.** GREEN: 9 tests for quote state and restore classification.
* **A6.** GREEN: 6 tests. RED initially: `cannot find function select_mint_for_token`.
* **A9.** 3 tautologies replaced by 4 tests that drive the router via `oneshot`.
* **A8.** Runner drives the real binary and compares to `corpus/manifest.json`.

## A8 measured output (committed as `conformance/verdicts.json`)

```
PASS 13   FAIL 0   UNVERIFIED 14
```

Reachable and passing: 7/7 fixture decode, the four HTTP-01 contract vectors
(absent Content-Type, unsupported type, >1 MiB body, signed coded notice),
HTTP-02 `/whoami`, HTTP-03 `/usage`.

## What is NOT verified (read this before claiming conformance)

1. **`verify` and `spend` are UNVERIFIED — 14 of 27 checks.** Both require a live
   mint for NUT-07 checkstate. The offline run cannot certify them and does not
   pretend to. A run with `--mint` is required, and even then this runner does not
   yet implement the live check (§ "not implemented" below).
2. **A5 does not obtain a real invoice.** The `request` field is empty and the
   quote is not payable: fetching an invoice needs a CDK wallet bound to a mint,
   which the wallet layer does not do. The state machine and its failure modes are
   real and tested; the mint call is absent. Deliberately not faked.
3. **A6 is selection only.** `state.wallet` still holds a single `TollWallet`.
   Per-mint wallet instances are a CDK wiring change, not a selection change.
4. **Hardware paths.** `/tmp/dhcp.leases`, `/proc/net/arp`, `ndsctl state <mac>`
   behaviour, and the MT6000 dataplane are all Path B. The resolvers and the
   metering parser are tested against fixtures and fake binaries respectively.
5. **Sessions and quotes are in-memory.** A restart loses them. That is a
   pre-existing documented gap, unchanged here, and it is the same class of defect
   TIP-05 (#40) argues must be specified rather than left silent.
6. **`/whoami` returned `mac=` (empty) in the conformance run** because the test
   container has no DHCP lease for `192.168.1.50`. The shape passes; real identity
   resolution needs a router.

## Bugs the runner found in my own work

Two, both recorded because they are the point of A8:

1. **The handler hung on an unaccepted mint.** `verify()` performed a NUT-07
   network call BEFORE the allowlist check, so a token from an unaccepted mint
   cost a full 30 s mint timeout before being refused. Fixed by moving mint
   selection ahead of any network call, in `pay.rs`.
2. **My runner's own absent-Content-Type test was a false FAIL.** `urllib` adds
   `Content-Type: application/x-www-form-urlencoded` whenever `data=` is passed,
   so the server saw a type and answered 415 for a reason the test never intended.
   Rewritten to POST over a raw socket so the header is genuinely absent.

## Not in this Path

A8 does not implement: a 405 for non-POST methods, converting axum's own
body-limit rejection into a notice, or a live-mint verify/spend lane. All three
are named rather than guessed at.

---

# Round 2 — the gaps the first report listed, closed or re-proven

The first round closed the binding and said plainly what was unproven. This round
attacks those items one by one. Two of them turned out to be code gaps, not just
missing evidence.

## Item 7 was a real money bug, not a carve-out

The first report recorded "keyless rail still accepts registrations (documented
carve-out; cannot settle, cannot lose money)". The second clause is false. By the time
a registration body reaches the payee, the payer has already committed the funding in
the channel **at the mint**; the only key that can ever release it is the channel's
receiver key. A keyless payee that answers 200 therefore strands the payer's money
with no error on any side.

`SpilmanRail::register_channel` → `enforce_receiver_binding` now returns
`InvalidRegistration` (HTTP 400) when `self.receiver_key` is `None`, naming the reason.
`LedgerPayeeHost::new` still answers `false` to `receiver_key_is_acceptable` — a
verification-only host is legitimate — but such a host may no longer *accept a channel*.

Regression: `a_keyless_rail_refuses_registration_and_persists_nothing` (400, reason
names the missing key, nothing persisted). Mutation-verified: restoring
`return Ok(())` makes it fail.

## Item 6: `mint_and_keyset_is_acceptable` now has a caller, honestly

Upstream calls both host policies only from its own funding path
(`cdk-spilman/src/bridge.rs:1648` and `:1663`, `validate_new_channel_funding`). This
module has its own registration path, so both hooks were dead code here — unit-tested,
never consulted.

New `SpilmanRail::enforce_mint_binding`, called from `enforce_receiver_binding`, builds
a host with the **trusted** configured mint (`spilman.mint_url` from operator config)
and the body's keyset info, then asks `mint_and_keyset_is_acceptable`.

What that honestly proves, stated so it is not overclaimed in the other direction:

- **The mint URL is a real check.** It is compared against operator configuration, not
  against payer-supplied bytes. A channel funded at another mint can never be redeemed
  here (the close swap is issued to `self.mint_url`), so this must be refused at the
  door.
- **The keyset id is only self-consistency at registration.** The only keyset bytes in a
  registration body come from the payer (`keyset_info_json`), and comparing
  `params.keyset_id` to them is what `validate_registration` already does. The keyset
  becomes trustworthy only at close, where it is fetched from the configured mint — that
  is the point where `mint_and_keyset_is_acceptable` does real work.
- No configured mint at all ⇒ refusal, for the same reason as the keyless case.

Regression: `a_channel_funded_at_another_mint_is_refused` (400 naming both the channel's
mint and the configured one, nothing persisted). Mutation-verified.

## Items 2–5: real processes, not in-process harnesses

`scripts/spilman_receiver_binding_e2e.sh` (added) builds the module binary, the
`spilman-payer` example and the standalone `cdk-spilman-test-mintd`, then drives them
as **separate OS processes** over loopback HTTP. Log:
`~/reports/spilman_receiver_e2e.log`. 18 checks, 0 failed:

| claim | observed |
|---|---|
| `/spilman/params` advertises a key | `receiver_pubkey=022adfa94fac96572179644fcde7a6aa5786096353b16297d9546a1476b320ca1a` |
| key file on a real FS, owner-only | `stat -c %a` = **600**, 64 hex chars, dir on **ext4** (not tmpfs) |
| survives a real restart | SIGTERM → new PID, new port → **identical** pubkey; key file sha256 unchanged (`fda8d1a3…`) |
| unusable config dir fails loudly | exit **78** (EX_CONFIG), `Permission denied (os error 13)`, no key written |
| real payer process settles | `PAYER_EXIT=0`, `PAYER_OPEN_OK channel_id=1483b090…`, `PAYER_PAYMENT_OK … balance=1 payee_credited=1`, `PAYER_SETTLED receiver_sum=1 sender_sum=127 total_value=128`; close returned **200, not 409** |

This is item 3 (payer `main()` really executed) and item 4 (restart across a real exec)
and item 5 (0600 on a non-tmpfs filesystem) — proven against the real binaries, not by a
source-level assertion. It is still **not** a physical-router run: the router is aarch64
and that toolchain is another agent's, so the 409 fix is measured on x86_64 with the
real processes and a real mint daemon, not on the device.

Re-run: `scripts/spilman_receiver_binding_e2e.sh` (self-contained; picks free ports,
polls readiness, trap-kills only its own PIDs).

## A defect this round found and did NOT paper over

On a mint that charges an input fee (the test mint's default is 400 ppk), the close
**succeeds at the mint** (`POST /spilman/close` → 200, proofs move) but the payer then
aborts with `close receipt does not match signed settlement` and exits 1.
`CloseSuccess.receiver_sum` carries the nominal pre-fee sum of the receiver outputs
(2 for `balance=1` at 400 ppk) while `src/spilman/payer.rs:285` compares it against the
net signed `payment.balance` (1).

Reproduce: `MINT_FEE_PPK=400 scripts/spilman_receiver_binding_e2e.sh` (the script
defaults to 0 and says why). This is **not** a receiver-binding failure and is **not**
fixed here: fixing it means deciding what a fee-bearing receipt's receiver share *means*
and comparing against the fee-adjusted net — a payer-side accounting change that would
weaken or rewrite an assertion if done carelessly. Reported rather than tuned away.

## Test-isolation flake fixed in passing

`src/cli/mod.rs`'s test `Once` set `TOLLGATE_TEST_CONFIG_DIR` outside the shared
`config::tests::env_guard()`, so it could land between
`config::tests::config_dir_reports_correct_directory`'s `remove_var` and its assertion.
Adding a third env-var-using suite exposed it. The `Once` body now takes the same guard
every other env-var test uses.

## Still unproven, precisely

1. **No physical router, no aarch64, no real sats.** aarch64 belongs to another agent.
   Settlement is proven against the in-process test mint (in-suite) and the standalone
   test mint daemon (E2E) — real swap code, real sockets, fake wallet, zero value.
2. **Fee-bearing close accounting is broken on the payer side** (above). The green E2E
   run is fee-free; with fees the module settles and the payer reports failure after the
   money moved.
3. **`enforce_mint_binding`'s keyset half is not an independent trust check** at
   registration time; the trusted keyset check happens at close.
4. **Key rotation/backup is undocumented.** Losing `spilman-receiver.key` makes every
   channel opened against it unsettleable — there is no recovery path and no warning at
   startup beyond the file being created once.
5. **The E2E script is not part of `cargo test`.** It is a separate, self-contained
   script; nothing in CI would run it.
