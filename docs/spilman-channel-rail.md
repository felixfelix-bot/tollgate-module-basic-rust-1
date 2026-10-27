# Spilman × TollGate — findings and progress

**Branch:** `pr/spilman-channel-rail`
**Scope:** a Spilman channel payment rail so a router can buy internet from an
upstream router in small increments without a mint round trip per purchase.

This document is the honest record: what works, what does not, and what is not yet
attempted. It exists because a PR that only lists successes is not reviewable.

---

## 1. The goal, restated precisely

The operator's ask: routers buy internet **from each other** in small increments
**without needing to talk to the mint all the time**.

The honest reading, which this work adopts: the mint cannot be eliminated from a
channel's life — it is touched at **open** and **settle**. What is eliminated is
the mint round trip **per purchase**. In between, a payment is a signature over a
balance update plus a local durable write.

So the win is **amortisation, not elimination**: one open + one settle per channel
lifetime, instead of one round trip per 21 MiB step.

---

## 2. What works

### 2.1 The dependency conflict is solved (this was the blocker)

`cdk-spilman` does not depend on `cdk`. It takes `cashu` from **git tag v0.18.1**,
while this module took `cashu` from crates.io (resolving 0.18.2). Cargo treats git
and registry sources as distinct crates, so there were **two `cashu` instances** and
`cdk::nuts::Proof` was not the same nominal type as cdk-spilman's `Proof`.

`[patch.crates-io]` **cannot** fix it: crates.io `cdk-common 0.18.2` pins
`cashu = "=0.18.2"` exactly. The fix is to move the whole stack onto the single git
source (as MONAD does). Result: one `cashu 0.18.1`, package count 332 → 382, and all
194 pre-existing tests still green with zero behavioural change.

### 2.2 Exact billing, with a correction to the reference analysis

Live config: `step_size = 22020096` bytes per `price_per_step = 1` sat.

**`in_bytes_per_millisat = 22_020` overcharges by 100% at step granularity.**
`22_020_096 / 1_000 = 22_020.096`, so the exact ceil at rate 22,020 is **1001 msat**,
which rounds up to **2 sat instead of 1**:

```
rate=22020: exact=1000.0044 msat/step -> ceil=1001 msat -> 2 sat/step  (overcharge)
rate=22021: exact= 999.9589 msat/step -> ceil=1000 msat -> 1 sat/step  (exact)
```

**22,021 is the parity rate.** Both constants exist and are pinned by tests so
neither can drift.

### 2.3 The HTTP surface is real, and its disabled state is observable

```
GET  /spilman/params   mint URL + rate + the payee's receiver pubkey
                       (public config; no state leaked)
POST /spilman/payment  a signed balance update
GET  /spilman/status   the payee's view of one channel
```

`/spilman/params` advertises `receiver_pubkey`: the compressed secp256k1 (33-byte,
`02…`/`03…`) hex public key of the key this payee signs channel closes with. It is the
same encoding `registration.rs` parses out of `params_json`, so a payer can copy the value
straight into the channel parameters. It is derived from
`<config dir>/spilman-receiver.key` (`0600`, created once, reloaded on every boot), so it
is **stable across restarts** — a per-boot key would leave every channel opened before
the restart uncloseable. A payee that holds no key (read-only/verification-only context)
advertises `null` and refuses to settle.

The field is additive: existing consumers that ignore it keep working, and
`receiver_key_is_acceptable` in `payee_host.rs` compares an offered key against this one,
returning `false` only when the host genuinely holds no key.

The mount is **conditional on the rail existing**. With Spilman off, no route is
mounted at all, so every `/spilman` path 404s **without a handler running**.
Absence is stronger than abstention, and this is pinned in both directions so the
404 case cannot pass trivially because the route never existed.

### 2.4 The library is proven to RUN on the physical router

Deployed to the real bench router (`tollgate-0195`, aarch64 musl) and executed
there — not merely linked, not merely emulated:

```
$ sha256sum libcdk_spilman_go.so spilman_probe     # on the router
dbf2d1d4ad4df56075e21f265d0e2aeeebd6c34fe5803a61716db6a20d934b5a  libcdk_spilman_go.so
d4d1144823d51f31def39ba995c47eff24b8cbe38a4e00af07c25bdc9b9537fa  spilman_probe

$ LD_LIBRARY_PATH=/usr/lib:/lib /tmp/spilman_probe
spilman-go static link smoke. library keyset versions: [v1 v2]
probe_exit=0

$ ldd /tmp/spilman_probe
    libcdk_spilman_go.so => /usr/lib/libcdk_spilman_go.so
    libc.so => /lib/ld-musl-aarch64.so.1
    libgcc_s.so.1 => /lib/libgcc_s.so.1
```

Three things hold at once: the router's own checksums **match the host's** (the
bytes that ran are the bytes built); the FFI executes; and every NEEDED dependency
resolves on the device. The two native deps the gap analysis could not confirm from
code are **present**: `/lib/libgcc_s.so.1` and `/lib/libc.so`.

### 2.5 Host E2E — 10/10

`host-e2e-spilman.sh` runs the **real binary** with a real TCP listener, a real
durable ledger, and real HTTP requests:

```
PASS  GET /whoami is 200                                  (rail ON)
PASS  GET /spilman/params is 200
PASS  params reports the parity rate 22021
PASS  params reports the configured mint
PASS  GET /spilman/status unknown channel is 404
PASS  POST /spilman/payment to an unknown channel is 409
PASS  spilman.db created
PASS  GET /spilman/params is 404 when disabled
PASS  POST /spilman/payment is 404 when disabled
PASS  GET /whoami still 200 when disabled
RESULT: 10 passed, 0 failed
```

---

## 3. What does NOT work — read this before reviewing

### 3.1 A critical fund-safety hole was found and hot-fixed (still needs the real fix)

The host E2E found that a **forged payment was accepted**:

```
POST /spilman/payment  {"channel_id":"deadbeef","balance":5,"signature":"00"}
-> 200 {"status":1,"outcome":"Accepted"}
```

on a channel that was **never funded**, with a 2-hex-character signature. Anyone
who could reach the surface could mint credit for any channel id, and the ledger
would then treat that forged balance as the CAS baseline.

**Root cause.** `record_payment` checked only that the balance *strictly advances*.
Monotonicity is not authenticity: a higher balance was always accepted, from
anyone, for any channel, with any signature. The rail's own docstrings promised
"durably record a **signed** balance update", but nothing verified the signature.

**Why the unit tests missed it.** `ledger_test.rs` correctly pins the CAS and
monotonicity behaviour that does exist, and passes. No test asserted *authenticity*,
because the ledger had no notion of it. The gap was in the design, not in the
tests' rigour — which is why executing the real binary is what surfaced it.

**Hot-fix (intermediate state):** fail **closed**. Every payment was refused with
`UnknownChannel` → HTTP 409. Refusing is strictly safer than accepting: the payee
serves no bytes and loses nothing, whereas accepting hands out credit it cannot
collect. Three regression tests pin this (`tests/spilman_payment_authenticity.rs`).

**The real fix — DONE, in this PR.** The refusal is now a *check*, replacing a
blanket no:

1. a per-channel **funding record** (params, funding proofs, channel secret, keyset
   info) is durable, written at registration;
2. a payee host serves it to cdk-spilman's validator;
3. `record_payment` loads the record — absent still means `UnknownChannel`, the same
   fail-closed refusal — then calls **upstream's own**
   `SpilmanBridge::validate_payment` (`bridge.rs:1312`) and refuses on **any** error;
4. only then the durable CAS write, still against the exact previous balance.

Verification and replay are different questions and both are still asked: a re-sent
*valid* signature verifies perfectly and must not be credited twice — which is what
the CAS is for.

**Evidence — and the positive case is the load-bearing one.** Seven new tests in
`tests/spilman_payee_verification.rs`, against a real in-process mint:
garbage signature refused; correctly-shaped but wrong signature refused; balance
above capacity refused; replay of the exact previous balance refused; unfunded
channel still unknown; a refusal leaves **no** balance row; and
**`a_real_signed_payment_is_accepted`** — a genuinely signed payment, from a real
channel opened against the mint, is accepted.

Tests 1–6 are all refusals, and **"refuse everything" passes every one of them.**
Only the positive case distinguishes a working verifier from a dead one. The funding
record under test is not hand-assembled JSON either: a reference `ConfigurableHost`
(cdk-spilman's own payee host) processes registration and the five values are copied
out via `get_funding_data`, so the bytes the rail verifies against are the bytes
upstream derived.

### 3.2 Channel-protocol E2E: done **in-process**, NOT yet on the router

The verify fix (§3.1) unblocked the protocol. It now runs — the payer suite opens a
channel against a real in-process mint, signs, settles, and both kill-recovery cases
pass; the payee suite accepts a real signed payment. That is the whole purchase flow
minus the hardware.

What is **not** done: the same flow **on the physical router**. The bench lane
(`ROUTER-LANE.md`, PRTA) asserts the reachable surface on-device and reports the
protocol assertions as SKIP with this reason. So:

| assertion | in-process | on the router |
|---|---|---|
| (a) channel opens against a mint | **PASS** | **SKIP** |
| (b) zero mint calls between open and settle | **PASS** | **SKIP** |
| (c) settle pays the payee exactly | **PASS** | **SKIP** |
| (d) restart mid-stream keeps the latest signature | **PASS** | **SKIP** |

Deployment is proven on the router (§2.4) and the HTTP surface is proven on the
router (§2.5), but **no router-to-router purchase has been demonstrated.** The gap
is now build-and-run, not design.

### 3.3 There is no payee-side host in this module

`upstream_*` config is inert here (`src/config/schema.rs:38-42`, consumed only in
`config/tests.rs`). A router buying from another router needs **both** sides
deployed. An un-upgraded upstream cannot be paid over a channel — there is no
fallback except today's per-purchase token path.

### 3.4 Roaming is unresolved, and it is the biggest design question

A channel's capacity is a prepayment to a **specific** upstream. If the router
switches upstreams, the channel is stranded. Nothing here addresses that.

### 3.5 Channel-id determinism: EXPLAINED (was previously mis-attributed)

Two runs of the same test with identical inputs produced **different** ids once and
**equal** ids the next time. An assertion claiming determinism was **removed** as
unsound in both directions. This section used to blame `PreMintSecrets::random`
(`cdk-spilman` `bindings.rs:233`). **That attribution was wrong**, and a cold review
caught it: `PreMintSecrets` appears **0 times** in `cdk-spilman/src/params.rs`.

The id is derived by `get_channel_id_bytes` (`params.rs:562`), which hashes

```
mint|unit|capacity|funding_token_amount|keyset_id|input_fee_ppk|
maximum_amount_for_one_output|setup_timestamp|sender_pubkey|receiver_pubkey|
expiry_timestamp|channel_secret
```

`setup_timestamp` is an input, and it is a **wall-clock** value at open time. Two
opens a second apart hash differently; two within the same second hash the same.
That is exactly the observed behaviour — sometimes equal, sometimes not — and it is
not randomness.

**Why in-tree tests can never reproduce it:** `src/spilman/registration.rs:318`
hardcodes `"setup_timestamp": 1_700_000_000`, so every fixture pins the input that
varies. The field observation came from real opens, which use the real clock.

**Does it block anything?** No. Recovery keys on the **persisted** id, never on a
re-derived one, so nothing load-bearing depends on reproducibility. The unsound
assertion stays removed: neither `assert_eq` nor `assert_ne` is correct, because
the value is neither guaranteed equal nor guaranteed different. The honest fix, if
anyone wants one, is to make `setup_timestamp` an explicit parameter rather than a
clock read — a change in upstream `cdk-spilman`, not here.

---

## 4. Test evidence (all reproducible)

| suite | result |
|---|---|
| `cargo test --all-targets` (default) | 226 lib + 2 wiring + 3 mount + 14 billing + 3 authenticity, **0 failed** |
| `-- --ignored` (payee verification, real mint) | 7 passed, **0 failed** (incl. `a_real_signed_payment_is_accepted`) |
| `-- --ignored` (payer lifecycle, real mint) | 3 passed, **0 failed** (incl. both kill-recovery cases) |
| `--features test-support` | as above + 1 wiring (credit arithmetic), **0 failed** |
| `--test spilman_payer_lifecycle -- --ignored` | 3 passed (incl. both kill-recovery cases) |
| `host-e2e-spilman.sh` (real binary, real HTTP) | **10/10** |
| router FFI probe (on device) | **PASS**, checksums matched |

### Why `test-support` exists

The forgery fix broke `rail_credits_exactly_what_was_recorded`, which asserts the
credit *arithmetic* and needs to record a balance. Loosening the production refusal
to make a test pass would have been the wrong trade, so the ledger operation is
exposed behind a **non-default** feature. It could not be `#[cfg(test)]`:
integration tests in `tests/` are a separate crate and cannot see test-cfg items.
The one test that needs it is itself `#[cfg(feature = "test-support")]`, so the
**default** run — what CI executes — stays green.

---

## 5. Deliberate non-goals in this PR

- The retail `handle_pay` token path and `AppState.wallet` are **untouched**. The
  rail is a sibling, not a replacement.
- No wallet-generic refactor. The seam is a `PaymentRail` trait plus a concrete
  `SpilmanRail`, so the retail path cannot regress.
- No upstream fork. `cdk-spilman` is consumed at a pinned rev.

---

## 6. What a reviewer should scrutinise hardest

1. **§3.1's real fix.** The current refusal is a hot-fix. The funding record and
   the upstream validator call are the substance.
2. **The seam choice** — `PaymentRail` sibling vs a generic wallet. The rationale is
   in `src/spilman/mod.rs` and `src/spilman/rail.rs`.
3. **The 22,021 correction.** If you disagree, the arithmetic is in
   `src/spilman/billing.rs` and pinned by tests; the disagreement is checkable.
4. **`record_payment` ordering** — verification must precede the durable write, and
   the write must stay CAS against the exact previous balance.
