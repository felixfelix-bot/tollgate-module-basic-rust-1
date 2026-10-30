#!/usr/bin/env bash
# spilman_receiver_binding_e2e.sh — REAL-PROCESS proof of the payee receiver key
#
# Every check below is performed against separate OS processes (a mint daemon, the
# module binary, and the payer example binary). Nothing is in-process: no test
# harness, no tokio runtime shared between "payee" and "payer", no in-memory mint.
#
# WHAT IS PROVEN
#   1. /spilman/params advertises a receiver_pubkey, and the key file lands on a real
#      (non-tmpfs) filesystem at mode 0600, 64 hex chars (32 bytes).
#   2. The key file's bytes and the advertised pubkey are UNCHANGED after a real
#      SIGTERM -> new process -> new port restart. This is the property the whole
#      branch exists for: a per-boot key made every pre-restart channel unsettleable
#      (measured as HTTP 409 at POST /spilman/close).
#   3. The module refuses to start (EX_CONFIG = 78) when the config dir is read-only
#      and no key exists yet — fail closed, never a throwaway key.
#   4. The REAL examples/spilman_payer.rs binary, as its own process, funds at a real
#      HTTP mint, opens a channel against the *advertised* key, pays, and completes
#      the cooperative close (PAYER_EXIT=0 / PAYER_OPEN_OK / PAYER_PAYMENT_OK /
#      PAYER_SETTLED). A close failure is a hard failure here, not a warning.
#
# WHY THE PORTS AND PATHS ARE WHAT THEY ARE
#   Ports are picked by binding :0 with python3, because a hardcoded port can be
#   occupied by a resident mint or another context window and then the "proof" is
#   about somebody else's service. The config dirs live under $HOME/reports on ext4,
#   because /tmp is tmpfs on this host and the point of check 1 is a real filesystem.
#
# USAGE
#   scripts/spilman_receiver_binding_e2e.sh                # build, then prove
#   E2E_BUILD=0 scripts/spilman_receiver_binding_e2e.sh    # use existing binaries
#   E2E_LOG=/path/to.log scripts/spilman_receiver_binding_e2e.sh
#
# THE MINT'S INPUT FEE, AND WHY IT IS 0 HERE
#   The fakewallet test mint defaults to 400 ppk input fee. On a fee-charging mint the
#   cooperative close still succeeds at the mint (POST /spilman/close -> 200) but the
#   receipt's `receiver_sum` is the NOMINAL pre-fee sum of the receiver outputs while
#   `src/spilman/payer.rs::SettlementReceipt` compares it against the net signed
#   `balance` (`receipt.receiver_sum != self.payment.balance`). For balance=1 that is
#   nominal=2 vs net=1, so the payer reports "close receipt does not match signed
#   settlement" and exits 1 AFTER the money moved. Set MINT_FEE_PPK=400 to reproduce
#   that defect; the default here is 0 so check 5 measures the binding, not the
#   fee-accounting gap. THIS IS NOW FIXED in src/spilman/payer.rs (the receipt check is
#   fee-aware), so the default here is 400 — the mint's own default — because a fee-free
#   mint is the unrepresentative case. MINT_FEE_PPK=0 still works.
#
# Exit: 0 = all checks passed, 1 = at least one check failed.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORTS="${REPORTS:-$HOME/reports}"
LOG="${E2E_LOG:-$REPORTS/spilman_receiver_e2e.log}"

# Reuse the worktree's own target/ by default.
#
# It used to default to a directory under the manager cache. That looked tidier and was
# worse in both directions: it recompiled the whole cdk tree (~3 GB of rlibs) on every
# run, and it is not a directory anyone has sized for that, so a full run died with
# "No space left on device (os error 28)" and reported it as a *test* failure. Sharing
# the worktree target means the binaries are already built, and the disk-space
# precondition below refuses early with a clear message when there genuinely is no room.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$REPO/target}"
MODULE_BIN="${MODULE_BIN:-$CARGO_TARGET_DIR/debug/tollgate-module-basic-rust}"
PAYER_BIN="${PAYER_BIN:-$CARGO_TARGET_DIR/debug/examples/spilman-payer}"
MINTD_BIN="${MINTD_BIN:-$CARGO_TARGET_DIR/debug/cdk-spilman-test-mintd}"
CHECKOUT="${SPILMAN_CHECKOUT:-$HOME/.cargo/git/checkouts/cashu_spilman_channels-19b6c716dcde9523/c2083de}"
E2E_BUILD="${E2E_BUILD:-1}"
# See "THE MINT'S INPUT FEE" above. 0 = prove the binding; 400 = reproduce the
# fee-accounting defect in the payer's receipt check.
MINT_FEE_PPK="${MINT_FEE_PPK:-400}"

mkdir -p "$REPORTS"
# Everything this script says goes to the console AND to the log file.
exec > >(tee "$LOG") 2>&1
echo "# spilman_receiver_binding_e2e.sh — $(date -Is)"
echo "# repo=$REPO"
echo "# target=$CARGO_TARGET_DIR"

# Fail fast and legibly. Building this tree needs a couple of GB of headroom; discovering
# that halfway through a build reads as a protocol failure in the log, which it is not.
AVAIL_KB="$(df -Pk "$CARGO_TARGET_DIR" 2>/dev/null | awk 'NR==2 {print $4}')"
if [ -n "$AVAIL_KB" ] && [ "$AVAIL_KB" -lt 2000000 ]; then
    echo "FAIL: only $((AVAIL_KB / 1024)) MiB free on the target filesystem; need ~2 GiB"
    echo "      free space or set CARGO_TARGET_DIR to one that has it"
    exit 1
fi

FAILURES=0
CHECKS=0
pass() { CHECKS=$((CHECKS + 1)); printf 'PASS: %s\n' "$*"; }
fail() { CHECKS=$((CHECKS + 1)); FAILURES=$((FAILURES + 1)); printf 'FAIL: %s\n' "$*"; }
say()  { printf '\n--- %s\n' "$*"; }

# ── child process bookkeeping ────────────────────────────────────────────────
# Only PIDs started here are killed, and each kill is confirmed. No `pkill -f`:
# another context window's mint or module must not die because of a pattern this
# script found convenient.
CHILD_PIDS=()
LAST_PID=""
# Sets $LAST_PID. Deliberately NOT `pid=$(start_child ...)`: a command substitution
# runs in a subshell, so the CHILD_PIDS append would be lost and cleanup would kill
# nothing while still reporting success.
start_child() {  # start_child <logfile> <cmd...>
    local log="$1"; shift
    "$@" >"$log" 2>&1 &
    LAST_PID=$!
    CHILD_PIDS+=("$LAST_PID")
}
kill_child() {  # kill_child <pid> [sig]
    local pid="${1:-}" sig="${2:-TERM}" i
    [ -n "$pid" ] || return 0
    kill -"$sig" "$pid" 2>/dev/null || return 0
    for i in $(seq 1 100); do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 0.05
    done
    kill -KILL "$pid" 2>/dev/null || true
    for i in $(seq 1 40); do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 0.05
    done
    return 0
}
cleanup() {
    local pid
    for pid in "${CHILD_PIDS[@]:-}"; do
        [ -n "$pid" ] || continue
        kill_child "$pid" TERM
    done
    # A read-only dir left behind breaks re-runs of the same scratch path.
    [ -n "${RO_DIR:-}" ] && [ -d "$RO_DIR" ] && chmod 755 "$RO_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── helpers ─────────────────────────────────────────────────────────────────
free_port() {
    python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'
}
# Three distinct ports. Each is bound-and-released, so a repeat is possible in
# principle; the loop makes it not happen in practice.
FREE_PORTS=()
pick_ports() {
    local want=$1 i p seen
    while [ "${#FREE_PORTS[@]}" -lt "$want" ]; do
        p="$(free_port)"
        seen=0
        for i in "${FREE_PORTS[@]:-}"; do [ "$i" = "$p" ] && seen=1; done
        [ "$seen" = 0 ] && FREE_PORTS+=("$p")
    done
}

# Readiness by polling the endpoint that matters — never `sleep N`. 100 x 50ms.
wait_http() {  # wait_http <url> [tries]
    local url="$1" tries="${2:-100}" i
    for i in $(seq 1 "$tries"); do
        curl --fail --silent --show-error --max-time 2 "$url" >/dev/null 2>&1 && return 0
        sleep 0.05
    done
    return 1
}
json_get() {  # json_get <key>  (stdin: json)
    python3 -c 'import json,sys
d=json.load(sys.stdin)
v=d.get(sys.argv[1])
print("" if v is None else v)' "$1"
}

write_config() {  # write_config <dir> <mint_url> <db_path>
    local dir="$1" mint="$2" db="$3"
    mkdir -p "$dir"
    cat >"$dir/config.json" <<JSON
{
  "config_version": "1",
  "log_level": "info",
  "accepted_mints": [],
  "spilman": {
    "enabled": true,
    "mint_url": "$mint",
    "in_bytes_per_millisat": 22021,
    "channel_db_path": "$db"
  }
}
JSON
    [ -f "$dir/identities.json" ] || cat >"$dir/identities.json" <<'JSON'
{
  "config_version": "v0.0.1",
  "owned_identities": [
    {
      "name": "merchant",
      "privatekey": "0000000000000000000000000000000000000000000000000000000000000001"
    }
  ],
  "public_identities": []
}
JSON
}

# ── preconditions ───────────────────────────────────────────────────────────
say "preconditions"
for tool in curl python3 stat df; do
    command -v "$tool" >/dev/null || { echo "FATAL: missing tool $tool" >&2; exit 1; }
done

if [ "$E2E_BUILD" = 1 ]; then
    say "build (module + payer example + standalone fakewallet mint)"
    ( cd "$REPO" \
        && cargo build --bin tollgate-module-basic-rust --features payer-driver \
        && cargo build --example spilman-payer --features payer-driver ) \
        || { echo "FATAL: cargo build (module/payer) failed" >&2; exit 1; }
    cargo build --manifest-path "$CHECKOUT/Cargo.toml" -p cdk-spilman-test-mint \
        --bin cdk-spilman-test-mintd --features http \
        || { echo "FATAL: cargo build (test mint) failed" >&2; exit 1; }
fi
for bin in "$MODULE_BIN" "$PAYER_BIN" "$MINTD_BIN"; do
    [ -x "$bin" ] || { echo "FATAL: not executable: $bin" >&2; exit 1; }
done
echo "module: $MODULE_BIN"
echo "payer:  $PAYER_BIN"
echo "mint:   $MINTD_BIN"

pick_ports 4
MINT_PORT="${FREE_PORTS[0]}"
MOD1_PORT="${FREE_PORTS[1]}"
MOD2_PORT="${FREE_PORTS[2]}"
RO_PORT="${FREE_PORTS[3]}"
MINT_URL="http://127.0.0.1:$MINT_PORT"
BASE1="http://127.0.0.1:$MOD1_PORT"
BASE2="http://127.0.0.1:$MOD2_PORT"
echo "ports:  mint=$MINT_PORT module1=$MOD1_PORT module2=$MOD2_PORT ro=$RO_PORT"

# The filesystem under test must be real. /tmp here is tmpfs, so prove it instead
# of assuming it.
CFG_DIR="$REPORTS/e2e-cfg-$$"
DB_PATH="$REPORTS/e2e-spilman-$$.db"
RO_DIR="$REPORTS/e2e-ro-cfg-$$"
STATE_DB="$REPORTS/e2e-state-$$.db"
rm -rf "$CFG_DIR" "$RO_DIR"
mkdir -p "$CFG_DIR" "$RO_DIR"
FS_TYPE="$(df -T "$CFG_DIR" | awk 'NR==2 {print $2}')"
if [ "$FS_TYPE" = "tmpfs" ] || [ "$FS_TYPE" = "ramfs" ]; then
    echo "FATAL: $CFG_DIR is on $FS_TYPE; this check needs a real filesystem" >&2
    exit 1
fi
pass "config dir on a real filesystem ($CFG_DIR is $FS_TYPE, not tmpfs/ramfs)"

# ── 0. the mint that pays its own quotes ────────────────────────────────────
say "0. real fakewallet mint on 127.0.0.1:$MINT_PORT"
MINT_LOG="$REPORTS/e2e-mint-$$.log"
echo "mint input fee: TEST_MINT_FEE_PPK_SAT=$MINT_FEE_PPK"
start_child "$MINT_LOG" env TEST_MINT_FEE_PPK_SAT="$MINT_FEE_PPK" \
    "$MINTD_BIN" --listen-host 127.0.0.1 --listen-port "$MINT_PORT"
MINT_PID="$LAST_PID"
if wait_http "$MINT_URL/v1/info" 200; then
    pass "mint answers $MINT_URL/v1/info"
else
    fail "mint never answered $MINT_URL/v1/info (log: $MINT_LOG)"
    echo "--- $MINT_LOG ---"; tail -30 "$MINT_LOG" || true
    exit 1
fi

# ── 1. first boot: the payee advertises a key, and the key file is 0600 ─────
say "1. first boot (module on 127.0.0.1:$MOD1_PORT)"
write_config "$CFG_DIR" "$MINT_URL" "$DB_PATH"
KEY_FILE="$CFG_DIR/spilman-receiver.key"
MOD1_LOG="$REPORTS/e2e-mod1-$$.log"
start_child "$MOD1_LOG" env \
    TOLLGATE_TEST_CONFIG_DIR="$CFG_DIR" \
    TOLLGATE_BIND="127.0.0.1:$MOD1_PORT" \
    TOLLGATE_STATE_DB="$STATE_DB" \
    "$MODULE_BIN"
MOD1_PID="$LAST_PID"

if wait_http "$BASE1/spilman/params" 300; then
    PARAMS1="$(curl --fail -sS --max-time 5 "$BASE1/spilman/params")"
    PK1="$(printf '%s' "$PARAMS1" | json_get receiver_pubkey)"
    echo "params[$BASE1/spilman/params] = $PARAMS1"
    if [ -n "$PK1" ]; then
        pass "check-1 GET /spilman/params advertises receiver_pubkey=$PK1"
    else
        fail "check-1 /spilman/params advertised no receiver_pubkey: $PARAMS1"
    fi
else
    fail "check-1 module never answered /spilman/params (log: $MOD1_LOG)"
    echo "--- $MOD1_LOG ---"; tail -40 "$MOD1_LOG" || true
    PARAMS1=""; PK1=""
fi

if [ -f "$KEY_FILE" ]; then
    MODE="$(stat -c %a "$KEY_FILE")"
    KEY_BYTES="$(tr -d '[:space:]' <"$KEY_FILE")"
    KEY_HEX_LEN="${#KEY_BYTES}"
    echo "stat -c %a $KEY_FILE = $MODE (len=$KEY_HEX_LEN hex chars)"
    [ "$MODE" = "600" ] && pass "check-2 key file mode is 600" \
        || fail "check-2 key file mode is $MODE, want 600"
    if [ "$KEY_HEX_LEN" = "64" ] && printf '%s' "$KEY_BYTES" | grep -qE '^[0-9a-fA-F]{64}$'; then
        pass "check-2 key file is 32 bytes of hex (64 chars)"
    else
        fail "check-2 key file is not 64 hex chars (len=$KEY_HEX_LEN)"
    fi
    KEY_SHA1="$(sha256sum "$KEY_FILE" | awk '{print $1}')"
    echo "key file sha256 = $KEY_SHA1"
else
    fail "check-2 key file $KEY_FILE was never created"
    MODE=""; KEY_SHA1=""
fi

# ── 2. THE RESTART PROOF ────────────────────────────────────────────────────
say "2. real restart: SIGTERM, then a NEW process on 127.0.0.1:$MOD2_PORT"
kill_child "$MOD1_PID" TERM
if kill -0 "$MOD1_PID" 2>/dev/null; then
    fail "check-3 the first module process did not exit on SIGTERM"
else
    pass "check-3 first module process exited on SIGTERM (pid $MOD1_PID)"
fi
echo "first-run tail: $(tail -3 "$MOD1_LOG" 2>/dev/null | tr '\n' ' ')"

MOD2_LOG="$REPORTS/e2e-mod2-$$.log"
start_child "$MOD2_LOG" env \
    TOLLGATE_TEST_CONFIG_DIR="$CFG_DIR" \
    TOLLGATE_BIND="127.0.0.1:$MOD2_PORT" \
    TOLLGATE_STATE_DB="$STATE_DB" \
    "$MODULE_BIN"
MOD2_PID="$LAST_PID"

if wait_http "$BASE2/spilman/params" 300; then
    PARAMS2="$(curl --fail -sS --max-time 5 "$BASE2/spilman/params")"
    PK2="$(printf '%s' "$PARAMS2" | json_get receiver_pubkey)"
    echo "params[$BASE2/spilman/params] = $PARAMS2"
    if [ -n "$PK2" ] && [ "$PK2" = "$PK1" ]; then
        pass "check-3 receiver_pubkey identical across the restart ($PK1)"
    else
        fail "check-3 receiver_pubkey changed across the restart: before=$PK1 after=${PK2:-<none>}"
    fi
else
    fail "check-3 restarted module never answered /spilman/params (log: $MOD2_LOG)"
    echo "--- $MOD2_LOG ---"; tail -40 "$MOD2_LOG" || true
    PK2=""
fi
if [ -n "${KEY_SHA1:-}" ] && [ -f "$KEY_FILE" ]; then
    KEY_SHA2="$(sha256sum "$KEY_FILE" | awk '{print $1}')"
    [ "$KEY_SHA2" = "$KEY_SHA1" ] \
        && pass "check-3 key file bytes unchanged after restart (sha256 $KEY_SHA2)" \
        || fail "check-3 key file bytes changed after restart: $KEY_SHA1 -> $KEY_SHA2"
fi

# ── 3. read-only config dir must be EX_CONFIG (78) ─────────────────────────
say "3. read-only config dir -> EX_CONFIG"
# The ledger path is deliberately OUTSIDE the read-only dir: if the exit were 78
# merely because the channel DB could not be opened, the receiver-key refusal would
# not have been exercised at all. With a writable ledger path, the only thing that
# can fail is the 0600 key creation — which is exactly the refusal under test.
write_config "$RO_DIR" "$MINT_URL" "$REPORTS/e2e-ro-spilman-$$.db"
cp "$CFG_DIR/identities.json" "$RO_DIR/identities.json"
chmod 555 "$RO_DIR"
RO_LOG="$REPORTS/e2e-ro-$$.log"
set +e
timeout 60 env \
    TOLLGATE_TEST_CONFIG_DIR="$RO_DIR" \
    TOLLGATE_BIND="127.0.0.1:$RO_PORT" \
    TOLLGATE_STATE_DB="$STATE_DB" \
    "$MODULE_BIN" >"$RO_LOG" 2>&1
RO_RC=$?
set -e
chmod 755 "$RO_DIR"
echo "read-only run exit code = $RO_RC"
echo "--- read-only stderr/stdout (last 5) ---"
tail -5 "$RO_LOG" || true
echo "--- end ---"
[ "$RO_RC" = "78" ] \
    && pass "check-4 read-only config dir exits 78 (EX_CONFIG)" \
    || fail "check-4 read-only config dir exited $RO_RC, want 78"
if grep -qi 'receiver key' "$RO_LOG"; then
    pass "check-4 the refusal names the receiver key (fail closed, no throwaway key)"
else
    fail "check-4 the refusal did not mention the receiver key: $(tail -3 "$RO_LOG" | tr '\n' ' ')"
fi
[ ! -f "$RO_DIR/spilman-receiver.key" ] \
    && pass "check-4 no key file was written into the read-only dir" \
    || fail "check-4 a key file appeared in the read-only dir"

# ── 4. the real payer binary, as its own process ───────────────────────────
say "4. settle with the REAL spilman-payer example against $BASE2"
PAYER_LOG="$REPORTS/e2e-payer-$$.log"
set +e
( cd "$REPORTS" && "$PAYER_BIN" \
    --mint-url "$MINT_URL" \
    --module-url "$BASE2" \
    --flow open-settle ) >"$PAYER_LOG" 2>&1
PAYER_RC=$?
set -e
echo "payer process exit status = $PAYER_RC"
echo "--- payer output ---"
cat "$PAYER_LOG"
echo "--- end payer output ---"

grep -q '^PAYER_EXIT=0$' "$PAYER_LOG" \
    && pass "check-5 payer printed PAYER_EXIT=0" \
    || fail "check-5 payer did not print PAYER_EXIT=0 ($(grep -m1 '^PAYER_EXIT=' "$PAYER_LOG" || echo 'no PAYER_EXIT line'))"
[ "$PAYER_RC" = "0" ] \
    && pass "check-5 payer process exited 0" \
    || fail "check-5 payer process exited $PAYER_RC"

CHANNEL_ID=""
if grep -q '^PAYER_OPEN_OK channel_id=' "$PAYER_LOG"; then
    CHANNEL_ID="$(sed -n 's/^PAYER_OPEN_OK channel_id=\([0-9a-fA-F]*\).*/\1/p' "$PAYER_LOG" | head -1)"
    pass "check-5 PAYER_OPEN_OK channel_id=$CHANNEL_ID"
else
    fail "check-5 no PAYER_OPEN_OK marker"
fi

if grep -q '^PAYER_PAYMENT_OK channel_id=' "$PAYER_LOG"; then
    PAY_LINE="$(grep -m1 '^PAYER_PAYMENT_OK ' "$PAYER_LOG")"
    BAL="$(sed -n 's/.* balance=\([0-9]*\).*/\1/p' <<<"$PAY_LINE")"
    CRED="$(sed -n 's/.* payee_credited=\([0-9]*\).*/\1/p' <<<"$PAY_LINE")"
    pass "check-5 $PAY_LINE"
    [ -n "$BAL" ] && [ "$BAL" = "$CRED" ] \
        && pass "check-5 payee credited what the payer signed (balance=$BAL)" \
        || fail "check-5 balance=$BAL but payee_credited=$CRED"
else
    fail "check-5 no PAYER_PAYMENT_OK marker"
fi

# The close is the whole point: a 409 here is the bug this branch fixes.
if grep -q '^PAYER_SETTLED ' "$PAYER_LOG"; then
    pass "check-5 close succeeded — $(grep -m1 '^PAYER_SETTLED ' "$PAYER_LOG")"
elif grep -qiE '409|close authorization refused|POST /spilman/close' "$PAYER_LOG"; then
    fail "check-5 THE CLOSE FAILED (409-class) — this is the branch's bug:"
    grep -inE '409|close|FAILED' "$PAYER_LOG" | head -10 || true
    echo "--- module log tail ---"; tail -20 "$MOD2_LOG" || true
elif grep -q 'close receipt does not match signed settlement' "$PAYER_LOG"; then
    fail "check-5 the mint closed the channel (HTTP 200) but the payer rejected the receipt:"
    echo "        this is the fee-bearing receipt regression: receipt.receiver_sum is the"
    echo "        NOMINAL sum, and the payer must check it against the channel's own"
    echo "        inverse_deterministic_value_after_fees(balance) — not against the net"
    echo "        balance. If this fires, that check in src/spilman/payer.rs regressed."
else
    fail "check-5 no PAYER_SETTLED marker; close not proven"
fi

if [ -n "$CHANNEL_ID" ]; then
    STATUS_JSON="$(curl -sS --max-time 5 "$BASE2/spilman/status?channel_id=$CHANNEL_ID" || true)"
    echo "status[$BASE2/spilman/status?channel_id=$CHANNEL_ID] = $STATUS_JSON"
    ST_BAL="$(printf '%s' "$STATUS_JSON" | json_get balance 2>/dev/null || true)"
    if [ -n "$ST_BAL" ]; then
        pass "check-5 GET /spilman/status reports balance=$ST_BAL for the settled channel"
    else
        fail "check-5 /spilman/status reported no balance: $STATUS_JSON"
    fi
fi

# ── summary ─────────────────────────────────────────────────────────────────
say "summary"
printf '%d checks, %d failed\n' "$CHECKS" "$FAILURES"
echo "key file: $KEY_FILE (mode ${MODE:-<none>})"
echo "log: $LOG"
if [ "$FAILURES" -ne 0 ]; then
    echo "RESULT: FAIL"
    exit 1
fi
echo "RESULT: PASS — stable persisted receiver key across a real restart, mode 0600 on"
echo "        $FS_TYPE, EX_CONFIG(78) on a read-only config dir, and a full open->pay->close"
echo "        settled by the real payer binary as a separate process."
exit 0