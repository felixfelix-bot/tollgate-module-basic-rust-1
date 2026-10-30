#!/usr/bin/env bash
# Prove the receiver binding and a real settle against a **public third-party mint**
# (testnut.cashu.space — real HTTP, real keysets, real fee schedule, test-value ecash),
# instead of only against the in-process test mint or our own mint daemon.
#
# This does not spend anyone's money: the mint is a FakeWallet test mint, so its quotes
# are always paid. It is the closest thing available to "a real mint" from this host.
#
# Exit: 0 = settled, non-zero = the reason is printed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MINT_URL="${MINT_URL:-https://testnut.cashu.space}"
CFG="$(mktemp -d "${TMPDIR:-/tmp}/spilman-public.XXXXXX")"
MOD_LOG="$CFG/module.log"
PAYER_LOG="$CFG/payer.log"
MODPID=""

cleanup() {
    if [ -n "$MODPID" ] && kill -0 "$MODPID" 2>/dev/null; then
        kill "$MODPID" 2>/dev/null || true
        wait "$MODPID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

free_port() {
    python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'
}

PORT="$(free_port)"
cat > "$CFG/config.json" <<JSON
{"config_version":"1","accepted_mints":[],"spilman":{"enabled":true,"mint_url":"$MINT_URL","in_bytes_per_millisat":22021,"channel_db_path":"$CFG/spilman.db"}}
JSON

echo "# public-mint probe: $MINT_URL"
echo "# config dir: $CFG"

TOLLGATE_TEST_CONFIG_DIR="$CFG" TOLLGATE_BIND="127.0.0.1:$PORT" \
    "$ROOT/target/debug/tollgate-module-basic-rust" >"$MOD_LOG" 2>&1 &
MODPID=$!

for _ in $(seq 1 150); do
    if curl -sf "http://127.0.0.1:$PORT/spilman/params" >/dev/null 2>&1; then break; fi
    sleep 0.2
done

PARAMS="$(curl -sf "http://127.0.0.1:$PORT/spilman/params")" || { echo "FAIL: params never answered"; tail -5 "$MOD_LOG"; exit 1; }
echo "params: $PARAMS"
PUBKEY="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1]).get("receiver_pubkey") or "")' "$PARAMS")"
[ -n "$PUBKEY" ] || { echo "FAIL: no receiver_pubkey advertised"; exit 1; }
echo "PASS: advertised receiver_pubkey=$PUBKEY"

echo "--- real payer process, mint=$MINT_URL ---"
set +e
(timeout 420 "$ROOT/target/debug/examples/spilman-payer" \
    --mint-url "$MINT_URL" --module-url "http://127.0.0.1:$PORT" --flow open-settle) \
    >"$PAYER_LOG" 2>&1
RC=$?
set -e
tail -25 "$PAYER_LOG"
echo "PAYER_RC=$RC"

if [ "$RC" -ne 0 ]; then
    echo "FAIL: the payer did not settle against $MINT_URL (rc=$RC)"
    grep -iE 'error|failed|refus|reject' "$PAYER_LOG" | head -5 || true
    exit 1
fi
grep -q 'PAYER_SETTLED' "$PAYER_LOG" || { echo "FAIL: rc=0 but no PAYER_SETTLED marker"; exit 1; }
echo "PASS: settled against the public mint $MINT_URL"
grep 'PAYER_SETTLED' "$PAYER_LOG"
