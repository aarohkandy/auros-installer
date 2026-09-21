#!/usr/bin/env bash
# Drive internal/deskbus against a REAL dbus-daemon and a REAL notification
# service. See notifier.py for why the unit tests are not enough on their own.
#
# Requires: dbus-daemon, python3-dbus, python3-gi. On a machine without them
# this prints why and exits 0 — it is extra evidence, not a gate.
set -o errexit -o nounset -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

for need in dbus-daemon python3; do
  command -v "$need" >/dev/null || { echo "dbus-e2e: no $need on this machine; skipping."; exit 0; }
done
python3 -c 'import dbus, gi' 2>/dev/null || {
  echo "dbus-e2e: python3-dbus / python3-gi are not installed; skipping."
  exit 0
}

TMP="$(mktemp -d)"
ADDR_FILE="$TMP/addr"
PID_FILE="$TMP/pid"
OUT="$TMP/received.json"
cleanup() {
  [ -f "$PID_FILE" ] && kill "$(cat "$PID_FILE")" 2>/dev/null || true
  [ -n "${NOTIFIER_PID:-}" ] && kill "$NOTIFIER_PID" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

dbus-daemon --session --fork --print-address="3" --print-pid="4" \
  3>"$ADDR_FILE" 4>"$PID_FILE"
ADDR="$(cat "$ADDR_FILE")"
echo "dbus-e2e: session bus at $ADDR"
export DBUS_SESSION_BUS_ADDRESS="$ADDR"

python3 "$HERE/notifier.py" "$OUT" 2>"$TMP/notifier.err" &
NOTIFIER_PID=$!
for _ in $(seq 1 50); do
  grep -q ready "$TMP/notifier.err" 2>/dev/null && break
  sleep 0.1
done
grep -q ready "$TMP/notifier.err" || {
  echo "dbus-e2e: the notification service never started:"; cat "$TMP/notifier.err"; exit 1;
}

AUROS_DBUS_E2E=1 go test "$REPO/internal/deskbus" \
  -run 'TestSend_AgainstARealSessionBus' -count=1 -v

for _ in $(seq 1 50); do [ -s "$OUT" ] && break; sleep 0.1; done
[ -s "$OUT" ] || { echo "dbus-e2e: the service received nothing."; exit 1; }

echo "dbus-e2e: the notification service decoded:"
python3 -m json.tool "$OUT"

# Assert, against a decoder that is not ours, that every argument arrived
# intact. A body that is one pad byte out would show up here as a truncated or
# shifted string rather than as a green unit test.
python3 - "$OUT" <<'PY'
import json, sys
got = json.load(open(sys.argv[1], encoding='utf-8'))
want = {
    "app_name": "Auros",
    "replaces_id": 0,
    "app_icon": "document-save",
    "summary": "Your files are here",
    "body": "18000 files came across from your old computer — éà字",
    "actions": [],
    "expire_timeout": -1,
}
bad = [f"{k}: got {got.get(k)!r}, want {v!r}" for k, v in want.items() if got.get(k) != v]
if got.get("hints", {}).get("urgency") != 2:
    bad.append(f"hints.urgency: got {got.get('hints')!r}, want 2")
if got.get("hints", {}).get("category") != "transfer.complete":
    bad.append(f"hints.category: got {got.get('hints')!r}, want 'transfer.complete'")
if bad:
    print("dbus-e2e: FAIL")
    for b in bad:
        print("  " + b)
    sys.exit(1)
print("dbus-e2e: every argument arrived intact, decoded by libdbus rather than by our own encoder.")
PY
