#!/usr/bin/env bash
# VibePN end-to-end smoke test: two daemons on one host, different ports.
# Requires: Linux, /dev/net/tun, root (or sudo), ip, ping, curl.
# Set KEEP=1 to retain the work directory on failure.
set -uo pipefail

VPN="${VPN:-./vpn}"
VPNCTL="${VPNCTL:-./vpnctl}"
WORK="${WORK:-$(mktemp -d /tmp/vibepn-e2e.XXXXXX)}"
A="$WORK/a"
B="$WORK/b"
mkdir -p "$A" "$B"

PASS=0
FAIL=0
step() { printf '\n=== %s ===\n' "$*"; }
ok()   { PASS=$((PASS+1)); printf '  PASS: %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL: %s\n' "$*"; }

cleanup() {
  set +e
  kill "$PID_A" "$PID_B" 2>/dev/null
  wait "$PID_A" "$PID_B" 2>/dev/null
  if [ "${KEEP:-0}" != 1 ]; then rm -rf "$WORK"; else echo "KEPT WORKDIR: $WORK"; fi
}
trap cleanup EXIT

step "Onboarding node A"
"$VPNCTL" init -config "$A/config.toml" -cert "$A/node.crt" -key "$A/node.key" \
  -name node-a -network corp -prefix 10.42.0.0/24 -address auto >/dev/null
FP_A=$(grep -m1 fingerprint "$A/config.toml" | awk '{print $3}' | tr -d '"')
ok "node A fingerprint ${FP_A:0:12}..."

step "Invite node B via one-line token"
TOKEN=$("$VPNCTL" invite -config "$A/config.toml" -network corp -address 127.0.0.1:51820 \
  -name node-a -token)
case "$TOKEN" in
  vibepn://*) ok "token: ${TOKEN:0:40}..." ;;
  *) bad "unexpected token format: $TOKEN" ;;
esac

step "Onboard node B (join via token)"
"$VPNCTL" join -config "$B/config.toml" -cert "$B/node.crt" -key "$B/node.key" \
  -name node-b -invite "$TOKEN" -address auto >/dev/null
FP_B=$(grep -m1 fingerprint "$B/config.toml" | awk '{print $3}' | tr -d '"')
ok "node B fingerprint ${FP_B:0:12}..."

step "Add node B as peer of node A"
"$VPNCTL" add-peer -config "$A/config.toml" -name node-b -address 127.0.0.1:51821 \
  -fingerprint "$FP_B" -networks corp >/dev/null
ok "peer added"

step "ls shows configured peers and networks"
LS_A=$("$VPNCTL" ls -config "$A/config.toml")
echo "$LS_A" | grep -q "node-b" && ok "ls shows node-b" || bad "ls missing node-b"
echo "$LS_A" | grep -q "corp" && ok "ls shows corp network" || bad "ls missing corp"

step "rm-peer then re-add (round-trip)"
"$VPNCTL" rm-peer -config "$A/config.toml" -name node-b >/dev/null && ok "rm-peer removed node-b" || bad "rm-peer failed"
"$VPNCTL" add-peer -config "$A/config.toml" -name node-b -address 127.0.0.1:51821 \
  -fingerprint "$FP_B" -networks corp >/dev/null && ok "re-added node-b" || bad "re-add failed"

step "Validate both configs"
"$VPNCTL" doctor -config "$A/config.toml" >/dev/null && ok "doctor A" || bad "doctor A"
"$VPNCTL" doctor -config "$B/config.toml" >/dev/null && ok "doctor B" || bad "doctor B"

step "Start daemons"
sudo "$VPN" -config "$A/config.toml" -listen 127.0.0.1:51820 -socket "$A/vibepn.sock" \
  -metrics 127.0.0.1:19100 -tofu "$A/peers.json" >"$A/vpn.log" 2>&1 &
PID_A=$!
sudo "$VPN" -config "$B/config.toml" -listen 127.0.0.1:51821 -socket "$B/vibepn.sock" \
  -metrics 127.0.0.1:19101 -tofu "$B/peers.json" >"$B/vpn.log" 2>&1 &
PID_B=$!
sleep 3

step "Daemons alive?"
if kill -0 "$PID_A" 2>/dev/null; then ok "daemon A running"; else bad "daemon A died: $(tail -3 "$A/vpn.log")"; fi
if kill -0 "$PID_B" 2>/dev/null; then ok "daemon B running"; else bad "daemon B died: $(tail -3 "$B/vpn.log")"; fi

step "Control socket status"
"$VPNCTL" status -socket "$A/vibepn.sock" >/dev/null 2>&1 && ok "status A" || bad "status A ($("$VPNCTL" status -socket "$A/vibepn.sock" 2>&1))"
"$VPNCTL" status -socket "$B/vibepn.sock" >/dev/null 2>&1 && ok "status B" || bad "status B ($("$VPNCTL" status -socket "$B/vibepn.sock" 2>&1))"

step "Wait for peer connection (up to 15s)"
CONNECTED=0
PA=0; PB=0
for i in $(seq 1 15); do
  PA=$("$VPNCTL" peers -socket "$A/vibepn.sock" 2>/dev/null | grep -c node-b || true)
  PB=$("$VPNCTL" peers -socket "$B/vibepn.sock" 2>/dev/null | grep -c node-a || true)
  if [ "$PA" -ge 1 ] && [ "$PB" -ge 1 ]; then CONNECTED=1; break; fi
  sleep 1
done
if [ "$CONNECTED" = 1 ]; then ok "peers connected both ways"; else bad "peers not connected (A sees node-b=$PA, B sees node-a=$PB)"; fi

step "Routes learned"
RA=$("$VPNCTL" routes -socket "$A/vibepn.sock" 2>/dev/null | grep -c "10.42.0.0/24" || true)
RB=$("$VPNCTL" routes -socket "$B/vibepn.sock" 2>/dev/null | grep -c "10.42.0.0/24" || true)
[ "$RA" -ge 1 ] && ok "A has route 10.42.0.0/24" || bad "A missing route ($("$VPNCTL" routes -socket "$A/vibepn.sock" 2>&1))"
[ "$RB" -ge 1 ] && ok "B has route 10.42.0.0/24" || bad "B missing route ($("$VPNCTL" routes -socket "$B/vibepn.sock" 2>&1))"

step "vpnctl test (latency probe)"
sleep 3  # let connection churn settle
TEST_OUT=""
for i in $(seq 1 5); do
  TEST_OUT=$("$VPNCTL" test -socket "$A/vibepn.sock" 2>&1)
  if echo "$TEST_OUT" | grep -q "OK"; then break; fi
  sleep 1
done
echo "$TEST_OUT" | grep -q "OK" && ok "test OK: $TEST_OUT" || bad "test failed: $TEST_OUT"

step "vpnctl logs"
LOGS=$("$VPNCTL" logs -socket "$A/vibepn.sock" 2>&1)
echo "$LOGS" | grep -q "VibePN started" && ok "logs contain startup line" || bad "logs missing startup line"

step "Resolve auto addresses"
ADDR_A=$(ip -o addr show 2>/dev/null | awk '/10\.42\./{print $4}' | head -1 | cut -d/ -f1 || true)
ADDR_B=$(ip -o addr show 2>/dev/null | awk '/10\.42\./{print $4}' | tail -1 | cut -d/ -f1 || true)
ok "A addr=$ADDR_A B addr=$ADDR_B"

step "Ping across the tunnel (up to 20s)"
PINGED=0
if [ -n "$ADDR_A" ] && [ -n "$ADDR_B" ] && [ "$ADDR_A" != "$ADDR_B" ]; then
  for i in $(seq 1 20); do
    if ping -c1 -W1 "$ADDR_B" >/dev/null 2>&1; then PINGED=1; break; fi
    sleep 1
  done
  [ "$PINGED" = 1 ] && ok "ping A -> B ($ADDR_B)" || bad "ping A -> B failed"
else
  bad "could not determine both tunnel addresses (A=$ADDR_A B=$ADDR_B)"
fi

step "Metrics endpoint"
M=$(curl -s http://127.0.0.1:19100/metrics 2>/dev/null | grep -c vibepn_ || true)
[ "$M" -ge 1 ] && ok "metrics present ($M vibepn_ lines)" || bad "metrics missing"

step "Reload"
"$VPNCTL" reload -socket "$A/vibepn.sock" >/dev/null 2>&1 && ok "reload A" || bad "reload A ($("$VPNCTL" reload -socket "$A/vibepn.sock" 2>&1))"

step "Goodbye"
"$VPNCTL" goodbye -socket "$A/vibepn.sock" >/dev/null 2>&1 && ok "goodbye A" || bad "goodbye A ($("$VPNCTL" goodbye -socket "$A/vibepn.sock" 2>&1))"
sleep 2

printf '\n===== RESULTS: PASS=%d FAIL=%d =====\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]