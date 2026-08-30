#!/usr/bin/env bash
# VibePN resilience test: start two daemons, kill one, verify reconnect.
# Self-contained: does its own onboarding and cleanup.
# Requires: Linux, /dev/net/tun, root (or sudo), ip, ping.
set -uo pipefail

VPN="${VPN:-./vpn}"
VPNCTL="${VPNCTL:-./vpnctl}"
WORK="${WORK:-$(mktemp -d /tmp/vibepn-res.XXXXXX)}"
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
  sudo pkill -9 -f "vpn -config $A/config.toml" 2>/dev/null
  sudo pkill -9 -f "vpn -config $B/config.toml" 2>/dev/null
  sleep 1
  if [ "${KEEP:-0}" != 1 ]; then rm -rf "$WORK"; else echo "KEPT WORKDIR: $WORK"; fi
}
trap cleanup EXIT

step "Onboard node A"
"$VPNCTL" init -config "$A/config.toml" -cert "$A/node.crt" -key "$A/node.key" \
  -name node-a -network corp -prefix 10.42.0.0/24 -address auto >/dev/null
"$VPNCTL" invite -config "$A/config.toml" -network corp -address 127.0.0.1:51830 \
  -name node-a -out "$A/invite.json" >/dev/null
FP_A=$(grep -m1 fingerprint "$A/config.toml" | awk '{print $3}' | tr -d '"')
ok "node A onboarded"

step "Onboard node B"
"$VPNCTL" join -config "$B/config.toml" -cert "$B/node.crt" -key "$B/node.key" \
  -name node-b -invite-file "$A/invite.json" -address auto >/dev/null
FP_B=$(grep -m1 fingerprint "$B/config.toml" | awk '{print $3}' | tr -d '"')
"$VPNCTL" add-peer -config "$A/config.toml" -name node-b -address 127.0.0.1:51831 \
  -fingerprint "$FP_B" -networks corp >/dev/null
ok "node B onboarded"

step "Start daemons"
sudo "$VPN" -config "$A/config.toml" -listen 127.0.0.1:51830 -socket "$A/vibepn.sock" \
  -metrics 127.0.0.1:19200 -tofu "$A/peers.json" >"$A/vpn.log" 2>&1 &
PID_A=$!
sudo "$VPN" -config "$B/config.toml" -listen 127.0.0.1:51831 -socket "$B/vibepn.sock" \
  -metrics 127.0.0.1:19201 -tofu "$B/peers.json" >"$B/vpn.log" 2>&1 &
PID_B=$!
sleep 3

step "Wait for initial connection (up to 15s)"
CONNECTED=0
for i in $(seq 1 15); do
  PA=$("$VPNCTL" peers -socket "$A/vibepn.sock" 2>/dev/null | grep -c node-b || true)
  if [ "$PA" -ge 1 ]; then CONNECTED=1; break; fi
  sleep 1
done
[ "$CONNECTED" = 1 ] && ok "A connected to node-b" || bad "A never connected to node-b"

step "Kill daemon B"
sudo pkill -9 -f "vpn -config $B/config.toml" 2>/dev/null

step "Wait for A to notice B is gone (liveness timeout, up to 45s)"
DROPPED=0
for i in $(seq 1 45); do
  PA=$("$VPNCTL" peers -socket "$A/vibepn.sock" 2>/dev/null | grep -c node-b || true)
  if [ "$PA" -eq 0 ]; then DROPPED=1; break; fi
  sleep 1
done
[ "$DROPPED" = 1 ] && ok "A dropped node-b after kill (${i}s)" || bad "A still lists node-b after 45s"

step "Restart daemon B"
sudo "$VPN" -config "$B/config.toml" -listen 127.0.0.1:51831 -socket "$B/vibepn.sock" \
  -metrics 127.0.0.1:19201 -tofu "$B/peers.json" >"$B/vpn-restart.log" 2>&1 &
PID_B=$!

step "Wait for reconnect (up to 25s)"
RECONNECTED=0
for i in $(seq 1 25); do
  PA=$("$VPNCTL" peers -socket "$A/vibepn.sock" 2>/dev/null | grep -c node-b || true)
  if [ "$PA" -ge 1 ]; then RECONNECTED=1; break; fi
  sleep 1
done
[ "$RECONNECTED" = 1 ] && ok "A reconnected to node-b" || bad "A did not reconnect (last count=$PA)"

step "Ping again after reconnect (up to 15s)"
ADDR_B=$(ip -o addr show 2>/dev/null | awk '/10\.42\./{print $4}' | tail -1 | cut -d/ -f1 || true)
PINGED=0
if [ -n "$ADDR_B" ]; then
  for i in $(seq 1 15); do
    if ping -c1 -W1 "$ADDR_B" >/dev/null 2>&1; then PINGED=1; break; fi
    sleep 1
  done
  [ "$PINGED" = 1 ] && ok "ping A -> B after reconnect ($ADDR_B)" || bad "ping failed after reconnect"
else
  bad "could not determine B address"
fi

printf '\n===== RESILIENCE RESULTS: PASS=%d FAIL=%d =====\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]