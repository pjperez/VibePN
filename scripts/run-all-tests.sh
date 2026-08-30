#!/usr/bin/env bash
# Full VibePN e2e + resilience suite.
# Requires: Linux, /dev/net/tun, root (or sudo), ip, ping, curl.
# Binaries default to ./vpn and ./vpnctl next to this script; override with
# VPN=/path/to/vpn VPNCTL=/path/to/vpnctl.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VPN="${VPN:-$DIR/vpn}"
VPNCTL="${VPNCTL:-$DIR/vpnctl}"
WORK="${WORK:-$(mktemp -d /tmp/vibepn-full.XXXXXX)}"

echo "== Running e2e test =="
WORK="$WORK" VPN="$VPN" VPNCTL="$VPNCTL" bash "$DIR/e2e-test.sh"
E2E=$?
echo
echo "== Running resilience test =="
WORK="$WORK" VPN="$VPN" VPNCTL="$VPNCTL" bash "$DIR/resilience-test.sh"
RES=$?

if [ "${KEEP:-0}" != 1 ]; then rm -rf "$WORK"; else echo "KEPT WORKDIR: $WORK"; fi

echo
if [ "$E2E" -eq 0 ] && [ "$RES" -eq 0 ]; then
  echo "ALL TESTS PASSED"
  exit 0
else
  echo "TESTS FAILED (e2e=$E2E resilience=$RES)"
  exit 1
fi