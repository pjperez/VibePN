# VibePN

VibePN is a peer-to-peer VPN daemon written in Go. It uses QUIC for encrypted transport, TUN interfaces for packet I/O, and route announcements over a control stream.

## Current Status

This repository builds and runs, but it is still in active stabilization.  
The following high-impact issues were fixed in this pass:

- `log.Fatalf` now terminates the process (previously it only logged).
- Network config is now registered in the control package at startup and on `reload`.
- `reload` now reads from the daemon's configured config path instead of a hardcoded `~` path.
- Outbound peer handshake no longer writes an extra raw nonce payload that broke control-stream framing.
- Raw packet stream framing is now consistent (network context + `2-byte length + packet`) between sender and receiver.
- Duplicate outbound TUN sender setup was removed from `cmd/vpn` to avoid conflicting packet readers.
- Liveness tracker now respects the timeout passed by `NewLivenessTracker(...)`.
- Raw data-plane framing now includes network context (`network + packet length + packet`) so inbound routing can target the correct interface.
- Inbound forwarding now writes packets to the mapped TUN device for the decoded network instead of a single hardcoded device.
- Stream-open operations in high-traffic/control paths now use bounded timeouts to reduce blocking risk on degraded peers.
- Global control net-config state is now protected with mutexed access and defensive map copies.
- TOFU verification now rejects certificates that are not yet valid or already expired.
- Added initial unit tests for `config.ResolveAddressForNetwork`.

## Build, Test, Vet

```bash
# Build daemon and CLI
go build -o vpn ./cmd/vpn
go build -o vpnctl ./cmd/vpnctl

# Run all tests (no test files yet)
go test ./...

# Run static checks
go vet ./...
```

Single-test command format (when tests are added):

```bash
go test ./path/to/package -run TestName
```

## Running

```bash
./vpn -config /etc/vibepn/config.toml
```

## Run as a systemd service

```bash
# Build and install the daemon binary.
go build -o vpn ./cmd/vpn
sudo install -m 0755 vpn /usr/local/bin/vpn

# Install config and unit file.
sudo install -d -m 0755 /etc/vibepn
sudo install -m 0644 example/config.toml /etc/vibepn/config.toml
sudo install -m 0644 example/systemd/vibepn.service /etc/systemd/system/vibepn.service

# Create dedicated service account (if needed).
sudo getent group vibepn >/dev/null || sudo groupadd --system vibepn
sudo id -u vibepn >/dev/null 2>&1 || sudo useradd --system --gid vibepn --home /var/lib/vibepn --shell /usr/sbin/nologin vibepn

# Reload units and start on boot.
sudo systemctl daemon-reload
sudo systemctl enable vibepn
sudo systemctl start vibepn
```

Control CLI (via Unix socket `/var/run/vibepn.sock`):

```bash
./vpnctl status
./vpnctl peers
./vpnctl routes
./vpnctl reload
./vpnctl goodbye
```

Onboarding helpers:

```bash
./vpnctl init -config /etc/vibepn/config.toml
./vpnctl invite -config /etc/vibepn/config.toml -network corp -address 198.51.100.20:51820
./vpnctl join -config /etc/vibepn/config.toml -invite-file invite.json
./vpnctl add-peer -config /etc/vibepn/config.toml -name node3 -address 203.0.113.9:51820 -fingerprint <sha256> -networks corp
./vpnctl doctor -config /etc/vibepn/config.toml
```

## Quick setup (2 peers)

```bash
# Peer 1 (reachable at 198.51.100.20:51820)
./vpnctl init -config /etc/vibepn/config.toml -name peer1 -network corp -prefix 10.42.0.0/24 -address auto
./vpnctl invite -config /etc/vibepn/config.toml -network corp -address 198.51.100.20:51820 -name peer1 -out /tmp/peer1-invite.json

# Copy /tmp/peer1-invite.json to peer 2 manually.
# Peer 2 (reachable at 203.0.113.9:51820)
./vpnctl join -config /etc/vibepn/config.toml -name peer2 -invite-file /tmp/peer1-invite.json -address auto

# Back on peer 1, use the fingerprint printed by peer 2's join command output.
./vpnctl add-peer -config /etc/vibepn/config.toml -name peer2 -address 203.0.113.9:51820 -fingerprint <peer2_fingerprint> -networks corp

# Run on each peer.
./vpnctl doctor -config /etc/vibepn/config.toml
```

## Architecture (High Level)

- `cmd/vpn`: daemon wiring (config, interfaces, QUIC listener, control server, route table, peer registry)
- `peer`: peer connection management, control-message handling, liveness tracking
- `quic`: listener/accept loop and session stream handling
- `forward`: packet forwarding between TUN and QUIC raw streams
- `netgraph`: in-memory route table keyed by network
- `control`: control protocol messages + local UDS command server
- `iface` / `tun`: network interface setup and TUN device operations

For full implementation detail and subsystem-by-subsystem completeness status, see:

- `docs/architecture-deep-dive.md`

## Major Completion Areas (Current)

1. Testing and CI expansion (beyond initial config tests)
2. Multi-network forwarding hardening and protocol evolution
3. Control-plane reload semantics (full runtime reconfiguration)
4. Session resilience under peer churn and packet loss
5. Security/trust hardening for TOFU and operational key lifecycle

## Known Gaps

- Test coverage is still very limited (currently only `config/address` tests).
- Peer reconnect exists but remains basic and lacks richer failure classification/backoff tuning.
- `reload` revalidates/re-announces routes but does not reinitialize interfaces, peers, or listeners.
- Route-policy enforcement for peer announcements is not yet implemented.
