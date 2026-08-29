# VibePN

VibePN is a peer-to-peer VPN daemon written in Go. It creates encrypted overlay
networks between nodes using QUIC for transport, TUN interfaces for packet I/O,
and certificate-fingerprint (TOFU) identity for authentication.

## Features

- **Encrypted transport** — QUIC (TLS 1.3) with ALPN `vibepn/0.1`.
- **Trust on first use** — peer certificates are pinned by SHA-256 fingerprint
  on both the dialing *and* accepting side; expired/invalid certs are rejected.
- **Multi-network** — one TUN device per named overlay network, each with its
  own prefix and export policy.
- **Deterministic addressing** — `address = "auto"` derives a stable per-node
  IP from the node fingerprint and network name.
- **Route learning** — peers announce/withdraw prefixes over a control stream;
  the route table uses longest-prefix matching with metric preference.
- **Route policy** — a peer may only announce routes for networks it is
  configured for.
- **Resilience** — automatic reconnects with exponential backoff + jitter,
  keepalive-driven liveness tracking, and duplicate-connection replacement.
- **Operability** — Unix-socket control CLI (`vpnctl`), Prometheus metrics,
  structured leveled logging, and a `doctor` config checker.

## Build, Test, Vet

```bash
# Build daemon and CLI
go build -o vpn ./cmd/vpn
go build -o vpnctl ./cmd/vpnctl

# Run all tests (with race detector)
go test -race ./...

# Run static checks
go vet ./...
```

## Running

```bash
./vpn -config /etc/vibepn/config.toml
```

Daemon flags:

| Flag | Default | Purpose |
|---|---|---|
| `-config` | `/etc/vibepn/config.toml` | Config file path |
| `-socket` | `/var/run/vibepn.sock` | Control socket path |
| `-listen` | `:51820` | QUIC listen address |
| `-metrics` | `:9000` | Prometheus metrics address |
| `-tofu` | `~/.vibepn/known_peers.json` | TOFU trust store path |

Log verbosity is controlled with the `VIBEPN_LOG_LEVEL` environment variable
(`debug`, `info`, `warn`, `error`).

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

Control CLI (via Unix socket):

```bash
./vpnctl status
./vpnctl peers
./vpnctl routes
./vpnctl reload
./vpnctl goodbye
./vpnctl --json status
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

- `cmd/vpn`: daemon wiring (config, interfaces, QUIC listener, control server,
  route table, peer registry, connection manager)
- `peer`: connection manager (dial/reconnect/backoff), control-message
  handling, liveness tracking, route policy
- `protocol`: binary control-plane message encoding/decoding (framed, length
  prefixed, type-tagged)
- `quic`: listener/accept loop and session stream handling
- `forward`: packet forwarding between TUN and QUIC raw streams
- `netgraph`: in-memory route table with longest-prefix matching
- `control`: local UDS command server (`status/routes/peers/reload/goodbye`)
- `crypto`: TLS identity, TOFU trust store (client + server verification)
- `iface` / `tun`: network interface setup and TUN device operations
- `metrics`: Prometheus endpoint with packet/peer/route counters
- `log`: leveled structured logger

For full implementation detail, see `docs/architecture-deep-dive.md`.

## Security model

- Every node has a self-signed ECDSA P-256 certificate.
- Peers authenticate each other by the SHA-256 fingerprint of the presented
  certificate.
- The first time a peer is seen, its fingerprint is pinned in the TOFU store
  (`~/.vibepn/known_peers.json`, mode 0600). Any later certificate for the
  same peer name must match the pin or the connection is rejected.
- Certificates outside their validity window are always rejected.
- Route announcements are validated against the local network config and the
  announcing peer's configured network assignments.