# Copilot Instructions for VibePN

## What This Project Is

VibePN is a peer-to-peer VPN daemon written in Go. It creates encrypted overlay networks between nodes using QUIC as the transport layer, TUN virtual interfaces for packet I/O, and TOFU-based TLS identity (via X.509 certificate fingerprints).

## Build Commands

```bash
# Build the daemon
go build -o vpn ./cmd/vpn

# Build the control CLI
go build -o vpnctl ./cmd/vpnctl

# Run the daemon
./vpn -config /etc/vibepn/config.toml

# Run tests (none exist yet)
go test ./...

# Vet
go vet ./...
```

Go 1.23+ required (toolchain 1.24.1). Module name is `vibepn`.

## Architecture Overview

```
cmd/vpn (daemon)
  ├── config       – TOML config loading (identity, peers, networks)
  ├── crypto       – TLS identity, certificate fingerprinting (SHA256)
  ├── quic         – QUIC listener/connection wrapper (quic-go)
  ├── peer         – Registry of active connections, liveness tracking
  ├── netgraph     – CIDR route table keyed by peer ID
  ├── tun/iface    – TUN device creation (water library), IP config
  ├── forward      – Packet dispatcher (TUN→QUIC) + inbound handler (QUIC→TUN)
  ├── control      – Unix domain socket server for vpnctl queries
  ├── metrics      – Prometheus endpoint on :9000
  └── log          – Structured logger with component tagging

cmd/vpnctl – thin Unix socket client; queries the daemon's control socket
```

**Packet data path (outbound):** `forward.Dispatcher` reads raw IP packets from a specific network TUN → extracts dst IP → looks up `netgraph.RouteTable` for that network → gets connection from `peer.Registry` → opens a QUIC stream → writes a per-packet frame: `network_name_length (1 byte) + network_name + packet_length (2 bytes, big-endian) + raw packet`.

**Packet data path (inbound):** QUIC stream accept loop → `forward.Inbound` decodes `network_name + packet_length + packet` frames → looks up target TUN from the network name → writes raw packet to that network's TUN device.

**Identity model:** Each node has a TLS cert/key pair. Peers are authenticated by their certificate's SHA256 fingerprint (TOFU). The fingerprint is embedded in config and compared on connection.

## Key Conventions

### Logger naming
Every component creates its logger with a slash-separated path matching the package hierarchy:
```go
logger := log.New("forward/dispatcher")
logger := log.New("quic/listener")
logger := log.New("peer/registry")
```

### Concurrency
Shared state (peer registry, route table, liveness tracker) is protected with `sync.Mutex`/`sync.RWMutex`. Keep lock/unlock pairs tight and use `defer` right after locking.

### Error handling
- Fatal startup errors: `logger.Fatalf(...)` in `main`
- Runtime errors in goroutines: `logger.Errorf(...)` then `continue` or `return` — never panic
- Errors wrapped with `fmt.Errorf("context: %w", err)`

### Stream protocol
Raw packet streams use binary framing: each packet is encoded as `uint8 network_name_length`, `network_name bytes`, `uint16 packet_length` (big-endian), then packet bytes.

### Package exports
Keep exports minimal. Only export what other packages actually need. Internal helpers stay unexported.

### Config structure
Networks are keyed by name (e.g., `"corp"`, `"local"`). `address = "auto"` means the TUN IP is derived automatically. `export = true` means the local prefix is advertised to peers.

## Example Config

See `example/config.toml` for the full structure (identity, peers, networks sections).

## Key Dependencies

| Dependency | Role |
|---|---|
| `github.com/quic-go/quic-go` | QUIC transport |
| `github.com/songgao/water` | TUN device creation |
| `github.com/BurntSushi/toml` | Config parsing |
| `github.com/prometheus/client_golang` | Metrics |
