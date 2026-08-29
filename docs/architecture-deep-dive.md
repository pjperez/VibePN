# VibePN Architecture Deep Dive

This document describes the current implementation in detail.

## 1) System Purpose

VibePN is a peer-to-peer VPN daemon that:

- Creates TUN interfaces for one or more named overlay networks.
- Exchanges routes over QUIC control streams.
- Forwards raw IP packets between local TUN devices and remote peers over QUIC raw streams.

Main binaries:

- `cmd/vpn`: daemon.
- `cmd/vpnctl`: local control client over Unix domain socket.

## 2) Runtime Component Map

### Daemon core (`cmd/vpn/main.go`)

`main()` wires all subsystems:

1. Parses flags (`-config`, `-socket`, `-listen`, `-metrics`, `-tofu`).
2. Loads and validates TOML config (`config.Load` + `Config.Validate`).
3. Loads local TLS identity (`crypto.LoadTLS`), enforces expected fingerprint.
4. Loads the TOFU trust store and wraps the server TLS config so incoming
   peer certificates are verified (server-side TOFU).
5. Creates route table (`netgraph.NewRouteTable`), liveness tracker with
   watcher, and peer registry with connect/disconnect callbacks.
6. Registers local (self) routes for exported networks.
7. Builds the route policy from config (peer → allowed networks).
8. Registers control-plane wiring (`peer.RegisterControl`).
9. Starts the connection manager (outbound dial loops per peer).
10. Initializes TUN interfaces (`iface.Init`), starts one packet dispatcher
    goroutine per network, and builds the inbound raw-stream handler.
11. Starts metrics server and control socket server.
12. Starts QUIC listener and accept loop.
13. Installs SIGINT/SIGTERM shutdown handler.

### Control client (`cmd/vpnctl/main.go`)

`vpnctl`:

- Dials the control socket (`-socket`, default `/var/run/vibepn.sock`).
- Sends `{"cmd":"..."}` JSON.
- Reads `CommandResponse`.
- Supports `status|routes|peers|reload|goodbye` plus `version`.
- Optional `--json` pretty-prints raw output.

#### Onboarding commands (`init|invite|join|add-peer|doctor`)

- `init`: generates a self-signed ECDSA P-256 cert/key pair, computes the
  SHA-256 fingerprint, and writes a fresh config (atomic write, mode 0600).
- `invite`: emits a JSON invite payload for an exported network.
- `join`: validates an invite payload, generates local identity, writes a
  config with the inviter pre-added as a peer.
- `add-peer`: appends a peer entry with validation.
- `doctor`: runs local consistency checks (config parse, identity, CIDR,
  addresses, fingerprints, peer network references).

## 3) Configuration Model (`config/`)

### Schema (`config.Config`)

- `identity`: `cert`, `key`, `fingerprint` (optional pin).
- `peers[]`: `name`, `address` (`host:port`), `fingerprint` (optional; empty
  means TOFU), `networks` (allowed networks for route announcements).
- `networks.<name>`: `address` (`auto` or static IP), `prefix` CIDR, `export`.

### Validation (`Config.Validate`)

Checks identity fields, fingerprint format, network prefix/address validity,
peer address format, duplicate peer names, and peer network references.

### Address resolution (`config/address.go`)

`ResolveAddressForNetwork(name, nodeID, networks)`:

- Static mode: validates IP parse.
- Auto mode:
  - Parses CIDR (IPv4 only, requires ≥2 host bits).
  - Hashes `network + ":" + nodeID`.
  - Derives a host offset that never lands on the network or broadcast
    address.

## 4) Network Interface Layer (`iface/`, `tun/`)

### Interface manager (`iface.Init`)

For each configured network: resolves the IP, computes the CIDR with the
network mask, opens a TUN device, and stores it by network name. Networks that
fail are skipped; init fails only if no device could be created.

### TUN device implementation (`tun/device.go`)

`tun.Open(cidr, nodeID, networkName)`:

- Creates the TUN interface (`water.New`).
- Renames it to a deterministic per-network name
  `vibepn-<hash(nodeID)[:6]>-<hash(networkName)[:4]>` (≤15 chars), so multiple
  networks do not collide.
- Configures the IP via `ip addr add` / `ip link set up`.

## 5) QUIC Transport and Session Model (`quic/`)

### Listener

`quic.Listen(addr, tlsConf)` uses quic-go with keepalives, a 90s idle timeout,
and 1024 max incoming streams.

### Accept loop

`quic.AcceptLoop(listener, registry, inbound, tofu)`:

- Accepts incoming QUIC connections (TLS layer already verified the peer cert
  via TOFU).
- Extracts the peer certificate SHA-256 fingerprint and resolves it to the configured peer name via the TOFU store (falling back to the raw fingerprint).
- Registers the connection and starts a session handler.

### Session handling

`handleSession`:

1. Accepts the first stream as the control stream (10s timeout).
2. Sends a Hello message.
3. Announces exported routes from the net-config snapshot.
4. Starts the keepalive writer and control reader.
5. Accepts further streams as raw packet streams → `forward.Inbound`.

## 6) Peer Lifecycle and Control Protocol (`peer/`, `protocol/`)

### Connection manager (`peer/manager.go`)

One goroutine per configured peer:

1. Skips dialing while a live connection exists (5s poll).
2. Builds a client TLS config from the TOFU store.
3. Dials QUIC with a 5s timeout.
4. Opens the control stream, sends Hello, registers the connection.
5. Announces exported routes.
6. Starts keepalive writer + control reader.
7. Blocks until the connection dies, then reconnects with exponential backoff
   (2s → 30s) plus ±30% jitter.

### Registry (`peer/registry.go`)

- `conns map[peerID]quic.Connection` keyed by peer name (dialer) or
  fingerprint (acceptor).
- `Add` replaces any existing connection (the loser is closed), fires
  `onConnect`, and spawns a watcher that removes the connection on close and
  fires `onDisconnect` only if it was still the active one.
- `DisconnectAll` sends a Goodbye over a fresh stream, then closes sessions.
- Implements `control.PeerManager` (`ListPeers`, `SendRoute`, `ReconcilePeers`,
  `DisconnectAll`).

### Control protocol (`protocol/protocol.go`)

All control messages are framed as `2-byte big-endian length + payload`, where
the payload starts with a type byte:

- `H` Hello: `8-byte nonce`
- `A` Route-Announce: `1-byte networkLen + network + repeated (1-byte prefixLen
  + prefix + 2-byte metric)`
- `W` Route-Withdraw: `1-byte networkLen + network + 1-byte prefixLen + prefix`
- `K` Keepalive: `8-byte unix timestamp`
- `G` Goodbye: empty body

Encoding/decoding is fully unit-tested, including malformed-input rejection.

### Control stream handling (`peer/control.go`)

- Hello: logged (tie-break handled by connection replacement).
- Route-Announce: each prefix is validated against the route policy before
  being added to the route table.
- Route-Withdraw: removes the matching route.
- Keepalive: updates liveness.
- Goodbye: closes the connection.

### Route policy (`peer/control.go`)

`ConfigRoutePolicy.Allow(peerID, network, prefix)`:

- Rejects unknown networks and malformed CIDRs.
- If the peer has configured network assignments, only those are allowed.
- Peers without assignments may announce any configured network (open policy).

### Liveness (`peer/liveness.go`)

- `MarkAlive`/`UpdatePeer` record last-seen timestamps.
- The watcher sweeps at an interval scaled to the timeout, removes stale peers,
  and drops their routes.

## 7) Data Plane (`forward/`)

### Outbound forwarding (`forward/dispatcher.go`)

One goroutine per local network device:

1. Reads a packet from the network TUN.
2. Extracts the destination IPv4.
3. Looks up the best route (`netgraph.RouteTable.Lookup`, longest-prefix +
   metric).
4. Opens a raw stream with a 5s timeout.
5. Writes the frame: `1-byte networkLen + network + 2-byte packetLen + packet`.
6. Closes the stream.

### Inbound forwarding (`forward/inbound.go`)

For each accepted raw stream, decodes frames and writes packets into the TUN
device for the announced network. Unknown networks drop the packet and
continue.

## 8) Routing Model (`netgraph/`)

`RouteTable` (mutex protected):

- `routes map[network][]Route`.
- `AddRoute` deduplicates on `(network, prefix, peerID)`.
- `Lookup(network, ip)` returns the longest-prefix match, preferring lower
  metrics on ties.
- `RemoveByPeer`, `RemoveRoute`, `RoutesForNetwork`, `AllRoutes`, `ReapExpired`.
- `Route.ExpiresAt` (zero = never) is honored by lookups and reaping.

## 9) Security and Trust Model (`crypto/`)

### Local identity (`crypto/identity.go`)

- Loads the local cert/key pair, computes the SHA-256 fingerprint, optionally
  enforces the configured expected fingerprint.
- Sets ALPN `vibepn/0.1`.

### TOFU store (`crypto/tofu.go`)

- `TOFUStore` persists `peerName → fingerprint` to a JSON file (mode 0600,
  atomic writes).
- `ClientTLS` presents the local cert and verifies the peer via TOFU.
- `ServerTLS` wraps the server config so incoming peer certs are verified too.
- Verification rejects missing certs, expired/not-yet-valid certs, and
  fingerprint mismatches; first sight pins the fingerprint.

## 10) Metrics and Logging

### Metrics (`metrics/http.go`)

Prometheus endpoint on `/metrics` with:

- `vibepn_packets_forwarded_total{network}`
- `vibepn_packets_received_total{network}`
- `vibepn_packets_dropped_total{reason}`
- `vibepn_active_peers`
- `vibepn_routes`
- `vibepn_uptime_seconds`

### Logging (`log/logger.go`)

- Leveled (`debug|info|warn|error|fatal`), controlled by `VIBEPN_LOG_LEVEL`.
- Single-line format: `[RFC3339 UTC] LEVEL [component] message`.
- `Fatalf` logs and exits with status 1.

## 11) End-to-End Flows

### Outbound packet flow (local → remote)

1. Packet enters local TUN for network `N`.
2. Dispatcher reads it, parses the destination IP.
3. Route table returns the best route for `N`.
4. Peer connection fetched from registry.
5. Raw stream opened, frame written (network + length + packet).
6. Remote inbound handler writes the packet to the remote TUN for `N`.

### Inbound route learning

1. Peer sends Route-Announce on the control stream.
2. Each prefix is validated by the route policy.
3. Approved routes are added with `Network`, `Prefix`, `PeerID`, `Metric`.
4. The dispatcher can now route matching packets to that peer.

### Reload flow

1. `vpnctl reload` sends a command over the UDS.
2. `control.Handler` reloads and validates the config.
3. Self routes are re-added and re-announced to live peers.
4. Peer reconciliation is invoked (currently a no-op hook; connection manager
   owns dialing).

## 12) Implementation Completeness Assessment

| Area | Status | Notes |
|---|---|---|
| Daemon bootstrap and shutdown | Complete | Flag-driven, validated config, graceful shutdown. |
| Multi-network TUN setup | Complete | Deterministic per-network device names. |
| Raw packet framing | Complete | Network-aware frames, shared encode/decode. |
| Routing | Complete | Longest-prefix + metric preference, expiry. |
| Peer dial lifecycle | Complete | Reconnect loop, exponential backoff + jitter. |
| Duplicate connection handling | Complete | New connection replaces old; loser closed. |
| Control command surface | Complete | status/routes/peers/reload/goodbye/version. |
| Reload semantics | Partial | Re-announces routes; interface/listener reinit not yet supported. |
| Route policy | Complete | Peer network assignments enforced. |
| TOFU security | Complete | Client + server verification, validity windows, persistence. |
| Tests | Partial | config, crypto, protocol, netgraph, control, peer, forward, tun; more coverage welcome. |
| CI | Complete | Build, vet, race tests on push/PR. |
| Observability | Complete | Custom Prometheus counters/gauges. |