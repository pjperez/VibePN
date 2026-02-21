# VibePN Architecture Deep Dive

This document describes the current implementation in detail and evaluates how complete each subsystem is.

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

1. Parses `-config` path (default `/etc/vibepn/config.toml`).
2. Loads TOML config (`config.Load`).
3. Loads local TLS identity (`crypto.LoadTLS`), validates optional expected fingerprint.
4. Creates route table (`netgraph.NewRouteTable`).
5. Creates liveness tracker (`peer.NewLivenessTracker`) + timeout watcher.
6. Creates peer registry (`peer.NewRegistry`) and disconnect callback removing peer routes.
7. Registers control-plane globals/callbacks (`control.Register`, `RegisterNetConfig`, `RegisterConfigPath`, goodbye callback).
8. Initializes all local TUN interfaces (`iface.Init`).
9. Starts one packet dispatcher goroutine per local network (`forward.Dispatcher.Start`).
10. Creates inbound raw-stream handler (`forward.NewInbound`) with map of all network devices.
11. Starts metrics server (`metrics.Serve(":9000")`).
12. Starts local control socket server (`control.StartUDS("/var/run/vibepn.sock")`).
13. Starts QUIC listener (`quic.Listen(":51820", tlsConf)`).
14. Starts QUIC accept loop (`quic.AcceptLoop`).
15. Starts outbound peer dial attempts (`peer.ConnectToPeers`).
16. Installs SIGINT/SIGTERM shutdown handler (`registry.DisconnectAll`, then exit).
17. Blocks forever (`select {}`).

### Control client (`cmd/vpnctl/main.go`)

`vpnctl`:

- Dials `/var/run/vibepn.sock`.
- Sends `{"cmd":"..."}` JSON.
- Reads `CommandResponse`.
- Supports `status|routes|peers|reload|goodbye`.
- Optional `--json` pretty-prints raw output.

#### Onboarding commands (`init|invite|join|add-peer|doctor`)

`vpnctl` also includes local onboarding helpers that operate on config/cert files:

- `init`: generates a new self-signed cert/key pair, computes cert SHA-256 fingerprint, and writes a fresh config with one network and no peers.
- `invite`: loads an existing config, requires an exported `--network`, and emits JSON (`version`, `network`, `prefix`, `inviter{name,address,fingerprint}`).
- `join`: accepts exactly one of `--invite` or `--invite-file`, validates invite fields/CIDR, generates local identity, and writes a new config with the inviter pre-added as a peer.
- `add-peer`: appends one peer entry (`name`, `address`, `fingerprint`, `networks`) to an existing config with basic validation.
- `doctor`: runs local consistency checks across config parse, identity, CIDR/address formatting, fingerprint format, and peer network references.

Current limitations:

- These commands only read/write local files; they do not push updates into a running daemon process.
- Invite payloads are plain JSON and are not signed, encrypted, or expiry-bound.
- `join` writes a full target config and requires `--force` to overwrite existing config/cert/key files.
- `add-peer` validates host:port, network references, optional fingerprint format, and duplicate peer names, but does not validate remote reachability.

## 3) Configuration Model (`config/`)

### Schema (`config.Config`)

- `identity`:
  - `cert` path
  - `key` path
  - `fingerprint` (optional pin)
- `peers[]`:
  - `name`
  - `address` (`host:port`)
  - `fingerprint` (optional pin in config, not currently enforced in dial path)
  - `networks` (declared intended peer networks; currently informational in runtime)
- `networks.<name>`:
  - `address` (`auto` or static IP)
  - `prefix` CIDR
  - `export` route advertisement toggle

### Address resolution (`config/address.go`)

`ResolveAddressForNetwork(name, nodeID, networks)`:

- Static mode: validates IP parse.
- Auto mode:
  - Parses CIDR (IPv4 only).
  - Hashes `network + ":" + nodeID`.
  - Derives host offset inside subnet.
  - Avoids network/broadcast hosts.

Tests exist only for this package (`config/address_test.go`).

## 4) Network Interface Layer (`iface/`, `tun/`)

### Interface manager (`iface.Init`)

For each configured network:

- Resolves IP address.
- Computes CIDR with network mask from `prefix`.
- Calls `tun.Open(cidr, nodeID)`.
- Stores in `map[networkName]*tun.Device`.

Failures are logged and skipped per-network; init succeeds if at least one device was created.

### TUN device implementation (`tun/device.go`)

`tun.Open`:

- Creates TUN interface (`water.New`).
- Renames to deterministic `vibepn-<sha256(nodeID)[:6]>`.
- Configures IP via shell commands:
  - `ip addr add <cidr> dev <name>`
  - `ip link set up dev <name>`

`tun.Device` methods:

- `Read([]byte)`, `Write([]byte)`, `Close()`, `Name()`.

Note: `tun/reader.go` contains channel-based reader utility that is currently unused by main flow.

## 5) QUIC Transport and Session Model (`quic/`)

### Listener

`quic.Listen(addr, tlsConf)`:

- Uses `quic-go`.
- Enables datagrams in config, but current data path uses streams only.

### Accept loop

`quic.AcceptLoop(listener, tracker, routes, registry, inbound)`:

- Accepts incoming QUIC connection.
- Extracts peer cert fingerprint (`sha256(cert.Raw)`).
- Generates local tie-break nonce and immediately calls `registry.Add(peerID, conn, nonce)`.
- Starts per-connection session handler goroutine.

### Session handling

`handleSession`:

1. Accepts first stream as control stream.
2. Sends Hello control message with nonce.
3. Announces exported routes from `control.GetNetConfig()`.
4. Starts `peer.HandleControlStream` on that control stream.
5. Accepts additional streams as raw streams and routes them to `forward.Inbound`.

## 6) Peer Lifecycle and Control Protocol (`peer/`, `control/`)

## 6.1 Outbound peer connect (`peer.ConnectToPeers`)

For each configured peer (one goroutine each):

1. Builds TLS config via TOFU (`crypto.LoadPeerTLSWithTOFU`).
2. Dials QUIC with 5s timeout.
3. Opens control stream with 2s timeout.
4. Sends Hello nonce.
5. Stores nonce in global nonce map.
6. Adds connection to registry (duplicate tie-break logic).
7. Sends Route-Announce for each exported local network.
8. Starts keepalive loop.
9. Starts control stream reader (`HandleControlStream`).

Current behavior: one-shot dial attempt per peer; no reconnect loop/backoff.

## 6.2 Registry (`peer/registry.go`)

State:

- `conns map[peerID]quic.Connection`.
- callbacks: `onConnect`, `onDisconnect`.
- identity/netcfg snapshots.
- global `peerNonces` map (package-level, not per-registry instance).

Duplicate connection handling (`Add`):

- If existing connection for same peer:
  - Reads stored peer nonce.
  - Lower nonce wins.
  - Loser connection is closed.

Disconnect behavior:

- Connection watcher goroutine removes closed session from map.
- `DisconnectAll` attempts goodbye stream (2s timeout), then closes all sessions.

## 6.3 Control protocol framing (`control/send.go`, `peer/manager.go`)

All control messages use:

- 2-byte big-endian message length
- payload:
  - first byte = type
  - remaining bytes = type-specific body

Types:

- `H` (Hello): `8-byte nonce`
- `A` (Route-Announce):
  - `1-byte networkLen`
  - `networkName`
  - repeated route tuples:
    - `1-byte prefixLen`
    - `prefix`
    - `2-byte metric`
- `W` (Route-Withdraw):
  - `networkName` + one prefix
- `K` (Keepalive): `8-byte unix timestamp`
- `G` (Goodbye): empty body

Control message decode logic is in `peer.HandleControlStream`.

## 6.4 Keepalive (`control/keepalive.go`)

- Every 10s, sends Keepalive message on stream.
- Stops loop on first send error.

Current behavior: no explicit cancellation channel; exits only on stream write error.

## 6.5 Local control socket API (`control/uds.go`, `control/handlers.go`)

UDS server:

- Socket path is removed then recreated.
- Permission set to `0600`.
- Per-connection 2s deadline.

Commands:

- `status`: uptime + peer count + route count.
- `peers`: tracker peer list.
- `routes`: route table dump.
- `reload`:
  - reloads config from registered path.
  - validates networks + identity fields.
  - registers new net config snapshot.
  - removes self routes by fingerprint.
  - re-announces configured networks to connected peers.
- `goodbye`: triggers registered shutdown callback.

## 7) Data Plane (`forward/`)

## 7.1 Outbound forwarding (`forward/dispatcher.go`)

One goroutine per local network device:

1. Reads packet from network-specific TUN device.
2. Extracts destination IP (IPv4 only).
3. Looks up first matching route in route table for this same network.
4. Gets peer session from registry.
5. Opens raw stream with 2s timeout.
6. Writes packet frame:
   - `1-byte networkName length`
   - `networkName bytes`
   - `2-byte packet length`
   - raw packet bytes
7. Closes stream.

Route lookup currently scans routes linearly and returns first CIDR match (no longest-prefix selection).

## 7.2 Inbound forwarding (`forward/inbound.go`)

For each accepted raw stream:

Loop:

1. Read `networkName length` (1 byte).
2. Read `networkName`.
3. Read packet length (2 bytes).
4. Read packet bytes.
5. Find local `tun.Device` by network name from map.
6. Write packet into corresponding TUN.

If network name is unknown locally, packet is dropped and loop continues.

## 7.3 Legacy outbound path (`forward/outbound.go`)

`Outbound.SendPackets` exists but is currently not wired from `cmd/vpn/main.go`.
It uses older framing (`packetLen + packet` only) and a single long-lived stream.

## 8) Routing Model (`netgraph/`)

`RouteTable` (mutex protected):

- `routes map[network][]Route`.
- `AddRoute` deduplicates on `(network, prefix, peerID)`.
- `RemoveByPeer` removes all routes for disconnected peer.
- `RemoveRoute(network,prefix)` removes matching prefix in one network.
- `RoutesForNetwork(network, excludePeer)` returns copy filtered by peer.
- `AllRoutes` flattens all network route slices.

`Route.ExpiresAt` exists but expiry logic is not currently populated by route announcements.

## 9) Liveness Model (`peer/liveness.go`)

`LivenessTracker`:

- Maintains `map[peerID]PeerState{LastSeen}`.
- `UpdatePeer`/`MarkAlive` set current timestamp.
- Watcher ticker every 10s:
  - removes peers with `now - LastSeen > timeout`.
  - removes peer routes from route table.

Liveness updates currently depend on received keepalive messages in control stream.

## 10) Security and Trust Model (`crypto/`)

## 10.1 Local identity (`crypto/identity.go`)

- Loads local cert/key pair.
- Computes cert fingerprint.
- Optionally enforces expected fingerprint from config.
- Sets ALPN protocol `vibepn/0.1`.

## 10.2 Peer TOFU (`crypto/tofu.go`)

Dial path uses:

- `InsecureSkipVerify: true`
- custom `VerifyPeerCertificate` callback:
  - parse peer certificate
  - reject certs outside validity window (`NotBefore`/`NotAfter`)
  - fingerprint peer cert
  - load/compare/store fingerprint in TOFU file (`~/.vibepn/known_peers.json`)

TOFU store properties:

- directory mode `0700`, file mode `0600`.
- keyed by peer name (`peerName -> fingerprint`).

## 11) Metrics and Logging

### Metrics (`metrics/http.go`)

- Exposes Prometheus handler on `/metrics`.
- Served via `http.ListenAndServe`.

### Logging (`log/logger.go`)

Structured single-line format:

`[RFC3339 UTC timestamp] LEVEL  [component] message`

`Fatalf` logs and exits process with status 1.

## 12) Global State Inventory

The codebase uses several package-level mutable states:

- `control` package:
  - route table pointer
  - peer tracker pointer
  - sendRoute function pointer
  - goodbye callback
  - startup time
  - config path
  - network config snapshot (RWMutex-protected)
- `quic` package:
  - `ownFingerprint` string
- `peer` package:
  - global nonce map (`peerNonces`)
- `crypto` package:
  - TOFU path/store/mutex

These are central to runtime behavior and make reset/isolation in tests harder.

## 13) End-to-End Flows

## 13.1 Outbound packet flow (local -> remote)

1. Packet enters local TUN for network `N`.
2. Dispatcher `Start(N, dev)` reads packet.
3. Destination IP parsed.
4. Route matched in `RouteTable` under network `N`.
5. Peer connection fetched from registry.
6. Raw stream opened.
7. Frame written: network + length + packet.
8. Remote inbound handler writes packet to remote TUN for same network name.

## 13.2 Inbound route learning

1. Peer sends control `A` message on control stream.
2. `peer.HandleControlStream` parses route announce.
3. Adds learned route(s) with `Network`, `Prefix`, `PeerID`, `Metric`.
4. Dispatcher can now route packets matching those prefixes.

## 13.3 Reload flow

1. `vpnctl reload` sends command over UDS.
2. `control.Handle("reload")` reloads and validates config file.
3. Replaces `control` network-config snapshot.
4. Removes self routes by local fingerprint.
5. Re-announces configured networks to currently known peers.

No reinit of interfaces, listener, or peer dial topology is performed.

## 14) Implementation Completeness Assessment

Status key:

- **Complete**: implemented and wired in main flow.
- **Partial**: implemented but with notable limitations.
- **Missing**: expected production capability not present.

| Area | Status | Notes |
|---|---|---|
| Daemon bootstrap and basic run loop | Complete | Main startup/shutdown path is wired and buildable. |
| Multi-network local interface creation | Complete | Multiple network devices are created and tracked by name. |
| Raw packet framing consistency | Complete | Outbound and inbound use same network-aware binary frame. |
| Data-plane routing correctness basics | Partial | First-match CIDR lookup only; no longest-prefix preference or policy checks. |
| Peer dial lifecycle | Partial | One goroutine per peer with one-shot dial; no automatic reconnect/backoff. |
| Duplicate connection tie-break | Partial | Nonce tie-break exists, but lifecycle races still possible under churn. |
| Control command surface (`status/routes/peers/reload/goodbye`) | Complete | CLI and UDS handlers are wired end-to-end. |
| Reload semantics | Partial | Re-announces routes but does not reconfigure interfaces, peer set, or listeners. |
| Route expiry handling | Missing | `ExpiresAt` field exists but not actively driven by protocol timers. |
| Access control on route announcements | Missing | No enforcement that peer may only announce allowed networks/prefixes. |
| Security (TOFU + cert validity windows) | Partial | Fingerprint pinning + validity checks exist; trust still keyed only by peer name. |
| Tests | Partial | Only `config/address` tests currently exist; most subsystems untested. |
| CI pipeline | Missing | No repository CI workflow currently present. |
| Observability metrics breadth | Partial | Prometheus endpoint exists, but no custom counters/gauges emitted yet. |

## 15) High-Priority Remaining Work

1. **Reconnect/backoff strategy**
   - Add persistent connection manager loop per peer.
2. **Reload semantics completion**
   - Define/implement what is hot-reloaded (interfaces, peers, routes) and synchronize transitions.
3. **Route policy + validation**
   - Validate announced routes against configured peer/network policy.
4. **Routing algorithm improvements**
   - Longest-prefix match and deterministic best-route selection.
5. **Test coverage expansion**
   - Add unit tests for control, registry, route table, forwarding framing, and TOFU behavior.
6. **CI workflow**
   - Gate PRs on `go test ./...`, `go vet ./...`, and daemon/cli build.

## 16) Notes on Documentation Accuracy

This deep dive reflects the current code under:

- `cmd/`, `config/`, `control/`, `crypto/`, `forward/`, `iface/`, `log/`, `metrics/`, `netgraph/`, `peer/`, `quic/`, `tun/`, and `shared/`.

If runtime behavior differs from this document, the code is the source of truth and the doc should be updated immediately.
