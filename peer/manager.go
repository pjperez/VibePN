package peer

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	"vibepn/config"
	"vibepn/crypto"
	"vibepn/log"
	"vibepn/protocol"

	"github.com/quic-go/quic-go"
)

const (
	dialTimeout        = 5 * time.Second
	streamOpenTimeout  = 5 * time.Second
	initialBackoff     = 2 * time.Second
	maxBackoff         = 30 * time.Second
	backoffJitterRatio = 0.3
)

func generateNonce() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("failed to generate random nonce: %w", err)
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

// ConnectionManager dials configured peers and maintains one connection per
// peer with exponential backoff and jitter.
type ConnectionManager struct {
	logger    *log.Logger
	registry  *Registry
	tofu      *crypto.TOFUStore
	identity  config.Identity
	netcfg    func() map[string]config.NetworkConfig
	handleRaw func(io.Reader)

	mu          sync.Mutex
	peerConfigs map[string]config.Peer // name → config (peers with active dial loops)

	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// NewConnectionManager builds a connection manager.
func NewConnectionManager(
	registry *Registry,
	tofu *crypto.TOFUStore,
	identity config.Identity,
	netcfg func() map[string]config.NetworkConfig,
	handleRaw func(io.Reader),
) *ConnectionManager {
	return &ConnectionManager{
		logger:      log.New("peer/manager"),
		registry:    registry,
		tofu:        tofu,
		identity:    identity,
		netcfg:      netcfg,
		handleRaw:   handleRaw,
		peerConfigs: make(map[string]config.Peer),
		stop:        make(chan struct{}),
	}
}

// Start launches a dial loop per configured peer.
func (m *ConnectionManager) Start(peers []config.Peer) {
	for _, p := range peers {
		m.startDialLoop(p)
	}
}

// startDialLoop launches a dial loop for a peer unless one already exists.
func (m *ConnectionManager) startDialLoop(peer config.Peer) {
	m.mu.Lock()
	if _, exists := m.peerConfigs[peer.Name]; exists {
		m.mu.Unlock()
		return
	}
	m.peerConfigs[peer.Name] = peer
	m.mu.Unlock()

	m.wg.Add(1)
	go m.dialLoop(peer)
}

// ReconcilePeers starts dial loops for any configured peers that are not
// already being dialed. It returns an error only if the config is invalid.
func (m *ConnectionManager) ReconcilePeers(cfg *config.Config) error {
	if cfg == nil {
		return fmt.Errorf("nil config")
	}
	for _, p := range cfg.Peers {
		m.startDialLoop(p)
	}
	return nil
}

// Stop terminates all dial loops and waits for them to finish.
func (m *ConnectionManager) Stop() {
	m.stopOnce.Do(func() { close(m.stop) })
	m.wg.Wait()
}

func (m *ConnectionManager) dialLoop(peer config.Peer) {
	defer m.wg.Done()
	m.logger.Infof("Dial loop for %s started", peer.Name)

	backoff := initialBackoff
	for {
		select {
		case <-m.stop:
			m.logger.Infof("Dial loop for %s stopped", peer.Name)
			return
		default:
		}

		// Skip dialing if we already have a live connection.
		if m.registry.Get(peer.Name) != nil {
			select {
			case <-m.stop:
				m.logger.Infof("Dial loop for %s stopped", peer.Name)
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}

		conn, err := m.dialOnce(peer)
		if err != nil {
			wait := jittered(backoff)
			m.logger.Warnf("Dial %s (%s) failed: %v (retrying in %s)", peer.Name, peer.Address, err, wait)
			if !sleepCtx(m.stop, wait) {
				m.logger.Infof("Dial loop for %s stopped", peer.Name)
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}

		m.logger.Infof("Connection established to %s (%s)", peer.Name, peer.Address)
		backoff = initialBackoff
		m.runSession(peer, conn)
	}
}

func (m *ConnectionManager) dialOnce(peer config.Peer) (quic.Connection, error) {
	tlsConf, err := m.tofu.ClientTLS(m.identity.Cert, m.identity.Key, peer.Name)
	if err != nil {
		return nil, fmt.Errorf("build TLS config: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	conn, err := quic.DialAddr(ctx, peer.Address, tlsConf, quicConfig())
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// runSession drives a single connection: opens the control stream, performs
// the hello exchange, announces routes, and blocks until the connection dies.
func (m *ConnectionManager) runSession(peer config.Peer, conn quic.Connection) {
	ctx, cancel := context.WithTimeout(context.Background(), streamOpenTimeout)
	stream, err := conn.OpenStreamSync(ctx)
	cancel()
	if err != nil {
		m.logger.Warnf("Failed to open control stream to %s: %v", peer.Name, err)
		_ = conn.CloseWithError(0, "failed to open control stream")
		return
	}

	myNonce, err := generateNonce()
	if err != nil {
		_ = conn.CloseWithError(0, "failed to generate nonce")
		return
	}

	if err := protocol.WriteMessage(stream, protocol.Hello{Nonce: myNonce}); err != nil {
		m.logger.Warnf("Failed to send hello to %s: %v", peer.Name, err)
		_ = conn.CloseWithError(0, "failed to send hello")
		return
	}

	// Register the connection; the registry resolves duplicate tie-breaks.
	m.registry.Add(peer.Name, conn)

	// Announce exported local routes.
	m.announceRoutes(stream)

	// Start the keepalive writer and the control reader.
	stopKeepalive := StartKeepaliveLoop(stream)
	defer stopKeepalive()
	go HandleControlStream(conn, stream, peer.Name)

	// The dialer side must also accept streams: when this connection wins the
	// tie-break, remote probes and packet streams arrive on it.
	AcceptStreams(conn, peer.Name, m.handleRaw)

	// Block until the connection ends so the dial loop can reconnect.
	<-conn.Context().Done()
}

func (m *ConnectionManager) announceRoutes(stream quic.Stream) {
	for netName, netCfg := range m.netcfg() {
		if !netCfg.Export {
			continue
		}
		if err := protocol.WriteMessage(stream, protocol.RouteAnnounce{
			Network:  netName,
			Prefixes: []string{netCfg.Prefix},
			Metric:   1,
		}); err != nil {
			m.logger.Warnf("Failed to announce route for network %s: %v", netName, err)
		}
	}
}

// nextBackoff doubles the current backoff, capped at maxBackoff.
func nextBackoff(current time.Duration) time.Duration {
	next := current * 2
	if next > maxBackoff {
		next = maxBackoff
	}
	return next
}

// jittered applies ±30% jitter to a backoff, keeping it within
// [initialBackoff, maxBackoff].
func jittered(base time.Duration) time.Duration {
	jitter := time.Duration(float64(base) * backoffJitterRatio)
	delta := time.Duration(randInt64(int64(-jitter), int64(jitter)))
	out := base + delta
	if out < initialBackoff {
		out = initialBackoff
	}
	if out > maxBackoff {
		out = maxBackoff
	}
	return out
}

func randInt64(min, max int64) int64 {
	if max <= min {
		return min
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return min
	}
	n := int64(binary.BigEndian.Uint64(b[:]) & math.MaxInt64)
	return min + n%(max-min+1)
}

func sleepCtx(stop <-chan struct{}, d time.Duration) bool {
	select {
	case <-stop:
		return false
	case <-time.After(d):
		return true
	}
}

// quicConfig returns the shared QUIC configuration.
func quicConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams:       false,
		MaxIdleTimeout:        90 * time.Second,
		KeepAlivePeriod:       15 * time.Second,
		MaxIncomingStreams:    1024,
		MaxIncomingUniStreams: -1,
	}
}
