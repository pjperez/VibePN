package peer

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"vibepn/config"
	"vibepn/crypto"
	"vibepn/netgraph"
	"vibepn/protocol"
	"vibepn/shared"

	gquic "github.com/quic-go/quic-go"
)

// fakeConn is a minimal quic.Connection for registry tests.
type fakeConn struct {
	ctx    context.Context
	cancel context.CancelFunc
	closed bool
	mu     sync.Mutex
}

func newFakeConn() *fakeConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &fakeConn{ctx: ctx, cancel: cancel}
}

func (f *fakeConn) AcceptStream(context.Context) (gquic.Stream, error) { return nil, nil }
func (f *fakeConn) AcceptUniStream(context.Context) (gquic.ReceiveStream, error) {
	return nil, nil
}
func (f *fakeConn) OpenStream() (gquic.Stream, error) { return nil, nil }
func (f *fakeConn) OpenStreamSync(context.Context) (gquic.Stream, error) {
	return nil, errors.New("streams not supported by fake")
}
func (f *fakeConn) OpenUniStream() (gquic.SendStream, error) { return nil, nil }
func (f *fakeConn) OpenUniStreamSync(context.Context) (gquic.SendStream, error) {
	return nil, nil
}
func (f *fakeConn) LocalAddr() net.Addr  { return nil }
func (f *fakeConn) RemoteAddr() net.Addr { return nil }
func (f *fakeConn) CloseWithError(gquic.ApplicationErrorCode, string) error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	f.cancel()
	return nil
}
func (f *fakeConn) Context() context.Context { return f.ctx }
func (f *fakeConn) ConnectionState() gquic.ConnectionState {
	return gquic.ConnectionState{}
}
func (f *fakeConn) SendDatagram([]byte) error                       { return nil }
func (f *fakeConn) ReceiveDatagram(context.Context) ([]byte, error) { return nil, nil }

func (f *fakeConn) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

func TestRegistryAddReplaceAndDisconnect(t *testing.T) {
	reg := NewRegistry(config.Identity{Fingerprint: "self"})

	conn1 := newFakeConn()
	reg.Add("peer-a", conn1)
	if reg.Get("peer-a") != conn1 {
		t.Fatalf("expected conn1 registered")
	}

	// Replacing closes the old connection.
	conn2 := newFakeConn()
	reg.Add("peer-a", conn2)
	if reg.Get("peer-a") != conn2 {
		t.Fatalf("expected conn2 registered")
	}
	if !conn1.isClosed() {
		t.Fatalf("expected old connection to be closed")
	}

	// Closing the active connection removes it and fires onDisconnect.
	disconnected := make(chan string, 1)
	reg.SetOnDisconnect(func(peerID string) { disconnected <- peerID })
	conn2.cancel()

	select {
	case id := <-disconnected:
		if id != "peer-a" {
			t.Fatalf("unexpected disconnect id %q", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("expected onDisconnect callback")
	}

	if reg.Get("peer-a") != nil {
		t.Fatalf("expected connection removed")
	}
}

func TestRegistryDisconnectAll(t *testing.T) {
	reg := NewRegistry(config.Identity{Fingerprint: "self"})
	conn1 := newFakeConn()
	conn2 := newFakeConn()
	reg.Add("peer-a", conn1)
	reg.Add("peer-b", conn2)

	reg.DisconnectAll()
	if !conn1.isClosed() || !conn2.isClosed() {
		t.Fatalf("expected all connections closed")
	}
	if len(reg.All()) != 0 {
		t.Fatalf("expected empty registry after DisconnectAll")
	}
}

func TestConnectionManagerReconcileAndStop(t *testing.T) {
	tofu, err := crypto.NewTOFUStore(t.TempDir() + "/peers.json")
	if err != nil {
		t.Fatalf("tofu store: %v", err)
	}

	reg := NewRegistry(config.Identity{Fingerprint: "self"})
	cm := NewConnectionManager(
		reg,
		tofu,
		config.Identity{Cert: "/nonexistent.crt", Key: "/nonexistent.key"},
		func() map[string]config.NetworkConfig { return nil },
	)

	// Reconcile with an unreachable peer; the dial loop should keep retrying
	// with backoff and Stop() must terminate it promptly.
	cfg := &config.Config{
		Peers: []config.Peer{
			{Name: "unreachable", Address: "127.0.0.1:1", Networks: []string{"corp"}},
		},
	}
	if err := cm.ReconcilePeers(cfg); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// Give the dial loop a moment to attempt (and fail) a dial.
	time.Sleep(300 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		cm.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("Stop() did not terminate dial loops")
	}
}

func TestRegistryImplementsPeerManager(t *testing.T) {
	reg := NewRegistry(config.Identity{Fingerprint: "self"})
	_ = reg.ListPeers()
	reg.UpdatePeer("x")
	_ = reg.ReconcilePeers(&config.Config{})
	reg.DisconnectAll()
}

var _ = netgraph.Route{}
var _ = protocol.Hello{}
var _ = shared.PeerState{}
