package control

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vibepn/config"
	"vibepn/log"
	"vibepn/netgraph"
	"vibepn/shared"
)

const testFP = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type fakePeerManager struct {
	peers   []shared.PeerState
	sent    []string
	goodbye bool
}

func (f *fakePeerManager) ListPeers() []shared.PeerState { return f.peers }
func (f *fakePeerManager) UpdatePeer(string)             {}
func (f *fakePeerManager) SendRoute(peerID, network string, route netgraph.Route) error {
	f.sent = append(f.sent, peerID+"/"+network+"/"+route.Prefix)
	return nil
}
func (f *fakePeerManager) DisconnectAll()                      { f.goodbye = true }
func (f *fakePeerManager) ReconcilePeers(*config.Config) error { return nil }

func testDeps(t *testing.T) (ServerDeps, *fakePeerManager) {
	t.Helper()
	pm := &fakePeerManager{
		peers: []shared.PeerState{{ID: "peer-a", LastSeen: time.Now()}},
	}
	rt := netgraph.NewRouteTable()
	rt.AddRoute(netgraph.Route{Network: "corp", Prefix: "10.42.0.0/24", PeerID: "peer-a", Metric: 1})

	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	cfg := &config.Config{
		Identity: config.Identity{
			Cert:        "/c",
			Key:         "/k",
			Fingerprint: testFP,
		},
		Networks: map[string]config.NetworkConfig{
			"corp": {Address: "auto", Prefix: "10.42.0.0/24", Export: true},
		},
	}
	if err := config.Write(cfgPath, cfg); err != nil {
		t.Fatalf("write config: %v", err)
	}

	return ServerDeps{
		ConfigPath: cfgPath,
		Routes:     rt,
		Peers:      pm,
		IdentityFP: testFP,
		Logger:     log.New("control/test"),
	}, pm
}

func TestHandlerRoutes(t *testing.T) {
	deps, _ := testDeps(t)
	resp := Handler(deps)("routes", deps.Logger)
	if resp.Status != "ok" {
		t.Fatalf("status = %q, error = %q", resp.Status, resp.Error)
	}
	out, ok := resp.Output.([]map[string]interface{})
	if !ok || len(out) != 1 {
		t.Fatalf("unexpected routes output: %#v", resp.Output)
	}
	if out[0]["network"] != "corp" || out[0]["prefix"] != "10.42.0.0/24" {
		t.Fatalf("unexpected route: %#v", out[0])
	}
}

func TestHandlerPeersAndStatus(t *testing.T) {
	deps, _ := testDeps(t)
	h := Handler(deps)

	resp := h("peers", deps.Logger)
	if resp.Status != "ok" {
		t.Fatalf("peers failed: %#v", resp)
	}
	out := resp.Output.([]map[string]interface{})
	if len(out) != 1 || out[0]["id"] != "peer-a" {
		t.Fatalf("unexpected peers output: %#v", resp.Output)
	}

	resp = h("status", deps.Logger)
	if resp.Status != "ok" {
		t.Fatalf("status failed: %#v", resp)
	}
	status := resp.Output.(map[string]interface{})
	if status["peers"] != 1 || status["routes"] != 1 {
		t.Fatalf("unexpected status: %#v", resp.Output)
	}
}

func TestHandlerReload(t *testing.T) {
	deps, pm := testDeps(t)
	resp := Handler(deps)("reload", deps.Logger)
	if resp.Status != "ok" {
		t.Fatalf("reload failed: %#v", resp)
	}

	// Self route should be present after reload (re-added).
	routes := deps.Routes.AllRoutes()
	foundSelf := false
	for _, r := range routes {
		if r.PeerID == testFP {
			foundSelf = true
		}
	}
	if !foundSelf {
		t.Fatalf("expected self route after reload, got %+v", routes)
	}

	// Announcement should have been sent to the live peer.
	if len(pm.sent) != 1 || pm.sent[0] != "peer-a/corp/10.42.0.0/24" {
		t.Fatalf("unexpected announcements: %v", pm.sent)
	}
}

func TestHandlerReloadInvalidConfig(t *testing.T) {
	deps, _ := testDeps(t)
	// Corrupt the config file.
	if err := os.WriteFile(deps.ConfigPath, []byte("not [valid toml"), 0600); err != nil {
		t.Fatalf("write corrupt config: %v", err)
	}
	resp := Handler(deps)("reload", deps.Logger)
	if resp.Status != "error" {
		t.Fatalf("expected reload to fail, got %#v", resp)
	}
}

func TestHandlerGoodbyeAndUnknown(t *testing.T) {
	deps, pm := testDeps(t)
	h := Handler(deps)

	resp := h("goodbye", deps.Logger)
	if resp.Status != "ok" || !pm.goodbye {
		t.Fatalf("goodbye failed: %#v", resp)
	}

	resp = h("bogus", deps.Logger)
	if resp.Status != "error" {
		t.Fatalf("expected error for unknown command")
	}
}

func TestUDSServerRoundTrip(t *testing.T) {
	deps, _ := testDeps(t)
	sockPath := filepath.Join(t.TempDir(), "vibepn.sock")
	server := NewServer(sockPath, Handler(deps))
	errCh := server.Start()
	if err := <-errCh; err != nil {
		t.Fatalf("server start: %v", err)
	}

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial socket: %v", err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(CommandRequest{Cmd: "status"}); err != nil {
		t.Fatalf("send request: %v", err)
	}

	var resp CommandResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.Status != "ok" {
		t.Fatalf("unexpected response: %#v", resp)
	}
	status, ok := resp.Output.(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected output type: %T", resp.Output)
	}
	if status["peers"].(float64) != 1 || status["routes"].(float64) != 1 {
		t.Fatalf("unexpected status output: %#v", resp.Output)
	}
}

func TestUptime(t *testing.T) {
	if u := Uptime(); !strings.Contains(u, "s") {
		t.Fatalf("expected uptime string, got %q", u)
	}
}
