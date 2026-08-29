package main

import (
	"crypto/tls"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"vibepn/config"
	"vibepn/control"
	"vibepn/crypto"
	"vibepn/forward"
	"vibepn/iface"
	"vibepn/log"
	"vibepn/metrics"
	"vibepn/netgraph"
	"vibepn/peer"
	"vibepn/quic"

	gquic "github.com/quic-go/quic-go"
)

func main() {
	logger := log.New("main")

	var (
		configPath  string
		socketPath  string
		listenAddr  string
		metricsAddr string
		tofuPath    string
	)
	flag.StringVar(&configPath, "config", "/etc/vibepn/config.toml", "Path to config file")
	flag.StringVar(&socketPath, "socket", "/var/run/vibepn.sock", "Path to control socket")
	flag.StringVar(&listenAddr, "listen", ":51820", "QUIC listen address")
	flag.StringVar(&metricsAddr, "metrics", ":9000", "Prometheus metrics listen address")
	flag.StringVar(&tofuPath, "tofu", "", "Path to TOFU trust store (default ~/.vibepn/known_peers.json)")
	flag.Parse()

	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Fatalf("Failed to load config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		logger.Fatalf("Config validation failed: %v", err)
	}

	// TLS identity (server side).
	tlsConf, err := crypto.LoadTLS(
		cfg.Identity.Cert,
		cfg.Identity.Key,
		cfg.Identity.Fingerprint,
	)
	if err != nil {
		logger.Fatalf("Failed to load TLS identity: %v", err)
	}
	tlsConf.ClientAuth = tls.RequireAnyClientCert

	// TOFU trust store (verifies peers on both client and server sides).
	tofu, err := crypto.NewTOFUStore(tofuPath)
	if err != nil {
		logger.Fatalf("Failed to load TOFU store: %v", err)
	}
	tlsConf = tofu.ServerTLS(tlsConf)

	// Core subsystems.
	routeTable := netgraph.NewRouteTable()
	tracker := peer.NewLivenessTracker(30 * time.Second)
	tracker.StartWatcher(routeTable)

	registry := peer.NewRegistry(cfg.Identity)
	registry.SetOnDisconnect(func(peerID string) {
		routeTable.RemoveByPeer(peerID)
		metrics.ActivePeers.Set(float64(len(registry.All())))
	})
	registry.SetOnConnect(func(_ string, _ gquic.Connection) {
		metrics.ActivePeers.Set(float64(len(registry.All())))
	})

	// Register local routes (self) so the dispatcher can route to local
	// networks and reload can re-announce them.
	for name, netCfg := range cfg.Networks {
		if !netCfg.Export {
			continue
		}
		routeTable.AddRoute(netgraph.Route{
			Network: name,
			Prefix:  netCfg.Prefix,
			PeerID:  cfg.Identity.Fingerprint,
			Metric:  1,
		})
	}

	// Route policy: peers may only announce networks they are configured for.
	policy := peer.NewConfigRoutePolicy(
		func() map[string]config.NetworkConfig { return cfg.Networks },
		func() map[string][]string {
			out := make(map[string][]string, len(cfg.Peers))
			for _, p := range cfg.Peers {
				out[p.Name] = p.Networks
			}
			return out
		},
	)

	peer.RegisterControl(routeTable, tracker, policy)

	// Connection manager (outbound dialing with reconnect + backoff).
	connMgr := peer.NewConnectionManager(
		registry,
		tofu,
		cfg.Identity,
		func() map[string]config.NetworkConfig { return cfg.Networks },
	)
	connMgr.Start(cfg.Peers)

	// Interfaces.
	ifaceMgr, err := iface.Init(cfg.Networks, cfg.Identity.Fingerprint)
	if err != nil {
		logger.Fatalf("Interface setup failed: %v", err)
	}

	// Data plane.
	dispatcher := forward.NewDispatcher(routeTable, ifaceMgr.Devices, registry)
	for netName, d := range ifaceMgr.Devices {
		dispatcher.Start(netName, d)
	}
	inbound := forward.NewInbound(ifaceMgr.Devices)

	// Auxiliary servers.
	go metrics.Serve(metricsAddr)
	quic.SetNetConfig(cfg.Networks)

	uds := control.NewServer(socketPath, control.Handler(control.ServerDeps{
		ConfigPath: configPath,
		Routes:     routeTable,
		Peers:      registry,
		IdentityFP: cfg.Identity.Fingerprint,
		Logger:     logger,
	}))
	if err := <-uds.Start(); err != nil {
		logger.Fatalf("Failed to start control socket: %v", err)
	}

	// QUIC listener.
	ln, err := quic.Listen(listenAddr, tlsConf)
	if err != nil {
		logger.Fatalf("Failed to start QUIC listener: %v", err)
	}
	go quic.AcceptLoop(*ln, registry, inbound, tofu)

	// Graceful shutdown.
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig

		logger.Infof("Shutting down...")
		registry.DisconnectAll()
		connMgr.Stop()
		os.Exit(0)
	}()

	logger.Infof("VibePN started (listen=%s, socket=%s)", listenAddr, socketPath)
	select {}
}
