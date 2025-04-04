package main

import (
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
)

func main() {
	logger := log.New("main")

	var configPath string
	flag.StringVar(&configPath, "config", "/etc/vibepn/config.toml", "Path to config file")
	flag.Parse()

	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Fatalf("Failed to load config: %v", err)
	}

	tlsConf, err := crypto.LoadTLS(
		cfg.Identity.Cert,
		cfg.Identity.Key,
		cfg.Identity.Fingerprint,
	)
	if err != nil {
		logger.Fatalf("Failed to load TLS identity: %v", err)
	}

	routeTable := netgraph.NewRouteTable()
	tracker := peer.NewLivenessTracker(30 * time.Second)
	tracker.StartWatcher(routeTable)

	registry := peer.NewRegistry(cfg.Identity, cfg.Networks)

	// Register control handlers
	control.Register(routeTable, tracker, func(peerID, network string, route control.Route) {
		conn := registry.Get(peerID)
		if conn != nil {
			control.SendRouteAnnounce(conn, network, []control.Route{route}, log.New("control/reload"))
		}
	})
	control.RegisterGoodbyeCallback(func() {
		registry.DisconnectAll()
	})

	ifaceMgr, err := iface.Init(cfg.Networks, cfg.Identity.Fingerprint)
	if err != nil {
		logger.Fatalf("Interface setup failed: %v", err)
	}

	dispatcher := forward.NewDispatcher(routeTable, ifaceMgr.Devices, registry)
	for netName, dev := range ifaceMgr.Devices {
		dispatcher.Start(netName, dev)
	}

	inbound := forward.NewInbound(ifaceMgr.Devices)

	go metrics.Serve(":9000")
	go control.StartUDS("/var/run/vibepn.sock")

	ln, err := quic.Listen(":51820", tlsConf)
	if err != nil {
		logger.Fatalf("Failed to start QUIC listener: %v", err)
	}

	go quic.AcceptLoop(*ln, tracker, routeTable, registry, inbound)

	peer.ConnectToPeers(cfg.Peers, cfg.Identity, routeTable, cfg.Networks, registry)

	// Graceful shutdown
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig

		logger.Infof("Shutting down...")
		registry.DisconnectAll()
		os.Exit(0)
	}()

	logger.Infof("VibePN started and running")
	select {}
}
