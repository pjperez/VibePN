package main

import (
	"context"
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
	"vibepn/tun"

	gquic "github.com/quic-go/quic-go" // alias to avoid confusion
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

	quic.SetOwnFingerprint(cfg.Identity.Fingerprint)

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
	control.Register(routeTable, tracker, func(peerID, network string, route netgraph.Route) {
		conn := registry.Get(peerID)
		if conn != nil {
			stream, err := conn.OpenStreamSync(context.Background())
			if err != nil {
				logger.Warnf("Failed to open stream to send route-announce: %v", err)
				return
			}
			defer stream.Close()

			err = control.SendRouteAnnounce(stream, network, []string{route.Prefix})
			if err != nil {
				logger.Warnf("Failed to send route-announce: %v", err)
			}
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
	for netName, d := range ifaceMgr.Devices {
		dispatcher.Start(netName, d)
	}

	// Grab one device (for now only supporting 1)
	var dev *tun.Device
	for _, d := range ifaceMgr.Devices {
		dev = d
		break
	}

	inbound := forward.NewInbound(*dev)
	outbound := forward.NewOutbound(*dev)

	go metrics.Serve(":9000")
	go control.StartUDS("/var/run/vibepn.sock")

	ln, err := quic.Listen(":51820", tlsConf)
	if err != nil {
		logger.Fatalf("Failed to start QUIC listener: %v", err)
	}

	go quic.AcceptLoop(*ln, tracker, routeTable, registry, inbound)

	// ⚡ Setup outbound sending on peer connect
	registry.SetOnConnect(func(peerID string, conn gquic.Connection) {
		go outbound.SendPackets(context.Background(), conn)
	})

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
