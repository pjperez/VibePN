package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"vibepn/config"
	vpncrypto "vibepn/crypto"
)

// version is the vpnctl release version.
const version = "0.3.0"

const (
	defaultSocketPath = "/var/run/vibepn.sock"
	defaultConfigPath = "/etc/vibepn/config.toml"
	defaultCertPath   = "/etc/vibepn/certs/node.crt"
	defaultKeyPath    = "/etc/vibepn/certs/node.key"
)

// inviteScheme is the one-line invite token prefix, e.g.
// vibepn://corp@1.2.3.4:51820#<fingerprint>?name=node-a&prefix=10.42.0.0%2F24
const inviteScheme = "vibepn://"

type CommandRequest struct {
	Cmd string `json:"cmd"`
}

type CommandResponse struct {
	Status string      `json:"status"`
	Output interface{} `json:"output,omitempty"`
	Error  string      `json:"error,omitempty"`
}

type InvitePayload struct {
	Version int        `json:"version"`
	Network string     `json:"network"`
	Prefix  string     `json:"prefix"`
	Inviter InvitePeer `json:"inviter"`
}

type InvitePeer struct {
	Name        string `json:"name"`
	Address     string `json:"address"`
	Fingerprint string `json:"fingerprint"`
}

func main() {
	jsonMode := flag.Bool("json", false, "Output raw JSON for daemon commands")
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	cmd := flag.Arg(0)
	args := flag.Args()[1:]

	var err error
	switch cmd {
	case "status", "routes", "peers", "reload", "goodbye", "test", "logs":
		err = runDaemonCommand(cmd, *jsonMode, args)
	case "version":
		fmt.Printf("vpnctl %s\n", version)
	case "init":
		err = runInit(args)
	case "invite":
		err = runInvite(args)
	case "join":
		err = runJoin(args)
	case "add-peer":
		err = runAddPeer(args)
	case "rm-peer":
		err = runRmPeer(args)
	case "ls":
		err = runLs(args)
	case "doctor":
		err = runDoctor(args)
	default:
		flag.Usage()
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [--json] <command> [options]\n\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "Daemon control commands:")
	fmt.Fprintln(os.Stderr, "  status | routes | peers | test | reload | goodbye | logs")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Onboarding commands:")
	fmt.Fprintln(os.Stderr, "  init      Generate cert/key/fingerprint and write config TOML")
	fmt.Fprintln(os.Stderr, "  invite    Emit JSON invite payload (or one-line token) for an exported network")
	fmt.Fprintln(os.Stderr, "  join      Parse invite payload/token, generate cert/key, and write config")
	fmt.Fprintln(os.Stderr, "  add-peer  Append a peer entry to an existing config")
	fmt.Fprintln(os.Stderr, "  rm-peer   Remove a peer entry from an existing config")
	fmt.Fprintln(os.Stderr, "  ls        Show configured peers and networks in human form")
	fmt.Fprintln(os.Stderr, "  doctor    Validate config and identity/peer/network consistency")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Use '<command> -h' for command-specific flags.")
	flag.PrintDefaults()
}

func runDaemonCommand(cmd string, jsonMode bool, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	socket := fs.String("socket", defaultSocketPath, "Path to daemon control socket")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	req := CommandRequest{Cmd: cmd}

	conn, err := net.Dial("unix", *socket)
	if err != nil {
		return fmt.Errorf("failed to connect to socket %s: %w", *socket, err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}

	var resp CommandResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.Status != "ok" {
		return errors.New(resp.Error)
	}

	if jsonMode {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(resp.Output)
	}

	printOutput(cmd, resp.Output)
	return nil
}

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", defaultConfigPath, "Path to config file to write")
	certPath := fs.String("cert", defaultCertPath, "Path to node certificate to write")
	keyPath := fs.String("key", defaultKeyPath, "Path to node private key to write")
	name := fs.String("name", defaultNodeName(), "Node name / certificate common name")
	networkName := fs.String("network", "corp", "Network name to initialize")
	prefix := fs.String("prefix", "10.42.0.0/24", "CIDR prefix for initialized network")
	address := fs.String("address", "auto", "Local address for initialized network (or 'auto')")
	exportNet := fs.Bool("export", true, "Whether to export initialized network")
	force := fs.Bool("force", false, "Overwrite existing config/cert/key files")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s init [options]\n", os.Args[0])
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if *networkName == "" {
		return errors.New("--network is required")
	}
	if *prefix == "" {
		return errors.New("--prefix is required")
	}
	if _, _, err := net.ParseCIDR(*prefix); err != nil {
		return fmt.Errorf("invalid --prefix %q: %w", *prefix, err)
	}
	if !*force {
		for _, p := range []string{*configPath, *certPath, *keyPath} {
			if pathExists(p) {
				return fmt.Errorf("%q already exists (use --force to overwrite)", p)
			}
		}
	}

	fp, err := generateIdentity(*certPath, *keyPath, *name)
	if err != nil {
		return err
	}

	cfg := &config.Config{
		Identity: config.Identity{
			Cert:        *certPath,
			Key:         *keyPath,
			Fingerprint: fp,
		},
		Peers: make([]config.Peer, 0),
		Networks: map[string]config.NetworkConfig{
			*networkName: {
				Address: *address,
				Prefix:  *prefix,
				Export:  *exportNet,
			},
		},
	}

	if err := config.Write(*configPath, cfg); err != nil {
		return err
	}

	fmt.Printf("Initialized %s\nFingerprint: %s\n", *configPath, fp)
	return nil
}

func runInvite(args []string) error {
	fs := flag.NewFlagSet("invite", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", defaultConfigPath, "Path to existing config file")
	networkName := fs.String("network", "", "Exported network name to include in invite")
	address := fs.String("address", "", "Inviter reachable address (host:port)")
	name := fs.String("name", defaultNodeName(), "Inviter name in invite payload")
	outPath := fs.String("out", "-", "Output file for invite payload ('-' for stdout)")
	token := fs.Bool("token", false, "Emit a one-line vibepn:// token instead of JSON")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s invite [options]\n", os.Args[0])
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if *networkName == "" {
		return errors.New("--network is required")
	}
	if *address == "" {
		return errors.New("--address is required")
	}
	if err := validateHostPort(*address); err != nil {
		return fmt.Errorf("invalid --address: %w", err)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load config %q: %w", *configPath, err)
	}
	if strings.TrimSpace(cfg.Identity.Fingerprint) == "" {
		return errors.New("config identity fingerprint is empty")
	}

	netCfg, ok := cfg.Networks[*networkName]
	if !ok {
		return fmt.Errorf("network %q not found in config", *networkName)
	}
	if !netCfg.Export {
		return fmt.Errorf("network %q is not exported", *networkName)
	}
	if netCfg.Prefix == "" {
		return fmt.Errorf("network %q has empty prefix", *networkName)
	}

	payload := InvitePayload{
		Version: 1,
		Network: *networkName,
		Prefix:  netCfg.Prefix,
		Inviter: InvitePeer{
			Name:        *name,
			Address:     *address,
			Fingerprint: cfg.Identity.Fingerprint,
		},
	}

	if *token {
		tok := fmt.Sprintf("%s%s@%s#%s?name=%s&prefix=%s",
			inviteScheme, payload.Network, payload.Inviter.Address,
			payload.Inviter.Fingerprint, payload.Inviter.Name,
			urlEncode(payload.Prefix))
		if *outPath == "-" {
			fmt.Println(tok)
			return nil
		}
		if err := writeStrictFile(*outPath, []byte(tok+"\n"), 0600); err != nil {
			return err
		}
		fmt.Printf("Wrote invite token to %s\n", *outPath)
		return nil
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("encode invite payload: %w", err)
	}
	data = append(data, '\n')

	if *outPath == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}

	if err := writeStrictFile(*outPath, data, 0600); err != nil {
		return err
	}
	fmt.Printf("Wrote invite payload to %s\n", *outPath)
	return nil
}

func runJoin(args []string) error {
	fs := flag.NewFlagSet("join", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", defaultConfigPath, "Path to config file to write")
	certPath := fs.String("cert", defaultCertPath, "Path to node certificate to write")
	keyPath := fs.String("key", defaultKeyPath, "Path to node private key to write")
	name := fs.String("name", defaultNodeName(), "Node name / certificate common name")
	inviteJSON := fs.String("invite", "", "Invite payload JSON string or vibepn:// token")
	inviteFile := fs.String("invite-file", "", "Path to file containing invite payload JSON or token")
	address := fs.String("address", "auto", "Local address for invited network (or 'auto')")
	exportNet := fs.Bool("export", true, "Whether to export invited network")
	force := fs.Bool("force", false, "Overwrite existing config/cert/key files")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s join [options]\n", os.Args[0])
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	payload, err := loadInvitePayload(*inviteJSON, *inviteFile)
	if err != nil {
		return err
	}
	if !*force {
		for _, p := range []string{*configPath, *certPath, *keyPath} {
			if pathExists(p) {
				return fmt.Errorf("%q already exists (use --force to overwrite)", p)
			}
		}
	}

	fp, err := generateIdentity(*certPath, *keyPath, *name)
	if err != nil {
		return err
	}

	cfg := &config.Config{
		Identity: config.Identity{
			Cert:        *certPath,
			Key:         *keyPath,
			Fingerprint: fp,
		},
		Peers: []config.Peer{
			{
				Name:        payload.Inviter.Name,
				Address:     payload.Inviter.Address,
				Fingerprint: payload.Inviter.Fingerprint,
				Networks:    []string{payload.Network},
			},
		},
		Networks: map[string]config.NetworkConfig{
			payload.Network: {
				Address: *address,
				Prefix:  payload.Prefix,
				Export:  *exportNet,
			},
		},
	}

	if err := config.Write(*configPath, cfg); err != nil {
		return err
	}

	fmt.Printf("Joined %s using %s\nFingerprint: %s\n", payload.Network, *configPath, fp)
	return nil
}

func runAddPeer(args []string) error {
	fs := flag.NewFlagSet("add-peer", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", defaultConfigPath, "Path to existing config file")
	name := fs.String("name", "", "Peer name")
	address := fs.String("address", "", "Peer address (host:port)")
	fingerprint := fs.String("fingerprint", "", "Peer certificate fingerprint")
	networks := fs.String("networks", "", "Comma-separated networks for this peer")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s add-peer [options]\n", os.Args[0])
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if *name == "" {
		return errors.New("--name is required")
	}
	if *address == "" {
		return errors.New("--address is required")
	}
	if err := validateHostPort(*address); err != nil {
		return fmt.Errorf("invalid --address: %w", err)
	}
	if strings.TrimSpace(*fingerprint) != "" && !isValidFingerprint(*fingerprint) {
		return fmt.Errorf("invalid --fingerprint %q: must be 64 hex chars", *fingerprint)
	}

	peerNetworks := splitCSV(*networks)
	if len(peerNetworks) == 0 {
		return errors.New("--networks is required")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load config %q: %w", *configPath, err)
	}
	for _, networkName := range peerNetworks {
		if _, ok := cfg.Networks[networkName]; !ok {
			return fmt.Errorf("unknown network %q (must exist in config)", networkName)
		}
	}
	for _, peer := range cfg.Peers {
		if peer.Name == *name {
			return fmt.Errorf("peer %q already exists", *name)
		}
	}

	cfg.Peers = append(cfg.Peers, config.Peer{
		Name:        *name,
		Address:     *address,
		Fingerprint: *fingerprint,
		Networks:    peerNetworks,
	})

	if err := config.Write(*configPath, cfg); err != nil {
		return err
	}

	fmt.Printf("Added peer %s to %s\n", *name, *configPath)
	return nil
}

func runRmPeer(args []string) error {
	fs := flag.NewFlagSet("rm-peer", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", defaultConfigPath, "Path to existing config file")
	name := fs.String("name", "", "Peer name to remove")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s rm-peer [options]\n", os.Args[0])
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if *name == "" {
		return errors.New("--name is required")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load config %q: %w", *configPath, err)
	}

	found := false
	updated := cfg.Peers[:0]
	for _, peer := range cfg.Peers {
		if peer.Name == *name {
			found = true
			continue
		}
		updated = append(updated, peer)
	}
	if !found {
		return fmt.Errorf("peer %q not found in config", *name)
	}
	cfg.Peers = updated

	if err := config.Write(*configPath, cfg); err != nil {
		return err
	}

	fmt.Printf("Removed peer %s from %s\n", *name, *configPath)
	return nil
}

func runLs(args []string) error {
	fs := flag.NewFlagSet("ls", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", defaultConfigPath, "Path to existing config file")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s ls [options]\n", os.Args[0])
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load config %q: %w", *configPath, err)
	}

	fmt.Printf("Node: %s\n", cfg.Identity.Fingerprint[:12])
	fmt.Printf("Networks:\n")
	for name, netCfg := range cfg.Networks {
		export := "no"
		if netCfg.Export {
			export = "yes"
		}
		fmt.Printf("  %-12s prefix=%-18s address=%-15s export=%s\n",
			name, netCfg.Prefix, netCfg.Address, export)
	}
	fmt.Printf("Peers:\n")
	if len(cfg.Peers) == 0 {
		fmt.Printf("  (none)\n")
	}
	for _, peer := range cfg.Peers {
		fp := peer.Fingerprint
		if fp == "" {
			fp = "(tofu)"
		} else if len(fp) > 12 {
			fp = fp[:12] + "..."
		}
		fmt.Printf("  %-12s address=%-22s fp=%-16s networks=%s\n",
			peer.Name, peer.Address, fp, strings.Join(peer.Networks, ","))
	}
	return nil
}

func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", defaultConfigPath, "Path to config file")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s doctor [options]\n", os.Args[0])
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	passCount, warnCount, failCount := 0, 0, 0
	report := func(level, check, message string) {
		fmt.Printf("%s %s: %s\n", level, check, message)
		switch level {
		case "PASS":
			passCount++
		case "WARN":
			warnCount++
		case "FAIL":
			failCount++
		}
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		report("FAIL", "1) config parse/load", fmt.Sprintf("load config %q: %v", *configPath, err))
		fmt.Printf("Summary: PASS=%d WARN=%d FAIL=%d\n", passCount, warnCount, failCount)
		return fmt.Errorf("doctor detected %d failing checks", failCount)
	}
	report("PASS", "1) config parse/load", fmt.Sprintf("loaded %q", *configPath))

	missingIdentity := make([]string, 0, 3)
	if strings.TrimSpace(cfg.Identity.Cert) == "" {
		missingIdentity = append(missingIdentity, "cert")
	}
	if strings.TrimSpace(cfg.Identity.Key) == "" {
		missingIdentity = append(missingIdentity, "key")
	}
	if strings.TrimSpace(cfg.Identity.Fingerprint) == "" {
		missingIdentity = append(missingIdentity, "fingerprint")
	}
	if len(missingIdentity) > 0 {
		report("FAIL", "2) identity fields non-empty", "missing "+strings.Join(missingIdentity, ", "))
	} else {
		report("PASS", "2) identity fields non-empty", "cert/key/fingerprint are set")
	}

	if _, err := vpncrypto.LoadTLS(cfg.Identity.Cert, cfg.Identity.Key, cfg.Identity.Fingerprint); err != nil {
		report("FAIL", "3) cert+key load with expected fingerprint", err.Error())
	} else {
		report("PASS", "3) cert+key load with expected fingerprint", "certificate, key, and fingerprint match")
	}

	if len(cfg.Networks) == 0 {
		report("WARN", "4) network CIDR prefixes", "no networks configured")
	} else {
		invalidPrefixes := make([]string, 0)
		for name, netCfg := range cfg.Networks {
			prefix := strings.TrimSpace(netCfg.Prefix)
			if prefix == "" {
				invalidPrefixes = append(invalidPrefixes, fmt.Sprintf("%s=<empty>", name))
				continue
			}
			if _, _, err := net.ParseCIDR(prefix); err != nil {
				invalidPrefixes = append(invalidPrefixes, fmt.Sprintf("%s=%q (%v)", name, netCfg.Prefix, err))
			}
		}
		if len(invalidPrefixes) > 0 {
			report("FAIL", "4) network CIDR prefixes", strings.Join(invalidPrefixes, "; "))
		} else {
			report("PASS", "4) network CIDR prefixes", "all network prefixes are valid CIDRs")
		}
	}

	if len(cfg.Networks) == 0 {
		report("WARN", "5) network address format", "no networks configured")
	} else {
		invalidAddresses := make([]string, 0)
		for name, netCfg := range cfg.Networks {
			address := strings.TrimSpace(netCfg.Address)
			if address == "auto" {
				continue
			}
			if address == "" {
				invalidAddresses = append(invalidAddresses, fmt.Sprintf("%s=<empty>", name))
				continue
			}
			if net.ParseIP(address) == nil {
				invalidAddresses = append(invalidAddresses, fmt.Sprintf("%s=%q", name, netCfg.Address))
			}
		}
		if len(invalidAddresses) > 0 {
			report("FAIL", "5) network address format", strings.Join(invalidAddresses, "; "))
		} else {
			report("PASS", "5) network address format", "all network addresses are 'auto' or valid IPs")
		}
	}

	if len(cfg.Peers) == 0 {
		report("WARN", "6) peer name/address non-empty", "no peers configured")
	} else {
		invalidPeers := make([]string, 0)
		for i, peer := range cfg.Peers {
			missing := make([]string, 0, 2)
			if strings.TrimSpace(peer.Name) == "" {
				missing = append(missing, "name")
			}
			if strings.TrimSpace(peer.Address) == "" {
				missing = append(missing, "address")
			}
			if len(missing) > 0 {
				invalidPeers = append(invalidPeers, fmt.Sprintf("peer[%d] missing %s", i, strings.Join(missing, "+")))
			}
		}
		if len(invalidPeers) > 0 {
			report("FAIL", "6) peer name/address non-empty", strings.Join(invalidPeers, "; "))
		} else {
			report("PASS", "6) peer name/address non-empty", "all peers have name and address")
		}
	}

	invalidPeerAddresses := make([]string, 0)
	for i, peer := range cfg.Peers {
		address := strings.TrimSpace(peer.Address)
		host, port, err := net.SplitHostPort(address)
		if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
			invalidPeerAddresses = append(invalidPeerAddresses, fmt.Sprintf("peer[%d]=%q", i, peer.Address))
			continue
		}
		portNum, err := strconv.Atoi(port)
		if err != nil || portNum < 1 || portNum > 65535 {
			invalidPeerAddresses = append(invalidPeerAddresses, fmt.Sprintf("peer[%d]=%q", i, peer.Address))
		}
	}
	if len(invalidPeerAddresses) > 0 {
		report("FAIL", "7) peer address host:port parse", strings.Join(invalidPeerAddresses, "; "))
	} else {
		report("PASS", "7) peer address host:port parse", "all peer addresses parse as host:port")
	}

	invalidFingerprints := make([]string, 0)
	missingFingerprintCount := 0
	for i, peer := range cfg.Peers {
		fp := strings.TrimSpace(peer.Fingerprint)
		if fp == "" {
			missingFingerprintCount++
			continue
		}
		if len(fp) != 64 {
			invalidFingerprints = append(invalidFingerprints, fmt.Sprintf("peer[%d]=%q", i, peer.Fingerprint))
			continue
		}
		if _, err := hex.DecodeString(fp); err != nil {
			invalidFingerprints = append(invalidFingerprints, fmt.Sprintf("peer[%d]=%q", i, peer.Fingerprint))
		}
	}
	if len(invalidFingerprints) > 0 {
		report("FAIL", "8) peer fingerprint format", strings.Join(invalidFingerprints, "; "))
	} else if missingFingerprintCount > 0 {
		report("WARN", "8) peer fingerprint format", fmt.Sprintf("%d peer(s) have empty fingerprint (TOFU)", missingFingerprintCount))
	} else {
		report("PASS", "8) peer fingerprint format", "all peer fingerprints are 64 hex chars")
	}

	missingNetworkRefs := make([]string, 0)
	for i, peer := range cfg.Peers {
		for _, networkName := range peer.Networks {
			name := strings.TrimSpace(networkName)
			if name == "" {
				missingNetworkRefs = append(missingNetworkRefs, fmt.Sprintf("peer[%d] references empty network name", i))
				continue
			}
			if _, ok := cfg.Networks[name]; !ok {
				missingNetworkRefs = append(missingNetworkRefs, fmt.Sprintf("peer[%d] references unknown network %q", i, name))
			}
		}
	}
	if len(missingNetworkRefs) > 0 {
		report("FAIL", "9) peer network references", strings.Join(missingNetworkRefs, "; "))
	} else {
		report("PASS", "9) peer network references", "all peer network references exist")
	}

	fmt.Printf("Summary: PASS=%d WARN=%d FAIL=%d\n", passCount, warnCount, failCount)
	if failCount > 0 {
		return fmt.Errorf("doctor detected %d failing checks", failCount)
	}
	return nil
}

func loadInvitePayload(inviteJSON, inviteFile string) (InvitePayload, error) {
	if inviteJSON != "" && inviteFile != "" {
		return InvitePayload{}, errors.New("provide only one of --invite or --invite-file")
	}
	if inviteJSON == "" && inviteFile == "" {
		return InvitePayload{}, errors.New("one of --invite or --invite-file is required")
	}

	var raw []byte
	var err error
	if inviteFile != "" {
		raw, err = os.ReadFile(inviteFile)
		if err != nil {
			return InvitePayload{}, fmt.Errorf("read invite file %q: %w", inviteFile, err)
		}
	} else {
		raw = []byte(inviteJSON)
	}

	raw = []byte(strings.TrimSpace(string(raw)))

	// One-line token: vibepn://network@host:port#fingerprint?name=...&prefix=...
	if strings.HasPrefix(string(raw), inviteScheme) {
		return parseInviteToken(string(raw))
	}

	var payload InvitePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return InvitePayload{}, fmt.Errorf("parse invite payload: %w", err)
	}
	if payload.Network == "" {
		return InvitePayload{}, errors.New("invite payload missing network")
	}
	if payload.Prefix == "" {
		return InvitePayload{}, errors.New("invite payload missing prefix")
	}
	if _, _, err := net.ParseCIDR(payload.Prefix); err != nil {
		return InvitePayload{}, fmt.Errorf("invite payload has invalid prefix %q: %w", payload.Prefix, err)
	}
	if payload.Inviter.Name == "" {
		return InvitePayload{}, errors.New("invite payload missing inviter.name")
	}
	if payload.Inviter.Address == "" {
		return InvitePayload{}, errors.New("invite payload missing inviter.address")
	}
	if err := validateHostPort(payload.Inviter.Address); err != nil {
		return InvitePayload{}, fmt.Errorf("invite payload has invalid inviter.address: %w", err)
	}
	if payload.Inviter.Fingerprint == "" {
		return InvitePayload{}, errors.New("invite payload missing inviter.fingerprint")
	}
	if !isValidFingerprint(payload.Inviter.Fingerprint) {
		return InvitePayload{}, errors.New("invite payload has invalid inviter.fingerprint (must be 64 hex chars)")
	}
	return payload, nil
}

// parseInviteToken parses a one-line vibepn:// token into an InvitePayload.
// Format: vibepn://network@host:port#fingerprint?name=inviter&prefix=10.42.0.0%2F24
func parseInviteToken(token string) (InvitePayload, error) {
	rest := strings.TrimPrefix(token, inviteScheme)

	// Split off query (name=..., prefix=...).
	name := ""
	prefix := ""
	if idx := strings.IndexByte(rest, '?'); idx >= 0 {
		query := rest[idx+1:]
		rest = rest[:idx]
		for _, kv := range strings.Split(query, "&") {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) != 2 {
				continue
			}
			switch parts[0] {
			case "name":
				name = parts[1]
			case "prefix":
				prefix = urlDecode(parts[1])
			}
		}
	}

	// Split network@address#fingerprint.
	atIdx := strings.IndexByte(rest, '@')
	hashIdx := strings.IndexByte(rest, '#')
	if atIdx <= 0 || hashIdx <= atIdx+1 {
		return InvitePayload{}, errors.New("invalid invite token: expected vibepn://network@host:port#fingerprint[?name=...&prefix=...]")
	}

	network := rest[:atIdx]
	address := rest[atIdx+1 : hashIdx]
	fingerprint := rest[hashIdx+1:]

	if network == "" {
		return InvitePayload{}, errors.New("invite token missing network")
	}
	if err := validateHostPort(address); err != nil {
		return InvitePayload{}, fmt.Errorf("invite token has invalid address %q: %w", address, err)
	}
	if !isValidFingerprint(fingerprint) {
		return InvitePayload{}, errors.New("invite token has invalid fingerprint (must be 64 hex chars)")
	}
	if name == "" {
		return InvitePayload{}, errors.New("invite token missing ?name= (inviter name)")
	}
	if prefix == "" {
		return InvitePayload{}, errors.New("invite token missing ?prefix= (network prefix)")
	}
	if _, _, err := net.ParseCIDR(prefix); err != nil {
		return InvitePayload{}, fmt.Errorf("invite token has invalid prefix %q: %w", prefix, err)
	}

	return InvitePayload{
		Version: 1,
		Network: network,
		Prefix:  prefix,
		Inviter: InvitePeer{
			Name:        name,
			Address:     address,
			Fingerprint: fingerprint,
		},
	}, nil
}

// urlEncode percent-encodes a CIDR so the "/" in "10.42.0.0/24" survives
// shell copy/paste of the token.
func urlEncode(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '-' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

func urlDecode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func generateIdentity(certPath, keyPath, commonName string) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate private key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", fmt.Errorf("generate serial number: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return "", fmt.Errorf("create self-signed certificate: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("marshal private key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := writeStrictFile(certPath, certPEM, 0600); err != nil {
		return "", err
	}
	if err := writeStrictFile(keyPath, keyPEM, 0600); err != nil {
		return "", err
	}

	return vpncrypto.Fingerprint(certDER), nil
}

func writeStrictFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create directory for %q: %w", path, err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("write %q: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("set permissions on %q: %w", path, err)
	}
	return nil
}

func splitCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func defaultNodeName() string {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		return "node"
	}
	return hostname
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func validateHostPort(address string) error {
	host, port, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return err
	}
	if strings.TrimSpace(host) == "" {
		return errors.New("empty host")
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return errors.New("port must be 1-65535")
	}
	return nil
}

func isValidFingerprint(fingerprint string) bool {
	fp := strings.TrimSpace(fingerprint)
	if len(fp) != 64 {
		return false
	}
	_, err := hex.DecodeString(fp)
	return err == nil
}

func printOutput(cmd string, output interface{}) {
	switch cmd {
	case "status":
		m, _ := output.(map[string]interface{})
		fmt.Printf("Uptime: %v\n", m["uptime"])
		fmt.Printf("Peers:  %v\n", m["peers"])
		fmt.Printf("Routes: %v\n", m["routes"])
	case "peers":
		peers, _ := output.([]interface{})
		for _, item := range peers {
			p := item.(map[string]interface{})
			fmt.Printf("Peer: %s (last seen: %s)\n", p["id"], p["last_seen"])
		}
	case "routes":
		routes, _ := output.([]interface{})
		for _, item := range routes {
			r := item.(map[string]interface{})
			fmt.Printf("Net: %-10s Prefix: %-18s Peer: %-16s Metric: %v Expires: %s\n",
				r["network"], r["prefix"], r["peer"], r["metric"], r["expires"])
		}
	case "test":
		results, _ := output.(map[string]interface{})["results"].([]interface{})
		for _, item := range results {
			r := item.(map[string]interface{})
			if ok, _ := r["ok"].(bool); ok {
				fmt.Printf("Peer %s: OK (%.2f ms)\n", r["peer"], r["latency_ms"])
			} else {
				fmt.Printf("Peer %s: FAIL (%v)\n", r["peer"], r["error"])
			}
		}
	case "logs":
		m, _ := output.(map[string]interface{})
		logs, _ := m["logs"].([]interface{})
		for _, line := range logs {
			fmt.Println(line)
		}
	default:
		fmt.Println("OK")
	}
}
