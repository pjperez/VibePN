package crypto

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"vibepn/log"
)

var (
	tofuPath  = filepath.Join(os.Getenv("HOME"), ".vibepn", "known_peers.json")
	tofuStore = make(map[string]string) // peerName → fingerprint
	tofuMu    sync.Mutex
)

func init() {
	loadTOFU()
}

func loadTOFU() {
	tofuMu.Lock()
	defer tofuMu.Unlock()

	data, err := os.ReadFile(tofuPath)
	if err != nil {
		if os.IsNotExist(err) {
			return // no file yet
		}
		log.New("crypto/tofu").Warnf("Failed to load TOFU store: %v", err)
		return
	}
	err = json.Unmarshal(data, &tofuStore)
	if err != nil {
		log.New("crypto/tofu").Warnf("Failed to parse TOFU store: %v", err)
	}
}

func saveTOFU() {
	dir := filepath.Dir(tofuPath)
	_ = os.MkdirAll(dir, 0700)

	data, err := json.MarshalIndent(tofuStore, "", "  ")
	if err != nil {
		log.New("crypto/tofu").Errorf("Failed to encode TOFU store: %v", err)
		return
	}

	err = os.WriteFile(tofuPath, data, 0600)
	if err != nil {
		log.New("crypto/tofu").Errorf("Failed to save TOFU store: %v", err)
	}
}

func LoadPeerTLSWithTOFU(peerName string, address string) (*tls.Config, error) {
	return &tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: verifyTOFU(peerName, address),
	}, nil
}

func verifyTOFU(peerName, address string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no peer certificate presented")
		}

		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("failed to parse peer certificate: %v", err)
		}

		fp := sha256.Sum256(cert.Raw)
		peerFP := hex.EncodeToString(fp[:])
		logger := log.New("crypto/tofu")

		tofuMu.Lock()
		defer tofuMu.Unlock()

		pinned, ok := tofuStore[peerName]
		if !ok {
			// First-time trust
			logger.Infof("TOFU: trusting first fingerprint for %s (%s)", peerName, address)
			tofuStore[peerName] = peerFP
			saveTOFU()
			return nil
		}

		if pinned != peerFP {
			return fmt.Errorf("TOFU: fingerprint mismatch for %s: got %s, expected %s", peerName, peerFP, pinned)
		}

		logger.Infof("TOFU: fingerprint matched for %s", peerName)
		return nil
	}
}
