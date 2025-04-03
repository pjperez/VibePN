package crypto

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"vibepn/log"
)

var (
	tofuPath  = filepath.Join(os.Getenv("HOME"), ".vibepn", "known_peers.json")
	tofuMu    sync.Mutex
	tofuCache map[string]string // peerName → fingerprint
)

func LoadPeerTLSWithTOFU(peerName, address string) (*tls.Config, error) {
	logger := log.New("crypto/tofu")

	if err := loadTOFU(); err != nil {
		return nil, err
	}

	return &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no peer certificate presented")
			}

			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}

			sum := sha256.Sum256(cert.Raw)
			fingerprint := hex.EncodeToString(sum[:])

			tofuMu.Lock()
			defer tofuMu.Unlock()

			known, ok := tofuCache[peerName]
			if ok {
				if known != fingerprint {
					return fmt.Errorf("TOFU: fingerprint mismatch for peer %s\nexpected: %s\ngot:      %s",
						peerName, known, fingerprint)
				}
				logger.Infof("TOFU: verified fingerprint for %s (%s)", peerName, address)
			} else {
				logger.Infof("TOFU: trusting first fingerprint for %s (%s)", peerName, address)
				tofuCache[peerName] = fingerprint
				if err := saveTOFU(); err != nil {
					logger.Errorf("Failed to save TOFU database: %v", err)
				}
			}

			return nil
		},
	}, nil
}

func loadTOFU() error {
	tofuMu.Lock()
	defer tofuMu.Unlock()

	if tofuCache != nil {
		return nil
	}

	tofuCache = make(map[string]string)

	file, err := os.ReadFile(tofuPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // empty file, not an error
		}
		return err
	}

	return json.Unmarshal(file, &tofuCache)
}

func saveTOFU() error {
	tofuMu.Lock()
	defer tofuMu.Unlock()

	if err := os.MkdirAll(filepath.Dir(tofuPath), 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(tofuCache, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(tofuPath, data, 0600)
}
