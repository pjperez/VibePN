package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"vibepn/log"
)

// TOFUStore implements trust-on-first-use pinning of peer certificate
// fingerprints, keyed by peer name.
type TOFUStore struct {
	mu    sync.Mutex
	path  string
	peers map[string]string // peerName → fingerprint
	log   *log.Logger
}

// NewTOFUStore loads (or lazily initializes) a store at path.
func NewTOFUStore(path string) (*TOFUStore, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve home directory: %w", err)
		}
		path = filepath.Join(home, ".vibepn", "known_peers.json")
	}

	s := &TOFUStore{
		path:  path,
		peers: make(map[string]string),
		log:   log.New("crypto/tofu"),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *TOFUStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read TOFU store %s: %w", s.path, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := json.Unmarshal(data, &s.peers); err != nil {
		return fmt.Errorf("parse TOFU store %s: %w", s.path, err)
	}
	return nil
}

// saveLocked persists the store. The caller must hold s.mu.
func (s *TOFUStore) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(s.peers, "", "  ")
	if err != nil {
		return err
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		if rmErr := os.Remove(s.path); rmErr != nil && !os.IsNotExist(rmErr) {
			return rmErr
		}
		return os.Rename(tmp, s.path)
	}
	return nil
}

// Pinned returns the pinned fingerprint for a peer name, if any.
func (s *TOFUStore) Pinned(name string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fp, ok := s.peers[name]
	return fp, ok
}

// NameForFingerprint reverse-looks-up the peer name pinned to a fingerprint.
func (s *TOFUStore) NameForFingerprint(fp string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, pinned := range s.peers {
		if pinned == fp {
			return name, true
		}
	}
	return "", false
}

// verifyPeer validates a presented certificate against the store, pinning it
// on first sight. It rejects expired/not-yet-valid certificates.
func (s *TOFUStore) verifyPeer(peerName string, rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no peer certificate presented")
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("parse peer certificate: %w", err)
	}

	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("peer certificate not valid before %s", cert.NotBefore.Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("peer certificate expired at %s", cert.NotAfter.Format(time.RFC3339))
	}

	peerFP := Fingerprint(cert.Raw)

	s.mu.Lock()
	defer s.mu.Unlock()

	pinned, ok := s.peers[peerName]
	if !ok {
		s.log.Infof("TOFU: trusting first fingerprint for %s", peerName)
		s.peers[peerName] = peerFP
		if err := s.saveLocked(); err != nil {
			s.log.Warnf("TOFU: failed to persist store: %v", err)
		}
		return nil
	}

	if pinned != peerFP {
		return fmt.Errorf("TOFU: fingerprint mismatch for %s: got %s, expected %s", peerName, peerFP, pinned)
	}
	return nil
}

// ClientTLS builds a client TLS config that presents the local identity and
// verifies the peer via TOFU.
func (s *TOFUStore) ClientTLS(certPath, keyPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load cert/key: %w", err)
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, //nolint:gosec // identity is verified via TOFU below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return s.verifyPeer("", rawCerts)
		},
		NextProtos: []string{ALPNProtocol},
	}, nil
}

// ServerTLS wraps a base server TLS config so that peer certificates are
// verified against the TOFU store. The base config must already have
// ClientAuth set to RequireAnyClientCert.
func (s *TOFUStore) ServerTLS(base *tls.Config) *tls.Config {
	conf := base.Clone()
	conf.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		return s.verifyPeer("", rawCerts)
	}
	return conf
}
