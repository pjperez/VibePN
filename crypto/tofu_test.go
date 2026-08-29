package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testIdentity writes a fresh self-signed cert/key pair and returns their
// paths, the certificate fingerprint, and the raw DER certificate.
func testIdentity(t *testing.T, commonName string) (certPath, keyPath, fingerprint string, certDER []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err = x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	dir := t.TempDir()
	certPath = filepath.Join(dir, "node.crt")
	keyPath = filepath.Join(dir, "node.key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	return certPath, keyPath, Fingerprint(certDER), certDER
}

func TestLoadTLSFingerprintMismatch(t *testing.T) {
	certPath, keyPath, fp, _ := testIdentity(t, "node-a")

	conf, err := LoadTLS(certPath, keyPath, fp)
	if err != nil {
		t.Fatalf("LoadTLS with matching fingerprint failed: %v", err)
	}
	if len(conf.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(conf.Certificates))
	}

	if _, err := LoadTLS(certPath, keyPath, "deadbeef"); err == nil {
		t.Fatalf("expected fingerprint mismatch error")
	}

	if _, err := LoadTLS(filepath.Join(t.TempDir(), "missing.crt"), keyPath, fp); err == nil {
		t.Fatalf("expected load error for missing cert")
	}
}

func TestTOFUStorePinAndVerify(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "known_peers.json")
	store, err := NewTOFUStore(storePath)
	if err != nil {
		t.Fatalf("NewTOFUStore: %v", err)
	}

	_, _, fp, certDER := testIdentity(t, "peer-a")

	// First verification pins the fingerprint.
	if err := store.verifyPeer("peer-a", [][]byte{certDER}); err != nil {
		t.Fatalf("first verify failed: %v", err)
	}
	pinned, ok := store.Pinned("peer-a")
	if !ok || pinned != fp {
		t.Fatalf("expected pinned fingerprint %s, got %q (ok=%v)", fp, pinned, ok)
	}

	// A different certificate for the same name must be rejected.
	_, _, otherFP, otherDER := testIdentity(t, "peer-a")
	if otherFP == fp {
		t.Fatalf("test identities must differ")
	}
	if err := store.verifyPeer("peer-a", [][]byte{otherDER}); err == nil {
		t.Fatalf("expected fingerprint mismatch error")
	}

	// Missing certs are rejected.
	if err := store.verifyPeer("peer-a", nil); err == nil {
		t.Fatalf("expected error for missing certificate")
	}
}

func TestTOFUStorePersists(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "known_peers.json")
	store, err := NewTOFUStore(storePath)
	if err != nil {
		t.Fatalf("NewTOFUStore: %v", err)
	}

	_, _, fp, certDER := testIdentity(t, "peer-b")
	if err := store.verifyPeer("peer-b", [][]byte{certDER}); err != nil {
		t.Fatalf("verify failed: %v", err)
	}

	reloaded, err := NewTOFUStore(storePath)
	if err != nil {
		t.Fatalf("reload store: %v", err)
	}
	pinned, ok := reloaded.Pinned("peer-b")
	if !ok || pinned != fp {
		t.Fatalf("expected persisted fingerprint %s, got %q", fp, pinned)
	}
}

func TestTOFUStoreRejectsExpiredCert(t *testing.T) {
	store, err := NewTOFUStore(filepath.Join(t.TempDir(), "known_peers.json"))
	if err != nil {
		t.Fatalf("NewTOFUStore: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "expired"},
		NotBefore:    now.Add(-48 * time.Hour),
		NotAfter:     now.Add(-24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	if err := store.verifyPeer("expired", [][]byte{certDER}); err == nil {
		t.Fatalf("expected expired certificate to be rejected")
	}
}
