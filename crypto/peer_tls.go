package crypto

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"vibepn/log"
)

// LoadPeerTLS returns a tls.Config that verifies the peer’s certificate
// matches the expected SHA-256 fingerprint. It bypasses CA validation
// and uses TOFU-style pinning.
func LoadPeerTLS(expectedFingerprint string) *tls.Config {
	logger := log.New("crypto/peer")

	return &tls.Config{
		InsecureSkipVerify: true, // we verify manually below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no peer certificate presented")
			}

			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}

			sum := sha256.Sum256(cert.Raw)
			actual := hex.EncodeToString(sum[:])

			if actual != expectedFingerprint {
				logger.Warnf("Fingerprint mismatch: got %s, expected %s", actual, expectedFingerprint)
				return errors.New("certificate fingerprint mismatch")
			}

			logger.Infof("Verified peer fingerprint: %s", actual)
			return nil
		},
	}
}
