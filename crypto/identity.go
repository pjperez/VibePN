// Package crypto: identity and certificate management.
package crypto

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

// Fingerprint returns the SHA-256 fingerprint of a DER certificate.
func Fingerprint(certDER []byte) string {
	sum := sha256.Sum256(certDER)
	return hex.EncodeToString(sum[:])
}

// LoadTLS loads the local cert/key pair, verifies the optional expected
// fingerprint, and returns a server-side TLS config.
func LoadTLS(certPath, keyPath, expectedFP string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load cert/key: %w", err)
	}

	x509cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}

	fingerprint := Fingerprint(x509cert.Raw)
	if expectedFP != "" && fingerprint != expectedFP {
		return nil, fmt.Errorf("fingerprint mismatch: got %s, expected %s", fingerprint, expectedFP)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{ALPNProtocol},
	}
	return tlsConf, nil
}
