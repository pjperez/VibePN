// Package crypto: identity and certificate management
package crypto

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

func LoadTLS(certPath, keyPath, expectedFP string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load cert/key: %w", err)
	}

	x509cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}

	hash := sha256.Sum256(x509cert.Raw)
	fingerprint := hex.EncodeToString(hash[:])
	if expectedFP != "" && fingerprint != expectedFP {
		return nil, fmt.Errorf("fingerprint mismatch: got %s, expected %s", fingerprint, expectedFP)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"vibepn/0.1"},
	}
	return tlsConf, nil
}
