package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"vibepn/config"
)

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "empty",
			input: "",
			want:  []string{},
		},
		{
			name:  "trims whitespace and skips blanks",
			input: " corp, ,edge ,,  dmz ",
			want:  []string{"corp", "edge", "dmz"},
		},
		{
			name:  "single value",
			input: "corp",
			want:  []string{"corp"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitCSV(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("splitCSV(%q) = %#v, want %#v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateHostPort(t *testing.T) {
	if err := validateHostPort("127.0.0.1:51820"); err != nil {
		t.Fatalf("expected valid host:port, got error: %v", err)
	}
	if err := validateHostPort("invalid"); err == nil {
		t.Fatalf("expected invalid host:port error")
	}
	if err := validateHostPort("127.0.0.1:70000"); err == nil {
		t.Fatalf("expected invalid port error")
	}
}

func TestIsValidFingerprint(t *testing.T) {
	valid := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if !isValidFingerprint(valid) {
		t.Fatalf("expected valid fingerprint")
	}
	if isValidFingerprint("abcd") {
		t.Fatalf("expected short fingerprint to be invalid")
	}
	if isValidFingerprint(valid[:63] + "z") {
		t.Fatalf("expected non-hex fingerprint to be invalid")
	}
}

func TestLoadInvitePayloadValidJSONAndFile(t *testing.T) {
	invite := `{"version":1,"network":"corp","prefix":"10.42.0.0/24","inviter":{"name":"node-a","address":"127.0.0.1:3000","fingerprint":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}`
	want := InvitePayload{
		Version: 1,
		Network: "corp",
		Prefix:  "10.42.0.0/24",
		Inviter: InvitePeer{
			Name:        "node-a",
			Address:     "127.0.0.1:3000",
			Fingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	got, err := loadInvitePayload(invite, "")
	if err != nil {
		t.Fatalf("loadInvitePayload(json) returned error: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loadInvitePayload(json) = %#v, want %#v", got, want)
	}

	invitePath := filepath.Join(t.TempDir(), "invite.json")
	if err := os.WriteFile(invitePath, []byte(invite), 0600); err != nil {
		t.Fatalf("write invite file: %v", err)
	}

	fromFile, err := loadInvitePayload("", invitePath)
	if err != nil {
		t.Fatalf("loadInvitePayload(file) returned error: %v", err)
	}
	if !reflect.DeepEqual(fromFile, want) {
		t.Fatalf("loadInvitePayload(file) = %#v, want %#v", fromFile, want)
	}
}

func TestLoadInvitePayloadInvalidJSONAndFilePath(t *testing.T) {
	if _, err := loadInvitePayload("{", ""); err == nil || !strings.Contains(err.Error(), "parse invite payload") {
		t.Fatalf("expected parse invite payload error, got: %v", err)
	}

	missingPath := filepath.Join(t.TempDir(), "missing-invite.json")
	if _, err := loadInvitePayload("", missingPath); err == nil || !strings.Contains(err.Error(), "read invite file") {
		t.Fatalf("expected read invite file error, got: %v", err)
	}
}

func TestGenerateIdentityWritesFilesAndFingerprint(t *testing.T) {
	certPath := filepath.Join(t.TempDir(), "certs", "node.crt")
	keyPath := filepath.Join(filepath.Dir(certPath), "node.key")

	fingerprint, err := generateIdentity(certPath, keyPath, "node-test")
	if err != nil {
		t.Fatalf("generateIdentity returned error: %v", err)
	}
	if len(fingerprint) != 64 {
		t.Fatalf("fingerprint length = %d, want 64", len(fingerprint))
	}
	if _, err := hex.DecodeString(fingerprint); err != nil {
		t.Fatalf("fingerprint is not hex: %v", err)
	}

	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if len(keyBytes) == 0 {
		t.Fatalf("key file is empty")
	}

	block, _ := pem.Decode(certBytes)
	if block == nil {
		t.Fatalf("failed to decode cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	hash := sha256.Sum256(cert.Raw)
	gotFingerprint := hex.EncodeToString(hash[:])
	if gotFingerprint != fingerprint {
		t.Fatalf("fingerprint mismatch: got %q want %q", gotFingerprint, fingerprint)
	}
}

func TestRunDoctorInvalidAndValidConfigs(t *testing.T) {
	invalidConfigPath := filepath.Join(t.TempDir(), "invalid.toml")
	invalidCfg := []byte("[identity]\ncert = \"\"\nkey = \"\"\nfingerprint = \"\"\n")
	if err := os.WriteFile(invalidConfigPath, invalidCfg, 0600); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}
	if err := runDoctor([]string{"--config", invalidConfigPath}); err == nil {
		t.Fatalf("expected runDoctor to fail for invalid config")
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "node.crt")
	keyPath := filepath.Join(dir, "node.key")
	fingerprint, err := generateIdentity(certPath, keyPath, "doctor-test-node")
	if err != nil {
		t.Fatalf("generateIdentity for doctor config: %v", err)
	}

	validCfg := &config.Config{
		Identity: config.Identity{
			Cert:        certPath,
			Key:         keyPath,
			Fingerprint: fingerprint,
		},
	}
	validConfigPath := filepath.Join(dir, "valid.toml")
	if err := writeConfig(validConfigPath, validCfg); err != nil {
		t.Fatalf("write valid config: %v", err)
	}

	if err := runDoctor([]string{"--config", validConfigPath}); err != nil {
		t.Fatalf("runDoctor returned error for valid config: %v", err)
	}
}
