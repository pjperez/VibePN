package main

import (
	"strings"
	"testing"
)

func TestParseInviteToken(t *testing.T) {
	fp := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	token := "vibepn://corp@198.51.100.20:51820#" + fp + "?name=node-a&prefix=10.42.0.0%2F24"

	payload, err := parseInviteToken(token)
	if err != nil {
		t.Fatalf("parseInviteToken: %v", err)
	}
	if payload.Network != "corp" {
		t.Fatalf("network = %q, want corp", payload.Network)
	}
	if payload.Prefix != "10.42.0.0/24" {
		t.Fatalf("prefix = %q, want 10.42.0.0/24", payload.Prefix)
	}
	if payload.Inviter.Name != "node-a" {
		t.Fatalf("inviter name = %q, want node-a", payload.Inviter.Name)
	}
	if payload.Inviter.Address != "198.51.100.20:51820" {
		t.Fatalf("inviter address = %q", payload.Inviter.Address)
	}
	if payload.Inviter.Fingerprint != fp {
		t.Fatalf("inviter fingerprint mismatch")
	}
}

func TestParseInviteTokenErrors(t *testing.T) {
	fp := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	cases := []string{
		"vibepn://",                         // empty
		"vibepn://corp",                     // no @
		"vibepn://corp@198.51.100.20:51820", // no #
		"vibepn://@198.51.100.20:51820#" + fp + "?name=x&prefix=10.42.0.0%2F24", // empty network
		"vibepn://corp@bad#" + fp + "?name=x&prefix=10.42.0.0%2F24",             // bad address
		"vibepn://corp@1.2.3.4:51820#zz?name=x&prefix=10.42.0.0%2F24",           // bad fingerprint
		"vibepn://corp@1.2.3.4:51820#" + fp,                                     // missing query
		"vibepn://corp@1.2.3.4:51820#" + fp + "?name=x",                         // missing prefix
		"vibepn://corp@1.2.3.4:51820#" + fp + "?name=x&prefix=not-a-cidr",       // bad prefix
	}
	for _, c := range cases {
		if _, err := parseInviteToken(c); err == nil {
			t.Fatalf("expected error for token %q", c)
		}
	}
}

func TestLoadInvitePayloadAcceptsToken(t *testing.T) {
	fp := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	token := "vibepn://corp@198.51.100.20:51820#" + fp + "?name=node-a&prefix=10.42.0.0%2F24"

	payload, err := loadInvitePayload(token, "")
	if err != nil {
		t.Fatalf("loadInvitePayload(token): %v", err)
	}
	if payload.Network != "corp" {
		t.Fatalf("network = %q", payload.Network)
	}
	if payload.Prefix != "10.42.0.0/24" {
		t.Fatalf("prefix = %q", payload.Prefix)
	}
	if !strings.HasPrefix(payload.Inviter.Fingerprint, "0123456789abcdef") {
		t.Fatalf("fingerprint not parsed: %q", payload.Inviter.Fingerprint)
	}
}

func TestURLEncodeDecode(t *testing.T) {
	orig := "10.42.0.0/24"
	enc := urlEncode(orig)
	if strings.Contains(enc, "/") {
		t.Fatalf("urlEncode left a slash: %q", enc)
	}
	if dec := urlDecode(enc); dec != orig {
		t.Fatalf("urlDecode(%q) = %q, want %q", enc, dec, orig)
	}
}
