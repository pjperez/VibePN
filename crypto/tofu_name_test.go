package crypto

import (
	"path/filepath"
	"testing"
)

func TestTOFUStoreNameForFingerprint(t *testing.T) {
	store, err := NewTOFUStore(filepath.Join(t.TempDir(), "known_peers.json"))
	if err != nil {
		t.Fatalf("NewTOFUStore: %v", err)
	}

	_, _, fpA, certA := testIdentity(t, "node-a")
	_, _, fpB, certB := testIdentity(t, "node-b")

	if err := store.verifyPeer("node-a", [][]byte{certA}); err != nil {
		t.Fatalf("pin node-a: %v", err)
	}
	if err := store.verifyPeer("node-b", [][]byte{certB}); err != nil {
		t.Fatalf("pin node-b: %v", err)
	}

	if name, ok := store.NameForFingerprint(fpA); !ok || name != "node-a" {
		t.Fatalf("expected node-a for %s, got %q (ok=%v)", fpA, name, ok)
	}
	if name, ok := store.NameForFingerprint(fpB); !ok || name != "node-b" {
		t.Fatalf("expected node-b for %s, got %q (ok=%v)", fpB, name, ok)
	}

	if _, ok := store.NameForFingerprint("deadbeef"); ok {
		t.Fatalf("expected no name for unknown fingerprint")
	}
}
