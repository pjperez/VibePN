package tun

import (
	"strings"
	"testing"
)

func TestInterfaceNameDeterministicAndUnique(t *testing.T) {
	n1 := interfaceName("node-a", "corp")
	n2 := interfaceName("node-a", "corp")
	if n1 != n2 {
		t.Fatalf("expected deterministic name, got %q vs %q", n1, n2)
	}

	n3 := interfaceName("node-a", "dmz")
	if n1 == n3 {
		t.Fatalf("expected different names for different networks, got %q", n1)
	}

	n4 := interfaceName("node-b", "corp")
	if n1 == n4 {
		t.Fatalf("expected different names for different nodes, got %q", n1)
	}

	for _, name := range []string{n1, n3, n4} {
		if len(name) > 15 {
			t.Fatalf("interface name %q exceeds 15 chars", name)
		}
		if !strings.HasPrefix(name, "vibepn-") {
			t.Fatalf("interface name %q missing prefix", name)
		}
	}
}
