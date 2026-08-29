package protocol

import (
	"bytes"
	"testing"
)

func TestHelloRoundTrip(t *testing.T) {
	payload, err := Encode(Hello{Nonce: 42})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if payload[0] != TypeHello {
		t.Fatalf("expected type H, got %q", payload[0])
	}

	msg, err := Decode(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	hello, ok := msg.(Hello)
	if !ok || hello.Nonce != 42 {
		t.Fatalf("unexpected decoded message: %#v", msg)
	}
}

func TestRouteAnnounceRoundTrip(t *testing.T) {
	orig := RouteAnnounce{
		Network:  "corp",
		Prefixes: []string{"10.42.0.0/24", "10.42.1.0/24"},
		Metric:   7,
	}
	payload, err := Encode(orig)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	msg, err := Decode(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, ok := msg.(RouteAnnounce)
	if !ok {
		t.Fatalf("unexpected type %T", msg)
	}
	if got.Network != orig.Network || got.Metric != orig.Metric {
		t.Fatalf("mismatch: %+v vs %+v", got, orig)
	}
	if len(got.Prefixes) != 2 || got.Prefixes[0] != "10.42.0.0/24" || got.Prefixes[1] != "10.42.1.0/24" {
		t.Fatalf("prefixes mismatch: %v", got.Prefixes)
	}
}

func TestRouteWithdrawRoundTrip(t *testing.T) {
	orig := RouteWithdraw{Network: "corp", Prefix: "10.42.0.0/24"}
	payload, err := Encode(orig)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	msg, err := Decode(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, ok := msg.(RouteWithdraw)
	if !ok || got.Network != orig.Network || got.Prefix != orig.Prefix {
		t.Fatalf("mismatch: %+v vs %+v", got, orig)
	}
}

func TestKeepaliveAndGoodbyeRoundTrip(t *testing.T) {
	payload, err := Encode(Keepalive{Timestamp: 1234567890})
	if err != nil {
		t.Fatalf("encode keepalive: %v", err)
	}
	msg, err := Decode(payload)
	if err != nil {
		t.Fatalf("decode keepalive: %v", err)
	}
	if k, ok := msg.(Keepalive); !ok || k.Timestamp != 1234567890 {
		t.Fatalf("unexpected keepalive: %#v", msg)
	}

	payload, err = Encode(Goodbye{})
	if err != nil {
		t.Fatalf("encode goodbye: %v", err)
	}
	msg, err = Decode(payload)
	if err != nil {
		t.Fatalf("decode goodbye: %v", err)
	}
	if _, ok := msg.(Goodbye); !ok {
		t.Fatalf("unexpected goodbye: %#v", msg)
	}
}

func TestDecodeErrors(t *testing.T) {
	cases := [][]byte{
		nil,
		{TypeHello},                    // too short
		{TypeHello, 1, 2, 3},           // too short
		{TypeRouteAnnounce, 200, 'x'},  // network name truncated
		{TypeRouteAnnounce, 1, 'c', 5}, // prefix truncated
		{TypeRouteWithdraw, 1, 'c'},    // missing prefix
		{TypeKeepalive, 1, 2, 3},       // too short
		{TypeGoodbye, 1},               // non-empty body
		{'Z', 1, 2},                    // unknown type
	}
	for _, c := range cases {
		if _, err := Decode(c); err == nil {
			t.Fatalf("expected decode error for % x", c)
		}
	}
}

func TestEncodeErrors(t *testing.T) {
	if _, err := Encode(RouteAnnounce{Network: "", Prefixes: []string{"10.0.0.0/24"}}); err == nil {
		t.Fatalf("expected error for empty network")
	}
	if _, err := Encode(RouteAnnounce{Network: "corp", Prefixes: nil}); err == nil {
		t.Fatalf("expected error for no prefixes")
	}
	if _, err := Encode(struct{}{}); err == nil {
		t.Fatalf("expected error for unknown type")
	}
}

func TestFramedReadWrite(t *testing.T) {
	var buf bytes.Buffer

	msgs := []interface{}{
		Hello{Nonce: 1},
		RouteAnnounce{Network: "corp", Prefixes: []string{"10.0.0.0/24"}, Metric: 1},
		Keepalive{Timestamp: 2},
		RouteWithdraw{Network: "corp", Prefix: "10.0.0.0/24"},
		Goodbye{},
	}
	for _, m := range msgs {
		if err := WriteMessage(&buf, m); err != nil {
			t.Fatalf("write %T: %v", m, err)
		}
	}

	for i, want := range msgs {
		got, err := ReadMessage(&buf)
		if err != nil {
			t.Fatalf("read message %d: %v", i, err)
		}
		switch w := want.(type) {
		case Hello:
			if g := got.(Hello); g.Nonce != w.Nonce {
				t.Fatalf("hello nonce mismatch")
			}
		case RouteAnnounce:
			g := got.(RouteAnnounce)
			if g.Network != w.Network || len(g.Prefixes) != len(w.Prefixes) {
				t.Fatalf("route announce mismatch")
			}
		case Keepalive:
			if g := got.(Keepalive); g.Timestamp != w.Timestamp {
				t.Fatalf("keepalive mismatch")
			}
		case RouteWithdraw:
			g := got.(RouteWithdraw)
			if g.Network != w.Network || g.Prefix != w.Prefix {
				t.Fatalf("withdraw mismatch")
			}
		case Goodbye:
			if _, ok := got.(Goodbye); !ok {
				t.Fatalf("goodbye mismatch")
			}
		}
	}

	// Buffer should now be empty.
	if _, err := ReadMessage(&buf); err == nil {
		t.Fatalf("expected EOF on empty buffer")
	}
}

func TestFramedRejectsOversized(t *testing.T) {
	var buf bytes.Buffer
	// Hand-craft an oversized length field.
	buf.Write([]byte{0xFF, 0xFF})
	if _, err := ReadMessage(&buf); err == nil {
		t.Fatalf("expected error for oversized length")
	}
}
