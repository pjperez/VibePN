package protocol

import (
	"bytes"
	"testing"
)

func TestPingPongRoundTrip(t *testing.T) {
	payload, err := Encode(Ping{Nonce: 12345})
	if err != nil {
		t.Fatalf("encode ping: %v", err)
	}
	if payload[0] != TypePing {
		t.Fatalf("expected type P, got %q", payload[0])
	}
	msg, err := Decode(payload)
	if err != nil {
		t.Fatalf("decode ping: %v", err)
	}
	if p, ok := msg.(Ping); !ok || p.Nonce != 12345 {
		t.Fatalf("unexpected ping: %#v", msg)
	}

	payload, err = Encode(Pong{Nonce: 12345})
	if err != nil {
		t.Fatalf("encode pong: %v", err)
	}
	if payload[0] != TypePong {
		t.Fatalf("expected type p, got %q", payload[0])
	}
	msg, err = Decode(payload)
	if err != nil {
		t.Fatalf("decode pong: %v", err)
	}
	if p, ok := msg.(Pong); !ok || p.Nonce != 12345 {
		t.Fatalf("unexpected pong: %#v", msg)
	}
}

func TestPingPongFramed(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMessage(&buf, Ping{Nonce: 7}); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	if err := WriteMessage(&buf, Pong{Nonce: 7}); err != nil {
		t.Fatalf("write pong: %v", err)
	}

	msg, err := ReadMessage(&buf)
	if err != nil {
		t.Fatalf("read ping: %v", err)
	}
	if p, ok := msg.(Ping); !ok || p.Nonce != 7 {
		t.Fatalf("unexpected ping: %#v", msg)
	}

	msg, err = ReadMessage(&buf)
	if err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if p, ok := msg.(Pong); !ok || p.Nonce != 7 {
		t.Fatalf("unexpected pong: %#v", msg)
	}
}

func TestPingPongDecodeErrors(t *testing.T) {
	if _, err := Decode([]byte{TypePing}); err == nil {
		t.Fatalf("expected error for short ping")
	}
	if _, err := Decode([]byte{TypePing, 1, 2, 3}); err == nil {
		t.Fatalf("expected error for short ping body")
	}
	if _, err := Decode([]byte{TypePong}); err == nil {
		t.Fatalf("expected error for short pong")
	}
	if _, err := Decode([]byte{TypePong, 1, 2, 3}); err == nil {
		t.Fatalf("expected error for short pong body")
	}
}
