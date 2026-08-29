package forward

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestReadFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	network := "corp"
	pkt := []byte{0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x02}

	// Write a frame manually.
	buf.WriteByte(byte(len(network)))
	buf.WriteString(network)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(pkt)))
	buf.Write(lenBuf[:])
	buf.Write(pkt)

	gotNetwork, gotPkt, err := readFrame(&buf)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if gotNetwork != network {
		t.Fatalf("network = %q, want %q", gotNetwork, network)
	}
	if !bytes.Equal(gotPkt, pkt) {
		t.Fatalf("packet mismatch: % x vs % x", gotPkt, pkt)
	}
}

func TestReadFrameErrors(t *testing.T) {
	// Empty reader → EOF.
	if _, _, err := readFrame(bytes.NewReader(nil)); err == nil {
		t.Fatalf("expected EOF")
	}

	// Zero network length.
	if _, _, err := readFrame(bytes.NewReader([]byte{0})); err == nil {
		t.Fatalf("expected error for zero network length")
	}

	// Truncated network name.
	if _, _, err := readFrame(bytes.NewReader([]byte{5, 'c', 'o'})); err == nil {
		t.Fatalf("expected error for truncated network name")
	}

	// Zero packet length.
	var buf bytes.Buffer
	buf.WriteByte(4)
	buf.WriteString("corp")
	buf.Write([]byte{0, 0})
	if _, _, err := readFrame(&buf); err == nil {
		t.Fatalf("expected error for zero packet length")
	}

	// Truncated packet.
	buf.Reset()
	buf.WriteByte(4)
	buf.WriteString("corp")
	buf.Write([]byte{0, 10})
	buf.Write([]byte{1, 2, 3})
	if _, _, err := readFrame(&buf); err == nil {
		t.Fatalf("expected error for truncated packet")
	}
}

func TestParseDstIP(t *testing.T) {
	// IPv4 packet to 10.42.0.5.
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	pkt[16], pkt[17], pkt[18], pkt[19] = 10, 42, 0, 5

	ip := parseDstIP(pkt)
	if ip == nil || ip.String() != "10.42.0.5" {
		t.Fatalf("expected 10.42.0.5, got %v", ip)
	}

	// IPv6 packet → nil.
	v6 := make([]byte, 40)
	v6[0] = 0x60
	if ip := parseDstIP(v6); ip != nil {
		t.Fatalf("expected nil for IPv6, got %v", ip)
	}

	// Too short → nil.
	if ip := parseDstIP([]byte{0x45, 0x00}); ip != nil {
		t.Fatalf("expected nil for short packet, got %v", ip)
	}
}
