// Package protocol: binary control-plane message encoding/decoding.
package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// Message types.
const (
	TypeHello         byte = 'H'
	TypeRouteAnnounce byte = 'A'
	TypeRouteWithdraw byte = 'W'
	TypeKeepalive     byte = 'K'
	TypeGoodbye       byte = 'G'
)

// MaxMessageSize bounds control message payloads (2-byte length field).
const MaxMessageSize = 4096

// Hello is the tie-breaker nonce exchange.
type Hello struct {
	Nonce uint64
}

// RouteAnnounce advertises one or more prefixes for a network.
type RouteAnnounce struct {
	Network  string
	Prefixes []string
	Metric   uint16
}

// RouteWithdraw retracts a prefix for a network.
type RouteWithdraw struct {
	Network string
	Prefix  string
}

// Keepalive is a liveness heartbeat.
type Keepalive struct {
	Timestamp uint64
}

// Goodbye is a graceful shutdown signal.
type Goodbye struct{}

// Encode serializes a message into its wire payload (type byte + body).
func Encode(msg interface{}) ([]byte, error) {
	switch m := msg.(type) {
	case Hello:
		buf := make([]byte, 1+8)
		buf[0] = TypeHello
		binary.BigEndian.PutUint64(buf[1:], m.Nonce)
		return buf, nil

	case RouteAnnounce:
		if len(m.Network) == 0 || len(m.Network) > 255 {
			return nil, fmt.Errorf("network name length must be 1-255")
		}
		if len(m.Prefixes) == 0 {
			return nil, fmt.Errorf("route announce requires at least one prefix")
		}
		buf := []byte{TypeRouteAnnounce, byte(len(m.Network))}
		buf = append(buf, m.Network...)
		for _, p := range m.Prefixes {
			if len(p) == 0 || len(p) > 255 {
				return nil, fmt.Errorf("prefix length must be 1-255")
			}
			buf = append(buf, byte(len(p)))
			buf = append(buf, p...)
			var metric [2]byte
			binary.BigEndian.PutUint16(metric[:], m.Metric)
			buf = append(buf, metric[:]...)
		}
		return buf, nil

	case RouteWithdraw:
		if len(m.Network) == 0 || len(m.Network) > 255 {
			return nil, fmt.Errorf("network name length must be 1-255")
		}
		if len(m.Prefix) == 0 || len(m.Prefix) > 255 {
			return nil, fmt.Errorf("prefix length must be 1-255")
		}
		buf := []byte{TypeRouteWithdraw, byte(len(m.Network))}
		buf = append(buf, m.Network...)
		buf = append(buf, byte(len(m.Prefix)))
		buf = append(buf, m.Prefix...)
		return buf, nil

	case Keepalive:
		buf := make([]byte, 1+8)
		buf[0] = TypeKeepalive
		binary.BigEndian.PutUint64(buf[1:], m.Timestamp)
		return buf, nil

	case Goodbye:
		return []byte{TypeGoodbye}, nil

	default:
		return nil, fmt.Errorf("cannot encode message of type %T", msg)
	}
}

// Decode parses a message payload (type byte + body) into a typed message.
func Decode(payload []byte) (interface{}, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("empty message payload")
	}

	typ := payload[0]
	body := payload[1:]

	switch typ {
	case TypeHello:
		if len(body) != 8 {
			return nil, fmt.Errorf("hello body must be 8 bytes, got %d", len(body))
		}
		return Hello{Nonce: binary.BigEndian.Uint64(body)}, nil

	case TypeRouteAnnounce:
		return decodeRouteAnnounce(body)

	case TypeRouteWithdraw:
		return decodeRouteWithdraw(body)

	case TypeKeepalive:
		if len(body) != 8 {
			return nil, fmt.Errorf("keepalive body must be 8 bytes, got %d", len(body))
		}
		return Keepalive{Timestamp: binary.BigEndian.Uint64(body)}, nil

	case TypeGoodbye:
		if len(body) != 0 {
			return nil, fmt.Errorf("goodbye body must be empty, got %d bytes", len(body))
		}
		return Goodbye{}, nil

	default:
		return nil, fmt.Errorf("unknown message type %q", typ)
	}
}

func decodeRouteAnnounce(body []byte) (RouteAnnounce, error) {
	if len(body) < 1 {
		return RouteAnnounce{}, fmt.Errorf("route announce body too short")
	}
	networkLen := int(body[0])
	if len(body) < 1+networkLen {
		return RouteAnnounce{}, fmt.Errorf("route announce network name truncated")
	}
	network := string(body[1 : 1+networkLen])

	msg := RouteAnnounce{Network: network}
	cursor := 1 + networkLen
	for cursor < len(body) {
		if cursor+1 > len(body) {
			return RouteAnnounce{}, fmt.Errorf("route announce prefix length truncated")
		}
		prefixLen := int(body[cursor])
		if cursor+1+prefixLen+2 > len(body) {
			return RouteAnnounce{}, fmt.Errorf("route announce prefix truncated")
		}
		prefix := string(body[cursor+1 : cursor+1+prefixLen])
		metric := binary.BigEndian.Uint16(body[cursor+1+prefixLen : cursor+1+prefixLen+2])
		if msg.Metric == 0 {
			msg.Metric = metric
		} else if msg.Metric != metric {
			return RouteAnnounce{}, fmt.Errorf("route announce mixes metrics")
		}
		msg.Prefixes = append(msg.Prefixes, prefix)
		cursor += 1 + prefixLen + 2
	}
	if len(msg.Prefixes) == 0 {
		return RouteAnnounce{}, fmt.Errorf("route announce has no prefixes")
	}
	return msg, nil
}

func decodeRouteWithdraw(body []byte) (RouteWithdraw, error) {
	if len(body) < 1 {
		return RouteWithdraw{}, fmt.Errorf("route withdraw body too short")
	}
	networkLen := int(body[0])
	if len(body) < 1+networkLen {
		return RouteWithdraw{}, fmt.Errorf("route withdraw network name truncated")
	}
	network := string(body[1 : 1+networkLen])

	cursor := 1 + networkLen
	if cursor >= len(body) {
		return RouteWithdraw{}, fmt.Errorf("route withdraw missing prefix")
	}
	prefixLen := int(body[cursor])
	if cursor+1+prefixLen > len(body) {
		return RouteWithdraw{}, fmt.Errorf("route withdraw prefix truncated")
	}
	prefix := string(body[cursor+1 : cursor+1+prefixLen])
	return RouteWithdraw{Network: network, Prefix: prefix}, nil
}

// WriteMessage frames and writes a message to w.
func WriteMessage(w io.Writer, msg interface{}) error {
	payload, err := Encode(msg)
	if err != nil {
		return err
	}
	if len(payload) > MaxMessageSize {
		return fmt.Errorf("message too large: %d bytes", len(payload))
	}

	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(payload)))
	if _, err := w.Write(length[:]); err != nil {
		return fmt.Errorf("write message length: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write message payload: %w", err)
	}
	return nil
}

// ReadMessage reads one framed message from r.
func ReadMessage(r io.Reader) (interface{}, error) {
	var length [2]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(length[:])
	if n == 0 || n > MaxMessageSize {
		return nil, fmt.Errorf("invalid message length %d", n)
	}

	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return Decode(payload)
}

// NowTimestamp returns the current unix timestamp as a uint64.
func NowTimestamp() uint64 {
	return uint64(time.Now().Unix())
}
