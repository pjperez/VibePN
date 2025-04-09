package control

import (
	"encoding/binary"
	"fmt"
	"time"

	"vibepn/log"

	"github.com/quic-go/quic-go"
)

// 🚀 Send a Hello (only control type byte, no body)
func SendHello(stream quic.Stream) error {
	logger := log.New("control/hello")

	buf := []byte{'H'} // control type 'H'

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(buf)))

	_, err := stream.Write(length)
	if err != nil {
		return fmt.Errorf("send hello length: %w", err)
	}
	_, err = stream.Write(buf)
	if err != nil {
		return fmt.Errorf("send hello payload: %w", err)
	}

	logger.Infof("Sent Hello")
	return nil
}

// 🚀 Send a Route-Announce
func SendRouteAnnounce(stream quic.Stream, network string, prefixes []string) error {
	logger := log.New("control/route-announce")

	buf := []byte{'A'} // control type 'A'

	// network name
	if len(network) > 255 {
		return fmt.Errorf("network name too long")
	}
	buf = append(buf, byte(len(network)))
	buf = append(buf, []byte(network)...)

	for _, prefix := range prefixes {
		if len(prefix) > 255 {
			return fmt.Errorf("prefix too long")
		}
		buf = append(buf, byte(len(prefix)))
		buf = append(buf, []byte(prefix)...)
		metric := uint16(1) // Default metric
		metricBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(metricBuf, metric)
		buf = append(buf, metricBuf...)
	}

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(buf)))

	_, err := stream.Write(length)
	if err != nil {
		return fmt.Errorf("send route-announce length: %w", err)
	}
	_, err = stream.Write(buf)
	if err != nil {
		return fmt.Errorf("send route-announce payload: %w", err)
	}

	logger.Infof("Sent Route-Announce for network %s (%d prefixes)", network, len(prefixes))
	return nil
}

// 🚀 Send a Route-Withdraw
func SendRouteWithdraw(stream quic.Stream, network string, prefix string) error {
	logger := log.New("control/route-withdraw")

	buf := []byte{'W'} // control type 'W'

	// network name
	if len(network) > 255 {
		return fmt.Errorf("network name too long")
	}
	buf = append(buf, byte(len(network)))
	buf = append(buf, []byte(network)...)

	// prefix
	if len(prefix) > 255 {
		return fmt.Errorf("prefix too long")
	}
	buf = append(buf, byte(len(prefix)))
	buf = append(buf, []byte(prefix)...)

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(buf)))

	_, err := stream.Write(length)
	if err != nil {
		return fmt.Errorf("send route-withdraw length: %w", err)
	}
	_, err = stream.Write(buf)
	if err != nil {
		return fmt.Errorf("send route-withdraw payload: %w", err)
	}

	logger.Infof("Sent Route-Withdraw for network %s prefix %s", network, prefix)
	return nil
}

// 🚀 Send a Keepalive
func SendKeepalive(stream quic.Stream) error {
	logger := log.New("control/keepalive")

	buf := []byte{'K'} // control type 'K'

	timestamp := uint64(time.Now().Unix())
	timestampBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBuf, timestamp)

	buf = append(buf, timestampBuf...)

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(buf)))

	_, err := stream.Write(length)
	if err != nil {
		return fmt.Errorf("send keepalive length: %w", err)
	}
	_, err = stream.Write(buf)
	if err != nil {
		return fmt.Errorf("send keepalive payload: %w", err)
	}

	logger.Debugf("Sent Keepalive")
	return nil
}

// 🚀 Send a Goodbye
func SendGoodbye(stream quic.Stream) error {
	logger := log.New("control/goodbye")

	buf := []byte{'G'} // control type 'G'

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(buf)))

	_, err := stream.Write(length)
	if err != nil {
		return fmt.Errorf("send goodbye length: %w", err)
	}
	_, err = stream.Write(buf)
	if err != nil {
		return fmt.Errorf("send goodbye payload: %w", err)
	}

	logger.Infof("Sent Goodbye")
	return nil
}
