package control

import (
	"encoding/json"
	"math"
	"math/rand"
	"sync"
	"time"

	"vibepn/log"

	"github.com/quic-go/quic-go"
)

type KeepaliveMessage struct {
	Timestamp int64 `json:"timestamp"`
}

type keepaliveState struct {
	lastSent time.Time
	mu       sync.Mutex
}

// Constants
const (
	baseInterval      = 10 * time.Second
	maxBackoff        = 2 * time.Minute
	jitterWindowMs    = 1000 // ±1s
	enableDebugTimers = false
)

func SendKeepalive(conn quic.Connection, logger *log.Logger) {
	state := &keepaliveState{}
	failureCount := 0

	for {
		interval := nextJitteredInterval(baseInterval)

		if enableDebugTimers {
			logger.Infof("Keepalive interval: %s", interval)
		}

		time.Sleep(interval)

		if conn.Context().Err() != nil {
			return
		}

		if !shouldSend(state, baseInterval) {
			continue
		}

		stream, err := conn.OpenStream()
		if err != nil {
			failureCount++
			if enableDebugTimers {
				logger.Infof("Backoff due to %d failures: sleeping %s", failureCount, backoffDuration(failureCount))
			}
			logger.Warnf("Keepalive OpenStream error: %v (fail #%d)", err, failureCount)
			time.Sleep(backoffDuration(failureCount))
			continue
		}

		header := Header{Type: "keepalive"}
		msg := KeepaliveMessage{
			Timestamp: time.Now().Unix(),
		}

		enc := json.NewEncoder(stream)
		if err := enc.Encode(header); err != nil {
			logger.Warnf("Keepalive encode header failed: %v", err)
			_ = stream.Close()
			failureCount++
			time.Sleep(backoffDuration(failureCount))
			continue
		}

		if err := enc.Encode(msg); err != nil {
			logger.Warnf("Keepalive encode payload failed: %v", err)
			_ = stream.Close()
			failureCount++
			time.Sleep(backoffDuration(failureCount))
			continue
		}

		_ = stream.Close()
		logger.Debugf("Sent keepalive to %s", conn.RemoteAddr())

		failureCount = 0
		state.mu.Lock()
		state.lastSent = time.Now()
		state.mu.Unlock()
	}
}

func shouldSend(state *keepaliveState, minInterval time.Duration) bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	return time.Since(state.lastSent) >= minInterval
}

func nextJitteredInterval(base time.Duration) time.Duration {
	jitter := time.Duration(rand.Intn(jitterWindowMs*2)-jitterWindowMs) * time.Millisecond
	return base + jitter
}

func backoffDuration(failures int) time.Duration {
	backoff := baseInterval * time.Duration(math.Pow(2, float64(failures)))
	if backoff > maxBackoff {
		return maxBackoff
	}
	return backoff
}

func ParseKeepalive(dec *json.Decoder, logger *log.Logger) {
	var msg KeepaliveMessage
	if err := dec.Decode(&msg); err != nil {
		logger.Warnf("Failed to decode keepalive payload: %v", err)
		return
	}
	logger.Debugf("Received keepalive: timestamp=%d", msg.Timestamp)
}
