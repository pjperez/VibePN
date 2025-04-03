package shared

import "time"

type PeerState struct {
	ID       string
	LastSeen time.Time
}
