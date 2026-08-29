package control

import (
	"sync"
	"time"
)

var (
	startupOnce sync.Once
	startupTime time.Time
)

// Uptime returns the time since the daemon started.
func Uptime() string {
	startupOnce.Do(func() { startupTime = time.Now() })
	return time.Since(startupTime).Round(time.Second).String()
}
