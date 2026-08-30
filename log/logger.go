// Package log: structured logging with level filtering.
package log

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// Level is a log severity level.
type Level int

const (
	DebugLevel Level = iota
	InfoLevel
	WarnLevel
	ErrorLevel
	FatalLevel
)

var (
	levelMu sync.RWMutex
	level   = InfoLevel
)

func init() {
	if lvl, err := ParseLevel(os.Getenv("VIBEPN_LOG_LEVEL")); err == nil {
		SetLevel(lvl)
	}
}

// ParseLevel converts a string like "debug", "INFO", "warning" into a Level.
func ParseLevel(s string) (Level, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "DEBUG":
		return DebugLevel, nil
	case "INFO":
		return InfoLevel, nil
	case "WARN", "WARNING":
		return WarnLevel, nil
	case "ERROR":
		return ErrorLevel, nil
	case "FATAL":
		return FatalLevel, nil
	}
	return InfoLevel, fmt.Errorf("unknown log level %q", s)
}

// SetLevel sets the minimum level that will be emitted.
func SetLevel(l Level) {
	levelMu.Lock()
	level = l
	levelMu.Unlock()
}

// GetLevel returns the current minimum level.
func GetLevel() Level {
	levelMu.RLock()
	defer levelMu.RUnlock()
	return level
}

func levelName(l Level) string {
	switch l {
	case DebugLevel:
		return "DEBUG"
	case InfoLevel:
		return "INFO"
	case WarnLevel:
		return "WARN"
	case ErrorLevel:
		return "ERROR"
	case FatalLevel:
		return "FATAL"
	}
	return "?"
}

// ring is a small thread-safe in-memory log buffer used by `vpnctl logs`.
type ring struct {
	mu    sync.Mutex
	lines []string
	max   int
}

var logRing = &ring{max: 500}

func (r *ring) add(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, line)
	if len(r.lines) > r.max {
		r.lines = r.lines[len(r.lines)-r.max:]
	}
}

func (r *ring) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.lines))
	copy(out, r.lines)
	return out
}

// RecentLogs returns the last N buffered log lines (for `vpnctl logs`).
func RecentLogs(n int) []string {
	lines := logRing.snapshot()
	if n > 0 && len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

// Logger emits timestamped, level-tagged lines tagged with a component name.
type Logger struct {
	component string
	logger    *log.Logger
}

// New returns a Logger for the given component (e.g. "forward/dispatcher").
func New(component string) *Logger {
	return &Logger{
		component: component,
		logger:    log.New(os.Stderr, "", 0),
	}
}

func (l *Logger) logf(lvl Level, format string, args ...interface{}) {
	if lvl < GetLevel() {
		return
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	message := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("[%s] %s  [%s] %s", timestamp, levelName(lvl), l.component, message)
	l.logger.Println(line)
	logRing.add(line)
}

func (l *Logger) Debugf(format string, args ...interface{}) { l.logf(DebugLevel, format, args...) }
func (l *Logger) Infof(format string, args ...interface{})  { l.logf(InfoLevel, format, args...) }
func (l *Logger) Warnf(format string, args ...interface{})  { l.logf(WarnLevel, format, args...) }
func (l *Logger) Errorf(format string, args ...interface{}) { l.logf(ErrorLevel, format, args...) }

// Fatalf logs at FATAL level and terminates the process.
func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.logf(FatalLevel, format, args...)
	os.Exit(1)
}
