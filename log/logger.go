// Package log: structured logging
package log

import (
	"fmt"
	"log"
	"os"
	"time"
)

type Level string

const (
	DEBUG Level = "DEBUG"
	INFO  Level = "INFO"
	WARN  Level = "WARN"
	ERROR Level = "ERROR"
	FATAL Level = "FATAL"
)

type Logger struct {
	component string
	logger    *log.Logger
}

func New(component string) *Logger {
	return &Logger{
		component: component,
		logger:    log.New(os.Stdout, "", 0),
	}
}

func (l *Logger) logf(level Level, format string, args ...interface{}) {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	message := fmt.Sprintf(format, args...)
	l.logger.Printf("[%s] %s  [%s] %s", timestamp, level, l.component, message)
}

func (l *Logger) Debugf(format string, args ...interface{}) { l.logf(DEBUG, format, args...) }
func (l *Logger) Infof(format string, args ...interface{})  { l.logf(INFO, format, args...) }
func (l *Logger) Warnf(format string, args ...interface{})  { l.logf(WARN, format, args...) }
func (l *Logger) Errorf(format string, args ...interface{}) { l.logf(ERROR, format, args...) }
func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.logf(FATAL, format, args...)
	os.Exit(1)
}
