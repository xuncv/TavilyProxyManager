package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DailyRotateWriter is an io.WriteCloser that writes to daily-rotated log files.
// File name format: {dir}/{prefix}-{YYYY-MM-DD}.log
type DailyRotateWriter struct {
	dir    string
	prefix string

	mu      sync.Mutex
	current *os.File
	curDate string
}

func NewDailyRotateWriter(dir, prefix string) *DailyRotateWriter {
	return &DailyRotateWriter{dir: dir, prefix: prefix}
}

func (w *DailyRotateWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	today := time.Now().Format("2006-01-02")
	if w.current == nil || today != w.curDate {
		if err := w.rotateLocked(today); err != nil {
			return 0, err
		}
	}
	return w.current.Write(p)
}

func (w *DailyRotateWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.current != nil {
		err := w.current.Close()
		w.current = nil
		return err
	}
	return nil
}

func (w *DailyRotateWriter) rotateLocked(date string) error {
	if w.current != nil {
		_ = w.current.Close()
		w.current = nil
	}

	if err := os.MkdirAll(w.dir, 0o755); err != nil {
		return fmt.Errorf("create log dir: %w", err)
	}

	name := filepath.Join(w.dir, fmt.Sprintf("%s-%s.log", w.prefix, date))
	f, err := os.OpenFile(name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}

	w.current = f
	w.curDate = date
	return nil
}
