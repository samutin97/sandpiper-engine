package hcore

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// box.log, the file sing-box writes its log to (log-file, data/box.log by default), is opened by
// the core (sing-box's log.FileOpener) rather than as an append-only file of any size, mode 0644,
// with every line as it was: on a phone it kept the destinations of failed connections and the
// REALITY server names at the error level, and grew without end (D-10 of the emulator report).
// Now it is rotated at boxLogMaxSize, with boxLogBackups previous files (box.log.1), mode 0600,
// and each line is scrubbed as the lines sent to the app are (scrubLogLine: secrets always,
// addresses and host names unless the level is debug or trace).
const (
	boxLogMaxSize = 1 << 20
	boxLogBackups = 1
)

type boxLogOpener struct{}

func (boxLogOpener) OpenLogFile(path string) (io.WriteCloser, error) {
	if path == os.DevNull || path == "/dev/null" {
		return nopWriteCloser{}, nil
	}
	if !filepath.IsAbs(path) && sWorkingPath != "" {
		path = filepath.Join(sWorkingPath, path)
	}
	return openRotatingLog(path, boxLogMaxSize, boxLogBackups, scrubLogLine)
}

type nopWriteCloser struct{}

func (nopWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopWriteCloser) Close() error                { return nil }

// rotatingLog is a log file that is moved to path.1 (path.2 to path.3, and so on, up to backups)
// when the next line would take it past maxSize. Each Write is one entry, filtered first.
type rotatingLog struct {
	access  sync.Mutex
	path    string
	file    *os.File
	size    int64
	maxSize int64
	backups int
	filter  func(string) string
}

func openRotatingLog(path string, maxSize int64, backups int, filter func(string) string) (*rotatingLog, error) {
	log := &rotatingLog{path: path, maxSize: maxSize, backups: backups, filter: filter}
	if err := log.open(); err != nil {
		return nil, err
	}
	if log.size >= maxSize {
		if err := log.rotate(); err != nil {
			return nil, err
		}
	}
	return log, nil
}

func (l *rotatingLog) open() error {
	file, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	file.Chmod(0o600) // a box.log of an older core was 0644
	l.file, l.size = file, 0
	if info, err := file.Stat(); err == nil {
		l.size = info.Size()
	}
	return nil
}

func (l *rotatingLog) rotate() error {
	l.file.Close()
	l.file = nil
	if l.backups < 1 {
		os.Remove(l.path)
	}
	for i := l.backups; i >= 1; i-- {
		from := l.path
		if i > 1 {
			from = l.path + "." + strconv.Itoa(i-1)
		}
		os.Rename(from, l.path+"."+strconv.Itoa(i))
	}
	return l.open()
}

func (l *rotatingLog) Write(p []byte) (int, error) {
	line := string(p)
	if l.filter != nil {
		line = l.filter(line)
	}
	l.access.Lock()
	defer l.access.Unlock()
	if l.file == nil {
		return 0, os.ErrClosed
	}
	if l.size > 0 && l.size+int64(len(line)) > l.maxSize {
		if err := l.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := l.file.WriteString(line)
	l.size += int64(n)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (l *rotatingLog) Close() error {
	l.access.Lock()
	defer l.access.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}
