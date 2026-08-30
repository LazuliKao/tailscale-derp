package ops

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultOpsSocketPath is the default Unix socket used by the local Ops API.
const DefaultOpsSocketPath = "/var/run/tailscale-derp/ops.sock"

// ListenUnix creates a Unix listener, creating its parent directory and
// removing a stale socket left by an earlier process. A live socket is never
// removed.
func ListenUnix(path string) (net.Listener, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("unix socket path is empty")
	}
	path = filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create unix socket directory: %w", err)
	}

	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("unix socket path %q is not a socket", path)
		}
		conn, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return nil, fmt.Errorf("unix socket %q is already in use", path)
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("remove stale unix socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect unix socket: %w", err)
	}

	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on unix socket %q: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("restrict unix socket permissions: %w", err)
	}
	return &cleanupUnixListener{Listener: listener, path: path}, nil
}

type cleanupUnixListener struct {
	net.Listener
	path string
	once sync.Once
}

func (l *cleanupUnixListener) Close() error {
	var closeErr error
	l.once.Do(func() {
		closeErr = l.Listener.Close()
		if err := os.Remove(l.path); err != nil && !os.IsNotExist(err) && closeErr == nil {
			closeErr = err
		}
	})
	return closeErr
}

