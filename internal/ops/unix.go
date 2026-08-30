package ops

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
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

// NewUnixHTTPTransport returns an HTTP transport that routes requests whose
// host is "unix" to socketPath. Other requests retain the standard transport
// behavior, allowing this transport to be installed as http.DefaultTransport.
func NewUnixHTTPTransport(socketPath string) *http.Transport {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok || base == nil {
		base = &http.Transport{}
	}
	transport := base.Clone()
	proxy := transport.Proxy
	transport.Proxy = func(req *http.Request) (*url.URL, error) {
		if req.URL.Host == "unix" {
			return nil, nil
		}
		if proxy != nil {
			return proxy(req)
		}
		return nil, nil
	}
	dialer := &net.Dialer{}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host := address
		if parsedHost, _, err := net.SplitHostPort(address); err == nil {
			host = parsedHost
		}
		if host == "unix" {
			return dialer.DialContext(ctx, "unix", socketPath)
		}
		return dialer.DialContext(ctx, network, address)
	}
	return transport
}
