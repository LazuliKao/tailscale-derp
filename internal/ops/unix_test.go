package ops

import (
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func testSocketPath(t *testing.T, nested bool) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "d")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if nested {
		dir = filepath.Join(dir, "nested")
	}
	return filepath.Join(dir, "ops.sock")
}

func TestListenUnixCreatesAndCleansSocket(t *testing.T) {
	path := testSocketPath(t, true)
	listener, err := ListenUnix(path)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	info, statErr := os.Stat(path)
	if statErr != nil || info.Mode()&os.ModeSocket == 0 {
		var mode os.FileMode
		if info != nil {
			mode = info.Mode()
		}
		t.Fatalf("expected socket at %q, stat err=%v mode=%v", path, statErr, mode)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected socket cleanup, stat error=%v", err)
	}
}

func TestListenUnixRejectsLiveSocketAndReplacesStaleSocket(t *testing.T) {
	path := testSocketPath(t, false)
	live, err := ListenUnix(path)
	if err != nil {
		t.Fatalf("first ListenUnix: %v", err)
	}
	if _, err := ListenUnix(path); err == nil {
		t.Fatal("expected live socket to be rejected")
	}
	if err := live.Close(); err != nil {
		t.Fatalf("close live listener: %v", err)
	}

	raw, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("create stale socket: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close stale socket: %v", err)
	}
	replacement, err := ListenUnix(path)
	if err != nil {
		t.Fatalf("replace stale socket: %v", err)
	}
	defer replacement.Close()
}

func TestUnixHTTPTransport(t *testing.T) {
	path := testSocketPath(t, false)
	listener, err := ListenUnix(path)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	defer listener.Close()

	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/verify" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		io.WriteString(w, "ok")
	})}
	go server.Serve(listener)
	defer server.Close()

	client := &http.Client{Transport: NewUnixHTTPTransport(path)}
	resp, err := client.Get("http://unix/verify")
	if err != nil {
		t.Fatalf("GET over Unix socket: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestListenUnixDoesNotRemoveRegularFile(t *testing.T) {
	path := testSocketPath(t, false)
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenUnix(path); err == nil {
		t.Fatal("expected regular file to be rejected")
	}
	if content, err := os.ReadFile(path); err != nil || string(content) != "not a socket" {
		t.Fatalf("regular file was changed, content=%q err=%v", content, err)
	}
}
