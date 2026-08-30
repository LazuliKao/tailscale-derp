package derpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tailscale.com/derp"
	"tailscale.com/types/key"
)

func TestVerifyClientFuncRejectsAndReceivesClientDetails(t *testing.T) {
	server := New(key.NewNode(), t.Logf)
	nodeKey := key.NewNode().Public()
	wantErr := errors.New("not admitted")
	var gotContext context.Context
	var gotKey key.NodePublic
	var gotIP netip.Addr
	server.SetVerifyClientFunc(func(ctx context.Context, gotNodeKey key.NodePublic, clientIP netip.Addr) error {
		gotContext, gotKey, gotIP = ctx, gotNodeKey, clientIP
		return wantErr
	})

	err := server.verifyClient(context.Background(), nodeKey, nil, netip.MustParseAddr("192.0.2.1"))
	if !errors.Is(err, wantErr) {
		t.Fatalf("verifyClient error = %v, want wrapped %v", err, wantErr)
	}
	if gotContext == nil {
		t.Fatal("callback did not receive a context")
	}
	if gotKey != nodeKey {
		t.Fatalf("callback key = %v, want %v", gotKey, nodeKey)
	}
	if gotIP != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("callback IP = %v, want 192.0.2.1", gotIP)
	}
}

func TestVerifyClientFuncHasFiveSecondDeadline(t *testing.T) {
	server := New(key.NewNode(), t.Logf)
	server.SetVerifyClientFunc(func(ctx context.Context, _ key.NodePublic, _ netip.Addr) error {
		deadline, ok := ctx.Deadline()
		if !ok {
			return errors.New("callback context has no deadline")
		}
		remaining := time.Until(deadline)
		if remaining <= 0 || remaining > 5*time.Second {
			return errors.New("callback deadline is outside five-second bound")
		}
		return nil
	})
	if err := server.verifyClient(context.Background(), key.NewNode().Public(), nil, netip.Addr{}); err != nil {
		t.Fatalf("verifyClient: %v", err)
	}
}

func TestVerifyClientFuncComposesAfterURLVerifier(t *testing.T) {
	var callbackCalls int
	admission := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer admission.Close()

	server := New(key.NewNode(), t.Logf)
	server.SetVerifyClientURL(admission.URL)
	server.SetVerifyClientFunc(func(context.Context, key.NodePublic, netip.Addr) error {
		callbackCalls++
		return nil
	})
	if err := server.verifyClient(context.Background(), key.NewNode().Public(), nil, netip.Addr{}); err == nil {
		t.Fatal("verifyClient accepted a client rejected by the built-in URL verifier")
	}
	if callbackCalls != 0 {
		t.Fatalf("callback called %d times after URL rejection, want 0", callbackCalls)
	}
}

func TestVerifyClientFuncSkippedForMeshPeer(t *testing.T) {
	server := New(key.NewNode(), t.Logf)
	meshKey, err := key.ParseDERPMesh(strings.Repeat("01", 32))
	if err != nil {
		t.Fatal(err)
	}
	server.meshKey = meshKey
	called := false
	server.SetVerifyClientFunc(func(context.Context, key.NodePublic, netip.Addr) error {
		called = true
		return errors.New("must not run for mesh")
	})
	info := &derp.ClientInfo{MeshKey: meshKey}
	if err := server.verifyClient(context.Background(), key.NewNode().Public(), info, netip.Addr{}); err != nil {
		t.Fatalf("mesh peer rejected: %v", err)
	}
	if called {
		t.Fatal("callback ran for mesh peer")
	}
}

func TestVerifyClientFuncHonorsParentCancellation(t *testing.T) {
	server := New(key.NewNode(), t.Logf)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	server.SetVerifyClientFunc(func(callbackCtx context.Context, _ key.NodePublic, _ netip.Addr) error {
		<-callbackCtx.Done()
		return callbackCtx.Err()
	})
	if err := server.verifyClient(ctx, key.NewNode().Public(), nil, netip.Addr{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("verifyClient error = %v, want context.Canceled", err)
	}
}
