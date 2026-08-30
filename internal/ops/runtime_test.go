package ops

import (
	"context"
	"net/netip"
	"testing"

	"tailscale.com/types/key"
)

func TestRuntimeVerifierFailsClosedWhenUnavailable(t *testing.T) {
	var runtime *Runtime
	err := runtime.VerifyClientFunc()(context.Background(), key.NewNode().Public(), netip.MustParseAddr("192.0.2.1"))
	if err == nil {
		t.Fatal("unavailable runtime allowed a client")
	}
}
