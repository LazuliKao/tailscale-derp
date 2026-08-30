package portmap

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestIsPublicIPv4(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		address string
		want    bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"10.0.0.1", false},
		{"100.64.0.1", false},
		{"192.168.1.1", false},
		{"198.51.100.1", false},
		{"127.0.0.1", false},
		{"2001:4860:4860::8888", false},
	} {
		if got := IsPublicIPv4(netip.MustParseAddr(test.address)); got != test.want {
			t.Errorf("IsPublicIPv4(%q) = %v, want %v", test.address, got, test.want)
		}
	}
}

type backendFunc func(context.Context, Request) (*Mapping, error)

func (fn backendFunc) Map(ctx context.Context, request Request) (*Mapping, error) {
	return fn(ctx, request)
}

func TestClientFallsBackAndRejectsDifferentAddresses(t *testing.T) {
	t.Parallel()
	called := 0
	client := NewClientWithBackends([]string{"pcp", "upnp"}, map[string]Backend{
		"pcp": backendFunc(func(context.Context, Request) (*Mapping, error) {
			called++
			return nil, errors.New("unavailable")
		}),
		"upnp": backendFunc(func(context.Context, Request) (*Mapping, error) {
			called++
			return &Mapping{
				DERP: &Lease{ExternalIP: netip.MustParseAddr("8.8.8.8"), ExternalPort: 443, ExpiresAt: time.Now().Add(time.Hour)},
				STUN: &Lease{ExternalIP: netip.MustParseAddr("1.1.1.1"), ExternalPort: 3478, ExpiresAt: time.Now().Add(time.Hour)},
			}, nil
		}),
	})
	_, err := client.Map(context.Background(), Request{
		DERP: PortRequest{Protocol: TCP, InternalPort: 443, ExternalPort: 443},
		STUN: &PortRequest{Protocol: UDP, InternalPort: 3478, ExternalPort: 3478},
	})
	if err == nil {
		t.Fatal("Map succeeded with different TCP and UDP public addresses")
	}
	if called != 2 {
		t.Fatalf("called %d backends, want 2", called)
	}
}

func TestPCPBackendReusesLeaseNonce(t *testing.T) {
	t.Parallel()
	backend := &pcpBackend{}
	key := pcpLeaseKey{
		gateway:      netip.MustParseAddr("192.168.1.1"),
		source:       netip.MustParseAddr("192.168.1.2"),
		protocol:     TCP,
		internalPort: 3478,
	}
	first, created, err := backend.nonce(key)
	if err != nil || !created {
		t.Fatalf("first nonce = %x, %v, %v; want a newly created nonce", first, created, err)
	}
	second, created, err := backend.nonce(key)
	if err != nil || created || second != first {
		t.Fatalf("second nonce = %x, %v, %v; want reused %x", second, created, err, first)
	}
	backend.removeNonce(key, first)
	third, created, err := backend.nonce(key)
	if err != nil || !created || third == first {
		t.Fatalf("replacement nonce = %x, %v, %v; want a new nonce", third, created, err)
	}
}
