package portmap

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

type Protocol string

const (
	TCP Protocol = "tcp"
	UDP Protocol = "udp"
)

type PortRequest struct {
	Protocol     Protocol
	InternalPort uint16
	ExternalPort uint16
	Strict       bool
}

type Request struct {
	Interface string
	DERP      PortRequest
	STUN      *PortRequest
	Lifetime  time.Duration
}

type Lease struct {
	Protocol     Protocol
	InternalPort uint16
	ExternalPort uint16
	ExternalIP   netip.Addr
	ExpiresAt    time.Time
	release      func(context.Context) error
}

func (l *Lease) Release(ctx context.Context) error {
	if l == nil || l.release == nil {
		return nil
	}
	return l.release(ctx)
}

type Mapping struct {
	Method string
	DERP   *Lease
	STUN   *Lease
}

func (m *Mapping) Release(ctx context.Context) error {
	if m == nil {
		return nil
	}
	var errs []error
	if err := m.DERP.Release(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := m.STUN.Release(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (m *Mapping) ExpiresAt() time.Time {
	if m == nil || m.DERP == nil {
		return time.Time{}
	}
	expires := m.DERP.ExpiresAt
	if m.STUN != nil && (expires.IsZero() || m.STUN.ExpiresAt.Before(expires)) {
		expires = m.STUN.ExpiresAt
	}
	return expires
}

type Backend interface {
	Map(context.Context, Request) (*Mapping, error)
}

type Client struct {
	methods  []string
	backends map[string]Backend
}

func NewClient(methods []string) *Client {
	return NewClientWithBackends(methods, map[string]Backend{
		"pcp":    &pcpBackend{},
		"natpmp": natPMPBackend{},
		"upnp":   upnpBackend{},
	})
}

func NewClientWithBackends(methods []string, backends map[string]Backend) *Client {
	if len(methods) == 0 {
		methods = []string{"pcp", "natpmp", "upnp"}
	}
	normalized := make([]string, 0, len(methods))
	for _, method := range methods {
		method = strings.ToLower(strings.TrimSpace(method))
		if method != "" {
			normalized = append(normalized, method)
		}
	}
	return &Client{methods: normalized, backends: backends}
}

func (c *Client) Map(ctx context.Context, request Request) (*Mapping, error) {
	var errs []error
	for _, method := range c.methods {
		backend := c.backends[method]
		if backend == nil {
			errs = append(errs, fmt.Errorf("%s: unsupported mapping method", method))
			continue
		}
		mapping, err := backend.Map(ctx, request)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", method, err))
			continue
		}
		if err := validateMapping(mapping, request); err != nil {
			_ = mapping.Release(context.Background())
			errs = append(errs, fmt.Errorf("%s: %w", method, err))
			continue
		}
		mapping.Method = method
		return mapping, nil
	}
	if len(errs) == 0 {
		return nil, errors.New("no port mapping methods configured")
	}
	return nil, errors.Join(errs...)
}

func (c *Client) NetworkFingerprint(interfaceName string) (string, error) {
	return networkFingerprint(interfaceName)
}

func validateMapping(mapping *Mapping, request Request) error {
	if mapping == nil || mapping.DERP == nil {
		return errors.New("DERP TCP mapping is missing")
	}
	if !IsPublicIPv4(mapping.DERP.ExternalIP) {
		return fmt.Errorf("gateway returned non-public IPv4 address %v", mapping.DERP.ExternalIP)
	}
	if mapping.DERP.ExternalPort == 0 {
		return errors.New("gateway returned an empty DERP port")
	}
	if request.DERP.Strict && mapping.DERP.ExternalPort != request.DERP.ExternalPort {
		return fmt.Errorf("gateway returned DERP port %d instead of requested port %d", mapping.DERP.ExternalPort, request.DERP.ExternalPort)
	}
	if request.STUN == nil {
		return nil
	}
	if mapping.STUN == nil {
		return errors.New("STUN UDP mapping is missing")
	}
	if mapping.STUN.ExternalIP != mapping.DERP.ExternalIP {
		return fmt.Errorf("DERP and STUN mappings returned different public addresses")
	}
	if mapping.STUN.ExternalPort == 0 {
		return errors.New("gateway returned an empty STUN port")
	}
	if request.STUN.Strict && mapping.STUN.ExternalPort != request.STUN.ExternalPort {
		return fmt.Errorf("gateway returned STUN port %d instead of requested port %d", mapping.STUN.ExternalPort, request.STUN.ExternalPort)
	}
	return nil
}

var nonPublicIPv4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

func IsPublicIPv4(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.Is4() || !addr.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range nonPublicIPv4 {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}
