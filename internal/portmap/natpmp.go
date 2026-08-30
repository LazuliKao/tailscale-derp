package portmap

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	natpmp "github.com/jackpal/go-nat-pmp"
)

type natPMPBackend struct{}

func (natPMPBackend) Map(ctx context.Context, request Request) (*Mapping, error) {
	gateway, err := defaultGateway(request.Interface)
	if err != nil {
		return nil, err
	}
	client := natpmp.NewClientWithTimeout(net.IP(gateway.AsSlice()), 3*time.Second)
	external, err := client.GetExternalAddress()
	if err != nil {
		return nil, err
	}
	externalIP := netip.AddrFrom4(external.ExternalIPAddress)
	lifetime := normalizedLifetime(request.Lifetime)

	derp, err := acquireNATPMP(ctx, client, externalIP, request.DERP, lifetime)
	if err != nil {
		return nil, err
	}
	mapping := &Mapping{DERP: derp}
	if request.STUN != nil {
		mapping.STUN, err = acquireNATPMP(ctx, client, externalIP, *request.STUN, lifetime)
		if err != nil {
			_ = mapping.Release(context.Background())
			return nil, err
		}
	}
	return mapping, nil
}

func acquireNATPMP(ctx context.Context, client *natpmp.Client, externalIP netip.Addr, request PortRequest, lifetime time.Duration) (*Lease, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	requested := request.ExternalPort
	if requested == 0 {
		requested = request.InternalPort
	}
	seconds := int(lifetime / time.Second)
	result, err := client.AddPortMapping(string(request.Protocol), int(request.InternalPort), int(requested), seconds)
	if err != nil {
		return nil, err
	}
	lease := &Lease{
		Protocol: request.Protocol, InternalPort: request.InternalPort,
		ExternalPort: result.MappedExternalPort, ExternalIP: externalIP,
		ExpiresAt: time.Now().Add(time.Duration(result.PortMappingLifetimeInSeconds) * time.Second),
	}
	lease.release = func(context.Context) error {
		_, err := client.AddPortMapping(string(request.Protocol), int(request.InternalPort), int(lease.ExternalPort), 0)
		return err
	}
	if request.Strict && lease.ExternalPort != requested {
		_ = lease.Release(context.Background())
		return nil, fmt.Errorf("strict external port %d was not granted", requested)
	}
	return lease, nil
}

func normalizedLifetime(value time.Duration) time.Duration {
	if value <= 0 {
		return 2 * time.Hour
	}
	return value
}
