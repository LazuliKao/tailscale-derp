package portmap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway2"
)

type upnpBackend struct{}

type upnpService interface {
	LocalAddr() net.IP
	GetExternalIPAddressCtx(context.Context) (string, error)
	AddPortMappingCtx(context.Context, string, uint16, string, uint16, string, bool, string, uint32) error
	DeletePortMappingCtx(context.Context, string, uint16, string) error
}

type upnpAnyService interface {
	AddAnyPortMappingCtx(context.Context, string, uint16, string, uint16, string, bool, string, uint32) (uint16, error)
}

func (upnpBackend) Map(ctx context.Context, request Request) (*Mapping, error) {
	gateway, err := defaultGateway(request.Interface)
	if err != nil {
		return nil, err
	}
	source, err := sourceIPv4(gateway, request.Interface)
	if err != nil {
		return nil, err
	}
	var serviceErrs []error
	clients2, _, err2 := internetgateway2.NewWANIPConnection2ClientsCtx(ctx)
	for _, client := range clients2 {
		if mapping, err := mapUPnPService(ctx, client, request, source); err == nil {
			return mapping, nil
		} else {
			serviceErrs = append(serviceErrs, err)
		}
	}
	clients1, _, err1 := internetgateway2.NewWANIPConnection1ClientsCtx(ctx)
	for _, client := range clients1 {
		if mapping, err := mapUPnPService(ctx, client, request, source); err == nil {
			return mapping, nil
		} else {
			serviceErrs = append(serviceErrs, err)
		}
	}
	serviceErrs = append(serviceErrs, err2, err1, errors.New("no usable UPnP WANIPConnection service found"))
	return nil, errors.Join(serviceErrs...)
}

func mapUPnPService(ctx context.Context, service upnpService, request Request, source netip.Addr) (*Mapping, error) {
	localAddr, ok := netip.AddrFromSlice(service.LocalAddr())
	if !ok || localAddr.Unmap() != source.Unmap() {
		return nil, fmt.Errorf("UPnP service uses %s instead of default-route source %s", service.LocalAddr(), source)
	}
	externalRaw, err := service.GetExternalIPAddressCtx(ctx)
	if err != nil {
		return nil, err
	}
	externalIP, err := netip.ParseAddr(strings.TrimSpace(externalRaw))
	if err != nil {
		return nil, err
	}
	localIP := service.LocalAddr().String()
	lifetime := uint32(normalizedLifetime(request.Lifetime) / time.Second)
	derp, err := acquireUPnP(ctx, service, localIP, externalIP.Unmap(), request.DERP, lifetime)
	if err != nil {
		return nil, err
	}
	mapping := &Mapping{DERP: derp}
	if request.STUN != nil {
		mapping.STUN, err = acquireUPnP(ctx, service, localIP, externalIP.Unmap(), *request.STUN, lifetime)
		if err != nil {
			_ = mapping.Release(context.Background())
			return nil, err
		}
	}
	return mapping, nil
}

func acquireUPnP(ctx context.Context, service upnpService, localIP string, externalIP netip.Addr, request PortRequest, lifetime uint32) (*Lease, error) {
	protocol := strings.ToUpper(string(request.Protocol))
	requested := request.ExternalPort
	if requested == 0 {
		requested = request.InternalPort
	}
	granted := requested
	err := service.AddPortMappingCtx(ctx, "", requested, protocol, request.InternalPort, localIP, true, "tailscale-derp", lifetime)
	if err != nil && !request.Strict {
		if anyService, ok := service.(upnpAnyService); ok {
			granted, err = anyService.AddAnyPortMappingCtx(ctx, "", 0, protocol, request.InternalPort, localIP, true, "tailscale-derp", lifetime)
		}
	}
	if err != nil {
		return nil, err
	}
	lease := &Lease{
		Protocol: request.Protocol, InternalPort: request.InternalPort,
		ExternalPort: granted, ExternalIP: externalIP,
		ExpiresAt: time.Now().Add(time.Duration(lifetime) * time.Second),
	}
	lease.release = func(ctx context.Context) error {
		return service.DeletePortMappingCtx(ctx, "", lease.ExternalPort, protocol)
	}
	return lease, nil
}
