package portmap

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	pcpPort      = 5351
	pcpVersion   = 2
	pcpMapOpcode = 1
)

type pcpLeaseKey struct {
	gateway      netip.Addr
	source       netip.Addr
	protocol     Protocol
	internalPort uint16
}

type pcpBackend struct {
	mu     sync.Mutex
	nonces map[pcpLeaseKey][12]byte
}

func (b *pcpBackend) Map(ctx context.Context, request Request) (*Mapping, error) {
	gateway, err := defaultGateway(request.Interface)
	if err != nil {
		return nil, err
	}
	source, err := sourceIPv4(gateway, request.Interface)
	if err != nil {
		return nil, err
	}
	lifetime := normalizedLifetime(request.Lifetime)
	derp, err := b.acquire(ctx, gateway, source, request.DERP, lifetime)
	if err != nil {
		return nil, err
	}
	mapping := &Mapping{DERP: derp}
	if request.STUN != nil {
		mapping.STUN, err = b.acquire(ctx, gateway, source, *request.STUN, lifetime)
		if err != nil {
			_ = mapping.Release(context.Background())
			return nil, err
		}
	}
	return mapping, nil
}

func (b *pcpBackend) acquire(ctx context.Context, gateway, source netip.Addr, request PortRequest, lifetime time.Duration) (*Lease, error) {
	key := pcpLeaseKey{gateway: gateway, source: source, protocol: request.Protocol, internalPort: request.InternalPort}
	nonce, created, err := b.nonce(key)
	if err != nil {
		return nil, err
	}
	requested := request.ExternalPort
	if requested == 0 {
		requested = request.InternalPort
	}
	response, err := pcpMap(ctx, gateway, source, request, requested, uint32(lifetime/time.Second), nonce)
	if err != nil {
		if created {
			b.removeNonce(key, nonce)
		}
		return nil, err
	}
	lease := &Lease{
		Protocol: request.Protocol, InternalPort: request.InternalPort,
		ExternalPort: response.port, ExternalIP: response.ip,
		ExpiresAt: time.Now().Add(time.Duration(response.lifetime) * time.Second),
	}
	lease.release = func(ctx context.Context) error {
		_, err := pcpMap(ctx, gateway, source, request, lease.ExternalPort, 0, nonce)
		if err == nil {
			b.removeNonce(key, nonce)
		}
		return err
	}
	if request.Strict && lease.ExternalPort != requested {
		_ = lease.Release(context.Background())
		return nil, fmt.Errorf("strict external port %d was not granted", requested)
	}
	return lease, nil
}

func (b *pcpBackend) nonce(key pcpLeaseKey) ([12]byte, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if nonce, ok := b.nonces[key]; ok {
		return nonce, false, nil
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nonce, false, err
	}
	if b.nonces == nil {
		b.nonces = make(map[pcpLeaseKey][12]byte)
	}
	b.nonces[key] = nonce
	return nonce, true, nil
}

func (b *pcpBackend) removeNonce(key pcpLeaseKey, nonce [12]byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if current, ok := b.nonces[key]; ok && current == nonce {
		delete(b.nonces, key)
	}
}

type pcpMapResponse struct {
	ip       netip.Addr
	port     uint16
	lifetime uint32
}

func pcpMap(ctx context.Context, gateway, source netip.Addr, request PortRequest, externalPort uint16, lifetime uint32, nonce [12]byte) (pcpMapResponse, error) {
	protocol := byte(6)
	if request.Protocol == UDP {
		protocol = 17
	}
	packet := make([]byte, 60)
	packet[0] = pcpVersion
	packet[1] = pcpMapOpcode
	binary.BigEndian.PutUint32(packet[4:8], lifetime)
	sourceBytes := source.As16()
	copy(packet[8:24], sourceBytes[:])
	copy(packet[24:36], nonce[:])
	packet[36] = protocol
	binary.BigEndian.PutUint16(packet[40:42], request.InternalPort)
	binary.BigEndian.PutUint16(packet[42:44], externalPort)

	remote := net.UDPAddrFromAddrPort(netip.AddrPortFrom(gateway, pcpPort))
	conn, err := net.DialUDP("udp4", nil, remote)
	if err != nil {
		return pcpMapResponse{}, err
	}
	defer conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	response := make([]byte, 1100)
	retryDelay := 250 * time.Millisecond
	var n int
	for {
		if err := ctx.Err(); err != nil {
			return pcpMapResponse{}, err
		}
		if _, err := conn.Write(packet); err != nil {
			return pcpMapResponse{}, err
		}
		readDeadline := time.Now().Add(retryDelay)
		if deadline.Before(readDeadline) {
			readDeadline = deadline
		}
		_ = conn.SetReadDeadline(readDeadline)
		n, err = conn.Read(response)
		if err == nil {
			break
		}
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() || !time.Now().Before(deadline) {
			return pcpMapResponse{}, err
		}
		if retryDelay < time.Second {
			retryDelay *= 2
		}
	}
	response = response[:n]
	if len(response) < 60 || response[0] != pcpVersion || response[1] != 0x80|pcpMapOpcode {
		return pcpMapResponse{}, errors.New("invalid PCP MAP response")
	}
	if response[3] != 0 {
		return pcpMapResponse{}, fmt.Errorf("PCP MAP failed with result code %d", response[3])
	}
	if string(response[24:36]) != string(nonce[:]) || response[36] != protocol || binary.BigEndian.Uint16(response[40:42]) != request.InternalPort {
		return pcpMapResponse{}, errors.New("PCP MAP response did not match request")
	}
	ip, ok := netip.AddrFromSlice(response[44:60])
	if !ok {
		return pcpMapResponse{}, errors.New("PCP MAP returned an invalid address")
	}
	return pcpMapResponse{
		ip: ip.Unmap(), port: binary.BigEndian.Uint16(response[42:44]),
		lifetime: binary.BigEndian.Uint32(response[4:8]),
	}, nil
}
