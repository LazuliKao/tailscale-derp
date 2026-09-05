package portmap

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

func defaultGateway(interfaceName string) (netip.Addr, error) {
	_, gateway, err := defaultRoute(interfaceName)
	return gateway, err
}

func defaultRoute(interfaceName string) (string, netip.Addr, error) {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return "", netip.Addr{}, fmt.Errorf("read default route: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	bestInterface := ""
	bestGateway := netip.Addr{}
	bestMetric := int(^uint(0) >> 1)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 7 || fields[1] != "00000000" {
			continue
		}
		if interfaceName != "" && interfaceName != "auto" && fields[0] != interfaceName {
			continue
		}
		flags, err := parseRouteHex(fields[3])
		if err != nil || flags&0x2 == 0 {
			continue
		}
		raw, err := hex.DecodeString(fields[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		metric, err := strconv.Atoi(fields[6])
		if err != nil || metric >= bestMetric {
			continue
		}
		bestInterface = fields[0]
		bestGateway = netip.AddrFrom4([4]byte{raw[3], raw[2], raw[1], raw[0]})
		bestMetric = metric
	}
	if err := scanner.Err(); err != nil {
		return "", netip.Addr{}, err
	}
	if bestGateway.IsValid() {
		return bestInterface, bestGateway, nil
	}
	return "", netip.Addr{}, errors.New("IPv4 default gateway not found")
}

func networkFingerprint(interfaceName string) (string, error) {
	interfaceName, gateway, err := defaultRoute(interfaceName)
	if err != nil {
		return "", err
	}
	source, err := sourceIPv4(gateway, interfaceName)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s|%s|%s", interfaceName, gateway, source), nil
}

func parseRouteHex(value string) (uint64, error) {
	var result uint64
	for _, char := range value {
		result <<= 4
		switch {
		case char >= '0' && char <= '9':
			result |= uint64(char - '0')
		case char >= 'a' && char <= 'f':
			result |= uint64(char-'a') + 10
		case char >= 'A' && char <= 'F':
			result |= uint64(char-'A') + 10
		default:
			return 0, errors.New("invalid route flags")
		}
	}
	return result, nil
}

func sourceIPv4(gateway netip.Addr, interfaceName string) (netip.Addr, error) {
	if interfaceName != "" && interfaceName != "auto" {
		iface, err := net.InterfaceByName(interfaceName)
		if err != nil {
			return netip.Addr{}, err
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return netip.Addr{}, err
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err == nil && prefix.Addr().Is4() {
				return prefix.Addr(), nil
			}
		}
		return netip.Addr{}, fmt.Errorf("interface %s has no IPv4 address", interfaceName)
	}

	conn, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(gateway, 9)))
	if err != nil {
		return netip.Addr{}, err
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, errors.New("cannot determine local IPv4 address")
	}
	addr, ok := netip.AddrFromSlice(local.IP)
	if !ok || !addr.Unmap().Is4() {
		return netip.Addr{}, errors.New("cannot determine local IPv4 address")
	}
	return addr.Unmap(), nil
}

func publicIPv4(interfaceName string) (netip.Addr, error) {
	if interfaceName == "" || interfaceName == "auto" {
		var err error
		interfaceName, _, err = defaultRoute("auto")
		if err != nil {
			return netip.Addr{}, err
		}
	}
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return netip.Addr{}, err
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && IsPublicIPv4(prefix.Addr()) {
			return prefix.Addr(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("interface %s has no public IPv4 address", interfaceName)
}
