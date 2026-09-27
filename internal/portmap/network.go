package portmap

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
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

var nonPublicIPv6 = []netip.Prefix{
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// IsPublicIPv6 accepts globally routable unicast IPv6 addresses and rejects
// private and documentation ranges that IsGlobalUnicast otherwise permits.
func IsPublicIPv6(addr netip.Addr) bool {
	if !addr.IsValid() || !addr.Is6() || !addr.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range nonPublicIPv6 {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

func publicIPv6(interfaceName string) (netip.Addr, error) {
	if interfaceName == "" || interfaceName == "auto" {
		return sourceIPv6()
	}
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return netip.Addr{}, err
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	candidates := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && IsPublicIPv6(prefix.Addr()) {
			candidates = append(candidates, prefix.Addr())
		}
	}
	if len(candidates) == 0 {
		return netip.Addr{}, fmt.Errorf("interface %s has no public IPv6 address", interfaceName)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Compare(candidates[j]) < 0 })
	return candidates[0], nil
}

func sourceIPv6() (netip.Addr, error) {
	remote := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[2001:4860:4860::8888]:53"))
	conn, err := net.DialUDP("udp6", nil, remote)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("select IPv6 route source: %w", err)
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, errors.New("cannot determine local IPv6 address")
	}
	addr, ok := netip.AddrFromSlice(local.IP)
	if !ok || !IsPublicIPv6(addr) {
		return netip.Addr{}, errors.New("cannot determine a public IPv6 address")
	}
	return addr, nil
}
