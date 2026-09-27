package endpoint

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"tailscale.com/net/stun"
	"tailscale.com/net/tlsdial"
)

type LocalValidator struct {
	Timeout          time.Duration
	ExpectedCertHash func() []byte
}

func (v LocalValidator) Validate(ctx context.Context, endpoint Endpoint, names []string, stunEnabled bool) ValidationResult {
	timeout := v.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	result := ValidationResult{
		Scope: "local_reachability", State: "failed",
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
		STUN:      !stunEnabled,
	}
	var failures []string
	passed := 0
	if endpoint.IPv4 != "" {
		family := v.validateFamily(ctx, endpoint, endpoint.IPv4, "tcp4", "udp4", names, stunEnabled, timeout)
		result.IPv4 = &family
		if family.State == "passed" {
			passed++
		} else {
			failures = append(failures, "IPv4: "+family.Error)
		}
	}
	if endpoint.IPv6 != "" {
		family := v.validateFamily(ctx, endpoint, endpoint.IPv6, "tcp6", "udp6", names, stunEnabled, timeout)
		result.IPv6 = &family
		if family.State == "passed" {
			passed++
		} else {
			failures = append(failures, "IPv6: "+family.Error)
		}
	}
	if passed == 0 {
		result.Error = strings.Join(failures, "; ")
		if result.Error == "" {
			result.Error = "no endpoint address is available"
		}
		return result
	}
	result.DERP = passed > 0
	result.STUN = !stunEnabled || passed > 0
	if len(failures) == 0 {
		result.State = "passed"
	} else {
		result.State = "degraded"
		result.Error = strings.Join(failures, "; ")
	}
	return result
}

func (v LocalValidator) validateFamily(ctx context.Context, endpoint Endpoint, address, tcpNetwork, udpNetwork string, names []string, stunEnabled bool, timeout time.Duration) FamilyValidation {
	result := FamilyValidation{State: "failed", STUN: !stunEnabled}
	if len(names) == 0 {
		result.Error = "a hostname or certificate name is required for TLS validation"
		return result
	}
	for _, name := range uniqueNames(names) {
		var expectedHash []byte
		if v.ExpectedCertHash != nil {
			expectedHash = v.ExpectedCertHash()
		}
		if err := validateDERP(ctx, address, endpoint.DERPPort, name, tcpNetwork, timeout, expectedHash); err != nil {
			result.Error = err.Error()
			return result
		}
	}
	result.DERP = true
	if stunEnabled {
		if endpoint.STUNPort <= 0 {
			result.Error = "mapped STUN port is unavailable"
			return result
		}
		if err := validateSTUN(ctx, address, endpoint.STUNPort, udpNetwork, timeout); err != nil {
			result.Error = err.Error()
			return result
		}
		result.STUN = true
	}
	result.State = "passed"
	return result
}

func validateDERP(ctx context.Context, address string, port uint16, serverName, network string, timeout time.Duration, expectedHash []byte) error {
	serverName = strings.TrimSpace(serverName)
	if serverName == "" {
		return errors.New("empty TLS server name")
	}
	target := net.JoinHostPort(address, fmt.Sprint(port))
	tlsConfig := &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
	if len(expectedHash) > 0 {
		if len(expectedHash) != 32 {
			return errors.New("automatic TLS certificate hash is invalid")
		}
		tlsdial.SetConfigExpectedCertHash(tlsConfig, hex.EncodeToString(expectedHash))
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, target)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout}
	requestURL := (&url.URL{Scheme: "https", Host: net.JoinHostPort(serverName, fmt.Sprint(port)), Path: "/derp/probe"}).String()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("DERP TLS loopback check failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("DERP loopback check returned HTTP %d", response.StatusCode)
	}
	return nil
}

func validateSTUN(ctx context.Context, address string, port int, network string, timeout time.Duration) error {
	remote, err := net.ResolveUDPAddr(network, net.JoinHostPort(address, fmt.Sprint(port)))
	if err != nil {
		return err
	}
	conn, err := net.DialUDP(network, nil, remote)
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	_ = conn.SetDeadline(deadline)
	txID := stun.NewTxID()
	if _, err := conn.Write(stun.Request(txID)); err != nil {
		return fmt.Errorf("STUN loopback request failed: %w", err)
	}
	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)
	if err != nil {
		return fmt.Errorf("STUN loopback response failed: %w", err)
	}
	responseID, _, err := stun.ParseResponse(buffer[:n])
	if err != nil {
		return fmt.Errorf("invalid STUN loopback response: %w", err)
	}
	if responseID != txID {
		return errors.New("STUN loopback response transaction ID did not match")
	}
	return nil
}

func uniqueNames(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
