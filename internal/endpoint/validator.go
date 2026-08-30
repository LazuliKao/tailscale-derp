package endpoint

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"tailscale.com/net/stun"
)

type LocalValidator struct {
	Timeout time.Duration
}

func (v LocalValidator) Validate(ctx context.Context, endpoint Endpoint, names []string, stunEnabled bool) ValidationResult {
	timeout := v.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	result := ValidationResult{
		Scope: "local_nat_loopback", State: "failed",
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
		STUN:      !stunEnabled,
	}
	if len(names) == 0 {
		result.Error = "a hostname or certificate name is required for TLS validation"
		return result
	}
	for _, name := range uniqueNames(names) {
		if err := validateDERP(ctx, endpoint, name, timeout); err != nil {
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
		if err := validateSTUN(ctx, endpoint, timeout); err != nil {
			result.Error = err.Error()
			return result
		}
		result.STUN = true
	}
	result.State = "passed"
	return result
}

func validateDERP(ctx context.Context, endpoint Endpoint, serverName string, timeout time.Duration) error {
	serverName = strings.TrimSpace(serverName)
	if serverName == "" {
		return errors.New("empty TLS server name")
	}
	target := net.JoinHostPort(endpoint.IPv4, fmt.Sprint(endpoint.DERPPort))
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, target)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout}
	requestURL := (&url.URL{Scheme: "https", Host: net.JoinHostPort(serverName, fmt.Sprint(endpoint.DERPPort)), Path: "/derp/probe"}).String()
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

func validateSTUN(ctx context.Context, endpoint Endpoint, timeout time.Duration) error {
	remote, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(endpoint.IPv4, fmt.Sprint(endpoint.STUNPort)))
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp4", nil, remote)
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
