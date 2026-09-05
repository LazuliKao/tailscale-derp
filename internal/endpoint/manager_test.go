package endpoint

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/LazuliKao/tailscale-derp/internal/portmap"
)

type fakeMapper struct {
	err         error
	fingerprint string
	publicIP    netip.Addr
	calls       int
}

func (m *fakeMapper) Map(context.Context, portmap.Request) (*portmap.Mapping, error) {
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	expires := time.Now().Add(time.Hour)
	return &portmap.Mapping{
		Method: "pcp",
		DERP:   &portmap.Lease{Protocol: portmap.TCP, InternalPort: 3478, ExternalPort: 443, ExternalIP: netip.MustParseAddr("8.8.8.8"), ExpiresAt: expires},
		STUN:   &portmap.Lease{Protocol: portmap.UDP, InternalPort: 3478, ExternalPort: 3478, ExternalIP: netip.MustParseAddr("8.8.8.8"), ExpiresAt: expires},
	}, nil
}

func (m *fakeMapper) NetworkFingerprint(string) (string, error) {
	return m.fingerprint, nil
}

func (m *fakeMapper) PublicIPv4(string) (netip.Addr, error) {
	if !m.publicIP.IsValid() {
		return netip.Addr{}, errors.New("no public IPv4")
	}
	return m.publicIP, nil
}

type fakeCertificateUpdater struct {
	addresses []string
}

func (c *fakeCertificateUpdater) UpdateEndpointIP(address string) error {
	c.addresses = append(c.addresses, address)
	return nil
}

func (c *fakeCertificateUpdater) ExpectedCertHash() []byte { return nil }

type fakeValidator struct {
	pass bool
}

func (v *fakeValidator) Validate(context.Context, Endpoint, []string, bool) ValidationResult {
	if v.pass {
		return ValidationResult{Scope: "local_nat_loopback", State: "passed", DERP: true, STUN: true}
	}
	return ValidationResult{Scope: "local_nat_loopback", State: "failed", Error: "loopback failed"}
}

type fakeSyncer struct {
	publishes   int
	withdraws   int
	withdrawErr error
}

func (s *fakeSyncer) Publish(context.Context, Endpoint) ([]InstanceStatus, error) {
	s.publishes++
	return []InstanceStatus{{Name: "one", State: "published"}}, nil
}

func (s *fakeSyncer) Withdraw(context.Context) ([]InstanceStatus, error) {
	s.withdraws++
	return []InstanceStatus{{Name: "one", State: "withdrawn"}}, s.withdrawErr
}

func TestValidationWithdrawsAfterThreeFailuresAndRecovers(t *testing.T) {
	mapper := &fakeMapper{}
	validator := &fakeValidator{}
	syncer := &fakeSyncer{}
	manager := NewManager(Config{
		Enabled: true, ValidateEndpoint: true, TLSConfigured: true, STUNEnabled: true,
		ValidationNames: []string{"derp.example.com"}, DERPPort: "auto", STUNPort: "auto",
	}, mapper, validator, syncer)
	manager.SetLocalPorts(3478, 3478)

	for attempt := 1; attempt <= 3; attempt++ {
		if err := manager.Reconcile(context.Background()); err == nil {
			t.Fatalf("attempt %d unexpectedly succeeded", attempt)
		}
	}
	status := manager.Status()
	if status.State != "withdrawn" || status.FailureCount != 3 || syncer.withdraws != 1 || syncer.publishes != 0 {
		t.Fatalf("unexpected status after failures: %#v, syncer=%#v", status, syncer)
	}

	validator.pass = true
	if err := manager.Reconcile(context.Background()); err != nil {
		t.Fatalf("recovery failed: %v", err)
	}
	status = manager.Status()
	if status.State != "ready" || status.FailureCount != 0 || syncer.publishes != 1 {
		t.Fatalf("unexpected recovered status: %#v, syncer=%#v", status, syncer)
	}
}

func TestDisabledValidationNeverWithdraws(t *testing.T) {
	mapper := &fakeMapper{err: errors.New("mapping failed")}
	syncer := &fakeSyncer{}
	manager := NewManager(Config{Enabled: true, TLSConfigured: true, DERPPort: "auto"}, mapper, &fakeValidator{}, syncer)
	manager.SetLocalPorts(3478, 0)
	for range 4 {
		_ = manager.Reconcile(context.Background())
	}
	status := manager.Status()
	if status.FailureCount != 0 || syncer.withdraws != 0 {
		t.Fatalf("validation-disabled failure withdrew endpoint: %#v", status)
	}
}

func TestPeriodicSyncValidationWithdrawsAndDoesNotRepeat(t *testing.T) {
	mapper := &fakeMapper{}
	validator := &fakeValidator{pass: true}
	syncer := &fakeSyncer{}
	manager := NewManager(Config{
		Enabled: true, ValidateEndpoint: true, TLSConfigured: true, STUNEnabled: true,
		ValidationNames: []string{"derp.example.com"}, DERPPort: "auto", STUNPort: "auto",
	}, mapper, validator, syncer)
	manager.SetLocalPorts(3478, 3478)
	if err := manager.Reconcile(context.Background()); err != nil {
		t.Fatalf("initial reconcile failed: %v", err)
	}

	validator.pass = false
	for attempt := 1; attempt <= 3; attempt++ {
		if err := manager.Sync(context.Background()); err == nil {
			t.Fatalf("sync %d unexpectedly succeeded", attempt)
		}
	}
	status := manager.Status()
	if status.State != "withdrawn" || status.FailureCount != 3 || syncer.withdraws != 1 {
		t.Fatalf("unexpected status after sync failures: %#v, syncer=%#v", status, syncer)
	}
	if err := manager.Reconcile(context.Background()); err == nil {
		t.Fatal("reconcile unexpectedly succeeded")
	}
	if syncer.withdraws != 1 {
		t.Fatalf("withdraw repeated after threshold: %#v", syncer)
	}
}

func TestManualCheckResetsConsecutiveFailures(t *testing.T) {
	validator := &fakeValidator{pass: true}
	manager := NewManager(Config{
		Enabled: true, ValidateEndpoint: true, TLSConfigured: true, STUNEnabled: true,
		ValidationNames: []string{"derp.example.com"}, DERPPort: "auto", STUNPort: "auto",
	}, &fakeMapper{}, validator, &fakeSyncer{})
	manager.SetLocalPorts(3478, 3478)
	if err := manager.Reconcile(context.Background()); err != nil {
		t.Fatalf("initial reconcile failed: %v", err)
	}

	validator.pass = false
	if err := manager.Check(context.Background()); err == nil {
		t.Fatal("failed check unexpectedly succeeded")
	}
	if got := manager.Status().FailureCount; got != 1 {
		t.Fatalf("failure count = %d, want 1", got)
	}
	validator.pass = true
	if err := manager.Check(context.Background()); err != nil {
		t.Fatalf("successful check failed: %v", err)
	}
	if status := manager.Status(); status.FailureCount != 0 || status.State != "ready" {
		t.Fatalf("successful check did not reset failures: %#v", status)
	}
}

func TestNetworkChangeTriggersReconcile(t *testing.T) {
	mapper := &fakeMapper{fingerprint: "wan|192.0.2.1|192.0.2.2"}
	manager := NewManager(Config{Enabled: true, TLSConfigured: true, DERPPort: "auto"}, mapper, &fakeValidator{}, &fakeSyncer{})
	manager.SetLocalPorts(3478, 0)
	if err := manager.Reconcile(context.Background()); err != nil {
		t.Fatalf("initial reconcile failed: %v", err)
	}
	mapper.fingerprint = "wwan|192.0.2.9|192.0.2.10"
	manager.maintain(context.Background())
	if mapper.calls != 2 {
		t.Fatalf("mapping calls = %d, want 2 after route change", mapper.calls)
	}
}

func TestDirectModePublishesInterfacePublicAddress(t *testing.T) {
	mapper := &fakeMapper{publicIP: netip.MustParseAddr("8.8.8.8")}
	certificates := &fakeCertificateUpdater{}
	syncer := &fakeSyncer{}
	manager := NewManager(Config{
		Enabled: true, Mode: ModeDirect, TLSConfigured: true, STUNEnabled: true,
		WANInterface: "wan",
	}, mapper, &fakeValidator{}, syncer, certificates)
	manager.SetLocalPorts(443, 3478)

	if err := manager.Reconcile(context.Background()); err != nil {
		t.Fatalf("direct reconcile failed: %v", err)
	}
	if mapper.calls != 0 {
		t.Fatalf("direct mode requested a port mapping %d times", mapper.calls)
	}
	if got := manager.Status().Endpoint; got == nil || got.IPv4 != "8.8.8.8" || got.DERPPort != 443 || got.STUNPort != 3478 || got.Method != ModeDirect {
		t.Fatalf("unexpected direct endpoint: %#v", got)
	}
	if len(certificates.addresses) != 1 || certificates.addresses[0] != "8.8.8.8" {
		t.Fatalf("certificate addresses = %#v", certificates.addresses)
	}
	if syncer.publishes != 1 {
		t.Fatalf("publishes = %d, want 1", syncer.publishes)
	}
}

func TestFailedWithdrawIsRetried(t *testing.T) {
	validator := &fakeValidator{}
	syncer := &fakeSyncer{withdrawErr: errors.New("policy API unavailable")}
	manager := NewManager(Config{
		Enabled: true, ValidateEndpoint: true, TLSConfigured: true,
		ValidationNames: []string{"derp.example.com"}, DERPPort: "auto",
	}, &fakeMapper{}, validator, syncer)
	manager.SetLocalPorts(3478, 0)
	for range 3 {
		_ = manager.Reconcile(context.Background())
	}
	if syncer.withdraws != 1 {
		t.Fatalf("withdraws = %d, want 1 at threshold", syncer.withdraws)
	}
	_ = manager.Reconcile(context.Background())
	if syncer.withdraws != 2 {
		t.Fatalf("withdraws = %d, want retry after failed withdrawal", syncer.withdraws)
	}
}
