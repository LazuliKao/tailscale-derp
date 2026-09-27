package endpoint

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LazuliKao/tailscale-derp/internal/portmap"
)

const failureThreshold = 3

const (
	ModeNAT    = "nat"
	ModeDirect = "direct"
	FamilyIPv4 = "ipv4"
	FamilyIPv6 = "ipv6"
	FamilyDual = "dual"
)

type Config struct {
	Enabled          bool
	Mode             string
	AddressFamily    string
	Methods          []string
	WANInterface     string
	DERPPort         string
	STUNPort         string
	LeaseDuration    time.Duration
	RetryInterval    time.Duration
	SyncInterval     time.Duration
	ValidateEndpoint bool
	TLSConfigured    bool
	ValidationNames  []string
	STUNEnabled      bool
}

type Endpoint struct {
	IPv4       string `json:"ipv4,omitempty"`
	IPv6       string `json:"ipv6,omitempty"`
	DERPPort   uint16 `json:"derpPort"`
	STUNPort   int    `json:"stunPort"`
	Method     string `json:"method"`
	LeaseUntil string `json:"leaseUntil,omitempty"`
}

type FamilyValidation struct {
	State string `json:"state"`
	DERP  bool   `json:"derp"`
	STUN  bool   `json:"stun"`
	Error string `json:"error,omitempty"`
}

type ValidationResult struct {
	Scope     string            `json:"scope"`
	State     string            `json:"state"`
	DERP      bool              `json:"derp"`
	STUN      bool              `json:"stun"`
	CheckedAt string            `json:"checkedAt,omitempty"`
	Error     string            `json:"error,omitempty"`
	IPv4      *FamilyValidation `json:"ipv4,omitempty"`
	IPv6      *FamilyValidation `json:"ipv6,omitempty"`
}

type InstanceStatus struct {
	Name        string `json:"name"`
	Label       string `json:"label,omitempty"`
	State       string `json:"state"`
	LastAttempt string `json:"lastAttempt,omitempty"`
	LastSuccess string `json:"lastSuccess,omitempty"`
	Error       string `json:"error,omitempty"`
}

type Status struct {
	Enabled           bool             `json:"enabled"`
	State             string           `json:"state"`
	LocalDERPPort     uint16           `json:"localDerpPort,omitempty"`
	LocalSTUNPort     uint16           `json:"localStunPort,omitempty"`
	Endpoint          *Endpoint        `json:"endpoint,omitempty"`
	Validation        ValidationResult `json:"validation"`
	ValidationEnabled bool             `json:"validationEnabled"`
	FailureCount      int              `json:"failureCount"`
	FailureThreshold  int              `json:"failureThreshold"`
	LastAttempt       string           `json:"lastAttempt,omitempty"`
	LastSuccess       string           `json:"lastSuccess,omitempty"`
	Error             string           `json:"error,omitempty"`
	Instances         []InstanceStatus `json:"instances"`
}

type Mapper interface {
	Map(context.Context, portmap.Request) (*portmap.Mapping, error)
}

type networkFingerprinter interface {
	NetworkFingerprint(string) (string, error)
}

type publicIPDiscoverer interface {
	PublicIPv4(string) (netip.Addr, error)
}

type publicIPv6Discoverer interface {
	PublicIPv6(string) (netip.Addr, error)
}

type Validator interface {
	Validate(context.Context, Endpoint, []string, bool) ValidationResult
}

type Syncer interface {
	Publish(context.Context, Endpoint) ([]InstanceStatus, error)
	Withdraw(context.Context) ([]InstanceStatus, error)
}

// CertificateUpdater refreshes automatic certificate SANs before an endpoint
// is checked or published.
type CertificateUpdater interface {
	UpdateEndpointIPs([]string) error
	ExpectedCertHash() []byte
}

type Manager struct {
	cfg       Config
	mapper    Mapper
	validator Validator
	syncer    Syncer
	cert      CertificateUpdater

	opMu sync.Mutex
	mu   sync.RWMutex

	started       bool
	wake          chan struct{}
	localDERPPort uint16
	localSTUNPort uint16
	supportsIPv4  bool
	supportsIPv6  bool
	active        *portmap.Mapping
	endpoint      *Endpoint
	nextRenew     time.Time
	nextSync      time.Time
	network       string
	withdrawRetry bool
	status        Status
}

func NewManager(cfg Config, mapper Mapper, validator Validator, syncer Syncer, certificates ...CertificateUpdater) *Manager {
	if cfg.LeaseDuration <= 0 {
		cfg.LeaseDuration = 2 * time.Hour
	}
	if cfg.RetryInterval <= 0 {
		cfg.RetryInterval = time.Minute
	}
	if cfg.SyncInterval <= 0 {
		cfg.SyncInterval = 5 * time.Minute
	}
	if cfg.Mode == "" {
		cfg.Mode = ModeNAT
	}
	if cfg.AddressFamily == "" {
		cfg.AddressFamily = FamilyIPv4
	}
	var certificate CertificateUpdater
	if len(certificates) > 0 {
		certificate = certificates[0]
	}
	state := "disabled"
	if cfg.Enabled {
		state = "discovering"
	}
	return &Manager{
		cfg: cfg, mapper: mapper, validator: validator, syncer: syncer, cert: certificate,
		wake: make(chan struct{}, 1), supportsIPv4: true, supportsIPv6: true,
		status: Status{
			Enabled: cfg.Enabled, State: state,
			ValidationEnabled: cfg.ValidateEndpoint,
			FailureThreshold:  failureThreshold,
			Validation:        ValidationResult{Scope: "local_reachability", State: "disabled"},
		},
	}
}

func (m *Manager) SetLocalPorts(derpPort, stunPort uint16) {
	m.SetLocalBindings(derpPort, stunPort, true, true)
}

// SetLocalBindings records the listener ports and families that were actually
// bound so an IPv4-only wildcard can never publish an IPv6 endpoint.
func (m *Manager) SetLocalBindings(derpPort, stunPort uint16, ipv4, ipv6 bool) {
	m.mu.Lock()
	m.localDERPPort = derpPort
	m.localSTUNPort = stunPort
	m.supportsIPv4 = ipv4
	m.supportsIPv6 = ipv6
	m.status.LocalDERPPort = derpPort
	m.status.LocalSTUNPort = stunPort
	m.mu.Unlock()
	m.signal()
}

func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.mu.Unlock()
	go m.loop(ctx)
}

func (m *Manager) loop(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	defer m.releaseActive()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
		case <-timer.C:
		}
		if m.cfg.Enabled {
			m.maintain(ctx)
		}
		timer.Reset(m.cfg.RetryInterval)
	}
}

func (m *Manager) maintain(ctx context.Context) {
	m.mu.RLock()
	active := m.endpoint != nil
	nextRenew := m.nextRenew
	nextSync := m.nextSync
	network := m.network
	localDERP := m.localDERPPort
	localSTUN := m.localSTUNPort
	m.mu.RUnlock()
	if localDERP == 0 || (m.cfg.STUNEnabled && localSTUN == 0) {
		return
	}
	if active && m.cfg.Mode == ModeNAT && m.wantsIPv4() {
		if fingerprinter, ok := m.mapper.(networkFingerprinter); ok {
			current, err := fingerprinter.NetworkFingerprint(m.cfg.WANInterface)
			if err != nil {
				_ = m.fail(ctx, fmt.Errorf("inspect external network route: %w", err))
				return
			}
			if network != "" && current != network {
				_ = m.Reconcile(ctx)
				return
			}
		}
	}
	now := time.Now()
	switch {
	case !active || !nextRenew.After(now):
		_ = m.Reconcile(ctx)
	case !nextSync.After(now):
		_ = m.Sync(ctx)
	}
}

func (m *Manager) Reconcile(ctx context.Context) error {
	return m.reconcile(ctx, false)
}

func (m *Manager) Check(ctx context.Context) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.mu.RLock()
	current := m.endpoint
	m.mu.RUnlock()
	if current == nil {
		return errors.New("no mapped endpoint is available")
	}
	result := m.validator.Validate(ctx, *current, m.cfg.ValidationNames, m.cfg.STUNEnabled)
	m.mu.Lock()
	m.status.Validation = result
	m.mu.Unlock()
	if result.State == "failed" {
		err := errors.New(result.Error)
		if m.cfg.ValidateEndpoint {
			return m.fail(ctx, err)
		}
		return err
	}
	if result.State == "degraded" {
		current, err := m.applyPartialValidation(ctx, current, result)
		if err != nil {
			return err
		}
		m.resetValidationFailures(false)
		return m.publish(ctx, *current)
	}
	m.resetValidationFailures(true)
	return nil
}

func (m *Manager) Sync(ctx context.Context) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.mu.RLock()
	current := m.endpoint
	m.mu.RUnlock()
	if current == nil {
		return errors.New("no mapped endpoint is available")
	}
	if m.cfg.ValidateEndpoint {
		result := m.validator.Validate(ctx, *current, m.cfg.ValidationNames, m.cfg.STUNEnabled)
		m.mu.Lock()
		m.status.Validation = result
		m.mu.Unlock()
		if result.State == "failed" {
			return m.fail(ctx, errors.New(result.Error))
		}
		if result.State == "degraded" {
			var err error
			current, err = m.applyPartialValidation(ctx, current, result)
			if err != nil {
				return err
			}
			m.resetValidationFailures(false)
		} else {
			m.resetValidationFailures(true)
		}
	}
	return m.publish(ctx, *current)
}

func (m *Manager) reconcile(ctx context.Context, forceValidation bool) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	if !m.cfg.Enabled {
		return errors.New("external endpoint management is disabled")
	}
	m.mu.RLock()
	localDERP := m.localDERPPort
	localSTUN := m.localSTUNPort
	supportsIPv4 := m.supportsIPv4
	supportsIPv6 := m.supportsIPv6
	m.mu.RUnlock()
	if localDERP == 0 || (m.cfg.STUNEnabled && localSTUN == 0) {
		return m.fail(ctx, errors.New("DERP/STUN listeners are not ready"))
	}
	m.setAttempt("mapping")
	var mapping *portmap.Mapping
	candidate := Endpoint{DERPPort: localDERP, STUNPort: -1, Method: ModeDirect}
	if m.cfg.STUNEnabled {
		candidate.STUNPort = int(localSTUN)
	}
	var problems []error
	if m.wantsIPv4() && !supportsIPv4 {
		problems = append(problems, errors.New("DERP/STUN listeners are not bound for IPv4"))
	} else if m.wantsIPv4() {
		if m.cfg.Mode == ModeDirect {
			discoverer, ok := m.mapper.(publicIPDiscoverer)
			if !ok {
				problems = append(problems, errors.New("public IPv4 discovery is unavailable"))
			} else if address, err := discoverer.PublicIPv4(m.cfg.WANInterface); err != nil {
				problems = append(problems, fmt.Errorf("discover public IPv4: %w", err))
			} else {
				candidate.IPv4 = address.String()
			}
		} else {
			request, err := m.mappingRequest(localDERP, localSTUN)
			if err != nil {
				problems = append(problems, err)
			} else if mapping, err = m.mapper.Map(ctx, request); err != nil {
				problems = append(problems, err)
			} else {
				candidate.IPv4 = mapping.DERP.ExternalIP.String()
				candidate.DERPPort = mapping.DERP.ExternalPort
				candidate.STUNPort = -1
				if mapping.STUN != nil {
					candidate.STUNPort = int(mapping.STUN.ExternalPort)
				}
				candidate.Method = mapping.Method
				candidate.LeaseUntil = mapping.ExpiresAt().UTC().Format(time.RFC3339)
			}
		}
	}
	if m.wantsIPv6() && !supportsIPv6 {
		problems = append(problems, errors.New("DERP/STUN listeners are not bound for IPv6"))
	} else if m.wantsIPv6() {
		discoverer, ok := m.mapper.(publicIPv6Discoverer)
		if !ok {
			problems = append(problems, errors.New("public IPv6 discovery is unavailable"))
		} else if address, err := discoverer.PublicIPv6(m.cfg.WANInterface); err != nil {
			problems = append(problems, fmt.Errorf("discover public IPv6: %w", err))
		} else {
			candidate.IPv6 = address.String()
		}
	}
	// A DERP map node has one port set. Do not advertise Direct IPv6 through a
	// different IPv4 NAT-assigned port.
	if candidate.IPv4 != "" && candidate.IPv6 != "" && mapping != nil &&
		(candidate.DERPPort != localDERP || (m.cfg.STUNEnabled && candidate.STUNPort != int(localSTUN))) {
		_ = mapping.Release(context.Background())
		mapping = nil
		candidate.IPv4 = ""
		candidate.DERPPort = localDERP
		candidate.STUNPort = -1
		if m.cfg.STUNEnabled {
			candidate.STUNPort = int(localSTUN)
		}
		candidate.Method = ModeDirect
		candidate.LeaseUntil = ""
		problems = append(problems, errors.New("IPv4 NAT mapping did not preserve the local port required for dual-stack publishing"))
	}
	if candidate.IPv4 == "" && candidate.IPv6 == "" {
		_ = mapping.Release(context.Background())
		return m.fail(ctx, errors.Join(problems...))
	}
	if candidate.IPv4 != "" && candidate.IPv6 != "" && mapping != nil {
		candidate.Method = "nat+direct"
	}
	if !m.cfg.TLSConfigured {
		_ = mapping.Release(context.Background())
		return m.fail(ctx, errors.New("TLS certificate and key are required before publishing a DERP endpoint"))
	}
	if m.cert != nil {
		if err := m.cert.UpdateEndpointIPs(candidate.addresses()); err != nil {
			_ = mapping.Release(context.Background())
			return m.fail(ctx, fmt.Errorf("refresh automatic TLS certificate: %w", err))
		}
	}
	network := ""
	if m.cfg.Mode == ModeNAT && candidate.IPv4 != "" {
		if fingerprinter, ok := m.mapper.(networkFingerprinter); ok {
			var err error
			network, err = fingerprinter.NetworkFingerprint(m.cfg.WANInterface)
			if err != nil {
				_ = mapping.Release(context.Background())
				return m.fail(ctx, fmt.Errorf("inspect external network route: %w", err))
			}
		}
	}
	if m.cfg.ValidateEndpoint || forceValidation {
		m.setState("validating", "")
		result := m.validator.Validate(ctx, candidate, m.cfg.ValidationNames, m.cfg.STUNEnabled)
		m.mu.Lock()
		m.status.Validation = result
		m.mu.Unlock()
		candidate = candidate.validated(result)
		if candidate.IPv4 == "" && candidate.IPv6 == "" {
			_ = mapping.Release(context.Background())
			return m.fail(ctx, errors.New(result.Error))
		}
		if result.State != "passed" && result.Error != "" {
			problems = append(problems, errors.New(result.Error))
		}
		if candidate.IPv4 == "" && mapping != nil {
			_ = mapping.Release(context.Background())
			mapping = nil
			candidate.DERPPort = localDERP
			candidate.STUNPort = -1
			if m.cfg.STUNEnabled {
				candidate.STUNPort = int(localSTUN)
			}
			candidate.Method = ModeDirect
			candidate.LeaseUntil = ""
			network = ""
		}
		if m.cert != nil {
			if err := m.cert.UpdateEndpointIPs(candidate.addresses()); err != nil {
				_ = mapping.Release(context.Background())
				return m.fail(ctx, fmt.Errorf("refresh automatic TLS certificate: %w", err))
			}
		}
	} else {
		m.mu.Lock()
		m.status.Validation = ValidationResult{Scope: "local_reachability", State: "disabled"}
		m.mu.Unlock()
	}

	m.mu.Lock()
	old := m.active
	oldNetwork := m.network
	m.active = mapping
	m.endpoint = &candidate
	if mapping == nil {
		m.nextRenew = time.Now().Add(m.cfg.RetryInterval)
	} else {
		m.nextRenew = midpoint(time.Now(), mapping.ExpiresAt())
	}
	m.network = network
	m.status.Endpoint = cloneEndpoint(&candidate)
	m.status.FailureCount = 0
	m.status.Error = ""
	if problem := errors.Join(problems...); problem != nil {
		m.status.Error = problem.Error()
	}
	m.status.State = "ready"
	if len(problems) > 0 || (m.cfg.ValidateEndpoint && m.status.Validation.State != "passed") {
		m.status.State = "degraded"
	}
	m.status.LastSuccess = time.Now().UTC().Format(time.RFC3339)
	m.mu.Unlock()
	if old != nil && (oldNetwork != network || !sameMapping(old, mapping)) {
		_ = old.Release(context.Background())
	}
	if err := m.publish(ctx, candidate); err != nil {
		m.setState("degraded", err.Error())
		return err
	}
	return nil
}

func (m *Manager) publish(ctx context.Context, value Endpoint) error {
	if m.syncer == nil {
		return nil
	}
	instances, err := m.syncer.Publish(ctx, value)
	m.mu.Lock()
	m.status.Instances = instances
	m.nextSync = time.Now().Add(m.cfg.SyncInterval)
	m.mu.Unlock()
	if err != nil {
		return err
	}
	return nil
}

func (m *Manager) applyPartialValidation(ctx context.Context, current *Endpoint, result ValidationResult) (*Endpoint, error) {
	pruned := current.validated(result)
	if pruned.IPv4 == "" && pruned.IPv6 == "" {
		return nil, m.fail(ctx, errors.New(result.Error))
	}
	if m.cert != nil {
		if err := m.cert.UpdateEndpointIPs(pruned.addresses()); err != nil {
			return nil, m.fail(ctx, fmt.Errorf("refresh automatic TLS certificate: %w", err))
		}
	}

	var release *portmap.Mapping
	m.mu.Lock()
	if current.IPv4 != "" && pruned.IPv4 == "" {
		release = m.active
		m.active = nil
		m.network = ""
		m.nextRenew = time.Now().Add(m.cfg.RetryInterval)
		pruned.DERPPort = m.localDERPPort
		pruned.STUNPort = -1
		if m.cfg.STUNEnabled {
			pruned.STUNPort = int(m.localSTUNPort)
		}
		pruned.Method = ModeDirect
		pruned.LeaseUntil = ""
	}
	m.endpoint = &pruned
	m.status.Endpoint = cloneEndpoint(&pruned)
	m.status.State = "degraded"
	m.status.Error = result.Error
	m.mu.Unlock()
	if release != nil {
		_ = release.Release(context.Background())
	}
	return &pruned, nil
}

func (m *Manager) fail(ctx context.Context, err error) error {
	m.mu.Lock()
	m.status.LastAttempt = time.Now().UTC().Format(time.RFC3339)
	wasWithdrawn := m.status.State == "withdrawn"
	m.status.Error = err.Error()
	if m.cfg.ValidateEndpoint {
		m.status.FailureCount++
		if wasWithdrawn || m.status.FailureCount >= failureThreshold {
			m.status.State = "withdrawn"
		} else {
			m.status.State = "degraded"
		}
	} else if m.active != nil {
		m.status.State = "stale"
	} else {
		m.status.State = "error"
	}
	if m.cfg.ValidateEndpoint && !wasWithdrawn && m.status.FailureCount == failureThreshold {
		m.withdrawRetry = true
	}
	withdraw := m.withdrawRetry
	m.mu.Unlock()
	if !withdraw || m.syncer == nil {
		return err
	}
	instances, withdrawErr := m.syncer.Withdraw(ctx)
	m.mu.Lock()
	m.status.Instances = instances
	m.status.State = "withdrawn"
	m.withdrawRetry = withdrawErr != nil
	m.mu.Unlock()
	m.releaseActive()
	return errors.Join(err, withdrawErr)
}

func (m *Manager) resetValidationFailures(markReady bool) {
	m.mu.Lock()
	hadFailures := m.status.FailureCount > 0
	m.status.FailureCount = 0
	m.withdrawRetry = false
	if hadFailures && markReady {
		m.status.Error = ""
		if m.endpoint != nil {
			m.status.State = "ready"
		}
	}
	m.mu.Unlock()
}

func (m *Manager) mappingRequest(localDERP, localSTUN uint16) (portmap.Request, error) {
	derpExternal, derpStrict, err := requestedPort(m.cfg.DERPPort, localDERP)
	if err != nil {
		return portmap.Request{}, fmt.Errorf("DERP port: %w", err)
	}
	request := portmap.Request{
		Interface: m.cfg.WANInterface, Lifetime: m.cfg.LeaseDuration,
		DERP: portmap.PortRequest{Protocol: portmap.TCP, InternalPort: localDERP, ExternalPort: derpExternal, Strict: derpStrict},
	}
	if m.cfg.STUNEnabled {
		stunExternal, stunStrict, err := requestedPort(m.cfg.STUNPort, localSTUN)
		if err != nil {
			return portmap.Request{}, fmt.Errorf("STUN port: %w", err)
		}
		request.STUN = &portmap.PortRequest{Protocol: portmap.UDP, InternalPort: localSTUN, ExternalPort: stunExternal, Strict: stunStrict}
	}
	return request, nil
}

func (m *Manager) wantsIPv4() bool {
	return m.cfg.AddressFamily == FamilyIPv4 || m.cfg.AddressFamily == FamilyDual
}

func (m *Manager) wantsIPv6() bool {
	return m.cfg.AddressFamily == FamilyIPv6 || m.cfg.AddressFamily == FamilyDual
}

func (e Endpoint) addresses() []string {
	addresses := make([]string, 0, 2)
	if e.IPv4 != "" {
		addresses = append(addresses, e.IPv4)
	}
	if e.IPv6 != "" {
		addresses = append(addresses, e.IPv6)
	}
	return addresses
}

func (e Endpoint) validated(result ValidationResult) Endpoint {
	if result.IPv4 != nil && result.IPv4.State != "passed" {
		e.IPv4 = ""
	}
	if result.IPv6 != nil && result.IPv6.State != "passed" {
		e.IPv6 = ""
	}
	// Older validator implementations only return the aggregate result.
	if result.IPv4 == nil && result.IPv6 == nil && result.State != "passed" {
		e.IPv4 = ""
		e.IPv6 = ""
	}
	return e
}

func requestedPort(value string, local uint16) (uint16, bool, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" || value == "auto" {
		return local, false, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 16)
	if err != nil || parsed == 0 {
		return 0, false, errors.New("must be auto or an integer from 1 to 65535")
	}
	return uint16(parsed), true, nil
}

func midpoint(start, end time.Time) time.Time {
	if end.IsZero() || !end.After(start) {
		return start.Add(time.Hour)
	}
	return start.Add(end.Sub(start) / 2)
}

func sameMapping(a, b *portmap.Mapping) bool {
	if a == nil || b == nil || a.Method != b.Method || !sameLease(a.DERP, b.DERP) {
		return false
	}
	return sameLease(a.STUN, b.STUN)
}

func sameLease(a, b *portmap.Lease) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Protocol == b.Protocol &&
		a.InternalPort == b.InternalPort &&
		a.ExternalPort == b.ExternalPort &&
		a.ExternalIP == b.ExternalIP
}

func (m *Manager) setAttempt(state string) {
	m.mu.Lock()
	m.status.State = state
	m.status.LastAttempt = time.Now().UTC().Format(time.RFC3339)
	m.status.Error = ""
	m.mu.Unlock()
}

func (m *Manager) setState(state, message string) {
	m.mu.Lock()
	m.status.State = state
	m.status.Error = message
	m.mu.Unlock()
}

func (m *Manager) releaseActive() {
	m.mu.Lock()
	active := m.active
	m.active = nil
	m.endpoint = nil
	m.network = ""
	m.status.Endpoint = nil
	m.mu.Unlock()
	if active != nil {
		_ = active.Release(context.Background())
	}
}

func (m *Manager) signal() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *Manager) Status() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	status := m.status
	status.Endpoint = cloneEndpoint(m.status.Endpoint)
	status.Instances = append([]InstanceStatus(nil), m.status.Instances...)
	return status
}

func cloneEndpoint(value *Endpoint) *Endpoint {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
