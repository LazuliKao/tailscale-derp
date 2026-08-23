package ops

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/LazuliKao/tailscale-derp/internal/httpjson"
	"github.com/LazuliKao/tailscale-derp/internal/tracker"
	"tailscale.com/client/local"
	tailscaleapi "tailscale.com/client/tailscale/v2"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	defaultDeviceSyncInterval = 5 * time.Minute
	defaultDeviceCacheTTL     = 15 * time.Minute
	deviceRequestTimeout      = 10 * time.Second
	deviceAPIBaseURL          = "https://api.tailscale.com"
)

// APIConfig identifies one Tailscale Official API tailnet. APIKey is kept in
// memory only and is never included in status or device responses.
type APIConfig struct {
	Name    string
	Label   string
	Tailnet string
	APIKey  string
}

type VerifyConfig struct {
	Enabled                 bool
	URLsEnabled             bool
	TailscaledEnabled       bool
	TailscaledSocketEnabled bool
	TailscaledSocket        string
	APIEnabled              bool
	URLs                    []string
	APIs                    []APIConfig
	SyncInterval            time.Duration
	CacheTTL                time.Duration
}

type Device struct {
	NodeID              string   `json:"nodeId,omitempty"`
	NodeKey             string   `json:"nodeKey,omitempty"`
	Name                string   `json:"name,omitempty"`
	Hostname            string   `json:"hostname,omitempty"`
	User                string   `json:"user,omitempty"`
	Addresses           []string `json:"addresses,omitempty"`
	OS                  string   `json:"os,omitempty"`
	ClientVersion       string   `json:"clientVersion,omitempty"`
	Authorized          bool     `json:"authorized"`
	ConnectedToControl  bool     `json:"connectedToControl"`
	LastSeen            string   `json:"lastSeen,omitempty"`
	Expires             string   `json:"expires,omitempty"`
	Tags                []string `json:"tags,omitempty"`
	IsExternal          bool     `json:"isExternal"`
	IsEphemeral         bool     `json:"isEphemeral"`
	MultipleConnections bool     `json:"multipleConnections"`
	Sources             []string `json:"sources,omitempty"`
}

type DeviceSyncStatus struct {
	Name        string `json:"name,omitempty"`
	Label       string `json:"label,omitempty"`
	Tailnet     string `json:"tailnet,omitempty"`
	Configured  bool   `json:"configured"`
	Fresh       bool   `json:"fresh"`
	LastAttempt string `json:"lastAttempt,omitempty"`
	LastSuccess string `json:"lastSuccess,omitempty"`
	DeviceCount int    `json:"deviceCount"`
	Error       string `json:"error,omitempty"`
}

type DevicesResponse struct {
	Devices   []Device           `json:"devices"`
	Instances []DeviceSyncStatus `json:"instances"`
}

type deviceCache struct {
	devices     map[string]Device
	lastAttempt time.Time
	lastSuccess time.Time
	err         string
}

type deviceStore struct {
	mu        sync.RWMutex
	refreshMu sync.Mutex
	configs   []APIConfig
	cache     map[string]deviceCache
	client    *http.Client
	baseURL   *url.URL
	interval  time.Duration
	ttl       time.Duration
}

func normalizeVerifyConfig(cfg VerifyConfig) VerifyConfig {
	if cfg.SyncInterval <= 0 {
		cfg.SyncInterval = defaultDeviceSyncInterval
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = defaultDeviceCacheTTL
	}
	return cfg
}

func newDeviceStore(cfg VerifyConfig) *deviceStore {
	cfg = normalizeVerifyConfig(cfg)
	configs := append([]APIConfig(nil), cfg.APIs...)
	cache := make(map[string]deviceCache, len(configs))
	for i := range configs {
		if strings.TrimSpace(configs[i].Tailnet) == "" {
			configs[i].Tailnet = "-"
		}
	}
	for _, instance := range configs {
		cache[instance.Name] = deviceCache{devices: map[string]Device{}}
	}
	return &deviceStore{
		configs:  configs,
		cache:    cache,
		client:   &http.Client{Timeout: deviceRequestTimeout},
		baseURL:  mustParseURL(deviceAPIBaseURL),
		interval: cfg.SyncInterval,
		ttl:      cfg.CacheTTL,
	}
}

func (s *deviceStore) start(ctx context.Context) {
	if len(s.configs) == 0 {
		return
	}
	go func() {
		_ = s.refresh(ctx)
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = s.refresh(ctx)
			}
		}
	}()
}

func (s *deviceStore) refresh(ctx context.Context) error {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()

	var firstErr error
	for _, instance := range s.configs {
		if strings.TrimSpace(instance.APIKey) == "" || strings.TrimSpace(instance.Tailnet) == "" {
			s.recordFailure(instance.Name, errors.New("tailnet and API key are required"))
			if firstErr == nil {
				firstErr = errors.New("one or more API instances are not configured")
			}
			continue
		}
		if err := s.refreshInstance(ctx, instance); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *deviceStore) refreshInstance(ctx context.Context, instance APIConfig) error {
	ctx, cancel := context.WithTimeout(ctx, deviceRequestTimeout)
	defer cancel()

	rawDevices, err := s.apiClient(instance).Devices().List(ctx, tailscaleapi.WithFields(tailscaleapi.IncludeFieldsDefault))
	if err != nil {
		s.recordFailure(instance.Name, err)
		return err
	}

	devices := make(map[string]Device, len(rawDevices))
	for _, raw := range rawDevices {
		device := sanitizeDevice(raw, instance)
		if device.NodeKey != "" {
			devices[device.NodeKey] = device
		}
	}
	now := time.Now()
	s.mu.Lock()
	s.cache[instance.Name] = deviceCache{
		devices:     devices,
		lastAttempt: now,
		lastSuccess: now,
	}
	s.mu.Unlock()
	return nil
}

func (s *deviceStore) apiClient(instance APIConfig) *tailscaleapi.Client {
	s.mu.RLock()
	client := s.client
	baseURL := s.baseURL
	s.mu.RUnlock()
	return &tailscaleapi.Client{
		APIKey:  instance.APIKey,
		BaseURL: baseURL,
		HTTP:    client,
		Tailnet: instance.Tailnet,
	}
}

func sanitizeDevice(raw tailscaleapi.Device, instance APIConfig) Device {
	label := instance.Label
	if label == "" {
		label = instance.Name
	}
	return Device{
		NodeID:             raw.NodeID,
		NodeKey:            raw.NodeKey,
		Name:               raw.Name,
		Hostname:           raw.Hostname,
		User:               raw.User,
		Addresses:          append([]string(nil), raw.Addresses...),
		OS:                 raw.OS,
		ClientVersion:      raw.ClientVersion,
		Authorized:         raw.Authorized,
		ConnectedToControl: raw.ConnectedToControl,
		LastSeen:           formatAPITime(raw.LastSeen),
		Expires:            formatAPITimeValue(raw.Expires),
		Tags:               append([]string(nil), raw.Tags...),
		IsExternal:         raw.IsExternal,
		IsEphemeral:        raw.IsEphemeral,
		Sources:            []string{label},
	}
}

func formatAPITime(value *tailscaleapi.Time) string {
	if value == nil {
		return ""
	}
	return formatAPITimeValue(*value)
}

func formatAPITimeValue(value tailscaleapi.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func mustParseURL(value string) *url.URL {
	parsed, err := url.Parse(value)
	if err != nil {
		panic(err)
	}
	return parsed
}

func (s *deviceStore) recordFailure(name string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.cache[name]
	entry.lastAttempt = time.Now()
	if err != nil {
		entry.err = err.Error()
	}
	s.cache[name] = entry
}

func (s *deviceStore) allowed(nodeKey key.NodePublic, now time.Time) bool {
	needle := nodeKey.String()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, entry := range s.cache {
		if entry.lastSuccess.IsZero() || now.Sub(entry.lastSuccess) > s.ttl {
			continue
		}
		device, ok := entry.devices[needle]
		if ok && device.Authorized && !deviceExpired(device.Expires, now) {
			return true
		}
	}
	return false
}

func deviceExpired(value string, now time.Time) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	expires, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return true
	}
	return !expires.After(now)
}

func (s *deviceStore) snapshot() DevicesResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()

	merged := make(map[string]Device)
	instances := make([]DeviceSyncStatus, 0, len(s.configs))
	now := time.Now()
	for _, cfg := range s.configs {
		entry := s.cache[cfg.Name]
		label := cfg.Label
		if label == "" {
			label = cfg.Name
		}
		status := DeviceSyncStatus{
			Name:        cfg.Name,
			Label:       label,
			Tailnet:     cfg.Tailnet,
			Configured:  cfg.APIKey != "" && cfg.Tailnet != "",
			Fresh:       !entry.lastSuccess.IsZero() && now.Sub(entry.lastSuccess) <= s.ttl,
			DeviceCount: len(entry.devices),
			Error:       entry.err,
		}
		if !entry.lastAttempt.IsZero() {
			status.LastAttempt = entry.lastAttempt.UTC().Format(time.RFC3339)
		}
		if !entry.lastSuccess.IsZero() {
			status.LastSuccess = entry.lastSuccess.UTC().Format(time.RFC3339)
		}
		instances = append(instances, status)
		for nodeKey, device := range entry.devices {
			if existing, ok := merged[nodeKey]; ok {
				existing.Sources = appendUnique(existing.Sources, device.Sources...)
				merged[nodeKey] = existing
			} else {
				merged[nodeKey] = device
			}
		}
	}

	devices := make([]Device, 0, len(merged))
	for _, device := range merged {
		devices = append(devices, device)
	}
	return DevicesResponse{Devices: devices, Instances: instances}
}

func appendUnique(values []string, additions ...string) []string {
	seen := make(map[string]struct{}, len(values)+len(additions))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	for _, value := range additions {
		if value != "" {
			if _, ok := seen[value]; !ok {
				values = append(values, value)
				seen[value] = struct{}{}
			}
		}
	}
	return values
}

type verifier struct {
	cfg   VerifyConfig
	local *local.Client
	store *deviceStore
	track *tracker.PeerTracker
}

func newVerifier(cfg VerifyConfig, track *tracker.PeerTracker) *verifier {
	cfg = normalizeVerifyConfig(cfg)
	store := newDeviceStore(cfg)
	store.start(context.Background())
	localClient := &local.Client{}
	if cfg.TailscaledSocketEnabled {
		localClient.Socket = cfg.TailscaledSocket
	}
	return &verifier{cfg: cfg, local: localClient, store: store, track: track}
}

func (v *verifier) verify(ctx context.Context, request tailcfg.DERPAdmitClientRequest, remoteAddr string) bool {
	if !v.cfg.Enabled {
		return true
	}
	if v.cfg.URLsEnabled && v.verifyURLs(request.NodePublic) {
		return v.accept(request.NodePublic, remoteAddr)
	}
	if v.cfg.TailscaledEnabled && v.verifyTailscaled(ctx, request.NodePublic) {
		return v.accept(request.NodePublic, remoteAddr)
	}
	if v.cfg.APIEnabled && v.store.allowed(request.NodePublic, time.Now()) {
		return v.accept(request.NodePublic, remoteAddr)
	}
	return false
}

func (v *verifier) accept(nodeKey key.NodePublic, remoteAddr string) bool {
	if v.track != nil {
		v.track.Add(nodeKey.String(), remoteAddr)
	}
	return true
}

func (v *verifier) verifyTailscaled(ctx context.Context, nodeKey key.NodePublic) bool {
	ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()
	_, err := v.local.WhoIsNodeKey(ctx, nodeKey)
	return err == nil
}

func (v *verifier) verifyURLs(nodeKey key.NodePublic) bool {
	for _, verifyURL := range v.cfg.URLs {
		if checkVerifyURL(verifyURL, nodeKey.String()) == nil {
			return true
		}
	}
	return false
}

func (v *verifier) devices() DevicesResponse {
	return v.store.snapshot()
}

func (v *verifier) refresh(ctx context.Context) DevicesResponse {
	_ = v.store.refresh(ctx)
	return v.store.snapshot()
}

func handleVerify(verifier *verifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpjson.Write(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
			return
		}
		var request tailcfg.DERPAdmitClientRequest
		decoder := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
		if err := decoder.Decode(&request); err != nil || request.NodePublic == (key.NodePublic{}) {
			httpjson.Write(w, http.StatusBadRequest, map[string]string{"error": "valid DERP admission request required"})
			return
		}
		allowed := verifier.verify(r.Context(), request, r.RemoteAddr)
		httpjson.Write(w, http.StatusOK, tailcfg.DERPAdmitClientResponse{Allow: allowed})
	}
}

func handleDevices(verifier *verifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httpjson.Write(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
			return
		}
		httpjson.Write(w, http.StatusOK, verifier.devices())
	}
}

func handleDevicesRefresh(verifier *verifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpjson.Write(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
			return
		}
		httpjson.Write(w, http.StatusOK, verifier.refresh(r.Context()))
	}
}

// The following hooks keep API client tests independent of the production
// endpoint without exposing the API key through any public response.
func (s *deviceStore) setHTTPClientForTest(client *http.Client, baseURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if client != nil {
		s.client = client
	}
	if baseURL != "" {
		s.baseURL = mustParseURL(strings.TrimRight(baseURL, "/"))
	}
}
