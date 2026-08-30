package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/LazuliKao/tailscale-derp/internal/endpoint"
	opsapi "github.com/LazuliKao/tailscale-derp/internal/ops"
)

// --- validateConfig tests ---

func TestBuildConfig_DefaultsWithoutUCI(t *testing.T) {
	cfg, err := buildConfig([]string{}, func(string) (*uciConfig, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if cfg.Enabled {
		t.Fatal("expected service disabled by default")
	}
	if cfg.Listen != ":3478" {
		t.Fatalf("expected default listen :3478, got %q", cfg.Listen)
	}
	if !cfg.STUN {
		t.Fatal("expected STUN enabled by default")
	}
	if cfg.OpsSocket != defaultOpsSocket {
		t.Fatalf("expected default ops socket %q, got %q", defaultOpsSocket, cfg.OpsSocket)
	}
	if cfg.Health != ":9912" {
		t.Fatalf("expected default health addr :9912, got %q", cfg.Health)
	}
	if cfg.External.Enabled || cfg.External.ValidateEndpoint {
		t.Fatal("expected external endpoint management and validation disabled by default")
	}
	if strings.Join(cfg.External.Methods, ",") != "pcp,natpmp,upnp" || cfg.External.WANInterface != "auto" {
		t.Fatalf("unexpected external discovery defaults: %+v", cfg.External)
	}
	if cfg.External.DERPPort != "auto" || cfg.External.STUNPort != "auto" {
		t.Fatalf("expected automatic external ports, got DERP=%q STUN=%q", cfg.External.DERPPort, cfg.External.STUNPort)
	}
	if cfg.External.LeaseDuration != 2*time.Hour || cfg.External.RetryInterval != time.Minute || cfg.External.SyncInterval != 5*time.Minute {
		t.Fatalf("unexpected external timing defaults: %+v", cfg.External)
	}
}

func TestBuildConfig_AppliesExternalAndDERPMapSync(t *testing.T) {
	tempDir := t.TempDir()
	configPath := tempDir + "/tailscale-derp"
	content := `config tls 'tls'
	option certfile '/etc/derp/cert.pem'
	option keyfile '/etc/derp/key.pem'

config external 'external'
	option enabled '1'
	list method 'upnp'
	list method 'natpmp'
	option wan_interface 'wan'
	option derp_port '8443'
	option stun_port '5349'
	option lease_seconds '3600'
	option retry_seconds '30'
	option sync_interval '120'
	option validate_endpoint '1'

config verify_api 'primary'
	option label 'Primary'
	option tailnet '-'
	option api_key 'tskey-api-primary'
	option derpmap_sync '1'
	option region_id '901'
	option region_code 'router'
	option region_name 'Router DERP'
	option node_name 'router-1'
	option hostname 'derp.example.com'
	option cert_name 'tls.example.com'
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := buildConfig([]string{"--config", configPath}, parseUCIConfig)
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	if !cfg.External.Enabled || !cfg.External.ValidateEndpoint || !cfg.External.TLSConfigured {
		t.Fatalf("unexpected external flags: %+v", cfg.External)
	}
	if strings.Join(cfg.External.Methods, ",") != "upnp,natpmp" || cfg.External.WANInterface != "wan" {
		t.Fatalf("unexpected external discovery config: %+v", cfg.External)
	}
	if cfg.External.DERPPort != "8443" || cfg.External.STUNPort != "5349" {
		t.Fatalf("unexpected external ports: %+v", cfg.External)
	}
	if cfg.External.LeaseDuration != time.Hour || cfg.External.RetryInterval != 30*time.Second || cfg.External.SyncInterval != 2*time.Minute {
		t.Fatalf("unexpected external timing config: %+v", cfg.External)
	}
	if len(cfg.Verify.APIs) != 1 {
		t.Fatalf("expected one API instance, got %d", len(cfg.Verify.APIs))
	}
	api := cfg.Verify.APIs[0]
	if !api.DERPMapSync || api.RegionID != 901 || api.RegionCode != "router" || api.RegionName != "Router DERP" || api.NodeName != "router-1" || api.Hostname != "derp.example.com" || api.CertName != "tls.example.com" {
		t.Fatalf("unexpected DERP map sync config: %+v", api)
	}
	if len(cfg.External.ValidationNames) != 1 || cfg.External.ValidationNames[0] != "tls.example.com" {
		t.Fatalf("unexpected validation names: %v", cfg.External.ValidationNames)
	}
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("validate config: %v", err)
	}
}

func TestBuildConfig_AppliesUCIConfig(t *testing.T) {
	parsed := &uciConfig{values: map[string]map[string][]string{
		"global": {
			"enabled": {"1"},
			"listen":  {":4444"},
			"stun":    {"0"},
		},
		"tls": {
			"certfile": {"/etc/derp/cert.pem"},
			"keyfile":  {"/etc/derp/key.pem"},
		},
		"mesh": {
			"enabled": {"1"},
			"key":     {"shared-mesh-key"},
		},
		"ops": {
			"socket": {"/tmp/custom-ops.sock"},
			"health": {":9002"},
		},
	}}

	cfg, err := buildConfig([]string{"--config", "test.conf"}, func(string) (*uciConfig, error) {
		return parsed, nil
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !cfg.Enabled || cfg.Listen != ":4444" || cfg.STUN {
		t.Fatalf("unexpected global config: %+v", cfg)
	}
	if cfg.CertFile != "/etc/derp/cert.pem" || cfg.KeyFile != "/etc/derp/key.pem" {
		t.Fatalf("unexpected TLS config: %+v", cfg)
	}
	if !cfg.Mesh {
		t.Fatal("expected mesh enabled from UCI")
	}
	if cfg.MeshKey != "shared-mesh-key" {
		t.Fatalf("unexpected mesh key: %q", cfg.MeshKey)
	}
	if cfg.OpsSocket != "/tmp/custom-ops.sock" || cfg.Health != ":9002" {
		t.Fatalf("unexpected ops config: %+v", cfg)
	}
}

func TestBuildConfig_AppliesCustomTailscaledSocketSettings(t *testing.T) {
	parsed := &uciConfig{values: map[string]map[string][]string{
		"verify": {
			"tailscaled_socket_enabled": {"1"},
			"tailscaled_socket":         {" /tmp/custom-tailscaled.sock "},
		},
	}}

	cfg, err := buildConfig([]string{"--config", "test.conf"}, func(string) (*uciConfig, error) {
		return parsed, nil
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !cfg.Verify.TailscaledSocketEnabled {
		t.Fatal("expected custom tailscaled socket to be enabled")
	}
	if cfg.Verify.TailscaledSocket != "/tmp/custom-tailscaled.sock" {
		t.Fatalf("unexpected custom tailscaled socket: %q", cfg.Verify.TailscaledSocket)
	}
}

func TestBuildConfig_FlagOverridesUCI(t *testing.T) {
	parsed := &uciConfig{values: map[string]map[string][]string{
		"global": {
			"enabled": {"0"},
			"listen":  {":4444"},
			"stun":    {"0"},
		},
		"mesh": {
			"enabled": {"0"},
		},
		"ops": {
			"socket": {"/tmp/uci-ops.sock"},
			"health": {":9002"},
		},
	}}

	args := []string{
		"--config", "test.conf",
		"--enabled",
		"--listen", ":5555",
		"--stun",
		"--mesh",
		"--mesh-key", "override-mesh-key",
		"--ops-socket", "/tmp/cli-ops.sock",
		"--health", ":9101",
	}

	cfg, err := buildConfig(args, func(string) (*uciConfig, error) {
		return parsed, nil
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !cfg.Enabled || cfg.Listen != ":5555" || !cfg.STUN || !cfg.Mesh {
		t.Fatalf("flag overrides were not applied: %+v", cfg)
	}
	if cfg.MeshKey != "override-mesh-key" {
		t.Fatalf("unexpected overridden mesh key: %q", cfg.MeshKey)
	}
	if cfg.OpsSocket != "/tmp/cli-ops.sock" || cfg.Health != ":9101" {
		t.Fatalf("unexpected overridden ops values: %+v", cfg)
	}
}

func TestBuildConfig_InvalidUCIBoolean(t *testing.T) {
	parsed := &uciConfig{values: map[string]map[string][]string{
		"global": {
			"enabled": {"maybe"},
		},
	}}

	_, err := buildConfig([]string{"--config", "test.conf"}, func(string) (*uciConfig, error) {
		return parsed, nil
	})
	if err == nil {
		t.Fatal("expected invalid boolean error")
	}
	if !strings.Contains(err.Error(), "global.enabled") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildConfig_MissingConfigFallsBackToDefaults(t *testing.T) {
	cfg, err := buildConfig([]string{"--config", "missing.conf"}, func(string) (*uciConfig, error) {
		return nil, &os.PathError{Op: "open", Path: "missing.conf", Err: os.ErrNotExist}
	})
	if err != nil {
		t.Fatalf("expected missing config to be tolerated, got: %v", err)
	}
	if cfg.Listen != ":3478" || !cfg.STUN || cfg.Enabled {
		t.Fatalf("unexpected fallback config: %+v", cfg)
	}
}

func TestBuildConfig_UnexpectedConfigReadError(t *testing.T) {
	_, err := buildConfig([]string{"--config", "denied.conf"}, func(string) (*uciConfig, error) {
		return nil, errors.New("permission denied")
	})
	if err == nil {
		t.Fatal("expected unexpected config read error")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseUCIConfig_InvalidDirective(t *testing.T) {
	tempDir := t.TempDir()
	configPath := tempDir + "/invalid.conf"
	content := "config settings 'global'\ninvalid key 'value'\n"
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	_, err := parseUCIConfig(configPath)
	if err == nil {
		t.Fatal("expected invalid directive error")
	}
	if !strings.Contains(err.Error(), "unsupported directive") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStatusFromConfig_RecoversAfterError(t *testing.T) {
	state := &runtimeState{}
	state.setError(fmt.Errorf("backend unreachable"))
	state.setRunning(true)

	status := statusFromConfig(&Config{
		Listen:    ":3478",
		STUN:      true,
		Mesh:      true,
		OpsSocket: defaultOpsSocket,
		Health:    ":9912",
	}, state)

	if !status.Running {
		t.Fatal("expected running state to recover after setRunning(true)")
	}
	if status.Error != "" {
		t.Fatalf("expected cleared error after recovery, got %q", status.Error)
	}
}

func TestValidateConfig_Valid(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Listen:  ":3478",
		STUN:    true,
		Health:  ":9912",
	}
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestValidateConfig_EmptyListen(t *testing.T) {
	cfg := &Config{
		Listen: "",
	}
	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("expected error for empty listen")
	}
	if !strings.Contains(err.Error(), "listen address is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateConfig_MeshWithoutKey(t *testing.T) {
	cfg := &Config{
		Listen:    ":3478",
		Mesh:      true,
		OpsSocket: defaultOpsSocket,
	}
	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("expected error for mesh without key")
	}
	if !strings.Contains(err.Error(), "mesh requires a shared key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateConfig_MeshWithKey(t *testing.T) {
	cfg := &Config{
		Listen:    ":3478",
		Mesh:      true,
		MeshKey:   "shared-mesh-key",
		OpsSocket: defaultOpsSocket,
	}
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestValidateConfig_CertFileWithoutKeyFile(t *testing.T) {
	cfg := &Config{
		Listen:   ":3478",
		CertFile: "/path/to/cert.pem",
		KeyFile:  "",
	}
	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("expected error for certfile without keyfile")
	}
	if !strings.Contains(err.Error(), "certfile requires keyfile") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateConfig_KeyFileWithoutCertFile(t *testing.T) {
	cfg := &Config{
		Listen:   ":3478",
		CertFile: "",
		KeyFile:  "/path/to/key.pem",
	}
	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("expected error for keyfile without certfile")
	}
	if !strings.Contains(err.Error(), "keyfile requires certfile") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateConfig_BothTLSFiles(t *testing.T) {
	cfg := &Config{
		Listen:    ":3478",
		CertFile:  "/path/to/cert.pem",
		KeyFile:   "/path/to/key.pem",
		OpsSocket: defaultOpsSocket,
	}
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestValidateConfig_ExternalEndpoint(t *testing.T) {
	valid := func() *Config {
		return &Config{
			Listen:   ":3478",
			CertFile: "/path/to/cert.pem",
			KeyFile:  "/path/to/key.pem",
			External: endpoint.Config{
				Enabled:       true,
				Methods:       []string{"pcp", "natpmp", "upnp"},
				DERPPort:      "auto",
				STUNPort:      "auto",
				TLSConfigured: true,
			},
			Verify: opsapi.VerifyConfig{APIs: []opsapi.APIConfig{{
				Name: "primary", Tailnet: "-", AuthType: opsapi.APIAuthTypeAPIKey, APIKey: "secret",
				DERPMapSync: true, RegionID: 901, RegionCode: "router", RegionName: "Router DERP",
				NodeName: "router-1", Hostname: "derp.example.com",
			}}},
		}
	}

	tests := []struct {
		name string
		edit func(*Config)
		want string
	}{
		{"missing TLS", func(cfg *Config) { cfg.External.TLSConfigured = false }, "requires TLS"},
		{"unsupported method", func(cfg *Config) { cfg.External.Methods = []string{"igd"} }, "unsupported method"},
		{"invalid port", func(cfg *Config) { cfg.External.DERPPort = "70000" }, "must be auto"},
		{"external disabled", func(cfg *Config) { cfg.External.Enabled = false }, "requires external.enabled"},
		{"missing credentials", func(cfg *Config) { cfg.Verify.APIs[0].APIKey = "" }, "requires tailnet and API credentials"},
		{"reserved region", func(cfg *Config) { cfg.Verify.APIs[0].RegionID = 100 }, "between 900 and 999"},
		{"missing metadata", func(cfg *Config) { cfg.Verify.APIs[0].NodeName = "" }, "metadata is incomplete"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid()
			test.edit(cfg)
			err := validateConfig(cfg)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateConfig() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

// --- handleOps tests ---

func decodeActionResult(t *testing.T, resp *http.Response) ActionResult {
	t.Helper()
	defer resp.Body.Close()

	var result ActionResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	return result
}

func TestHandleOps_Start(t *testing.T) {
	handler := handleOpsWithExecutor(func(action string) error {
		if action != "start" {
			t.Fatalf("expected action start, got %s", action)
		}
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/ops?action=start", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	result := decodeActionResult(t, resp)
	if result.Action != "start" || result.Result != "ok" {
		t.Fatalf("unexpected response: %v", result)
	}
}

func TestHandleOps_Stop(t *testing.T) {
	handler := handleOpsWithExecutor(func(action string) error {
		if action != "stop" {
			t.Fatalf("expected action stop, got %s", action)
		}
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/ops?action=stop", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	result := decodeActionResult(t, resp)
	if result.Action != "stop" || result.Result != "ok" {
		t.Fatalf("unexpected response: %v", result)
	}
}

func TestHandleOps_Restart(t *testing.T) {
	handler := handleOpsWithExecutor(func(action string) error {
		if action != "restart" {
			t.Fatalf("expected action restart, got %s", action)
		}
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/ops?action=restart", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	result := decodeActionResult(t, resp)
	if result.Action != "restart" || result.Result != "ok" {
		t.Fatalf("unexpected response: %v", result)
	}
}

func TestHandleOps_Reload(t *testing.T) {
	handler := handleOpsWithExecutor(func(action string) error {
		if action != "reload" {
			t.Fatalf("expected action reload, got %s", action)
		}
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/ops?action=reload", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	result := decodeActionResult(t, resp)
	if result.Action != "reload" || result.Result != "ok" {
		t.Fatalf("unexpected response: %v", result)
	}
}

func TestHandleOps_UnknownAction(t *testing.T) {
	handler := handleOpsWithExecutor(func(action string) error {
		t.Fatalf("executor should not be called for unknown action %s", action)
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/ops?action=invalid", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}

	result := decodeActionResult(t, resp)
	if result.Result != "error" || result.Error != "unknown action" {
		t.Fatalf("unexpected response: %+v", result)
	}
}

func TestHandleOps_GetMethodNotAllowed(t *testing.T) {
	handler := handleOpsWithExecutor(func(action string) error {
		t.Fatalf("executor should not be called for %s", action)
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "/ops?action=start", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}

	result := decodeActionResult(t, resp)
	if result.Result != "error" || result.Error != "POST required" {
		t.Fatalf("unexpected response: %+v", result)
	}
}

func TestHandleOps_ActionExecutionFailure(t *testing.T) {
	handler := handleOpsWithExecutor(func(action string) error {
		if action != "restart" {
			t.Fatalf("expected action restart, got %s", action)
		}
		return errors.New("service action restart failed: reload refused")
	})
	req := httptest.NewRequest(http.MethodPost, "/ops?action=restart", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", resp.StatusCode)
	}

	result := decodeActionResult(t, resp)
	if result.Action != "restart" || result.Result != "error" || !strings.Contains(result.Error, "reload refused") {
		t.Fatalf("unexpected response: %+v", result)
	}
}

func TestHandleOps_ServiceScriptMissing(t *testing.T) {
	handler := handleOpsWithExecutor(func(action string) error {
		if action != "start" {
			t.Fatalf("expected action start, got %s", action)
		}
		return exec.ErrNotFound
	})
	req := httptest.NewRequest(http.MethodPost, "/ops?action=start", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}

	result := decodeActionResult(t, resp)
	if result.Action != "start" || result.Result != "error" {
		t.Fatalf("unexpected response: %+v", result)
	}
}

// --- HTTP endpoint tests via mux ---

func setupTestMux(cfg *Config) http.Handler {
	mux := http.NewServeMux()
	state := &runtimeState{}
	state.setRunning(true)
	mux.HandleFunc("/status", handleStatus(cfg, state))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"version": version})
	})
	mux.HandleFunc("/ops", handleOpsWithExecutor(func(action string) error { return nil }))
	return mux
}

func TestStatusEndpoint(t *testing.T) {
	cfg := &Config{
		Listen: ":3478",
		STUN:   true,
		Mesh:   false,
	}
	handler := setupTestMux(cfg)
	server := httptest.NewServer(handler)
	defer server.Close()

	resp, err := http.Get(server.URL + "/status")
	if err != nil {
		t.Fatalf("failed to GET /status: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if result["listen"] != ":3478" {
		t.Fatalf("expected listen :3478, got %v", result["listen"])
	}
	if result["running"] != true {
		t.Fatalf("expected running true, got %v", result["running"])
	}
	if result["stun"] != true {
		t.Fatalf("expected stun true, got %v", result["stun"])
	}
	if result["opsSocket"] != defaultOpsSocket {
		t.Fatalf("expected ops socket %q, got %v", defaultOpsSocket, result["opsSocket"])
	}
	if result["health"] != ":9912" {
		t.Fatalf("expected health :9912, got %v", result["health"])
	}
}

func TestStatusEndpoint_ServiceUnavailable(t *testing.T) {
	cfg := &Config{
		Listen: ":3478",
		STUN:   false,
		Mesh:   false,
		Health: ":9912",
	}
	state := &runtimeState{}
	state.setError(fmt.Errorf("derp listener unavailable"))

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()
	handleStatus(cfg, state)(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result Status
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if result.Running {
		t.Fatal("expected running false when service has error")
	}
	if result.Error != "derp listener unavailable" {
		t.Fatalf("unexpected error field: %q", result.Error)
	}
}

func TestHealthEndpoint(t *testing.T) {
	cfg := &Config{Listen: ":3478"}
	handler := setupTestMux(cfg)
	server := httptest.NewServer(handler)
	defer server.Close()

	resp, err := http.Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("failed to GET /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if result["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", result["status"])
	}
}

func TestVersionEndpoint(t *testing.T) {
	cfg := &Config{Listen: ":3478"}
	handler := setupTestMux(cfg)
	server := httptest.NewServer(handler)
	defer server.Close()

	resp, err := http.Get(server.URL + "/version")
	if err != nil {
		t.Fatalf("failed to GET /version: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if result["version"] != "dev" {
		t.Fatalf("expected version dev, got %v", result["version"])
	}
}

// --- Config struct tests ---

func TestConfig_PeerParsing(t *testing.T) {
	cfg := &Config{
		Listen:  ":3478",
		Mesh:    true,
		MeshKey: "shared-mesh-key",
	}
	if cfg.MeshKey != "shared-mesh-key" {
		t.Fatalf("expected shared-mesh-key, got %s", cfg.MeshKey)
	}
}

func TestConfig_DefaultValues(t *testing.T) {
	cfg := &Config{
		Enabled:   true,
		Listen:    ":3478",
		STUN:      true,
		OpsSocket: defaultOpsSocket,
		Health:    ":9912",
	}
	if !cfg.Enabled {
		t.Fatal("expected Enabled to be true")
	}
	if cfg.Mesh {
		t.Fatal("expected Mesh to be false by default")
	}
	if cfg.CertFile != "" {
		t.Fatal("expected CertFile to be empty by default")
	}
}

func TestParseUCIConfig_RepeatedVerifyAPISections(t *testing.T) {
	tempDir := t.TempDir()
	configPath := tempDir + "/tailscale-derp"
	content := `config verify 'verify'
	option enabled '1'
	option api_enabled '1'
	list url 'https://admission.example/verify'

config verify_api 'primary'
	option label 'Primary'
	option api_key 'tskey-api-primary'

config verify_api 'secondary'
	option label 'Secondary'
	option tailnet 'T1234CNTRL'
	option api_key 'tskey-api-secondary'
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	parsed, err := parseUCIConfig(configPath)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	cfg, err := buildConfig([]string{"--config", configPath}, func(string) (*uciConfig, error) {
		return parsed, nil
	})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	if len(cfg.Verify.APIs) != 2 {
		t.Fatalf("expected two API instances, got %d", len(cfg.Verify.APIs))
	}
	if cfg.Verify.APIs[0].Tailnet != "-" || cfg.Verify.APIs[1].Tailnet != "T1234CNTRL" {
		t.Fatalf("unexpected API tailnets: %+v", cfg.Verify.APIs)
	}
	if cfg.Verify.APIs[0].AuthType != opsapi.APIAuthTypeAPIKey || cfg.Verify.APIs[1].AuthType != opsapi.APIAuthTypeAPIKey {
		t.Fatalf("expected API key authentication default: %+v", cfg.Verify.APIs)
	}
	if cfg.Verify.APIs[0].APIKey != "tskey-api-primary" || cfg.Verify.APIs[1].APIKey != "tskey-api-secondary" {
		t.Fatalf("expected API keys from main config: %+v", cfg.Verify.APIs)
	}
}

func TestParseUCIConfig_AnonymousVerifyAPISection(t *testing.T) {
	tempDir := t.TempDir()
	configPath := tempDir + "/tailscale-derp"
	content := `config verify_api
	option label 'Anonymous'
	option api_key 'tskey-api-anonymous'
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := buildConfig([]string{"--config", configPath}, parseUCIConfig)
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	if len(cfg.Verify.APIs) != 1 {
		t.Fatalf("expected one API instance, got %d", len(cfg.Verify.APIs))
	}
	if cfg.Verify.APIs[0].Name != "verify_api_1" || cfg.Verify.APIs[0].APIKey != "tskey-api-anonymous" {
		t.Fatalf("unexpected anonymous API instance: %+v", cfg.Verify.APIs[0])
	}
}

func TestParseUCIConfig_OAuthAPIInstance(t *testing.T) {
	tempDir := t.TempDir()
	configPath := tempDir + "/tailscale-derp"
	content := `config verify_api 'primary'
	option auth_type 'oauth'
	option tailnet 'T1234CNTRL'
	option oauth_client_id 'client-id-primary'
	option oauth_client_secret 'client-secret-primary'
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	parsed, err := parseUCIConfig(configPath)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	cfg, err := buildConfig([]string{"--config", configPath}, func(string) (*uciConfig, error) {
		return parsed, nil
	})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	if len(cfg.Verify.APIs) != 1 || cfg.Verify.APIs[0].AuthType != opsapi.APIAuthTypeOAuth || cfg.Verify.APIs[0].OAuthClientID != "client-id-primary" || cfg.Verify.APIs[0].OAuthClientSecret != "client-secret-primary" {
		t.Fatalf("expected OAuth API instance and credentials, got %+v", cfg.Verify.APIs)
	}
}

func TestParseUCIConfig_RejectsInvalidAPIAuthType(t *testing.T) {
	tempDir := t.TempDir()
	configPath := tempDir + "/tailscale-derp"
	if err := os.WriteFile(configPath, []byte("config verify_api 'primary'\n\toption auth_type 'oidc'\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := buildConfig([]string{"--config", configPath}, parseUCIConfig); err == nil {
		t.Fatal("expected invalid API authentication type to be rejected")
	}
}
