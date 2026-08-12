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
	if cfg.OpsAddr != "127.0.0.1:9911" {
		t.Fatalf("expected default ops addr 127.0.0.1:9911, got %q", cfg.OpsAddr)
	}
	if cfg.Health != ":9912" {
		t.Fatalf("expected default health addr :9912, got %q", cfg.Health)
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
			"metrics": {":9001"},
			"health":  {":9002"},
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
	if cfg.OpsAddr != ":9001" || cfg.Health != ":9002" {
		t.Fatalf("unexpected ops config: %+v", cfg)
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
			"metrics": {":9001"},
			"health":  {":9002"},
		},
	}}

	args := []string{
		"--config", "test.conf",
		"--enabled",
		"--listen", ":5555",
		"--stun",
		"--mesh",
		"--mesh-key", "override-mesh-key",
		"--ops", ":9100",
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
	if cfg.OpsAddr != ":9100" || cfg.Health != ":9101" {
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
		Listen:  ":3478",
		STUN:    true,
		Mesh:    true,
		OpsAddr: "127.0.0.1:9911",
		Health:  ":9912",
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
		OpsAddr: "127.0.0.1:9911",
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
		Listen:  ":3478",
		Mesh:    true,
		OpsAddr: "127.0.0.1:9911",
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
		Listen:  ":3478",
		Mesh:    true,
		MeshKey: "shared-mesh-key",
		OpsAddr: "127.0.0.1:9911",
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
		Listen:   ":3478",
		CertFile: "/path/to/cert.pem",
		KeyFile:  "/path/to/key.pem",
		OpsAddr:  "127.0.0.1:9911",
	}
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestValidateConfig_LoopbackOpsAddressAllowed(t *testing.T) {
	cfg := &Config{
		Listen:  ":3478",
		OpsAddr: "127.0.0.1:9911",
		Health:  ":9912",
	}

	if err := validateConfig(cfg); err != nil {
		t.Fatalf("expected loopback ops address to be allowed, got: %v", err)
	}
}

func TestValidateConfig_BareOpsPortRejected(t *testing.T) {
	cfg := &Config{
		Listen:  ":3478",
		OpsAddr: ":9911",
		Health:  ":9912",
	}

	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("expected bare ops port to be rejected")
	}
	if !strings.Contains(err.Error(), "ops must bind to loopback only") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateConfig_NonLoopbackOpsAddressRejected(t *testing.T) {
	cfg := &Config{
		Listen:  ":3478",
		OpsAddr: "10.0.0.5:9911",
		Health:  ":9912",
	}

	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("expected non-loopback ops address to be rejected")
	}
	if !strings.Contains(err.Error(), "ops must bind to loopback only") {
		t.Fatalf("unexpected error: %v", err)
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
	if result["metrics"] != "127.0.0.1:9911" {
		t.Fatalf("expected metrics 127.0.0.1:9911, got %v", result["metrics"])
	}
	if result["health"] != ":9912" {
		t.Fatalf("expected health :9912, got %v", result["health"])
	}
}

func TestStatusEndpoint_ServiceUnavailable(t *testing.T) {
	cfg := &Config{
		Listen:  ":3478",
		STUN:    false,
		Mesh:    false,
		OpsAddr: "127.0.0.1:9911",
		Health:  ":9912",
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
		Enabled: true,
		Listen:  ":3478",
		STUN:    true,
		OpsAddr: "127.0.0.1:9911",
		Health:  ":9912",
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
