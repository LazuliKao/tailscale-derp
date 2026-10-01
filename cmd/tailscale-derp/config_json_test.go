//go:build jsonconfig

package main

import (
	"os"
	"strings"
	"testing"

	"github.com/LazuliKao/tailscale-derp/internal/endpoint"
)

func TestLoadJSONConfig(t *testing.T) {
	path := t.TempDir() + "/tailscale-derp.json"
	content := `{
  "global": {"enabled": true, "listen": ":4444", "stun": false},
  "tls": {"mode": "self_signed", "state_dir": "/tmp/tls"},
  "external": {"enabled": true, "mode": "direct", "address_family": "dual", "methods": ["upnp"]},
  "verify": {"enabled": true, "urls": ["https://admission.example/verify"]},
  "verify_api": [{"name": "primary", "tailnet": "-", "api_key": "tskey-api-primary"}]
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := buildConfig([]string{"--config", path}, loadConfigFile)
	if err != nil {
		t.Fatalf("load JSON configuration: %v", err)
	}
	if !cfg.Enabled || cfg.Listen != ":4444" || cfg.STUN || cfg.TLSMode != "self_signed" || cfg.TLSStateDir != "/tmp/tls" {
		t.Fatalf("unexpected JSON configuration: %+v", cfg)
	}
	if !cfg.External.Enabled || cfg.External.Mode != endpoint.ModeDirect || cfg.External.AddressFamily != endpoint.FamilyDual || strings.Join(cfg.External.Methods, ",") != "upnp" {
		t.Fatalf("unexpected external JSON configuration: %+v", cfg.External)
	}
	if !cfg.Verify.Enabled || len(cfg.Verify.URLs) != 1 || len(cfg.Verify.APIs) != 1 || cfg.Verify.APIs[0].Name != "primary" {
		t.Fatalf("unexpected verification JSON configuration: %+v", cfg.Verify)
	}
}

func TestLoadJSONConfigRejectsUnknownFields(t *testing.T) {
	path := t.TempDir() + "/tailscale-derp.json"
	if err := os.WriteFile(path, []byte(`{"global":{"unknown":true}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadConfigFile(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}
