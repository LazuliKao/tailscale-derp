//go:build yamlconfig

package main

import (
	"os"
	"strings"
	"testing"

	opsapi "github.com/LazuliKao/tailscale-derp/internal/ops"
)

func TestLoadYAMLConfig(t *testing.T) {
	path := t.TempDir() + "/tailscale-derp.yaml"
	content := `global:
  enabled: true
  listen: ":4444"
  stun: false
mesh:
  enabled: true
  key: shared-mesh-key
verify_api:
  - name: primary
    tailnet: "-"
    auth_type: oauth
    oauth_client_id: client-id
    oauth_client_secret: client-secret
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := buildConfig([]string{"--config", path}, loadConfigFile)
	if err != nil {
		t.Fatalf("load YAML configuration: %v", err)
	}
	if !cfg.Enabled || cfg.Listen != ":4444" || cfg.STUN || !cfg.Mesh || cfg.MeshKey != "shared-mesh-key" {
		t.Fatalf("unexpected YAML configuration: %+v", cfg)
	}
	if len(cfg.Verify.APIs) != 1 || cfg.Verify.APIs[0].AuthType != opsapi.APIAuthTypeOAuth || cfg.Verify.APIs[0].OAuthClientID != "client-id" {
		t.Fatalf("unexpected verification YAML configuration: %+v", cfg.Verify)
	}
}

func TestLoadYAMLConfigRejectsUnknownFields(t *testing.T) {
	path := t.TempDir() + "/tailscale-derp.yml"
	if err := os.WriteFile(path, []byte("global:\n  unknown: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadConfigFile(path); err == nil || !strings.Contains(err.Error(), "field unknown not found") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}
