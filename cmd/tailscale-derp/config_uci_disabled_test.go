//go:build !uciconfig

package main

import (
	"os"
	"strings"
	"testing"
)

func TestUCIConfigRequiresBuildTag(t *testing.T) {
	path := t.TempDir() + "/tailscale-derp.conf"
	if err := os.WriteFile(path, []byte("config global 'global'"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfigFile(path); err == nil || !strings.Contains(err.Error(), "uciconfig") {
		t.Fatalf("expected uciconfig build-tag error, got %v", err)
	}
}

func TestDefaultConfigPathWithoutUCI(t *testing.T) {
	t.Setenv("GO_TAILSCALE_DERP_CONFIG", "")
	if path := defaultConfigPath(); path != "" {
		t.Fatalf("expected no default configuration path without uciconfig, got %q", path)
	}
}
