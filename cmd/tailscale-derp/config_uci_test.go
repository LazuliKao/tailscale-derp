//go:build uciconfig

package main

import (
	"os"
	"testing"
)

func TestLoadUCIConfigWhenEnabled(t *testing.T) {
	path := t.TempDir() + "/tailscale-derp.conf"
	if err := os.WriteFile(path, []byte("config global 'global'\n\toption enabled '1'\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := buildConfig([]string{"--config", path}, loadConfigFile)
	if err != nil {
		t.Fatalf("load UCI configuration: %v", err)
	}
	if !cfg.Enabled {
		t.Fatal("expected UCI configuration to enable the service")
	}
}
