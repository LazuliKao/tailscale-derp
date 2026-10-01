//go:build !yamlconfig

package main

import (
	"os"
	"strings"
	"testing"
)

func TestYAMLConfigRequiresBuildTag(t *testing.T) {
	path := t.TempDir() + "/tailscale-derp.yaml"
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfigFile(path); err == nil || !strings.Contains(err.Error(), "yamlconfig") {
		t.Fatalf("expected yamlconfig build-tag error, got %v", err)
	}
}
