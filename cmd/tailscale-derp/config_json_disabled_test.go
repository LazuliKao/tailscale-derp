//go:build !jsonconfig

package main

import (
	"os"
	"strings"
	"testing"
)

func TestJSONConfigRequiresBuildTag(t *testing.T) {
	path := t.TempDir() + "/tailscale-derp.json"
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfigFile(path); err == nil || !strings.Contains(err.Error(), "jsonconfig") {
		t.Fatalf("expected jsonconfig build-tag error, got %v", err)
	}
}
