//go:build schema

package main

import (
	"encoding/json"
	"os"
	"testing"
)

func TestGenerateConfigSchema(t *testing.T) {
	path := t.TempDir() + "/tailscale-derp.schema.json"
	if err := generateConfigSchema(path); err != nil {
		t.Fatalf("generate schema: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	if schema["title"] != "tailscale-derp configuration" {
		t.Fatalf("unexpected schema title: %v", schema["title"])
	}
}
