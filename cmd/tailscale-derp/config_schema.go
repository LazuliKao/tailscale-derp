//go:build schema

package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/invopop/jsonschema"
)

func generateConfigSchema(path string) error {
	reflector := &jsonschema.Reflector{AllowAdditionalProperties: false}
	schema := reflector.Reflect(&fileConfig{})
	schema.Title = "tailscale-derp configuration"
	schema.Description = "JSON Schema for tailscale-derp JSON and YAML configuration files."

	encoded, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(encoded, '\n'), 0o644)
}
