//go:build !schema

package main

func generateConfigSchema(string) error {
	return configFormatDisabled("JSON Schema generation", "schema")
}
