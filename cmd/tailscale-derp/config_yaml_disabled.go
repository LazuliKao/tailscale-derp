//go:build !yamlconfig

package main

func loadYAMLConfig(string) (*uciConfig, error) {
	return nil, configFormatDisabled("YAML", "yamlconfig")
}
