//go:build yamlconfig

package main

import (
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

func loadYAMLConfig(path string) (*uciConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	var config fileConfig
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("decode YAML configuration: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decode YAML configuration: multiple documents are not supported")
		}
		return nil, fmt.Errorf("decode YAML configuration: %w", err)
	}
	return config.toUCIConfig(), nil
}
