//go:build jsonconfig

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

func loadJSONConfig(path string) (*uciConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var config fileConfig
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("decode JSON configuration: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decode JSON configuration: multiple documents are not supported")
		}
		return nil, fmt.Errorf("decode JSON configuration: %w", err)
	}
	return config.toUCIConfig(), nil
}
