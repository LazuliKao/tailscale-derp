package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func loadConfigFile(path string) (*uciConfig, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}

	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return loadJSONConfig(path)
	case ".yaml", ".yml":
		return loadYAMLConfig(path)
	default:
		return loadUCIConfig(path)
	}
}

func configFormatDisabled(format, buildTag string) error {
	return fmt.Errorf("%s configuration support is disabled; rebuild with -tags %s", format, buildTag)
}
