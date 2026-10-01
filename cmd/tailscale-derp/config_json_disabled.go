//go:build !jsonconfig

package main

func loadJSONConfig(string) (*uciConfig, error) {
	return nil, configFormatDisabled("JSON", "jsonconfig")
}
