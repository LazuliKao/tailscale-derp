//go:build !uciconfig

package main

func loadUCIConfig(string) (*uciConfig, error) {
	return nil, configFormatDisabled("UCI", "uciconfig")
}
