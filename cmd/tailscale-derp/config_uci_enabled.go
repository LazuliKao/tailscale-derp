//go:build uciconfig

package main

func loadUCIConfig(path string) (*uciConfig, error) {
	return parseUCIConfig(path)
}
