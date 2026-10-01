//go:build !uciconfig

package main

func defaultConfigFilePath() string {
	return ""
}
