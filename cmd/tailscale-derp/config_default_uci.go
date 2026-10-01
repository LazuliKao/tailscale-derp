//go:build uciconfig

package main

func defaultConfigFilePath() string {
	return "/etc/config/tailscale-derp"
}
