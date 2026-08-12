package service

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const DefaultScriptPath = "/etc/init.d/tailscale-derp"

func AllowedAction(action string) bool {
	switch action {
	case "start", "stop", "restart", "reload":
		return true
	default:
		return false
	}
}

func RunAction(action, scriptPath string, timeout time.Duration) error {
	if !AllowedAction(action) {
		return fmt.Errorf("unknown action %q", action)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	command := exec.CommandContext(ctx, scriptPath, action)
	output, err := command.CombinedOutput()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("service action %s timed out after %s", action, timeout)
		}
		trimmed := strings.TrimSpace(string(output))
		if trimmed == "" {
			return fmt.Errorf("service action %s failed: %w", action, err)
		}
		return fmt.Errorf("service action %s failed: %s", action, trimmed)
	}

	return nil
}
