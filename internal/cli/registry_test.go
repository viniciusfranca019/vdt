package cli

import "testing"

func TestNewRootCmd_HasPingSubcommand(t *testing.T) {
	cmd := NewRootCmd()

	var found bool
	for _, sub := range cmd.Commands() {
		if sub.Name() == "ping" {
			found = true
			break
		}
	}

	if !found {
		names := make([]string, 0, len(cmd.Commands()))
		for _, sub := range cmd.Commands() {
			names = append(names, sub.Name())
		}
		t.Errorf("expected root command to have a %q subcommand, got commands: %v", "ping", names)
	}
}
