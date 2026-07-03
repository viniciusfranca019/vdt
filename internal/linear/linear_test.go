package linear

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestCommand_Registration(t *testing.T) {
	cmd := Command()

	if cmd.Use != "linear" {
		t.Errorf("Use = %q, want %q", cmd.Use, "linear")
	}

	authCmd := findSubcommand(cmd, "auth")
	if authCmd == nil {
		t.Fatal("expected \"auth\" subcommand to be registered under \"linear\"")
	}

	wantSubcommands := []string{"login", "logout"}
	for _, name := range wantSubcommands {
		if findSubcommand(authCmd, name) == nil {
			t.Errorf("expected %q subcommand to be registered under \"linear auth\"", name)
		}
	}
}

func TestCommand_Subcommands_AreWired(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "login", args: []string{"auth", "login"}},
		{name: "logout", args: []string{"auth", "logout"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := Command()
			buf := &bytes.Buffer{}
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if err == nil {
				t.Fatal("Execute() got nil error, want non-nil (stub not implemented)")
			}

			if strings.Contains(err.Error(), "unknown command") {
				t.Errorf("Execute() error = %q, want subcommand to be recognized, not unknown", err.Error())
			}
		})
	}
}

// findSubcommand returns the direct child of cmd named name, or nil if no
// such child is registered.
func findSubcommand(cmd *cobra.Command, name string) *cobra.Command {
	for _, sub := range cmd.Commands() {
		if sub.Name() == name {
			return sub
		}
	}

	return nil
}
