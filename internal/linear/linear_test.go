package linear

import (
	"bytes"
	"strings"
	"testing"
)

func TestCommand_Registration(t *testing.T) {
	cmd := Command()

	if cmd.Use != "linear" {
		t.Errorf("Use = %q, want %q", cmd.Use, "linear")
	}

	wantSubcommands := []string{"login", "logout"}
	for _, name := range wantSubcommands {
		var found bool
		for _, sub := range cmd.Commands() {
			if sub.Name() == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %q subcommand to be registered", name)
		}
	}
}

func TestCommand_Subcommands_AreWired(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "login", args: []string{"login"}},
		{name: "logout", args: []string{"logout"}},
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
