package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewRootCmd_Use(t *testing.T) {
	cmd := NewRootCmd()
	if cmd.Use != "vdt" {
		t.Errorf("Use = %q, want %q", cmd.Use, "vdt")
	}
}

func TestRootCmd_VersionSubcommand_PrintsVersion(t *testing.T) {
	cmd := NewRootCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() returned unexpected error: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, "vdt") {
		t.Errorf("output = %q, want it to contain %q", got, "vdt")
	}
}

func TestRootCmd_UnknownSubcommand_ReturnsError(t *testing.T) {
	cmd := NewRootCmd()
	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	cmd.SetOut(outBuf)
	cmd.SetErr(errBuf)
	cmd.SetArgs([]string{"definitely-not-a-command"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() with unknown subcommand: got nil error, want non-nil")
	}
}
