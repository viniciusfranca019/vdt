// This file is the single, explicit registration point for all vdt CLI
// modules. Modules do NOT self-register via init() side effects; each one
// must be imported and listed here so the full command set is always
// discoverable by reading this file alone.
//
// To add a new module: import its package and append its Command() to the
// slice returned by moduleCommands.
package cli

import (
	"github.com/spf13/cobra"

	"github.com/viniciusfranca/vdt/internal/linear"
	"github.com/viniciusfranca/vdt/internal/ping"
)

// moduleCommands returns every module command that should be attached to
// the root command.
func moduleCommands() []*cobra.Command {
	return []*cobra.Command{
		linear.Command(),
		ping.Command(),
	}
}
