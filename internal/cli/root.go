// Package cli assembles the vdt root command from explicitly registered
// modules.
package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/viniciusfranca/vdt/internal/version"
)

// NewRootCmd constructs the root "vdt" command with its built-in
// subcommands and all registered module commands attached.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "vdt",
		Short:         "vdt is a modular developer tools CLI",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the vdt version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), version.String())
			return nil
		},
	}

	root.AddCommand(versionCmd)
	root.AddCommand(moduleCommands()...)

	return root
}
