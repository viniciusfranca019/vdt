// Package linear implements the "linear" vdt module, which groups
// Linear-related subcommands (currently OAuth authentication, under
// "auth"; future Linear-facing subcommands will be added alongside it).
package linear

import (
	"github.com/spf13/cobra"

	"github.com/viniciusfranca/vdt/internal/linear/auth"
)

// Command builds the "linear" parent command, which groups Linear-related
// subcommands.
func Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "linear",
		Short: "Interact with Linear",
	}

	cmd.AddCommand(auth.Command())

	return cmd
}
