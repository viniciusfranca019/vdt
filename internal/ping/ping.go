// Package ping is the REFERENCE MODULE for vdt CLI modules.
//
// To create a new module, copy this package's structure:
//  1. Create internal/<module>/<module>.go
//  2. Expose a Command() *cobra.Command constructor
//  3. Register it explicitly in internal/cli/registry.go
//
// Do not rely on init()-based self-registration; modules are wired
// explicitly so the CLI's command set stays discoverable and predictable.
package ping

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Command builds the "ping" subcommand, which prints "pong" to stdout
// a configurable number of times.
func Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ping",
		Short: "Print pong, repeated a configurable number of times",
		RunE: func(cmd *cobra.Command, _ []string) error {
			count, err := cmd.Flags().GetInt("count")
			if err != nil {
				return err
			}

			if count < 1 {
				return fmt.Errorf("count must be >= 1, got %d", count)
			}

			for i := 0; i < count; i++ {
				fmt.Fprintln(cmd.OutOrStdout(), "pong")
			}

			return nil
		},
	}

	cmd.Flags().Int("count", 1, "number of times to print pong")

	return cmd
}
