// Package linear implements the "linear" vdt module, which authenticates
// against Linear via OAuth 2.0.
package linear

import (
	"errors"

	"github.com/spf13/cobra"
)

// Command builds the "linear" parent command, which groups OAuth-related
// subcommands for authenticating with Linear.
func Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "linear",
		Short: "Interact with Linear via OAuth 2.0",
	}

	cmd.AddCommand(loginCommand())
	cmd.AddCommand(logoutCommand())

	return cmd
}

// loginCommand builds the "login" subcommand, which will perform the
// OAuth 2.0 authorization code flow (with PKCE) against Linear.
func loginCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Authenticate with Linear",
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("not implemented")
		},
	}
}

// logoutCommand builds the "logout" subcommand, which will remove any
// stored Linear credentials.
func logoutCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Remove stored Linear credentials",
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("not implemented")
		},
	}
}
