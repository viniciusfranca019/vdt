// Package auth implements Linear OAuth 2.0 authentication (authorization
// code flow with PKCE): the "auth" vdt subcommand tree (login/logout), the
// on-disk credential store, and the OAuth/GraphQL client used by other
// Linear-facing modules.
package auth

import (
	"github.com/spf13/cobra"
)

// Command builds the "auth" parent command, which groups OAuth-related
// subcommands for authenticating with Linear.
func Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Authenticate with Linear via OAuth 2.0",
	}

	cmd.AddCommand(loginCommand())
	cmd.AddCommand(logoutCommand())
	cmd.AddCommand(refreshCommand())

	return cmd
}

// loginCommand builds the "login" subcommand, which will perform the
// OAuth 2.0 authorization code flow (with PKCE) against Linear.
func loginCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Authenticate with Linear",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}

			return c.login(cmd.Context(), cmd.OutOrStdout())
		},
	}
}

// logoutCommand builds the "logout" subcommand, which will remove any
// stored Linear credentials.
func logoutCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Remove stored Linear credentials",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}

			return c.logout(cmd.Context(), cmd.OutOrStdout())
		},
	}
}

// refreshCommand builds the "refresh" subcommand, which unconditionally
// exchanges the stored refresh token for a new access token, even if the
// current one has not yet expired.
func refreshCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "refresh",
		Short: "Force-refresh stored Linear credentials",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}

			return c.forceRefresh(cmd.Context(), cmd.OutOrStdout())
		},
	}
}
