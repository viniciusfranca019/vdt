package auth

import (
	"errors"
	"fmt"
	"io"

	"github.com/viniciusfranca/vdt/internal/config"
)

// credentialResolver resolves the Linear OAuth client_id/client_secret pair
// needed to build a *Client, trying each source in order and stopping at the
// first one that is fully satisfied:
//
//  1. Environment variables (LINEAR_CLIENT_ID / LINEAR_CLIENT_SECRET), both
//     required — a half-set pair is treated as unset and falls through.
//  2. The on-disk config file (see internal/config), if it already has both
//     a non-empty ClientID and ClientSecret.
//  3. Interactive prompting, when the session is a TTY: the client_id is
//     read via the visible promptLine, the client_secret via the masked
//     promptSecret, and the pair is then persisted via saveConfig so future
//     invocations hit step 2 instead of prompting again.
//  4. Otherwise, a didactic, actionable error naming both env vars and the
//     fixed OAuth redirect address — never a secret value.
//
// Every field is a function/interface value rather than a concrete
// dependency so tests can substitute fakes without touching the real
// environment, filesystem, or terminal.
type credentialResolver struct {
	getenv        func(string) string
	loadConfig    func() (*config.Config, error)
	saveConfig    func(clientID string, secret config.Secret) error
	isInteractive func() bool
	promptLine    func(label string) (string, error)
	promptSecret  func(label string) (string, error)
	out           io.Writer
}

// resolve returns the Linear OAuth client_id/client_secret pair, trying
// environment variables, then the on-disk config file, then interactive
// prompting (persisting what was typed), and finally failing with a
// didactic error. See the credentialResolver doc comment for the exact
// precedence.
func (r credentialResolver) resolve() (string, config.Secret, error) {
	if id, secret, ok := r.fromEnv(); ok {
		return id, secret, nil
	}

	id, secret, ok, err := r.fromConfig()
	if err != nil {
		return "", "", err
	}
	if ok {
		return id, secret, nil
	}

	if r.isInteractive() {
		return r.fromPrompt()
	}

	return "", "", missingCredentialsError()
}

// fromEnv reads LINEAR_CLIENT_ID and LINEAR_CLIENT_SECRET from the
// environment. Both must be non-empty for this source to be considered
// satisfied; a half-set pair reports ok=false so resolve falls through to
// the next source rather than silently accepting a partial credential.
func (r credentialResolver) fromEnv() (string, config.Secret, bool) {
	id := r.getenv("LINEAR_CLIENT_ID")
	secret := r.getenv("LINEAR_CLIENT_SECRET")
	if id == "" || secret == "" {
		return "", "", false
	}

	return id, config.Secret(secret), true
}

// fromConfig loads the on-disk config and reports it as satisfied (ok=true)
// only when both ClientID and ClientSecret are already non-empty.
// config.ErrNotConfigured (no file yet) is treated as "nothing usable yet"
// (ok=false, err=nil), letting resolve fall through to interactive prompting
// or the non-interactive error. Any OTHER load error (parse failure,
// permission error, ...) is a genuine failure: it is wrapped and returned so
// resolve aborts immediately instead of masking it behind the didactic
// missing-credentials error or silently falling through to prompting.
func (r credentialResolver) fromConfig() (string, config.Secret, bool, error) {
	cfg, err := r.loadConfig()
	if err != nil {
		if errors.Is(err, config.ErrNotConfigured) {
			return "", "", false, nil
		}

		return "", "", false, fmt.Errorf("load linear config: %w", err)
	}

	if cfg.Linear.ClientID == "" || string(cfg.Linear.ClientSecret) == "" {
		return "", "", false, nil
	}

	return cfg.Linear.ClientID, cfg.Linear.ClientSecret, true, nil
}

// fromPrompt interactively collects the client_id (visible) and
// client_secret (masked), persists them via saveConfig, and returns the
// real typed values. Any prompt or save failure short-circuits with an
// empty clientID/clientSecret and an error that never embeds the typed
// secret value.
func (r credentialResolver) fromPrompt() (string, config.Secret, error) {
	id, err := r.promptLine("Linear OAuth client_id")
	if err != nil {
		return "", "", fmt.Errorf("read linear client_id: %w", err)
	}

	secret, err := r.promptSecret("Linear OAuth client_secret")
	if err != nil {
		return "", "", fmt.Errorf("read linear client_secret: %w", err)
	}

	// Built without interpolating secret: err here is a filesystem/encoding
	// failure from saveConfig, never the secret value itself.
	if err := r.saveConfig(id, config.Secret(secret)); err != nil {
		return "", "", fmt.Errorf("save linear credentials: %w", err)
	}

	fmt.Fprintln(r.out, "Saved Linear OAuth credentials")

	return id, config.Secret(secret), nil
}

// missingCredentialsError builds the didactic, actionable error returned
// when no Linear OAuth credentials can be resolved from the environment,
// config file, or (non-interactively) a prompt. It names both required env
// vars and the fixed local redirect address the user must register in their
// Linear OAuth application, and never embeds a secret value. Shared by
// credentialResolver.resolve and newClient so the wording lives in one
// place.
func missingCredentialsError() error {
	return fmt.Errorf(
		"linear: missing OAuth credentials.\n\n"+
			"Set LINEAR_CLIENT_ID and LINEAR_CLIENT_SECRET, obtained by creating a Linear OAuth application\n"+
			"(Linear -> Settings -> API -> OAuth applications) with the redirect URI:\n\n"+
			"    http://127.0.0.1:%d/callback\n\n"+
			"Then export them, e.g.:\n"+
			"    export LINEAR_CLIENT_ID=...\n"+
			"    export LINEAR_CLIENT_SECRET=...\n\n"+
			"See internal/linear/README.md for the full setup guide",
		redirectPort,
	)
}
