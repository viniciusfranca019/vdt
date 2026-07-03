package linear

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/viniciusfranca/vdt/internal/config"
)

const (
	// defaultAuthorizeURL, defaultTokenURL, defaultRevokeURL and
	// defaultAPIURL are Linear's production OAuth 2.0 and GraphQL API
	// endpoints, wired into every *Client built by newClient. Tests build
	// their own *Client literal and point these fields at httptest servers
	// instead, so these constants are never referenced outside newClient.
	defaultAuthorizeURL = "https://linear.app/oauth/authorize"
	//nolint:gosec // G101 false positive: this is a public endpoint URL
	// (containing the path segment "token"), not a credential value.
	defaultTokenURL  = "https://api.linear.app/oauth/token"
	defaultRevokeURL = "https://api.linear.app/oauth/revoke"
	defaultAPIURL    = "https://api.linear.app/graphql"

	// redirectPort is the fixed loopback port vdt listens on for the OAuth
	// authorization redirect. It is fixed (rather than ephemeral, port 0)
	// because it must match the single redirect_uri
	// (http://127.0.0.1:53682/callback) registered in the Linear OAuth
	// application's settings.
	redirectPort = 53682

	// httpClientTimeout bounds every outgoing request newClient's *Client
	// makes to Linear's OAuth and GraphQL endpoints.
	httpClientTimeout = 30 * time.Second
)

// newClient builds a *Client wired for real use against Linear: production
// OAuth/API endpoints, the real system-browser opener, crypto/rand for
// PKCE/state generation, and an on-disk credentials store rooted under the
// user's OS config directory (via os.UserConfigDir, never a path relative to
// the working directory or repository — see CLAUDE.md "Config paths").
//
// Client credentials are read env-first (see CLAUDE.md "Secrets sourcing"):
// LINEAR_CLIENT_ID and LINEAR_CLIENT_SECRET must both be set. There is
// deliberately no on-disk fallback yet, since internal/config.Load is still
// a stub with no parsing for arbitrary per-module credentials.
func newClient() (*Client, error) {
	clientID := os.Getenv("LINEAR_CLIENT_ID")
	clientSecret := os.Getenv("LINEAR_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		return nil, errors.New("linear: LINEAR_CLIENT_ID and LINEAR_CLIENT_SECRET must both be set (see your Linear OAuth application's settings)")
	}

	userConfigDir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("resolve linear credentials directory: %w", err)
	}

	return &Client{
		http:         &http.Client{Timeout: httpClientTimeout},
		now:          time.Now,
		openBrowser:  openInBrowser,
		rand:         rand.Reader,
		store:        newStore(filepath.Join(userConfigDir, "vdt")),
		clientID:     clientID,
		clientSecret: config.Secret(clientSecret),
		authorizeURL: defaultAuthorizeURL,
		tokenURL:     defaultTokenURL,
		revokeURL:    defaultRevokeURL,
		apiURL:       defaultAPIURL,
		redirectPort: redirectPort,
	}, nil
}

// login performs the Linear OAuth 2.0 authorization code flow with PKCE
// (RFC 6749 §4.1 + RFC 7636), short-circuiting entirely — no browser, no
// callback server, no token exchange — whenever the store already holds a
// non-expired access token.
func (c *Client) login(ctx context.Context, out io.Writer) error {
	if access, err := c.validToken(ctx); err == nil {
		c.printAlreadyAuthenticated(ctx, access, out)
		return nil
	}

	verifier, err := newCodeVerifier(c.rand)
	if err != nil {
		return fmt.Errorf("generate linear pkce code verifier: %w", err)
	}
	challenge := codeChallengeS256(verifier)

	state, err := newState(c.rand)
	if err != nil {
		return fmt.Errorf("generate linear oauth state: %w", err)
	}

	srv, err := newCallbackServer(c.redirectPort, state)
	if err != nil {
		return fmt.Errorf("start linear oauth callback server: %w", err)
	}
	defer func() { _ = srv.Close() }()

	authURL := buildAuthorizeURL(c.authorizeURL, c.clientID, srv.redirectURI(), state, challenge)

	if err := c.openBrowser(authURL); err != nil {
		// Opening the browser is a convenience, not a hard requirement: the
		// user can still complete authorization by following the printed
		// URL manually, so this is not a fatal error.
		fmt.Fprintf(out, "Could not open a browser automatically. Open this URL to authenticate with Linear:\n%s\n", authURL)
	}

	code, err := srv.wait(ctx)
	if err != nil {
		return fmt.Errorf("linear oauth callback: %w", err)
	}

	tok, err := c.exchangeCode(ctx, code, verifier, srv.redirectURI())
	if err != nil {
		return fmt.Errorf("exchange linear authorization code: %w", err)
	}

	if err := c.store.save(tok); err != nil {
		return fmt.Errorf("save linear credentials: %w", err)
	}

	v, err := c.fetchViewer(ctx, tok.Access)
	if err != nil {
		// The token was still issued and persisted successfully; failing to
		// confirm the viewer's identity afterward is not a login failure.
		fmt.Fprintln(out, "Logged in, but could not confirm your Linear identity")
		return nil
	}

	fmt.Fprintf(out, "Logged in as %s\n", v.Name)

	return nil
}

// printAlreadyAuthenticated writes the already-authenticated confirmation
// for login's short-circuit path, naming the viewer when fetchViewer
// succeeds and falling back to a generic confirmation when it doesn't
// (e.g. transient network failure) — either way, no fresh login is
// triggered.
func (c *Client) printAlreadyAuthenticated(ctx context.Context, access config.Secret, out io.Writer) {
	v, err := c.fetchViewer(ctx, access)
	if err != nil {
		fmt.Fprintln(out, "Already authenticated")
		return
	}

	fmt.Fprintf(out, "Already authenticated as %s\n", v.Name)
}

// logout revokes the stored Linear access token with the provider
// (best-effort) and always deletes the local credentials file afterward,
// even when the revoke call fails — a failed revoke must never leave stale
// local credentials behind.
func (c *Client) logout(ctx context.Context, out io.Writer) error {
	tok, err := c.store.load()
	if err != nil {
		if errors.Is(err, ErrNoCredentials) {
			fmt.Fprintln(out, "Not logged in")
			return nil
		}

		return fmt.Errorf("load linear credentials: %w", err)
	}

	revokeErr := c.revoke(ctx, tok.Access)

	if err := c.store.delete(); err != nil {
		return fmt.Errorf("delete linear credentials: %w", err)
	}

	if revokeErr != nil {
		fmt.Fprintln(out, "Logged out locally, but could not revoke the token with Linear")
		return nil
	}

	fmt.Fprintln(out, "Logged out")

	return nil
}

// revoke posts access to c.revokeURL per RFC 7009. On a non-2xx response the
// returned error is built only from the HTTP status text — never the raw
// response body — so a revoke failure can never leak a secret-shaped value
// into a log line.
func (c *Client) revoke(ctx context.Context, access config.Secret) error {
	form := url.Values{}
	form.Set("token", string(access))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.revokeURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("build linear token revoke request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("send linear token revoke request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("linear token revoke request returned %s", http.StatusText(resp.StatusCode))
	}

	return nil
}

// openInBrowser opens targetURL in the user's default browser via a fixed,
// per-runtime.GOOS command. The command name is always one of a small,
// hardcoded set of literals (never derived from user input or
// configuration) and targetURL is passed as a separate argv entry — never
// interpolated into a shell string — so this does not shell out to
// attacker-influenced input.
//
// never variable; targetURL is a plain argv element, not a shell string.
//
//nolint:gosec // G204: command name is one of the fixed literals below,
func openInBrowser(targetURL string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", targetURL)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", targetURL)
	default:
		cmd = exec.Command("xdg-open", targetURL)
	}

	return cmd.Start()
}
