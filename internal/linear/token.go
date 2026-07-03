package linear

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/viniciusfranca/vdt/internal/config"
)

// tokenGrantType is the OAuth 2.0 grant type vdt exchanges an authorization
// code for, per RFC 6749 §4.1.3.
const tokenGrantType = "authorization_code"

// viewerQuery is the GraphQL query fetchViewer sends to the Linear API. It
// requests only the fields vdt actually needs (id, name) — never anything
// that would require broader scopes than the "read" scope already requested
// in buildAuthorizeURL.
const viewerQuery = `{"query":"{ viewer { id name } }"}`

// Client is a Linear OAuth 2.0 + API client. Every field is unexported and
// injected by whoever constructs a Client, so tests can substitute fakes
// (a stub HTTP server, a fixed clock, an in-memory store, etc.) without any
// of them reaching out to the network or the real filesystem.
type Client struct {
	http *http.Client
	now  func() time.Time
	//nolint:unused // wired up by the login-flow phase, which opens the
	// system browser to the authorize URL.
	openBrowser func(url string) error
	//nolint:unused // wired up by the login-flow phase for PKCE
	// verifier/state generation (see pkce.go's newCodeVerifier/newState).
	rand         io.Reader
	store        *store
	clientID     string
	clientSecret config.Secret
	//nolint:unused // wired up by the login-flow phase, passed to
	// buildAuthorizeURL (see authorize.go).
	authorizeURL string
	tokenURL     string
	//nolint:unused // wired up by the logout-flow phase to revoke tokens
	// with Linear.
	revokeURL string
	apiURL    string
	//nolint:unused // wired up by the login-flow phase, passed to
	// newCallbackServer (see callback.go) to bind the loopback listener.
	redirectPort int
}

// viewer is the subset of a Linear user's identity vdt needs after
// authenticating: just enough to confirm who logged in.
type viewer struct {
	ID   string
	Name string
}

// tokenResponse is the on-the-wire shape of a successful response from the
// Linear OAuth token endpoint.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// tokenErrorResponse is the on-the-wire shape of an error response from the
// Linear OAuth token endpoint (RFC 6749 §5.2). Only Error is ever read into
// an error message; ErrorDescription may echo back attacker- or
// server-controlled text (including, in principle, fragments of the
// request) and must never be surfaced.
type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// graphQLError is a single entry in a GraphQL response's top-level "errors"
// array. Only its presence is used by fetchViewer; Message is deliberately
// never included in the returned error, since the Linear API could in
// principle echo request-derived content (including the bearer token) back
// in an error message.
type graphQLError struct {
	Message string `json:"message"`
}

// viewerResponse is the on-the-wire shape of a response from the Linear
// GraphQL API to viewerQuery.
type viewerResponse struct {
	Data *struct {
		Viewer struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"viewer"`
	} `json:"data"`
	Errors []graphQLError `json:"errors"`
}

// httpClient returns the *http.Client to use for outgoing requests, falling
// back to http.DefaultClient if none was injected.
func (c *Client) httpClient() *http.Client {
	if c.http != nil {
		return c.http
	}

	return http.DefaultClient
}

// exchangeCode performs the RFC 6749 §4.1.3 authorization_code grant
// (extended with the RFC 7636 PKCE code_verifier) against c.tokenURL,
// exchanging an authorization code for a Token.
//
// On a non-2xx response, the returned error is built only from the
// token endpoint's typed "error" field (e.g. "invalid_grant") plus the HTTP
// status text — never from the raw response body or "error_description",
// either of which could otherwise leak attacker- or server-supplied
// secrets straight into logs.
func (c *Client) exchangeCode(ctx context.Context, code, verifier, redirectURI string) (*Token, error) {
	form := url.Values{}
	form.Set("grant_type", tokenGrantType)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", c.clientID)
	form.Set("client_secret", string(c.clientSecret))
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build linear token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("send linear token exchange request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read linear token exchange response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, tokenExchangeError(resp.StatusCode, body)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("decode linear token exchange response: %w", err)
	}

	return &Token{
		Access:  config.Secret(tr.AccessToken),
		Refresh: config.Secret(tr.RefreshToken),
		Expiry:  c.now().Add(time.Duration(tr.ExpiresIn) * time.Second),
	}, nil
}

// tokenExchangeError builds the error returned for a non-2xx response from
// the token endpoint. It reads only the typed "error" field out of body (if
// present and parseable) and the HTTP status text — deliberately never the
// raw body bytes or "error_description" — so a response body carrying a
// secret-shaped substring can never end up in an error message that a
// caller might log.
func tokenExchangeError(status int, body []byte) error {
	var te tokenErrorResponse
	if err := json.Unmarshal(body, &te); err != nil || te.Error == "" {
		return fmt.Errorf("linear token endpoint returned %s", http.StatusText(status))
	}

	return fmt.Errorf("linear token endpoint returned %s: %s", http.StatusText(status), te.Error)
}

// fetchViewer queries the Linear GraphQL API for the identity of the user
// the given access token belongs to.
//
// On a non-2xx response, or a 2xx response carrying a GraphQL "errors"
// array, the returned error is built only from the HTTP status text and a
// generic marker — never from the raw response body, the GraphQL error
// message, or the access token itself — since any of those could leak the
// bearer token straight into logs.
func (c *Client) fetchViewer(ctx context.Context, access config.Secret) (viewer, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL, strings.NewReader(viewerQuery))
	if err != nil {
		return viewer{}, fmt.Errorf("build linear viewer request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+string(access))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return viewer{}, fmt.Errorf("send linear viewer request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return viewer{}, fmt.Errorf("read linear viewer response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return viewer{}, fmt.Errorf("linear viewer request returned %s", http.StatusText(resp.StatusCode))
	}

	var vr viewerResponse
	if err := json.Unmarshal(body, &vr); err != nil {
		return viewer{}, fmt.Errorf("decode linear viewer response: %w", err)
	}

	if len(vr.Errors) > 0 {
		return viewer{}, fmt.Errorf("linear viewer request returned %d graphql error(s)", len(vr.Errors))
	}

	if vr.Data == nil {
		return viewer{}, fmt.Errorf("linear viewer response missing data")
	}

	return viewer{ID: vr.Data.Viewer.ID, Name: vr.Data.Viewer.Name}, nil
}
