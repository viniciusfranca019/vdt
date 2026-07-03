package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/viniciusfranca/vdt/internal/config"
)

// refreshGrantType is the OAuth 2.0 grant type validToken/refresh exchange a
// refresh token for, per RFC 6749 §6.
const refreshGrantType = "refresh_token"

// refreshGraceWindow bounds how long after a token's Expiry vdt will still
// accept a refresh response that omits a rotated refresh_token, retaining
// the previous one instead. Beyond this window, continuing to reuse a
// refresh token whose provider stopped confirming it is no longer safe, so
// refresh fails closed.
const refreshGraceWindow = 30 * time.Minute

// validToken returns a currently-usable Linear access token, transparently
// refreshing it via the refresh_token grant when the stored token has
// expired.
//
// If no credentials have ever been saved (or the store otherwise fails to
// load), the underlying error is propagated verbatim and no HTTP call is
// made. If the stored token is not yet expired, it is returned as-is with no
// HTTP call and no store write.
func (c *Client) validToken(ctx context.Context) (config.Secret, error) {
	cur, err := c.store.load()
	if err != nil {
		return "", err
	}

	if c.now().Before(cur.Expiry) {
		return cur.Access, nil
	}

	fresh, err := c.refresh(ctx, cur)
	if err != nil {
		return "", err
	}

	if err := c.store.save(fresh); err != nil {
		return "", fmt.Errorf("save refreshed linear credentials: %w", err)
	}

	return fresh.Access, nil
}

// forceRefresh unconditionally performs the refresh_token grant against
// c.tokenURL and persists the result, regardless of whether the currently
// stored token has expired. This is the behavior backing `vdt linear auth
// refresh`: unlike validToken, which only refreshes when necessary,
// forceRefresh always hits the network — useful for rotating credentials
// on demand or verifying that the stored refresh token still works.
//
// If no credentials have ever been saved, forceRefresh returns an
// actionable error that still satisfies errors.Is(err, ErrNoCredentials),
// and makes no HTTP call. Any other store.load failure is propagated
// verbatim. On success, forceRefresh writes a confirmation message to out
// that never echoes any token.
func (c *Client) forceRefresh(ctx context.Context, out io.Writer) error {
	cur, err := c.store.load()
	if err != nil {
		if errors.Is(err, ErrNoCredentials) {
			return fmt.Errorf("not authenticated, run `vdt linear auth login`: %w", ErrNoCredentials)
		}

		return err
	}

	fresh, err := c.refresh(ctx, cur)
	if err != nil {
		return err
	}

	if err := c.store.save(fresh); err != nil {
		return fmt.Errorf("save refreshed linear credentials: %w", err)
	}

	fmt.Fprintln(out, "Refreshed Linear credentials.")

	return nil
}

// refresh performs the RFC 6749 §6 refresh_token grant against c.tokenURL,
// exchanging cur's refresh token for a new access token.
//
// On a non-2xx response, refresh only deletes the local credentials when the
// token endpoint's typed "error" field indicates the grant itself is
// terminally dead (invalid_grant, invalid_client, unauthorized_client) — see
// isTerminalGrantError. Any other non-2xx response (a transient 5xx, a
// network-level failure surfaced as non-2xx, or a body that doesn't parse
// into a recognized error code) is treated as retryable and leaves the
// stored credentials untouched, so a caller can simply retry later instead
// of being forced through a full re-login. Either way, the returned error is
// built only from the token endpoint's typed "error" field plus the HTTP
// status text — never the raw response body or "error_description", either
// of which could otherwise leak attacker- or server-supplied secrets
// straight into logs.
//
// On a 2xx response that omits refresh_token (some providers don't rotate it
// on every refresh), the previous refresh token is retained as long as the
// prior token expired no more than refreshGraceWindow ago; beyond that
// window, refresh returns an error rather than silently continuing with a
// token that can no longer be safely rotated. Neither case persists
// anything — persisting the result on success is validToken's job.
func (c *Client) refresh(ctx context.Context, cur *Token) (*Token, error) {
	form := url.Values{}
	form.Set("grant_type", refreshGrantType)
	form.Set("refresh_token", string(cur.Refresh))
	form.Set("client_id", c.clientID)
	form.Set("client_secret", string(c.clientSecret))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build linear token refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("send linear token refresh request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read linear token refresh response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, c.refreshRejected(resp.StatusCode, body)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("decode linear token refresh response: %w", err)
	}

	fresh := &Token{
		Access: config.Secret(tr.AccessToken),
		Expiry: c.now().Add(time.Duration(tr.ExpiresIn) * time.Second),
	}

	if tr.RefreshToken != "" {
		fresh.Refresh = config.Secret(tr.RefreshToken)
		return fresh, nil
	}

	if c.now().Sub(cur.Expiry) > refreshGraceWindow {
		return nil, errors.New("linear refresh token grace window exceeded; run vdt linear login to re-authenticate")
	}

	fresh.Refresh = cur.Refresh

	return fresh, nil
}

// refreshRejected builds the error returned when the token endpoint rejects
// a refresh_token grant, deleting the local credentials only when
// isTerminalGrantError says the grant itself is dead — so the user is
// cleanly logged out and prompted to re-authenticate. A non-terminal
// rejection (transient 5xx, unparseable/unrecognized body) leaves the
// stored credentials in place so a later retry can still succeed. Either
// way, the returned error is built only from the typed "error" field (via
// tokenExchangeError) — never the raw body or "error_description" — so a
// rejected-grant response can never leak a secret-shaped substring into a
// log line.
func (c *Client) refreshRejected(status int, body []byte) error {
	rejectedErr := tokenExchangeError(status, body)

	if !isTerminalGrantError(status, body) {
		return rejectedErr
	}

	if delErr := c.store.delete(); delErr != nil {
		return fmt.Errorf("%w (also failed to clear local linear credentials: %v)", rejectedErr, delErr)
	}

	return rejectedErr
}

// terminalGrantErrors are the token endpoint's typed OAuth "error" codes
// (RFC 6749 §5.2) that indicate a refresh_token grant can never succeed
// again with the current credentials: the refresh token or client
// credentials themselves are dead, not merely rejected by a transient
// condition.
var terminalGrantErrors = map[string]bool{
	"invalid_grant":       true,
	"invalid_client":      true,
	"unauthorized_client": true,
}

// isTerminalGrantError reports whether a non-2xx refresh_token grant
// response indicates the grant is terminally dead and local credentials
// should be deleted. A 5xx status is always treated as non-terminal
// (transient server failure), regardless of body contents. Otherwise, body
// is unmarshaled into the same tokenErrorResponse shape tokenExchangeError
// uses; an unparseable body or an "error" code outside terminalGrantErrors
// is treated as non-terminal, so refresh only ever deletes credentials on a
// genuinely dead grant.
func isTerminalGrantError(status int, body []byte) bool {
	if status >= 500 {
		return false
	}

	var te tokenErrorResponse
	if err := json.Unmarshal(body, &te); err != nil {
		return false
	}

	return terminalGrantErrors[te.Error]
}
