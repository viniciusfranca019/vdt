package linear

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// callbackResult bundles the two return values of callbackServer.wait so a
// background goroutine can hand them back over a channel.
type callbackResult struct {
	code string
	err  error
}

// TestBuildAuthorizeURL_QueryParams pins the exact query parameters and
// their values that buildAuthorizeURL must emit for the Linear OAuth
// authorize endpoint, per RFC 6749 (authorization code) + RFC 7636 (PKCE).
func TestBuildAuthorizeURL_QueryParams(t *testing.T) {
	const (
		base        = "https://linear.app/oauth/authorize"
		clientID    = "client-abc-123"
		redirectURI = "http://127.0.0.1:53219/callback"
		state       = "state-xyz"
		challenge   = "challenge-value-does-not-matter-here"
	)

	got := buildAuthorizeURL(base, clientID, redirectURI, state, challenge)

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("buildAuthorizeURL produced an unparseable URL %q: %v", got, err)
	}

	if u.Scheme != "https" {
		t.Errorf("scheme = %q, want %q", u.Scheme, "https")
	}
	if u.Host != "linear.app" {
		t.Errorf("host = %q, want %q", u.Host, "linear.app")
	}
	if u.Path != "/oauth/authorize" {
		t.Errorf("path = %q, want %q", u.Path, "/oauth/authorize")
	}

	q := u.Query()
	tests := []struct {
		key  string
		want string
	}{
		{"response_type", "code"},
		{"client_id", clientID},
		{"redirect_uri", redirectURI},
		{"state", state},
		{"code_challenge", challenge},
		{"code_challenge_method", "S256"},
		{"scope", "read,write"},
	}

	for _, tt := range tests {
		if got := q.Get(tt.key); got != tt.want {
			t.Errorf("query[%q] = %q, want %q", tt.key, got, tt.want)
		}
	}
}

// TestBuildAuthorizeURL_RedirectURIIsPercentEncoded asserts redirectURI is
// embedded as a properly percent-encoded query value, not naively
// concatenated (which would produce a malformed/ambiguous URL since it
// contains ':' and '/').
func TestBuildAuthorizeURL_RedirectURIIsPercentEncoded(t *testing.T) {
	const (
		base        = "https://linear.app/oauth/authorize"
		clientID    = "client-abc"
		redirectURI = "http://127.0.0.1:9999/callback"
		state       = "state-1"
		challenge   = "challenge-1"
	)

	got := buildAuthorizeURL(base, clientID, redirectURI, state, challenge)

	encoded := url.QueryEscape(redirectURI)
	if !strings.Contains(got, "redirect_uri="+encoded) {
		t.Errorf("buildAuthorizeURL(%q) = %q, does not contain properly encoded redirect_uri=%s", redirectURI, got, encoded)
	}
}

// TestBuildAuthorizeURL_NeverLeaksVerifier is the critical security
// assertion for this phase: buildAuthorizeURL is only ever handed the
// derived code_challenge, never the code_verifier it came from. A known
// verifier value must be structurally impossible to find anywhere in the
// resulting URL.
func TestBuildAuthorizeURL_NeverLeaksVerifier(t *testing.T) {
	const verifier = "super-secret-verifier-must-not-leak-ANY-where"
	challenge := codeChallengeS256(verifier)

	got := buildAuthorizeURL(
		"https://linear.app/oauth/authorize",
		"client-abc",
		"http://127.0.0.1:9999/callback",
		"state-1",
		challenge,
	)

	if !strings.Contains(got, challenge) {
		t.Fatalf("buildAuthorizeURL result %q does not contain the code_challenge %q", got, challenge)
	}
	if strings.Contains(got, verifier) {
		t.Errorf("buildAuthorizeURL result %q leaks the raw verifier %q", got, verifier)
	}
}

// TestCallbackServer_RedirectURIShape (#5) asserts redirectURI() reports a
// loopback URL ending in /callback, bound to a real (non-zero) ephemeral
// port assigned by the OS when newCallbackServer is given port 0.
func TestCallbackServer_RedirectURIShape(t *testing.T) {
	srv, err := newCallbackServer(0, "any-state")
	if err != nil {
		t.Fatalf("newCallbackServer returned error: %v", err)
	}
	defer func() { _ = srv.Close() }()

	uri := srv.redirectURI()

	if !strings.HasPrefix(uri, "http://127.0.0.1:") {
		t.Errorf("redirectURI() = %q, want prefix %q", uri, "http://127.0.0.1:")
	}
	if !strings.HasSuffix(uri, "/callback") {
		t.Errorf("redirectURI() = %q, want suffix %q", uri, "/callback")
	}

	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("redirectURI() produced unparseable URL %q: %v", uri, err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("redirectURI() port %q is not numeric: %v", u.Port(), err)
	}
	if port == 0 {
		t.Errorf("redirectURI() port = 0, want a real ephemeral port assigned by the OS")
	}
}

// TestCallbackServer_Success (success path) drives the full happy path: a
// callback carrying the expected state must hand the authorization code
// back through wait().
func TestCallbackServer_Success(t *testing.T) {
	srv, err := newCallbackServer(0, "S123")
	if err != nil {
		t.Fatalf("newCallbackServer returned error: %v", err)
	}
	defer func() { _ = srv.Close() }()

	resultCh := make(chan callbackResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		code, waitErr := srv.wait(ctx)
		resultCh <- callbackResult{code: code, err: waitErr}
	}()

	mustGet(t, srv.redirectURI()+"?code=abc123&state=S123")

	select {
	case res := <-resultCh:
		if res.err != nil {
			t.Fatalf("wait() returned error: %v", res.err)
		}
		if res.code != "abc123" {
			t.Errorf("wait() code = %q, want %q", res.code, "abc123")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("wait() did not return in time")
	}
}

// TestCallbackServer_StateMismatchIsRejected (#2 state divergente / CSRF)
// pins the critical invariant: when the state returned by the callback does
// not match the state the server was created with, wait() must fail AND
// must never surface the code. Leaking the code on a state mismatch would
// defeat the entire purpose of the CSRF check.
func TestCallbackServer_StateMismatchIsRejected(t *testing.T) {
	srv, err := newCallbackServer(0, "S123")
	if err != nil {
		t.Fatalf("newCallbackServer returned error: %v", err)
	}
	defer func() { _ = srv.Close() }()

	resultCh := make(chan callbackResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		code, waitErr := srv.wait(ctx)
		resultCh <- callbackResult{code: code, err: waitErr}
	}()

	mustGet(t, srv.redirectURI()+"?code=abc123&state=WRONG")

	select {
	case res := <-resultCh:
		if res.err == nil {
			t.Fatal("wait() returned nil error for mismatched state, want non-nil")
		}
		// Critical invariant: mismatched state must NEVER surface a code.
		if res.code != "" {
			t.Errorf("wait() code = %q on state mismatch, want empty (code must never leak on CSRF failure)", res.code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("wait() did not return in time")
	}
}

// TestCallbackServer_UserDeniesAccess (#3 usuario cancela) covers the OAuth
// "access_denied" error callback (no code param at all): wait() must return
// a non-nil, non-leaky error and an empty code.
func TestCallbackServer_UserDeniesAccess(t *testing.T) {
	srv, err := newCallbackServer(0, "S123")
	if err != nil {
		t.Fatalf("newCallbackServer returned error: %v", err)
	}
	defer func() { _ = srv.Close() }()

	resultCh := make(chan callbackResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		code, waitErr := srv.wait(ctx)
		resultCh <- callbackResult{code: code, err: waitErr}
	}()

	const query = "?error=access_denied"
	mustGet(t, srv.redirectURI()+query)

	select {
	case res := <-resultCh:
		if res.err == nil {
			t.Fatal("wait() returned nil error when user denied access, want non-nil")
		}
		if res.code != "" {
			t.Errorf("wait() code = %q when user denied access, want empty", res.code)
		}
		if strings.Contains(res.err.Error(), query) {
			t.Errorf("wait() error %q leaks the raw query string %q", res.err.Error(), query)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("wait() did not return in time")
	}
}

// TestCallbackServer_WaitRespectsContextTimeout (timeout) asserts wait()
// returns promptly with a non-nil error when its context deadline expires
// before any callback ever arrives, rather than blocking forever.
func TestCallbackServer_WaitRespectsContextTimeout(t *testing.T) {
	srv, err := newCallbackServer(0, "S123")
	if err != nil {
		t.Fatalf("newCallbackServer returned error: %v", err)
	}
	defer func() { _ = srv.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	code, err := srv.wait(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("wait() returned nil error after context timeout with no callback received, want non-nil")
	}
	if code != "" {
		t.Errorf("wait() code = %q after timeout, want empty", code)
	}
	if elapsed > 2*time.Second {
		t.Errorf("wait() took %v to return after a 100ms timeout, want it to return promptly", elapsed)
	}
}

// mustGet performs an HTTP GET against uri with a short client timeout and
// fails the test if the request cannot be sent at all. The response
// status/body are irrelevant here: what these tests care about is whether
// callbackServer.wait observed the incoming request and how it decoded it.
func mustGet(t *testing.T, uri string) {
	t.Helper()

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(uri) //nolint:gosec,noctx // test helper hitting a loopback server we just started
	if err != nil {
		t.Fatalf("GET %q failed: %v", uri, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
}
