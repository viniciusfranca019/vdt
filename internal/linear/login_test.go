package linear

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/viniciusfranca/vdt/internal/config"
)

// fixedLoginNow anchors every login/logout test's injected clock, so
// "expired" vs "not expired" tokens are computed relative to a fixed instant
// rather than wall-clock time.
var fixedLoginNow = time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)

// httpGetShort performs an HTTP GET against uri with a short client timeout,
// discarding the response body. It exists so the in-process fake browser
// (openBrowser hooks below) can drive the loopback OAuth callback without
// ever risking an indefinite hang.
func httpGetShort(uri string) error {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(uri) //nolint:gosec,noctx // test helper hitting a loopback server we just started
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// fakeBrowser returns an openBrowser hook that simulates the Linear
// authorization redirect entirely in-process: it parses the redirect_uri and
// state login() embedded in the authorize URL it was handed, then fires a
// GET at that callback with a fixed authorization code and the *real* state,
// so the loopback callback server's CSRF check passes. This is what lets
// login() be exercised end-to-end with no real network call and no real
// browser.
func fakeBrowser(t *testing.T) func(string) error {
	t.Helper()

	return func(rawAuthURL string) error {
		u, err := url.Parse(rawAuthURL)
		if err != nil {
			return err
		}
		q := u.Query()
		redirectURI := q.Get("redirect_uri")
		state := q.Get("state")

		go func() {
			_ = httpGetShort(redirectURI + "?code=test-code-123&state=" + url.QueryEscape(state))
		}()

		return nil
	}
}

// TestClient_Login_Success pins scenario #1 (login bem-sucedido): starting
// from an empty store, login() must drive the full authorization-code +
// PKCE exchange against the fake provider, persist the resulting tokens
// verbatim, and print a confirmation naming the authenticated viewer.
func TestClient_Login_Success(t *testing.T) {
	var (
		mu         sync.Mutex
		tokenCalls int
		gotForm    url.Values
	)

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		tokenCalls++
		if err := r.ParseForm(); err != nil {
			t.Errorf("token server: ParseForm failed: %v", err)
		}
		gotForm = r.Form

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"AT-1","refresh_token":"RT-1","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer tokenServer.Close()

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"viewer":{"id":"u_1","name":"Ada Lovelace"}}}`))
	}))
	defer apiServer.Close()

	s := newStore(t.TempDir())

	c := &Client{
		http:         &http.Client{Timeout: 5 * time.Second},
		now:          func() time.Time { return fixedLoginNow },
		openBrowser:  fakeBrowser(t),
		rand:         bytes.NewReader(bytes.Repeat([]byte{0x42}, 256)),
		store:        s,
		clientID:     "client-id-login-success",
		clientSecret: config.Secret("client-secret-login-success"),
		authorizeURL: "https://linear.app/oauth/authorize",
		tokenURL:     tokenServer.URL,
		apiURL:       apiServer.URL,
		redirectPort: 0,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var buf bytes.Buffer
	if err := c.login(ctx, &buf); err != nil {
		t.Fatalf("login() returned error: %v", err)
	}

	stored, err := s.load()
	if err != nil {
		t.Fatalf("store.load() after login: %v", err)
	}
	if string(stored.Access) != "AT-1" {
		t.Errorf("stored Access = %q, want %q", string(stored.Access), "AT-1")
	}
	if string(stored.Refresh) != "RT-1" {
		t.Errorf("stored Refresh = %q, want %q", string(stored.Refresh), "RT-1")
	}

	mu.Lock()
	calls := tokenCalls
	form := gotForm
	mu.Unlock()

	if calls != 1 {
		t.Fatalf("token endpoint was called %d time(s), want exactly 1", calls)
	}
	if got := form.Get("grant_type"); got != "authorization_code" {
		t.Errorf("form[%q] = %q, want %q", "grant_type", got, "authorization_code")
	}
	if got := form.Get("code"); got != "test-code-123" {
		t.Errorf("form[%q] = %q, want %q", "code", got, "test-code-123")
	}
	if got := form.Get("code_verifier"); got == "" {
		t.Errorf("form[%q] is empty, want a non-empty PKCE code_verifier", "code_verifier")
	}

	if !strings.Contains(buf.String(), "Ada Lovelace") {
		t.Errorf("login() output %q does not confirm the authenticated viewer name %q", buf.String(), "Ada Lovelace")
	}
}

// TestClient_Login_AlreadyAuthenticated pins scenario #4 (já autenticado):
// when the store already holds a non-expired token, login() must short-
// circuit before ever starting the browser/authorize/exchange flow. The
// critical invariant is that openBrowser is never invoked and the token
// endpoint never receives an authorization_code grant.
func TestClient_Login_AlreadyAuthenticated(t *testing.T) {
	var (
		mu             sync.Mutex
		grantCodeCalls int
	)

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if err := r.ParseForm(); err == nil && r.Form.Get("grant_type") == "authorization_code" {
			grantCodeCalls++
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"AT-should-not-happen","refresh_token":"RT-should-not-happen","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer tokenServer.Close()

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"viewer":{"id":"u_1","name":"Already Authenticated User"}}}`))
	}))
	defer apiServer.Close()

	s := newStore(t.TempDir())
	if err := s.save(&Token{
		Access:  config.Secret("AT-already-valid"),
		Refresh: config.Secret("RT-already-valid"),
		Expiry:  fixedLoginNow.Add(1 * time.Hour),
	}); err != nil {
		t.Fatalf("seed store.save: %v", err)
	}

	var openBrowserCalled bool

	c := &Client{
		http: &http.Client{Timeout: 5 * time.Second},
		now:  func() time.Time { return fixedLoginNow },
		openBrowser: func(string) error {
			openBrowserCalled = true
			return nil
		},
		rand:         bytes.NewReader(bytes.Repeat([]byte{0x42}, 256)),
		store:        s,
		clientID:     "client-id-already-auth",
		clientSecret: config.Secret("client-secret-already-auth"),
		authorizeURL: "https://linear.app/oauth/authorize",
		tokenURL:     tokenServer.URL,
		apiURL:       apiServer.URL,
		redirectPort: 0,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var buf bytes.Buffer
	if err := c.login(ctx, &buf); err != nil {
		t.Fatalf("login() returned error: %v", err)
	}

	// Critical invariant: the short-circuit must never start the
	// browser/authorize/exchange flow. Never weaken this assertion.
	if openBrowserCalled {
		t.Fatal("openBrowser was called for an already-authenticated client, want it never invoked")
	}

	mu.Lock()
	calls := grantCodeCalls
	mu.Unlock()
	if calls != 0 {
		t.Errorf("token endpoint received %d authorization_code grant(s), want 0", calls)
	}

	if buf.Len() == 0 {
		t.Error("login() produced no output for the already-authenticated case, want some confirmation message")
	}
}

// TestClient_Logout pins scenario #8 (logout): logout() must revoke the
// stored access token with the provider and always remove the local
// credentials file, even when the revoke call itself fails.
func TestClient_Logout(t *testing.T) {
	t.Run("revoke succeeds", func(t *testing.T) {
		s := newStore(t.TempDir())
		if err := s.save(&Token{
			Access:  config.Secret("AT-to-revoke"),
			Refresh: config.Secret("RT-to-revoke"),
			Expiry:  fixedLoginNow.Add(1 * time.Hour),
		}); err != nil {
			t.Fatalf("seed store.save: %v", err)
		}

		var (
			mu              sync.Mutex
			revokeCalls     int
			gotRevokeMethod string
			gotRevokeToken  string
		)

		revokeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			revokeCalls++
			gotRevokeMethod = r.Method
			if err := r.ParseForm(); err != nil {
				t.Errorf("revoke server: ParseForm failed: %v", err)
			}
			gotRevokeToken = r.Form.Get("token")
			w.WriteHeader(http.StatusOK)
		}))
		defer revokeServer.Close()

		c := &Client{
			http:         &http.Client{Timeout: 5 * time.Second},
			now:          func() time.Time { return fixedLoginNow },
			store:        s,
			clientID:     "client-id-logout",
			clientSecret: config.Secret("client-secret-logout"),
			revokeURL:    revokeServer.URL,
		}

		var buf bytes.Buffer
		if err := c.logout(context.Background(), &buf); err != nil {
			t.Fatalf("logout() returned error: %v", err)
		}

		mu.Lock()
		calls := revokeCalls
		method := gotRevokeMethod
		tokenField := gotRevokeToken
		mu.Unlock()

		if calls != 1 {
			t.Fatalf("revoke endpoint was called %d time(s), want exactly 1", calls)
		}
		if method != http.MethodPost {
			t.Errorf("revoke request method = %q, want %q", method, http.MethodPost)
		}
		if tokenField != "AT-to-revoke" {
			t.Errorf("revoke request field %q = %q, want %q", "token", tokenField, "AT-to-revoke")
		}

		if _, err := s.load(); !errors.Is(err, ErrNoCredentials) {
			t.Errorf("store.load() after logout() = %v, want ErrNoCredentials (local credentials must be deleted)", err)
		}

		if buf.Len() == 0 {
			t.Error("logout() produced no output, want some confirmation message")
		}
	})

	t.Run("revoke fails but local creds still deleted", func(t *testing.T) {
		s := newStore(t.TempDir())
		if err := s.save(&Token{
			Access:  config.Secret("AT-revoke-fails"),
			Refresh: config.Secret("RT-revoke-fails"),
			Expiry:  fixedLoginNow.Add(1 * time.Hour),
		}); err != nil {
			t.Fatalf("seed store.save: %v", err)
		}

		revokeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer revokeServer.Close()

		c := &Client{
			http:         &http.Client{Timeout: 5 * time.Second},
			now:          func() time.Time { return fixedLoginNow },
			store:        s,
			clientID:     "client-id-logout-fail",
			clientSecret: config.Secret("client-secret-logout-fail"),
			revokeURL:    revokeServer.URL,
		}

		var buf bytes.Buffer
		// A failed revoke may surface as a nil error (soft-fail) or a
		// non-nil "soft" error — both are acceptable here. What is NOT
		// acceptable is leaving the local credentials in place.
		_ = c.logout(context.Background(), &buf)

		if _, err := s.load(); !errors.Is(err, ErrNoCredentials) {
			t.Errorf("store.load() after logout() with a failing revoke = %v, want ErrNoCredentials — local credentials must be deleted even when revoke fails", err)
		}
	})
}

// TestNewClient_ReadsEnvClientCredentials pins the env-first credential
// sourcing convention (see CLAUDE.md "Secrets sourcing"): newClient() must
// read LINEAR_CLIENT_ID / LINEAR_CLIENT_SECRET from the environment and
// build a *Client carrying them, with the secret held as config.Secret.
func TestNewClient_ReadsEnvClientCredentials(t *testing.T) {
	t.Setenv("LINEAR_CLIENT_ID", "cid")
	t.Setenv("LINEAR_CLIENT_SECRET", "csecret")

	c, err := newClient()
	if err != nil {
		t.Fatalf("newClient() returned error: %v", err)
	}
	if c == nil {
		t.Fatal("newClient() returned nil *Client with nil error")
	}
	if c.clientID != "cid" {
		t.Errorf("clientID = %q, want %q", c.clientID, "cid")
	}
	if string(c.clientSecret) != "csecret" {
		t.Errorf("clientSecret = %q, want %q", string(c.clientSecret), "csecret")
	}
}

// TestNewClient_MissingCredentialsErrors pins the failure mode when no
// client credentials are configured anywhere (env unset, and — since
// internal/config.Load is still a stub — no on-disk fallback either):
// newClient() must return a non-nil error, and that error must be a
// DIDACTIC, self-contained set of instructions so a CLI user who has just
// hit this for the first time knows exactly how to finish setup under the
// "each user creates their own Linear OAuth app" model — naming both env
// vars, the fixed redirect URI they must register
// (http://127.0.0.1:53682/callback), and hinting that an OAuth application
// is what needs to be created. The error must also never embed a
// secret-shaped value, even when one of the two credentials is actually
// present in the environment.
func TestNewClient_MissingCredentialsErrors(t *testing.T) {
	const presentSecretSentinel = "csecret-present-should-not-leak"

	tests := []struct {
		name         string
		clientID     string
		clientSecret string
	}{
		{
			name:         "both missing",
			clientID:     "",
			clientSecret: "",
		},
		{
			name:         "only client secret set",
			clientID:     "",
			clientSecret: presentSecretSentinel,
		},
		{
			name:         "only client id set",
			clientID:     "cid-present-should-not-leak",
			clientSecret: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("LINEAR_CLIENT_ID", tt.clientID)
			t.Setenv("LINEAR_CLIENT_SECRET", tt.clientSecret)

			_, err := newClient()
			if err == nil {
				t.Fatal("newClient() returned nil error with missing client credentials, want non-nil")
			}
			msg := err.Error()

			if !strings.Contains(msg, "LINEAR_CLIENT_ID") {
				t.Errorf("newClient() error %q does not mention %q, want it to name the missing env var", msg, "LINEAR_CLIENT_ID")
			}
			if !strings.Contains(msg, "LINEAR_CLIENT_SECRET") {
				t.Errorf("newClient() error %q does not mention %q, want it to name the missing env var", msg, "LINEAR_CLIENT_SECRET")
			}
			if !strings.Contains(msg, "127.0.0.1:53682") {
				t.Errorf("newClient() error %q does not mention the redirect URI %q the user must register in their Linear OAuth app", msg, "127.0.0.1:53682")
			}
			if !strings.Contains(strings.ToLower(msg), "oauth") {
				t.Errorf("newClient() error %q does not hint at creating an OAuth app (case-insensitive %q), want an actionable hint", msg, "oauth")
			}

			if tt.clientSecret == presentSecretSentinel && strings.Contains(msg, presentSecretSentinel) {
				t.Errorf("newClient() error %q leaks the present client secret value %q", msg, presentSecretSentinel)
			}
		})
	}
}
