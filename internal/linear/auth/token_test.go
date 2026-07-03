package auth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/viniciusfranca/vdt/internal/config"
)

// TestClient_ExchangeCode_Success pins the exact request exchangeCode must
// send to the token endpoint (method, content type, and every form field
// required by RFC 6749 authorization_code grant + RFC 7636 PKCE), and
// asserts the resulting Token is built from the response fields with the
// expiry computed via the injected now() rather than wall-clock time.
func TestClient_ExchangeCode_Success(t *testing.T) {
	const (
		code        = "auth-code-123"
		verifier    = "verifier-abc"
		redirectURI = "http://127.0.0.1:53219/callback"
		clientID    = "client-id-xyz"
	)
	clientSecret := config.Secret("client-secret-shh")
	fixedTime := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)

	var (
		gotMethod      string
		gotContentType string
		gotForm        url.Values
	)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		if err := r.ParseForm(); err != nil {
			t.Errorf("server: ParseForm failed: %v", err)
		}
		gotForm = r.Form

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"AT-real","refresh_token":"RT-real","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer ts.Close()

	c := &Client{
		http:         ts.Client(),
		now:          func() time.Time { return fixedTime },
		clientID:     clientID,
		clientSecret: clientSecret,
		tokenURL:     ts.URL,
	}

	tok, err := c.exchangeCode(context.Background(), code, verifier, redirectURI)
	if err != nil {
		t.Fatalf("exchangeCode returned error: %v", err)
	}
	if tok == nil {
		t.Fatal("exchangeCode returned nil token with nil error")
	}

	if gotMethod != http.MethodPost {
		t.Errorf("request method = %q, want %q", gotMethod, http.MethodPost)
	}
	if gotContentType != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want %q", gotContentType, "application/x-www-form-urlencoded")
	}

	formTests := []struct {
		key  string
		want string
	}{
		{"grant_type", "authorization_code"},
		{"code", code},
		{"code_verifier", verifier},
		{"redirect_uri", redirectURI},
		{"client_id", clientID},
		{"client_secret", string(clientSecret)},
	}
	for _, tt := range formTests {
		if got := gotForm.Get(tt.key); got != tt.want {
			t.Errorf("form[%q] = %q, want %q", tt.key, got, tt.want)
		}
	}

	if string(tok.Access) != "AT-real" {
		t.Errorf("tok.Access = %q, want %q", string(tok.Access), "AT-real")
	}
	if string(tok.Refresh) != "RT-real" {
		t.Errorf("tok.Refresh = %q, want %q", string(tok.Refresh), "RT-real")
	}

	wantExpiry := fixedTime.Add(3600 * time.Second)
	if !tok.Expiry.Equal(wantExpiry) {
		t.Errorf("tok.Expiry = %v, want %v (must be computed from injected now(), not wall-clock time)", tok.Expiry, wantExpiry)
	}
}

// TestClient_ExchangeCode_ErrorDoesNotLeakBody is the critical security
// assertion for this phase: on a non-2xx response from the token endpoint,
// exchangeCode must return a non-nil error and a nil *Token, and — the key
// invariant — the error text must NEVER contain the raw response body. A
// naive `fmt.Errorf("token exchange failed: %s", body)` would leak
// token-shaped secrets straight into logs/stderr; this test would catch it.
func TestClient_ExchangeCode_ErrorDoesNotLeakBody(t *testing.T) {
	const leaked = "lin_api_LEAKED_SECRET_TOKEN"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"bad code ` + leaked + `"}`))
	}))
	defer ts.Close()

	c := &Client{
		http:         ts.Client(),
		now:          time.Now,
		clientID:     "client-id",
		clientSecret: config.Secret("shh"),
		tokenURL:     ts.URL,
	}

	tok, err := c.exchangeCode(context.Background(), "bad-code", "verifier", "http://127.0.0.1:1/callback")
	if err == nil {
		t.Fatal("exchangeCode returned nil error for a 400 response, want non-nil")
	}
	if tok != nil {
		t.Errorf("exchangeCode returned non-nil token on error: %+v", tok)
	}
	if strings.Contains(err.Error(), leaked) {
		t.Errorf("exchangeCode error %q leaks the raw response body substring %q — the raw body must never be dumped into the error", err.Error(), leaked)
	}
}

// TestClient_FetchViewer_Success pins the request shape fetchViewer must
// send to the GraphQL API endpoint (bearer auth header, a query requesting
// viewer { id name }) and asserts the decoded viewer matches the response.
func TestClient_FetchViewer_Success(t *testing.T) {
	const accessToken = "AT-real-viewer-token"
	access := config.Secret(accessToken)

	var (
		gotAuth   string
		gotBody   string
		gotMethod string
	)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("server: read body failed: %v", err)
		}
		gotBody = string(body)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"viewer":{"id":"u_1","name":"Ada"}}}`))
	}))
	defer ts.Close()

	c := &Client{
		http:   ts.Client(),
		now:    time.Now,
		apiURL: ts.URL,
	}

	v, err := c.fetchViewer(context.Background(), access)
	if err != nil {
		t.Fatalf("fetchViewer returned error: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("request method = %q, want %q", gotMethod, http.MethodPost)
	}

	wantAuth := "Bearer " + accessToken
	if gotAuth != wantAuth {
		t.Errorf("Authorization header = %q, want %q", gotAuth, wantAuth)
	}

	if !strings.Contains(gotBody, "viewer") || !strings.Contains(gotBody, "id") || !strings.Contains(gotBody, "name") {
		t.Errorf("request body %q does not look like a GraphQL query requesting viewer { id name }", gotBody)
	}

	want := viewer{ID: "u_1", Name: "Ada"}
	if v != want {
		t.Errorf("fetchViewer() = %+v, want %+v", v, want)
	}
}

// TestClient_FetchViewer_ErrorDoesNotLeakToken covers non-2xx and GraphQL
// "errors" responses: fetchViewer must return a non-nil error and a zero
// viewer, and the error text must never contain the raw bearer access
// token — mirroring the same no-leak invariant enforced for exchangeCode.
func TestClient_FetchViewer_ErrorDoesNotLeakToken(t *testing.T) {
	const accessToken = "AT-must-not-leak-anywhere"
	access := config.Secret(accessToken)

	tests := []struct {
		name   string
		status int
		body   string
	}{
		{
			name:   "http error status",
			status: http.StatusUnauthorized,
			body:   `{"errors":[{"message":"Authentication required, not authenticated"}]}`,
		},
		{
			name:   "graphql errors field with 200 status",
			status: http.StatusOK,
			body:   `{"errors":[{"message":"some graphql error"}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer ts.Close()

			c := &Client{
				http:   ts.Client(),
				now:    time.Now,
				apiURL: ts.URL,
			}

			v, err := c.fetchViewer(context.Background(), access)
			if err == nil {
				t.Fatalf("fetchViewer returned nil error for response %q, want non-nil", tt.body)
			}
			if v != (viewer{}) {
				t.Errorf("fetchViewer returned non-zero viewer %+v on error, want zero value", v)
			}
			if strings.Contains(err.Error(), accessToken) {
				t.Errorf("fetchViewer error %q leaks the raw access token %q", err.Error(), accessToken)
			}
		})
	}
}
