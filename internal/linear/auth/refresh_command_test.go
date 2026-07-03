package auth

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/viniciusfranca/vdt/internal/config"
)

// TestClient_ForceRefresh_Success pins the core behavior of `vdt linear auth
// refresh`: forceRefresh must POST a refresh_token grant to the token
// endpoint and persist the resulting token EVEN THOUGH the stored token is
// not yet expired — this is exactly what distinguishes it from validToken,
// which would short-circuit and never touch the network in this situation.
func TestClient_ForceRefresh_Success(t *testing.T) {
	const (
		clientID     = "client-id-force-refresh"
		oldRefresh   = "RT-old-not-expired"
		newAccess    = "new-access"
		newRefresh   = "new-refresh"
		expiresInSec = 3600
	)
	clientSecret := config.Secret("client-secret-force-refresh")
	fixedNow := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	// Deliberately in the FUTURE: force refresh must refresh anyway.
	notExpiredAt := fixedNow.Add(1 * time.Hour)

	var (
		mu             sync.Mutex
		calls          int
		gotMethod      string
		gotContentType string
		gotForm        url.Values
	)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		if err := r.ParseForm(); err != nil {
			t.Errorf("server: ParseForm failed: %v", err)
		}
		gotForm = r.Form

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"` + newAccess + `","refresh_token":"` + newRefresh + `","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer ts.Close()

	dir := t.TempDir()
	s := newStore(dir)
	if err := s.save(&Token{
		Access:  config.Secret("old-access"),
		Refresh: config.Secret(oldRefresh),
		Expiry:  notExpiredAt,
	}); err != nil {
		t.Fatalf("seed store.save: %v", err)
	}

	c := &Client{
		http:         ts.Client(),
		now:          func() time.Time { return fixedNow },
		store:        s,
		clientID:     clientID,
		clientSecret: clientSecret,
		tokenURL:     ts.URL,
	}

	var buf bytes.Buffer
	if err := c.forceRefresh(context.Background(), &buf); err != nil {
		t.Fatalf("forceRefresh() returned error: %v", err)
	}

	mu.Lock()
	gotCalls := calls
	method := gotMethod
	contentType := gotContentType
	form := gotForm
	mu.Unlock()

	if gotCalls != 1 {
		t.Fatalf("token endpoint was called %d time(s), want exactly 1 — force refresh must hit the network even though the stored token is not expired", gotCalls)
	}
	if method != http.MethodPost {
		t.Errorf("request method = %q, want %q", method, http.MethodPost)
	}
	if contentType != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want %q", contentType, "application/x-www-form-urlencoded")
	}

	formTests := []struct {
		key  string
		want string
	}{
		{"grant_type", "refresh_token"},
		{"refresh_token", oldRefresh},
	}
	for _, tt := range formTests {
		if got := form.Get(tt.key); got != tt.want {
			t.Errorf("form[%q] = %q, want %q", tt.key, got, tt.want)
		}
	}

	stored, err := s.load()
	if err != nil {
		t.Fatalf("s.load() after forceRefresh: %v", err)
	}
	if string(stored.Access) != newAccess {
		t.Errorf("stored Access = %q, want %q", string(stored.Access), newAccess)
	}
	if string(stored.Refresh) != newRefresh {
		t.Errorf("stored Refresh = %q, want %q", string(stored.Refresh), newRefresh)
	}

	if buf.Len() == 0 {
		t.Error("forceRefresh() produced no output, want some confirmation message")
	}
}

// TestClient_ForceRefresh_NotLoggedIn pins the failure mode when no
// credentials have ever been saved: forceRefresh must return a non-nil,
// actionable error and must never attempt any HTTP call.
func TestClient_ForceRefresh_NotLoggedIn(t *testing.T) {
	var calls int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	dir := t.TempDir()
	s := newStore(dir)

	c := &Client{
		http:         ts.Client(),
		now:          time.Now,
		store:        s,
		clientID:     "client-id",
		clientSecret: config.Secret("client-secret"),
		tokenURL:     ts.URL,
	}

	var buf bytes.Buffer
	err := c.forceRefresh(context.Background(), &buf)
	if err == nil {
		t.Fatal("forceRefresh() returned nil error with no stored credentials, want non-nil")
	}
	if !errors.Is(err, ErrNoCredentials) {
		t.Errorf("forceRefresh() error = %v, want it to wrap ErrNoCredentials so the caller knows to run `vdt linear auth login`", err)
	}
	if calls != 0 {
		t.Errorf("token endpoint was called %d time(s), want 0 — no stored credentials means no refresh attempt", calls)
	}
}

// TestClient_ForceRefresh_RejectedDoesNotLeak pins the security invariant
// shared with refresh()/validToken(): when the token endpoint rejects the
// refresh_token grant, forceRefresh must return a non-nil error whose
// message never echoes the raw error_description, which could otherwise
// carry a leaked secret-shaped substring straight into logs.
func TestClient_ForceRefresh_RejectedDoesNotLeak(t *testing.T) {
	const leaked = "leak_TOKEN_XYZ"
	fixedNow := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"nope ` + leaked + `"}`))
	}))
	defer ts.Close()

	dir := t.TempDir()
	s := newStore(dir)
	if err := s.save(&Token{
		Access:  config.Secret("AT-rejected"),
		Refresh: config.Secret("RT-rejected"),
		Expiry:  fixedNow.Add(1 * time.Hour),
	}); err != nil {
		t.Fatalf("seed store.save: %v", err)
	}

	c := &Client{
		http:         ts.Client(),
		now:          func() time.Time { return fixedNow },
		store:        s,
		clientID:     "client-id",
		clientSecret: config.Secret("client-secret"),
		tokenURL:     ts.URL,
	}

	var buf bytes.Buffer
	err := c.forceRefresh(context.Background(), &buf)
	if err == nil {
		t.Fatal("forceRefresh() returned nil error for a rejected refresh_token grant, want non-nil")
	}
	if strings.Contains(err.Error(), leaked) {
		t.Errorf("forceRefresh() error %q leaks the raw error_description substring %q", err.Error(), leaked)
	}
}

// TestCommand_HasRefreshSubcommand pins the CLI wiring for `vdt linear auth
// refresh`: the "auth" parent command must register a "refresh" subcommand
// alongside the existing "login" and "logout".
func TestCommand_HasRefreshSubcommand(t *testing.T) {
	cmd := Command()

	names := map[string]bool{}
	for _, sub := range cmd.Commands() {
		names[sub.Name()] = true
	}

	for _, want := range []string{"login", "logout", "refresh"} {
		if !names[want] {
			t.Errorf("auth command subcommands = %v, want %q to be registered", names, want)
		}
	}
}
