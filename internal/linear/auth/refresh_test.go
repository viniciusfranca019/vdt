package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/viniciusfranca/vdt/internal/config"
)

// TestClient_ValidToken_NotExpired pins the baseline half of #5: when the
// stored token's Expiry is still in the future relative to the injected
// now(), validToken must return the stored access token as-is, without
// making any HTTP call to the token endpoint and without mutating the
// stored token.
func TestClient_ValidToken_NotExpired(t *testing.T) {
	fixedNow := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)

	var calls int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	dir := t.TempDir()
	s := newStore(dir)
	seeded := &Token{
		Access:  config.Secret("AT-still-valid"),
		Refresh: config.Secret("RT-still-valid"),
		Expiry:  fixedNow.Add(1 * time.Hour),
	}
	if err := s.save(seeded); err != nil {
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

	access, err := c.validToken(context.Background())
	if err != nil {
		t.Fatalf("validToken returned error: %v", err)
	}
	if string(access) != "AT-still-valid" {
		t.Errorf("validToken() = %q, want %q", string(access), "AT-still-valid")
	}
	if calls != 0 {
		t.Errorf("token endpoint was called %d time(s), want 0 — a non-expired token must never trigger a refresh", calls)
	}

	stored, err := s.load()
	if err != nil {
		t.Fatalf("s.load() after validToken: %v", err)
	}
	if string(stored.Access) != "AT-still-valid" || string(stored.Refresh) != "RT-still-valid" || !stored.Expiry.Equal(seeded.Expiry) {
		t.Errorf("stored token was mutated: got %+v, want unchanged %+v", stored, seeded)
	}
}

// TestClient_ValidToken_RefreshesAutomatically pins #5 (refresh automático):
// given an expired stored token, validToken must POST a refresh_token grant
// to the token endpoint with every required form field, return the fresh
// access token, and persist the new access+refresh+expiry to the store.
func TestClient_ValidToken_RefreshesAutomatically(t *testing.T) {
	const (
		clientID     = "client-id-xyz"
		oldRefresh   = "RT-old-valid"
		newAccess    = "AT-new"
		newRefresh   = "RT-new"
		expiresInSec = 3600
	)
	clientSecret := config.Secret("client-secret-shh")
	fixedNow := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	expiredAt := fixedNow.Add(-1 * time.Minute)

	var (
		gotMethod      string
		gotContentType string
		gotForm        url.Values
		calls          int
	)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		if err := r.ParseForm(); err != nil {
			t.Errorf("server: ParseForm failed: %v", err)
		}
		gotForm = r.Form

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"` + newAccess + `","refresh_token":"` + newRefresh + `","expires_in":` + strconv.Itoa(expiresInSec) + `,"token_type":"Bearer"}`))
	}))
	defer ts.Close()

	dir := t.TempDir()
	s := newStore(dir)
	if err := s.save(&Token{
		Access:  config.Secret("AT-old-expired"),
		Refresh: config.Secret(oldRefresh),
		Expiry:  expiredAt,
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

	access, err := c.validToken(context.Background())
	if err != nil {
		t.Fatalf("validToken returned error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("token endpoint was called %d time(s), want exactly 1", calls)
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
		{"grant_type", "refresh_token"},
		{"refresh_token", oldRefresh},
		{"client_id", clientID},
		{"client_secret", string(clientSecret)},
	}
	for _, tt := range formTests {
		if got := gotForm.Get(tt.key); got != tt.want {
			t.Errorf("form[%q] = %q, want %q", tt.key, got, tt.want)
		}
	}

	if string(access) != newAccess {
		t.Errorf("validToken() = %q, want %q", string(access), newAccess)
	}

	stored, err := s.load()
	if err != nil {
		t.Fatalf("s.load() after validToken: %v", err)
	}
	if string(stored.Access) != newAccess {
		t.Errorf("stored Access = %q, want %q", string(stored.Access), newAccess)
	}
	if string(stored.Refresh) != newRefresh {
		t.Errorf("stored Refresh = %q, want %q", string(stored.Refresh), newRefresh)
	}
	wantExpiry := fixedNow.Add(expiresInSec * time.Second)
	if !stored.Expiry.Equal(wantExpiry) {
		t.Errorf("stored Expiry = %v, want %v (computed from injected now(), not wall-clock time)", stored.Expiry, wantExpiry)
	}
}

// TestClient_ValidToken_GraceWithinThirtyMinutes pins #6 (grace period)
// within the 30-minute window: when the token expired only 20 minutes ago
// and the token endpoint's refresh response omits refresh_token (some
// providers don't rotate it every time), validToken must still succeed,
// return the new access token, and retain the OLD refresh token in the
// store (never overwrite it with an empty value).
func TestClient_ValidToken_GraceWithinThirtyMinutes(t *testing.T) {
	const oldRefresh = "RT-retained-within-grace"
	fixedNow := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	expiredAt := fixedNow.Add(-20 * time.Minute)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"AT-grace-new","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer ts.Close()

	dir := t.TempDir()
	s := newStore(dir)
	if err := s.save(&Token{
		Access:  config.Secret("AT-grace-old"),
		Refresh: config.Secret(oldRefresh),
		Expiry:  expiredAt,
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

	access, err := c.validToken(context.Background())
	if err != nil {
		t.Fatalf("validToken returned error within the 30-minute grace window: %v", err)
	}
	if string(access) != "AT-grace-new" {
		t.Errorf("validToken() = %q, want %q", string(access), "AT-grace-new")
	}

	stored, err := s.load()
	if err != nil {
		t.Fatalf("s.load() after validToken: %v", err)
	}
	if string(stored.Access) != "AT-grace-new" {
		t.Errorf("stored Access = %q, want %q", string(stored.Access), "AT-grace-new")
	}
	if string(stored.Refresh) != oldRefresh {
		t.Errorf("stored Refresh = %q, want retained old refresh %q — omitted refresh_token in the response must not wipe the existing one", string(stored.Refresh), oldRefresh)
	}
	wantExpiry := fixedNow.Add(3600 * time.Second)
	if !stored.Expiry.Equal(wantExpiry) {
		t.Errorf("stored Expiry = %v, want %v", stored.Expiry, wantExpiry)
	}
}

// TestClient_ValidToken_GraceBeyondThirtyMinutes pins #6 (grace period)
// beyond the 30-minute window: when the token expired 31 minutes ago and
// the refresh response still omits refresh_token, validToken must return a
// non-nil error rather than silently continuing with a token that can no
// longer be safely rotated.
func TestClient_ValidToken_GraceBeyondThirtyMinutes(t *testing.T) {
	fixedNow := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	expiredAt := fixedNow.Add(-31 * time.Minute)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"AT-too-late","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer ts.Close()

	dir := t.TempDir()
	s := newStore(dir)
	if err := s.save(&Token{
		Access:  config.Secret("AT-beyond-grace-old"),
		Refresh: config.Secret("RT-beyond-grace-old"),
		Expiry:  expiredAt,
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

	_, err := c.validToken(context.Background())
	if err == nil {
		t.Fatal("validToken returned nil error 31 minutes past expiry with no rotated refresh_token, want non-nil (grace window exceeded)")
	}
}

// TestClient_ValidToken_InvalidRefreshSelfHeals pins #7 (refresh inválido):
// when the token endpoint rejects the refresh_token grant (e.g. it was
// revoked or already rotated elsewhere), validToken must return a non-nil
// error that never echoes the raw error_description (which could carry a
// leaked secret-shaped substring), and it must delete the local credentials
// file so the user is cleanly logged out and prompted to re-authenticate.
func TestClient_ValidToken_InvalidRefreshSelfHeals(t *testing.T) {
	const leaked = "lin_api_LEAKED_TOKEN_XYZ"
	fixedNow := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	expiredAt := fixedNow.Add(-1 * time.Minute)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"token expired ` + leaked + `"}`))
	}))
	defer ts.Close()

	dir := t.TempDir()
	s := newStore(dir)
	if err := s.save(&Token{
		Access:  config.Secret("AT-rejected"),
		Refresh: config.Secret("RT-rejected"),
		Expiry:  expiredAt,
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

	_, err := c.validToken(context.Background())
	if err == nil {
		t.Fatal("validToken returned nil error for a rejected refresh_token grant, want non-nil")
	}
	if strings.Contains(err.Error(), leaked) {
		t.Errorf("validToken error %q leaks the raw error_description substring %q", err.Error(), leaked)
	}

	if _, err := s.load(); !errors.Is(err, ErrNoCredentials) {
		t.Errorf("s.load() after a rejected refresh = %v, want ErrNoCredentials — credentials must be deleted so the user is prompted to re-login", err)
	}
}

// TestClient_ValidToken_NoCredentials pins the case where no token has ever
// been saved: validToken must return ErrNoCredentials (checkable via
// errors.Is) and must never attempt any HTTP call.
func TestClient_ValidToken_NoCredentials(t *testing.T) {
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

	_, err := c.validToken(context.Background())
	if !errors.Is(err, ErrNoCredentials) {
		t.Errorf("validToken() error = %v, want ErrNoCredentials", err)
	}
	if calls != 0 {
		t.Errorf("token endpoint was called %d time(s), want 0 — no stored credentials means no refresh attempt", calls)
	}
}
