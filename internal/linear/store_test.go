package linear

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/viniciusfranca/vdt/internal/config"
)

// TestStoreSaveLoadRoundTrip pins behavior 1: save then load must return the
// exact Access/Refresh secret values and Expiry that went in - not zero
// values, not truncated values, not the redaction placeholder.
func TestStoreSaveLoadRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		access  string
		refresh string
		expiry  time.Time
	}{
		{
			name:    "utc expiry",
			access:  "real-access-token-abc123",
			refresh: "real-refresh-token-xyz789",
			expiry:  time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			name:    "non-utc expiry catches tz bugs",
			access:  "another-access-token-456",
			refresh: "another-refresh-token-789",
			expiry:  time.Date(2026, 12, 31, 23, 59, 59, 0, time.FixedZone("UTC-3", -3*60*60)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newStore(t.TempDir())

			want := &Token{
				Access:  config.Secret(tt.access),
				Refresh: config.Secret(tt.refresh),
				Expiry:  tt.expiry,
			}

			if err := s.save(want); err != nil {
				t.Fatalf("save() returned unexpected error: %v", err)
			}

			got, err := s.load()
			if err != nil {
				t.Fatalf("load() returned unexpected error: %v", err)
			}

			if string(got.Access) != tt.access {
				t.Errorf("loaded Access = %q, want %q", string(got.Access), tt.access)
			}
			if string(got.Refresh) != tt.refresh {
				t.Errorf("loaded Refresh = %q, want %q", string(got.Refresh), tt.refresh)
			}
			if !got.Expiry.Equal(tt.expiry) {
				t.Errorf("loaded Expiry = %v, want %v (equal-in-time)", got.Expiry, tt.expiry)
			}
		})
	}
}

// TestStoreSaveDoesNotPersistRedactionPlaceholder pins behavior 2: the
// on-disk file must contain the real secret values, never the
// config.Secret.MarshalJSON "[REDACTED]" placeholder. A naive
// json.Marshal(t) of a struct holding config.Secret fields would silently
// write "[REDACTED]" instead of the real token, destroying it. This test
// reads the raw bytes on disk and fails loudly if that happens.
func TestStoreSaveDoesNotPersistRedactionPlaceholder(t *testing.T) {
	dir := t.TempDir()
	s := newStore(dir)

	const (
		access  = "super-secret-access-token-should-be-on-disk"
		refresh = "super-secret-refresh-token-should-be-on-disk"
	)

	tok := &Token{
		Access:  config.Secret(access),
		Refresh: config.Secret(refresh),
		Expiry:  time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC),
	}

	if err := s.save(tok); err != nil {
		t.Fatalf("save() returned unexpected error: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "linear_credentials.json"))
	if err != nil {
		t.Fatalf("failed to read credentials file directly: %v", err)
	}

	if strings.Contains(string(raw), "[REDACTED]") {
		t.Fatalf("credentials file contains the redaction placeholder \"[REDACTED]\" "+
			"instead of the real token - the real secret was destroyed on save. raw contents: %s", raw)
	}

	if !strings.Contains(string(raw), access) {
		t.Errorf("credentials file does not contain the real access token %q; raw contents: %s", access, raw)
	}
	if !strings.Contains(string(raw), refresh) {
		t.Errorf("credentials file does not contain the real refresh token %q; raw contents: %s", refresh, raw)
	}

	// Sanity-check the file is valid JSON (not garbage), independent of the
	// concrete on-disk schema the builder chooses.
	var anyJSON map[string]any
	if err := json.Unmarshal(raw, &anyJSON); err != nil {
		t.Errorf("credentials file is not valid JSON: %v; raw contents: %s", err, raw)
	}
}

// TestStoreSaveFilePermissions pins behavior 3: the credentials file must be
// written with mode 0600 (owner read/write only), regardless of the
// process umask, since it holds live OAuth tokens.
func TestStoreSaveFilePermissions(t *testing.T) {
	dir := t.TempDir()
	s := newStore(dir)

	tok := &Token{
		Access:  config.Secret("perm-check-access"),
		Refresh: config.Secret("perm-check-refresh"),
		Expiry:  time.Now().Add(time.Hour),
	}

	if err := s.save(tok); err != nil {
		t.Fatalf("save() returned unexpected error: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "linear_credentials.json"))
	if err != nil {
		t.Fatalf("os.Stat on credentials file failed: %v", err)
	}

	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("credentials file mode = %o, want %o", got, 0o600)
	}
}

// TestStoreLoadMissingFileReturnsErrNoCredentials pins behavior 4: load on a
// store whose backing file has never been written must return
// ErrNoCredentials specifically (checked via errors.Is), not a generic I/O
// error, and must not panic or return a non-nil *Token.
func TestStoreLoadMissingFileReturnsErrNoCredentials(t *testing.T) {
	s := newStore(t.TempDir())

	got, err := s.load()

	if err == nil {
		t.Fatal("load() on missing file returned nil error, want ErrNoCredentials")
	}
	if !errors.Is(err, ErrNoCredentials) {
		t.Errorf("load() error = %v, want errors.Is match for ErrNoCredentials", err)
	}
	if got != nil {
		t.Errorf("load() returned non-nil Token %+v alongside error %v", got, err)
	}
}

// TestStoreDeleteIdempotent pins behavior 5: delete must be a no-op (nil
// error) when the file is already absent, and must actually remove a saved
// file such that a subsequent load reports ErrNoCredentials.
func TestStoreDeleteIdempotent(t *testing.T) {
	t.Run("delete without prior save is a no-op", func(t *testing.T) {
		s := newStore(t.TempDir())

		if err := s.delete(); err != nil {
			t.Errorf("delete() on absent file returned error: %v, want nil", err)
		}
	})

	t.Run("delete after save removes the file", func(t *testing.T) {
		s := newStore(t.TempDir())

		tok := &Token{
			Access:  config.Secret("delete-me-access"),
			Refresh: config.Secret("delete-me-refresh"),
			Expiry:  time.Now().Add(time.Hour),
		}
		if err := s.save(tok); err != nil {
			t.Fatalf("save() returned unexpected error: %v", err)
		}

		if err := s.delete(); err != nil {
			t.Fatalf("delete() returned unexpected error: %v", err)
		}

		if _, err := s.load(); !errors.Is(err, ErrNoCredentials) {
			t.Errorf("load() after delete() error = %v, want errors.Is match for ErrNoCredentials", err)
		}
	})

	t.Run("calling delete twice is still nil", func(t *testing.T) {
		s := newStore(t.TempDir())

		tok := &Token{
			Access:  config.Secret("delete-twice-access"),
			Refresh: config.Secret("delete-twice-refresh"),
			Expiry:  time.Now().Add(time.Hour),
		}
		if err := s.save(tok); err != nil {
			t.Fatalf("save() returned unexpected error: %v", err)
		}

		if err := s.delete(); err != nil {
			t.Fatalf("first delete() returned unexpected error: %v", err)
		}
		if err := s.delete(); err != nil {
			t.Errorf("second delete() (already absent) returned error: %v, want nil", err)
		}
	})
}

// TestStoreExpiryRoundTripsAcrossJSONBoundary pins behavior 6: the Expiry
// timestamp must survive the JSON encode/decode boundary intact - same
// instant in time - even when the original Time is in a non-UTC location,
// which is a classic source of off-by-timezone bugs.
func TestStoreExpiryRoundTripsAcrossJSONBoundary(t *testing.T) {
	loc := time.FixedZone("UTC+5:30", 5*60*60+30*60)

	tests := []struct {
		name   string
		expiry time.Time
	}{
		{name: "utc", expiry: time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)},
		{name: "non-utc offset", expiry: time.Date(2027, 1, 2, 3, 4, 5, 0, loc)},
		{name: "with nanoseconds", expiry: time.Date(2027, 6, 15, 10, 30, 0, 123456789, time.UTC)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newStore(t.TempDir())

			tok := &Token{
				Access:  config.Secret("expiry-check-access"),
				Refresh: config.Secret("expiry-check-refresh"),
				Expiry:  tt.expiry,
			}

			if err := s.save(tok); err != nil {
				t.Fatalf("save() returned unexpected error: %v", err)
			}

			got, err := s.load()
			if err != nil {
				t.Fatalf("load() returned unexpected error: %v", err)
			}

			if !got.Expiry.Equal(tt.expiry) {
				t.Errorf("loaded Expiry = %v, want an instant equal to %v", got.Expiry, tt.expiry)
			}
		})
	}
}
