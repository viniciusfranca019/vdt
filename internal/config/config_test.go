package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/viniciusfranca/vdt/internal/config"
)

// TestLoadFromSaveToRoundTrip pins behavior 1: SaveTo followed by LoadFrom
// returns a Config whose Linear.ClientID and Linear.ClientSecret (as a
// plain string) equal what was originally saved.
func TestLoadFromSaveToRoundTrip(t *testing.T) {
	tests := []struct {
		name         string
		clientID     string
		clientSecret string
	}{
		{
			name:         "typical credentials",
			clientID:     "linear-client-id-abc123",
			clientSecret: "linear-client-secret-super-sensitive-value",
		},
		{
			name:         "credentials with special yaml characters",
			clientID:     "id:with:colons",
			clientSecret: "secret \"with\" quotes and: colons",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")

			want := &config.Config{
				Linear: config.LinearConfig{
					ClientID:     tt.clientID,
					ClientSecret: config.Secret(tt.clientSecret),
				},
			}

			if err := config.SaveTo(path, want); err != nil {
				t.Fatalf("SaveTo(%q, ...) returned error: %v", path, err)
			}

			got, err := config.LoadFrom(path)
			if err != nil {
				t.Fatalf("LoadFrom(%q) returned error: %v", path, err)
			}

			if got.Linear.ClientID != tt.clientID {
				t.Errorf("Linear.ClientID = %q, want %q", got.Linear.ClientID, tt.clientID)
			}
			if string(got.Linear.ClientSecret) != tt.clientSecret {
				t.Errorf("Linear.ClientSecret = %q, want %q", string(got.Linear.ClientSecret), tt.clientSecret)
			}
		})
	}
}

// TestSaveToWritesRealSecretAt0600 pins behavior 2: the security-critical
// guarantee that the client secret is persisted to disk as its REAL value
// (not "[REDACTED]") and that the file is created with mode 0600. This
// guards against a future regression where Secret's redacting String() or
// MarshalJSON() leaks into the YAML encoding path instead of the real
// value being written.
func TestSaveToWritesRealSecretAt0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	const realSecret = "sk-linear-real-secret-value-do-not-redact"

	cfg := &config.Config{
		Linear: config.LinearConfig{
			ClientID:     "some-client-id",
			ClientSecret: config.Secret(realSecret),
		},
	}

	if err := config.SaveTo(path, cfg); err != nil {
		t.Fatalf("SaveTo(%q, ...) returned error: %v", path, err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading saved config file: %v", err)
	}

	if !strings.Contains(string(raw), realSecret) {
		t.Errorf("saved config file does not contain the real client secret; got:\n%s", raw)
	}
	if strings.Contains(string(raw), "[REDACTED]") {
		t.Errorf("saved config file contains the literal redaction marker \"[REDACTED]\" instead of the real secret; got:\n%s", raw)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat saved config file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("saved config file mode = %o, want %o", perm, 0o600)
	}
}

// TestLoadFromMissingFileReturnsErrNotConfigured pins behavior 3: loading a
// path that has no file at all returns the existing config.ErrNotConfigured
// sentinel, checked via errors.Is, distinguishing "not configured" from any
// other I/O error.
func TestLoadFromMissingFileReturnsErrNotConfigured(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist", "config.yaml")

	_, err := config.LoadFrom(path)
	if err == nil {
		t.Fatalf("LoadFrom(%q) returned nil error, want ErrNotConfigured", path)
	}
	if !errors.Is(err, config.ErrNotConfigured) {
		t.Errorf("LoadFrom(%q) error = %v, want errors.Is match for ErrNotConfigured", path, err)
	}
}

// TestSaveToCreatesParentDirectory pins behavior 4: SaveTo must create any
// missing parent directories (mode 0700) for the target path rather than
// failing because the directory doesn't exist yet.
func TestSaveToCreatesParentDirectory(t *testing.T) {
	dir := t.TempDir()
	// Nested, non-existent parent directories.
	path := filepath.Join(dir, "nested", "does", "not", "exist", "config.yaml")

	cfg := &config.Config{
		Linear: config.LinearConfig{
			ClientID:     "client-id",
			ClientSecret: config.Secret("client-secret"),
		},
	}

	if err := config.SaveTo(path, cfg); err != nil {
		t.Fatalf("SaveTo(%q, ...) returned error: %v", path, err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected config file to exist at %q after SaveTo, stat error: %v", path, err)
	}
}

// TestLoadFromPresentButEmptyLinearSection pins behavior 5: a config file
// that exists on disk but has no linear section (or an empty one) must load
// successfully with zero-value Linear fields and no error - distinguishing
// "file present but unset" from "file absent" (ErrNotConfigured).
func TestLoadFromPresentButEmptyLinearSection(t *testing.T) {
	tests := []struct {
		name     string
		contents string
	}{
		{name: "empty file", contents: ""},
		{name: "no linear key", contents: "some_other_key: value\n"},
		{name: "empty linear section", contents: "linear:\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")

			if err := os.WriteFile(path, []byte(tt.contents), 0o600); err != nil {
				t.Fatalf("writing seed config file: %v", err)
			}

			got, err := config.LoadFrom(path)
			if err != nil {
				t.Fatalf("LoadFrom(%q) returned error: %v, want nil", path, err)
			}

			if got.Linear.ClientID != "" {
				t.Errorf("Linear.ClientID = %q, want empty string", got.Linear.ClientID)
			}
			if string(got.Linear.ClientSecret) != "" {
				t.Errorf("Linear.ClientSecret = %q, want empty string", string(got.Linear.ClientSecret))
			}
		})
	}
}
