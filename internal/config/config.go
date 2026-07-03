// Package config handles vdt's configuration and secrets.
//
// Pattern for modules that need persisted configuration (e.g. the "linear"
// module's OAuth client credentials):
//
//  1. Env-first: always attempt to read secrets from environment variables
//     before touching any file on disk. Example: LINEAR_API_KEY. This keeps
//     CI/container usage simple and avoids writing secrets to disk unless the
//     user opts in.
//  2. XDG config dir fallback: if the environment variable is not set, fall
//     back to a per-user config file located via os.UserConfigDir() (never a
//     path relative to the repository or working directory). On Linux this
//     resolves to $XDG_CONFIG_HOME or $HOME/.config. vdt's own config lives
//     at <UserConfigDir>/vdt/config.yaml (see Path below); a module adds its
//     own section to that same file rather than inventing a new file per
//     module, unless there's a strong reason to isolate it.
//  3. Secrets are never stored or logged as plain strings. Any secret value
//     read from the environment or the config file must be wrapped in the
//     Secret type below so that accidental logging, fmt.Sprintf, or JSON
//     marshaling redacts it automatically instead of leaking the value. On
//     the YAML persistence boundary (LoadFrom/SaveTo), Secret values are
//     converted to/from plain strings via diskConfig so the real value -
//     not "[REDACTED]" - is what lands on disk.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// ErrNotConfigured is returned by Load when no config file exists yet at
// the path returned by Path. Callers should treat this as "use defaults /
// prompt the user to configure vdt", not as a fatal error.
var ErrNotConfigured = errors.New("vdt is not configured")

// Secret wraps a sensitive string value (API keys, tokens, passwords, etc.)
// so that it can be passed around and stored in structs without risking
// accidental exposure through logging, fmt printing, or JSON encoding.
//
// Every secret value read by any vdt module - present or future - should be
// held as a Secret, never as a plain string, once it leaves the boundary
// where it was read from the environment or config file.
type Secret string

// String implements fmt.Stringer. It deliberately never returns the
// underlying value so that Secret is safe to pass to fmt.Println, %v, %s,
// error messages, and logging calls.
func (s Secret) String() string {
	return "[REDACTED]"
}

// MarshalJSON implements json.Marshaler. It deliberately never encodes the
// underlying value so that Secret is safe to embed in any struct that gets
// serialized to JSON (e.g. for debug output or API request bodies that are
// logged).
func (s Secret) MarshalJSON() ([]byte, error) {
	return []byte(`"[REDACTED]"`), nil
}

// Config is the root vdt configuration. Modules add their own nested struct
// here as they gain persisted configuration needs.
type Config struct {
	Linear LinearConfig `yaml:"linear"`
}

// LinearConfig holds the persisted configuration for the linear module: the
// OAuth application's client ID and client secret. ClientSecret is a
// config.Secret so it self-redacts on any accidental fmt/logging/JSON-marshal
// path; SaveTo/LoadFrom cross the YAML boundary via diskConfig so the real
// value still lands on disk (see diskConfig below).
type LinearConfig struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret Secret `yaml:"client_secret"`
}

// diskConfig is the plain-string on-disk representation of Config. It exists
// solely so SaveTo/LoadFrom can cross the YAML boundary without relying on
// Secret's zero-value marshaling behavior: today Secret has no
// MarshalYAML/UnmarshalYAML, so yaml.v3 would encode/decode it as its
// underlying string anyway, but routing through this plain-string boundary
// type (mirroring internal/linear/store.go's diskToken) keeps that behavior
// explicit and immune to a future redacting method being added to Secret.
type diskConfig struct {
	Linear diskLinearConfig `yaml:"linear"`
}

// diskLinearConfig is the plain-string on-disk mirror of LinearConfig.
type diskLinearConfig struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
}

// Path returns the absolute path to vdt's config file, always rooted under
// the user's OS-appropriate config directory (via os.UserConfigDir) and
// never relative to the current working directory or the vdt repository.
//
// On Linux this typically resolves to $XDG_CONFIG_HOME/vdt/config.yaml or
// $HOME/.config/vdt/config.yaml.
func Path() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, "vdt", "config.yaml"), nil
}

// Load reads and parses vdt's configuration file, located at Path().
//
// If the file does not exist, Load returns ErrNotConfigured so callers can
// distinguish "not configured yet" from a genuine I/O or parse error.
func Load() (*Config, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}

	return LoadFrom(path)
}

// LoadFrom reads and parses the vdt configuration file at path.
//
// If no file exists at path, LoadFrom returns ErrNotConfigured (checkable
// via errors.Is) so callers can distinguish "not configured yet" from a
// genuine I/O or parse error. A file that exists but omits the linear
// section (or has an empty one) loads successfully with a zero-value
// LinearConfig.
func LoadFrom(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotConfigured
		}

		return nil, fmt.Errorf("read config file: %w", err)
	}

	var dc diskConfig
	if err := yaml.Unmarshal(raw, &dc); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}

	return &Config{
		Linear: LinearConfig{
			ClientID:     dc.Linear.ClientID,
			ClientSecret: Secret(dc.Linear.ClientSecret),
		},
	}, nil
}

// SaveTo writes c as YAML to path, creating any missing parent directories
// (mode 0700) and writing the file atomically at mode 0600: it stages the
// content in a temp file in the same directory, syncs and closes it, then
// renames it onto path. The temp file is removed if any step fails.
func SaveTo(path string, c *Config) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	dc := diskConfig{
		Linear: diskLinearConfig{
			ClientID:     c.Linear.ClientID,
			ClientSecret: string(c.Linear.ClientSecret),
		},
	}

	data, err := yaml.Marshal(dc)
	if err != nil {
		return fmt.Errorf("encode config file: %w", err)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp config file: %w", err)
	}
	tmpPath := tmp.Name()

	if err := writeAndCommit(tmp, tmpPath, path, data); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	return nil
}

// writeAndCommit writes data to the already-open temp file f (located at
// tmpPath), enforces mode 0600, syncs and closes it, then atomically renames
// it onto path. Any error leaves cleanup of tmpPath to the caller.
func writeAndCommit(f *os.File, tmpPath, path string, data []byte) error {
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("chmod temp config file: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write temp config file: %w", err)
	}

	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync temp config file: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp config file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp config file: %w", err)
	}

	return nil
}
