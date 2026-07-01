// Package config is the stub for vdt's future configuration and secrets
// handling.
//
// Pattern for FUTURE modules (e.g. a hypothetical "linear" module that talks
// to the Linear API with an API key):
//
//  1. Env-first: always attempt to read secrets from environment variables
//     before touching any file on disk. Example: LINEAR_API_KEY. This keeps
//     CI/container usage simple and avoids writing secrets to disk unless the
//     user opts in.
//  2. XDG config dir fallback: if the environment variable is not set, fall
//     back to a per-user config file located via os.UserConfigDir() (never a
//     path relative to the repository or working directory). On Linux this
//     resolves to $XDG_CONFIG_HOME or $HOME/.config. vdt's own config lives
//     at <UserConfigDir>/vdt/config.yaml (see Path below); a future module
//     would add its own section to that same file rather than inventing a
//     new file per module, unless there's a strong reason to isolate it.
//  3. Secrets are never stored or logged as plain strings. Any secret value
//     read from the environment or the config file must be wrapped in the
//     Secret type below so that accidental logging, fmt.Sprintf, or JSON
//     marshaling redacts it automatically instead of leaking the value.
//
// This file is intentionally a stub: Config carries no fields yet, and Load
// does not parse YAML. It exists so future modules have a single, agreed
// place to hang their configuration and a well-defined "not configured yet"
// error to check for.
package config

import (
	"errors"
	"os"
	"path/filepath"
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

// Config is the root vdt configuration. It is currently empty; future
// modules should add their own fields (or nested structs) here as they gain
// persisted configuration needs.
type Config struct{}

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

// Load reads and parses vdt's configuration file.
//
// If the file does not exist, Load returns ErrNotConfigured so callers can
// distinguish "not configured yet" from a genuine I/O or parse error.
//
// This is currently a stub: once a config file is found, an empty *Config is
// returned without parsing any YAML. Parsing will be added once Config
// grows real fields.
func Load() (*Config, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotConfigured
		}

		return nil, err
	}

	return &Config{}, nil
}
