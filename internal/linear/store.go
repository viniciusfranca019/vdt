package linear

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/viniciusfranca/vdt/internal/config"
)

// credentialsFileName is the name of the on-disk file holding the Linear
// OAuth credentials, relative to the directory passed to newStore. This is a
// file name, not a hardcoded credential value; the file itself is written
// with mode 0600 by store.save.
//
//nolint:gosec // see comment above
const credentialsFileName = "linear_credentials.json"

// ErrNoCredentials is returned by store.load when no credentials have been
// saved yet. Callers should treat this as "the user is not authenticated",
// not as a fatal error.
var ErrNoCredentials = errors.New("linear: not authenticated")

// Token holds the OAuth 2.0 tokens issued by Linear for the authenticated
// user. Access and Refresh are held as config.Secret so they self-redact on
// any accidental fmt/logging/JSON-marshal path.
type Token struct {
	Access  config.Secret
	Refresh config.Secret
	Expiry  time.Time
}

// diskToken is the plain-string on-disk representation of Token. It exists
// solely so save/load can cross the JSON boundary without ever invoking
// config.Secret.MarshalJSON, whose "[REDACTED]" output would otherwise be
// silently persisted in place of the real token.
type diskToken struct {
	Access  string    `json:"access_token"`
	Refresh string    `json:"refresh_token"`
	Expiry  time.Time `json:"expiry"`
}

// store persists a single Token on disk as JSON, at <dir>/linear_credentials.json.
type store struct {
	path string
}

// newStore builds a store whose backing file lives at
// filepath.Join(dir, "linear_credentials.json").
func newStore(dir string) *store {
	return &store{path: filepath.Join(dir, credentialsFileName)}
}

// load reads and decodes the stored Token. If no credentials file exists,
// load returns (nil, ErrNoCredentials).
func (s *store) load() (*Token, error) {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoCredentials
		}

		return nil, fmt.Errorf("read linear credentials: %w", err)
	}

	var dt diskToken
	if err := json.Unmarshal(raw, &dt); err != nil {
		return nil, fmt.Errorf("decode linear credentials: %w", err)
	}

	return &Token{
		Access:  config.Secret(dt.Access),
		Refresh: config.Secret(dt.Refresh),
		Expiry:  dt.Expiry,
	}, nil
}

// save atomically writes t to disk with mode 0600. It never marshals t
// directly (config.Secret would redact itself); instead it converts to the
// plain-string diskToken first.
func (s *store) save(t *Token) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create linear config dir: %w", err)
	}

	dt := diskToken{
		Access:  string(t.Access),
		Refresh: string(t.Refresh),
		Expiry:  t.Expiry,
	}

	//nolint:gosec // diskToken is the deliberate plaintext boundary type used
	// solely to persist the real token to a mode-0600 file on disk; it is
	// never logged or transmitted, so this is not a secret leak.
	data, err := json.Marshal(dt)
	if err != nil {
		return fmt.Errorf("encode linear credentials: %w", err)
	}

	tmp, err := os.CreateTemp(dir, credentialsFileName+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp linear credentials file: %w", err)
	}
	tmpPath := tmp.Name()

	if err := s.writeAndCommit(tmp, tmpPath, data); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	return nil
}

// writeAndCommit writes data to the already-open temp file f (located at
// tmpPath), enforces mode 0600, syncs and closes it, then atomically renames
// it onto s.path. Any error leaves cleanup of tmpPath to the caller.
func (s *store) writeAndCommit(f *os.File, tmpPath string, data []byte) error {
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("chmod temp linear credentials file: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write temp linear credentials file: %w", err)
	}

	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync temp linear credentials file: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp linear credentials file: %w", err)
	}

	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("rename temp linear credentials file: %w", err)
	}

	return nil
}

// delete removes the stored credentials file. It is idempotent: deleting an
// already-absent file returns nil.
func (s *store) delete() error {
	if err := os.Remove(s.path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return fmt.Errorf("delete linear credentials: %w", err)
	}

	return nil
}
