package linear

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/viniciusfranca/vdt/internal/config"
)

// TestCredentialResolver_EnvWins pins resolution step 1: when BOTH
// LINEAR_CLIENT_ID and LINEAR_CLIENT_SECRET are set in the environment,
// resolve() must use them directly and never touch config, and never
// prompt or save.
func TestCredentialResolver_EnvWins(t *testing.T) {
	env := map[string]string{
		"LINEAR_CLIENT_ID":     "env-client-id",
		"LINEAR_CLIENT_SECRET": "env-client-secret",
	}

	var loadConfigCalls, promptLineCalls, promptSecretCalls, saveConfigCalls int

	r := credentialResolver{
		getenv: func(key string) string { return env[key] },
		loadConfig: func() (*config.Config, error) {
			loadConfigCalls++
			return nil, errors.New("loadConfig should not be called when env vars are set")
		},
		saveConfig: func(string, config.Secret) error {
			saveConfigCalls++
			return nil
		},
		isInteractive: func() bool { return false },
		promptLine: func(string) (string, error) {
			promptLineCalls++
			return "", errors.New("promptLine should not be called")
		},
		promptSecret: func(string) (string, error) {
			promptSecretCalls++
			return "", errors.New("promptSecret should not be called")
		},
		out: &bytes.Buffer{},
	}

	clientID, clientSecret, err := r.resolve()
	if err != nil {
		t.Fatalf("resolve() returned error: %v", err)
	}
	if clientID != "env-client-id" {
		t.Errorf("clientID = %q, want %q", clientID, "env-client-id")
	}
	if string(clientSecret) != "env-client-secret" {
		t.Errorf("clientSecret = %q, want %q", string(clientSecret), "env-client-secret")
	}

	if loadConfigCalls != 0 {
		t.Errorf("loadConfig was called %d time(s), want 0 (env satisfied both vars)", loadConfigCalls)
	}
	if promptLineCalls != 0 {
		t.Errorf("promptLine was called %d time(s), want 0", promptLineCalls)
	}
	if promptSecretCalls != 0 {
		t.Errorf("promptSecret was called %d time(s), want 0", promptSecretCalls)
	}
	if saveConfigCalls != 0 {
		t.Errorf("saveConfig was called %d time(s), want 0", saveConfigCalls)
	}
}

// TestCredentialResolver_ConfigFallback pins resolution step 2: when the
// environment has neither var set but the loaded config already has both a
// non-empty ClientID and ClientSecret, resolve() must use those and never
// prompt or save (there is nothing new to persist).
func TestCredentialResolver_ConfigFallback(t *testing.T) {
	var promptLineCalls, promptSecretCalls, saveConfigCalls int

	r := credentialResolver{
		getenv: func(string) string { return "" },
		loadConfig: func() (*config.Config, error) {
			return &config.Config{
				Linear: config.LinearConfig{
					ClientID:     "cfg-client-id",
					ClientSecret: config.Secret("cfg-client-secret"),
				},
			}, nil
		},
		saveConfig: func(string, config.Secret) error {
			saveConfigCalls++
			return nil
		},
		isInteractive: func() bool { return false },
		promptLine: func(string) (string, error) {
			promptLineCalls++
			return "", errors.New("promptLine should not be called")
		},
		promptSecret: func(string) (string, error) {
			promptSecretCalls++
			return "", errors.New("promptSecret should not be called")
		},
		out: &bytes.Buffer{},
	}

	clientID, clientSecret, err := r.resolve()
	if err != nil {
		t.Fatalf("resolve() returned error: %v", err)
	}
	if clientID != "cfg-client-id" {
		t.Errorf("clientID = %q, want %q", clientID, "cfg-client-id")
	}
	if string(clientSecret) != "cfg-client-secret" {
		t.Errorf("clientSecret = %q, want %q", string(clientSecret), "cfg-client-secret")
	}

	if promptLineCalls != 0 {
		t.Errorf("promptLine was called %d time(s), want 0", promptLineCalls)
	}
	if promptSecretCalls != 0 {
		t.Errorf("promptSecret was called %d time(s), want 0", promptSecretCalls)
	}
	if saveConfigCalls != 0 {
		t.Errorf("saveConfig was called %d time(s), want 0 (nothing new to persist)", saveConfigCalls)
	}
}

// TestCredentialResolver_InteractivePromptSaves pins resolution step 3: when
// env and config both come up empty but the session is interactive,
// resolve() must prompt for the client_id via promptLine (visible) and the
// client_secret via promptSecret (masked) — NOT the other way around — save
// the REAL typed values via saveConfig exactly once, and return them.
//
// This is the critical scenario: it pins that (a) the secret returned by
// resolve() is sourced from the MASKED prompt, and (b) saveConfig receives
// the actual typed secret, not a placeholder or redacted value.
func TestCredentialResolver_InteractivePromptSaves(t *testing.T) {
	var (
		promptLineCalls   int
		promptSecretCalls int
		saveConfigCalls   int
		savedClientID     string
		savedSecret       config.Secret
	)

	r := credentialResolver{
		getenv: func(string) string { return "" },
		loadConfig: func() (*config.Config, error) {
			return nil, config.ErrNotConfigured
		},
		saveConfig: func(clientID string, secret config.Secret) error {
			saveConfigCalls++
			savedClientID = clientID
			savedSecret = secret
			return nil
		},
		isInteractive: func() bool { return true },
		promptLine: func(string) (string, error) {
			promptLineCalls++
			return "cid-typed", nil
		},
		promptSecret: func(string) (string, error) {
			promptSecretCalls++
			return "secret-typed", nil
		},
		out: &bytes.Buffer{},
	}

	clientID, clientSecret, err := r.resolve()
	if err != nil {
		t.Fatalf("resolve() returned error: %v", err)
	}
	if clientID != "cid-typed" {
		t.Errorf("clientID = %q, want %q", clientID, "cid-typed")
	}
	if string(clientSecret) != "secret-typed" {
		t.Errorf("clientSecret = %q, want %q", string(clientSecret), "secret-typed")
	}

	if promptLineCalls != 1 {
		t.Errorf("promptLine was called %d time(s), want exactly 1", promptLineCalls)
	}
	if promptSecretCalls != 1 {
		t.Errorf("promptSecret was called %d time(s), want exactly 1", promptSecretCalls)
	}

	// Critical invariant: the returned secret must be sourced from the
	// MASKED prompt (promptSecret), never the visible one (promptLine).
	// Never weaken this to merely "some prompt was called".
	if promptSecretCalls == 0 {
		t.Error("promptSecret was never called, want the masked prompt to source the client secret")
	}

	// Critical invariant: saveConfig must receive the REAL typed secret
	// value, not a placeholder, not the client_id, not a redacted stand-in.
	// Never weaken this assertion.
	if saveConfigCalls != 1 {
		t.Fatalf("saveConfig was called %d time(s), want exactly 1", saveConfigCalls)
	}
	if savedClientID != "cid-typed" {
		t.Errorf("saveConfig received clientID = %q, want %q", savedClientID, "cid-typed")
	}
	if string(savedSecret) != "secret-typed" {
		t.Errorf("saveConfig received secret = %q, want the real typed value %q", string(savedSecret), "secret-typed")
	}
}

// TestCredentialResolver_NonInteractiveErrors pins resolution step 4: when
// env and config both come up empty and the session is NOT interactive,
// resolve() must return the didactic, actionable error (no prompt, no
// hang) naming both env vars and the fixed redirect address, and must
// never call either prompt or saveConfig.
func TestCredentialResolver_NonInteractiveErrors(t *testing.T) {
	var promptLineCalls, promptSecretCalls, saveConfigCalls int

	r := credentialResolver{
		getenv: func(string) string { return "" },
		loadConfig: func() (*config.Config, error) {
			return nil, config.ErrNotConfigured
		},
		saveConfig: func(string, config.Secret) error {
			saveConfigCalls++
			return nil
		},
		isInteractive: func() bool { return false },
		promptLine: func(string) (string, error) {
			promptLineCalls++
			return "", errors.New("promptLine should not be called")
		},
		promptSecret: func(string) (string, error) {
			promptSecretCalls++
			return "", errors.New("promptSecret should not be called")
		},
		out: &bytes.Buffer{},
	}

	clientID, clientSecret, err := r.resolve()
	if err == nil {
		t.Fatal("resolve() returned nil error for non-interactive, unconfigured credentials, want a didactic error")
	}

	msg := err.Error()
	for _, want := range []string{"LINEAR_CLIENT_ID", "LINEAR_CLIENT_SECRET", "127.0.0.1:53682"} {
		if !strings.Contains(msg, want) {
			t.Errorf("resolve() error %q does not contain %q", msg, want)
		}
	}

	if clientID != "" {
		t.Errorf("clientID = %q, want empty string on error", clientID)
	}
	if string(clientSecret) != "" {
		t.Errorf("clientSecret = %q, want empty string on error", string(clientSecret))
	}
	if promptLineCalls != 0 {
		t.Errorf("promptLine was called %d time(s), want 0", promptLineCalls)
	}
	if promptSecretCalls != 0 {
		t.Errorf("promptSecret was called %d time(s), want 0", promptSecretCalls)
	}
	if saveConfigCalls != 0 {
		t.Errorf("saveConfig was called %d time(s), want 0", saveConfigCalls)
	}
}

// TestCredentialResolver_PartialEnvFallsThrough pins that a HALF-set
// environment (only LINEAR_CLIENT_ID, secret empty) is NOT enough to
// satisfy step 1: resolve() must fall through past env (never silently
// using the half-set value) to config, find nothing there either, and —
// being non-interactive — return the same didactic error as scenario 4.
func TestCredentialResolver_PartialEnvFallsThrough(t *testing.T) {
	env := map[string]string{
		"LINEAR_CLIENT_ID": "partial-cid",
		// LINEAR_CLIENT_SECRET deliberately left unset.
	}

	var promptLineCalls, promptSecretCalls, saveConfigCalls int

	r := credentialResolver{
		getenv: func(key string) string { return env[key] },
		loadConfig: func() (*config.Config, error) {
			return nil, config.ErrNotConfigured
		},
		saveConfig: func(string, config.Secret) error {
			saveConfigCalls++
			return nil
		},
		isInteractive: func() bool { return false },
		promptLine: func(string) (string, error) {
			promptLineCalls++
			return "", errors.New("promptLine should not be called")
		},
		promptSecret: func(string) (string, error) {
			promptSecretCalls++
			return "", errors.New("promptSecret should not be called")
		},
		out: &bytes.Buffer{},
	}

	clientID, clientSecret, err := r.resolve()
	if err == nil {
		t.Fatal("resolve() returned nil error for a half-set LINEAR_CLIENT_ID/LINEAR_CLIENT_SECRET pair, want the didactic error")
	}

	msg := err.Error()
	for _, want := range []string{"LINEAR_CLIENT_ID", "LINEAR_CLIENT_SECRET", "127.0.0.1:53682"} {
		if !strings.Contains(msg, want) {
			t.Errorf("resolve() error %q does not contain %q", msg, want)
		}
	}

	// Critical invariant: partial env must never be silently accepted as
	// "good enough". Never weaken this to allow a half-set pair through.
	if clientID == "partial-cid" {
		t.Error("resolve() used the half-set LINEAR_CLIENT_ID despite LINEAR_CLIENT_SECRET being empty, want it rejected")
	}
	if clientID != "" {
		t.Errorf("clientID = %q, want empty string on error", clientID)
	}
	if string(clientSecret) != "" {
		t.Errorf("clientSecret = %q, want empty string on error", string(clientSecret))
	}
	if promptLineCalls != 0 || promptSecretCalls != 0 || saveConfigCalls != 0 {
		t.Errorf("prompt/save were invoked (promptLine=%d promptSecret=%d saveConfig=%d), want all 0",
			promptLineCalls, promptSecretCalls, saveConfigCalls)
	}
}

// TestCredentialResolver_PromptSecretErrorPropagates pins that a failure
// from the masked secret prompt (e.g. stdin closed, read error) surfaces as
// a non-nil error from resolve() and must never reach saveConfig with a
// partial/garbage credential.
func TestCredentialResolver_PromptSecretErrorPropagates(t *testing.T) {
	var saveConfigCalls int

	r := credentialResolver{
		getenv: func(string) string { return "" },
		loadConfig: func() (*config.Config, error) {
			return nil, config.ErrNotConfigured
		},
		saveConfig: func(string, config.Secret) error {
			saveConfigCalls++
			return nil
		},
		isInteractive: func() bool { return true },
		promptLine: func(string) (string, error) {
			return "cid-typed", nil
		},
		promptSecret: func(string) (string, error) {
			return "", errors.New("simulated prompt failure (e.g. stdin closed)")
		},
		out: &bytes.Buffer{},
	}

	_, _, err := r.resolve()
	if err == nil {
		t.Fatal("resolve() returned nil error when promptSecret failed, want a non-nil error")
	}
	if saveConfigCalls != 0 {
		t.Errorf("saveConfig was called %d time(s) after a failed prompt, want 0", saveConfigCalls)
	}
}

// TestCredentialResolver_SaveFailureDoesNotLeakSecret pins that a failure
// from saveConfig (e.g. disk full, permission denied) surfaces as a
// non-nil error from resolve() — and, critically, that error message must
// NEVER embed the real typed secret value. Never weaken this to merely
// checking that an error occurred.
func TestCredentialResolver_SaveFailureDoesNotLeakSecret(t *testing.T) {
	const typedSecret = "top-secret-should-not-leak-in-error"

	r := credentialResolver{
		getenv: func(string) string { return "" },
		loadConfig: func() (*config.Config, error) {
			return nil, config.ErrNotConfigured
		},
		saveConfig: func(string, config.Secret) error {
			return errors.New("simulated disk write failure")
		},
		isInteractive: func() bool { return true },
		promptLine: func(string) (string, error) {
			return "cid-typed", nil
		},
		promptSecret: func(string) (string, error) {
			return typedSecret, nil
		},
		out: &bytes.Buffer{},
	}

	_, _, err := r.resolve()
	if err == nil {
		t.Fatal("resolve() returned nil error when saveConfig failed, want a non-nil error")
	}
	if strings.Contains(err.Error(), typedSecret) {
		t.Errorf("resolve() error %q leaks the typed client secret value %q", err.Error(), typedSecret)
	}
}
