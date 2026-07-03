package linear

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"regexp"
	"strings"
	"testing"
	"testing/iotest"
)

// rfc7636UnreservedRE matches the RFC 7636 code-verifier unreserved charset
// [A-Za-z0-9-._~]. RawURLEncoding produces the subset [A-Za-z0-9-_], which
// this class covers.
var rfc7636UnreservedRE = regexp.MustCompile(`^[A-Za-z0-9\-._~]+$`)

// base64URLNoPadRE matches base64url without padding: no '=', no '+', no '/'.
var base64URLNoPadRE = regexp.MustCompile(`^[A-Za-z0-9\-_]+$`)

// TestCodeChallengeS256KnownAnswer anchors the S256 math to the exact vector
// from RFC 7636, Appendix B. This proves correctness, not mere plausibility.
func TestCodeChallengeS256KnownAnswer(t *testing.T) {
	const (
		verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)

	if got := codeChallengeS256(verifier); got != expected {
		t.Errorf("codeChallengeS256(%q) = %q, want %q", verifier, got, expected)
	}
}

// TestCodeChallengeS256Shape verifies the challenge is base64url-no-pad and
// equals an independently recomputed S256 for arbitrary verifiers.
func TestCodeChallengeS256Shape(t *testing.T) {
	tests := []struct {
		name     string
		verifier string
	}{
		{name: "rfc7636 vector", verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
		{name: "short", verifier: "abc"},
		{name: "empty", verifier: ""},
		{name: "unreserved chars", verifier: "A-Za-z0-9-._~"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := codeChallengeS256(tt.verifier)

			if strings.ContainsAny(got, "=+/") {
				t.Errorf("challenge %q contains non-base64url chars (=, + or /)", got)
			}
			if !base64URLNoPadRE.MatchString(got) {
				t.Errorf("challenge %q is not base64url-no-pad", got)
			}

			sum := sha256.Sum256([]byte(tt.verifier))
			want := base64.RawURLEncoding.EncodeToString(sum[:])
			if got != want {
				t.Errorf("codeChallengeS256(%q) = %q, want %q", tt.verifier, got, want)
			}
		})
	}
}

// TestNewCodeVerifierValidity feeds a deterministic reader and checks the
// verifier length is in [43,128] and uses only the RFC 7636 unreserved set,
// with no '=' padding.
func TestNewCodeVerifierValidity(t *testing.T) {
	// 32 fixed bytes of entropy.
	seed := bytes.Repeat([]byte{0xAB}, 32)

	got, err := newCodeVerifier(bytes.NewReader(seed))
	if err != nil {
		t.Fatalf("newCodeVerifier returned error: %v", err)
	}

	if n := len(got); n < 43 || n > 128 {
		t.Errorf("verifier length = %d, want in [43,128]", n)
	}
	if strings.Contains(got, "=") {
		t.Errorf("verifier %q contains '=' padding", got)
	}
	if !rfc7636UnreservedRE.MatchString(got) {
		t.Errorf("verifier %q contains chars outside RFC 7636 unreserved set", got)
	}
}

// TestNewCodeVerifierDeterminismAndVariation asserts same bytes -> same
// verifier, and different bytes -> different verifier.
func TestNewCodeVerifierDeterminismAndVariation(t *testing.T) {
	seedA := bytes.Repeat([]byte{0x01}, 32)
	seedB := bytes.Repeat([]byte{0x02}, 32)

	first, err := newCodeVerifier(bytes.NewReader(seedA))
	if err != nil {
		t.Fatalf("newCodeVerifier(seedA) error: %v", err)
	}
	again, err := newCodeVerifier(bytes.NewReader(seedA))
	if err != nil {
		t.Fatalf("newCodeVerifier(seedA) repeat error: %v", err)
	}
	other, err := newCodeVerifier(bytes.NewReader(seedB))
	if err != nil {
		t.Fatalf("newCodeVerifier(seedB) error: %v", err)
	}

	if first != again {
		t.Errorf("same reader bytes produced different verifiers: %q vs %q", first, again)
	}
	if first == other {
		t.Errorf("different reader bytes produced identical verifier: %q", first)
	}
}

// TestNewStateValidity asserts state is non-empty and base64url-no-pad.
func TestNewStateValidity(t *testing.T) {
	seed := bytes.Repeat([]byte{0x7F}, 32)

	got, err := newState(bytes.NewReader(seed))
	if err != nil {
		t.Fatalf("newState returned error: %v", err)
	}

	if got == "" {
		t.Fatal("newState returned empty string")
	}
	if strings.ContainsAny(got, "=+/") {
		t.Errorf("state %q contains non-base64url chars (=, + or /)", got)
	}
	if !base64URLNoPadRE.MatchString(got) {
		t.Errorf("state %q is not base64url-no-pad", got)
	}
}

// TestNewStateVariation asserts different reader bytes -> different state.
func TestNewStateVariation(t *testing.T) {
	seedA := bytes.Repeat([]byte{0x10}, 32)
	seedB := bytes.Repeat([]byte{0x20}, 32)

	a, err := newState(bytes.NewReader(seedA))
	if err != nil {
		t.Fatalf("newState(seedA) error: %v", err)
	}
	b, err := newState(bytes.NewReader(seedB))
	if err != nil {
		t.Fatalf("newState(seedB) error: %v", err)
	}

	if a == b {
		t.Errorf("different reader bytes produced identical state: %q", a)
	}
}

// TestReaderErrorPropagates verifies a failing reader yields a non-nil error
// (and no panic, no partial string) from both generators.
func TestReaderErrorPropagates(t *testing.T) {
	tests := []struct {
		name string
		fn   func(r io.Reader) (string, error)
	}{
		{
			name: "newCodeVerifier",
			fn:   newCodeVerifier,
		},
		{
			name: "newState",
			fn:   newState,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.fn(iotest.ErrReader(iotest.ErrTimeout))
			if err == nil {
				t.Fatalf("%s: expected error from failing reader, got nil (result %q)", tt.name, got)
			}
			if got != "" {
				t.Errorf("%s: expected empty string on error, got %q", tt.name, got)
			}
		})
	}
}
