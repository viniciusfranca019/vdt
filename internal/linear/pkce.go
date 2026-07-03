package linear

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

// codeVerifierEntropyBytes is the number of random bytes read to build a
// PKCE code verifier. 32 raw bytes base64url-encode (no padding) to 43
// characters, satisfying the RFC 7636 minimum length of 43.
const codeVerifierEntropyBytes = 32

// stateEntropyBytes is the number of random bytes read to build the OAuth
// "state" parameter used for CSRF protection.
const stateEntropyBytes = 32

// codeChallengeS256 derives the PKCE code challenge from a code verifier
// using the S256 transform defined in RFC 7636: BASE64URL-ENCODE(SHA256(verifier)).
func codeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// newCodeVerifier generates a PKCE code verifier by reading
// codeVerifierEntropyBytes of randomness from r and base64url-encoding
// (no padding) the result.
func newCodeVerifier(r io.Reader) (string, error) {
	return randomToken(r, codeVerifierEntropyBytes)
}

// newState generates an OAuth "state" value by reading stateEntropyBytes of
// randomness from r and base64url-encoding (no padding) the result.
func newState(r io.Reader) (string, error) {
	return randomToken(r, stateEntropyBytes)
}

// randomToken reads n bytes from r and returns them base64url-encoded
// (no padding). It returns an empty string and a non-nil error if the read
// fails or is short.
func randomToken(r io.Reader, n int) (string, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}
