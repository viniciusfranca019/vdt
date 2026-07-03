package linear

import "net/url"

// codeChallengeMethodS256 is the literal PKCE transform identifier sent as
// the code_challenge_method query parameter, per RFC 7636 §4.3. It is a
// constant, not a parameter, because S256 is the only transform vdt ever
// generates a challenge for (see codeChallengeS256 in pkce.go).
const codeChallengeMethodS256 = "S256"

// authorizeScope is the space-free, comma-joined scope list requested for
// the Linear OAuth 2.0 authorization code flow.
const authorizeScope = "read,write"

// buildAuthorizeURL builds the Linear OAuth 2.0 authorization URL for the
// authorization code flow with PKCE (RFC 6749 §4.1.1 + RFC 7636 §4.3).
//
// It deliberately accepts only the already-derived PKCE code_challenge,
// never the code_verifier it was derived from: there is no parameter here a
// caller could (even accidentally) pass a verifier into, so the verifier
// can never end up embedded in a URL that gets opened in a browser, logged,
// or stored in shell history.
func buildAuthorizeURL(base, clientID, redirectURI, state, challenge string) string {
	u, err := url.Parse(base)
	if err != nil {
		// base is a fixed endpoint supplied by this module's own caller
		// (never end-user input), so a parse failure here is a programming
		// error, not a runtime condition worth inventing a fallback for.
		return base
	}

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", codeChallengeMethodS256)
	q.Set("scope", authorizeScope)
	u.RawQuery = q.Encode()

	return u.String()
}
