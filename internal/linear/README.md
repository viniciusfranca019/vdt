# `vdt linear`

Authenticate with [Linear](https://linear.app) from the CLI via OAuth 2.0 +
PKCE. Once authenticated, other `vdt linear` subcommands (and future ones)
can act on your behalf.

Subcommands (grouped under `vdt linear auth`):

- `vdt linear auth login` — runs the OAuth authorization flow and stores a
  token.
- `vdt linear auth logout` — revokes the stored token and removes it
  locally.
- `vdt linear auth refresh` — force-refreshes the stored access token, even
  if it hasn't expired yet.

## Prerequisite: create your own Linear OAuth application

This module follows a **bring-your-own-OAuth-app** model: there is no
shared/public `vdt` client. Each user creates their own Linear OAuth
application and points it at their local machine.

### 1. Create the OAuth application

In Linear, open your workspace **Settings → API → OAuth applications**
(the exact menu label may vary slightly by Linear version) and create a new
application.

### 2. Set the redirect URI

Set the application's redirect URI to **exactly**:

```
http://127.0.0.1:53682/callback
```

This must match character-for-character. `vdt linear auth login` starts a
local callback server on `127.0.0.1:53682` to receive the authorization
code; if the registered redirect URI differs in any way (scheme, host,
port, path, trailing slash), Linear will reject the token exchange with a
`redirect_uri` mismatch.

### 3. Request scopes

Request the `read,write` scopes for the application.

### 4. Copy the Client ID and Client Secret

Once the application is created, copy its **Client ID** and **Client
Secret** — you'll need both in the next step.

### 5. Provide your credentials

`vdt` resolves the Linear OAuth client_id/client_secret pair by trying each
of these sources in order, stopping at the first one that's fully
satisfied:

1. **Environment variables** — export both values in your shell:

   ```sh
   export LINEAR_CLIENT_ID=your-client-id
   export LINEAR_CLIENT_SECRET=your-client-secret
   ```

   Add these lines to your `~/.bashrc` or `~/.zshrc` so they persist across
   shell sessions.

2. **The on-disk config file** (`~/.config/vdt/config.yaml`, resolved via
   `os.UserConfigDir()`) — if it already has both a `client_id` and
   `client_secret` under the `linear` section.

3. **Interactive prompt** — if neither of the above is set and you're
   running `vdt` from a terminal (TTY), it prompts for the client_id
   (visible) and client_secret (masked), then saves both to the config file
   above so future invocations skip straight to step 2.

4. Otherwise (no env vars, no config, non-interactive session — e.g. a
   script or CI), `vdt` fails with a didactic error naming both env vars
   and the fixed redirect address.

### 6. Log in

```sh
vdt linear auth login
```

This opens your default browser on Linear's authorization page. Approve
the request, and on success the CLI confirms your identity (via Linear's
`viewer { id name }` GraphQL query):

```
Logged in as Ada Lovelace
```

If a browser can't be opened automatically, `vdt linear auth login` prints
the authorization URL so you can open it yourself.

## Where credentials are stored

After a successful login, tokens are written to:

```
~/.config/vdt/linear/credentials.json
```

(resolved via `os.UserConfigDir()`, so this follows XDG conventions on
Linux). The file is created with mode `0600` — readable and writable only
by your user.

Access tokens are refreshed automatically when expired. Tokens are never
printed to the terminal or written to logs.

## Refreshing credentials on demand

```sh
vdt linear auth refresh
```

Unlike the automatic refresh that happens transparently when a stored
token has expired, `vdt linear auth refresh` unconditionally exchanges the
stored refresh token for a new access token, even if the current one is
still valid. Use it to proactively rotate credentials or to verify that
the stored refresh token still works.

If you haven't logged in yet, it fails with an actionable error telling
you to run `vdt linear auth login` first.

## Logging out

```sh
vdt linear auth logout
```

This revokes the token with Linear and deletes the local credentials file.
The local file is deleted even if the revoke call to Linear fails — a
failed revoke must never leave stale local credentials behind.

## Troubleshooting

**"missing OAuth credentials" error**
`LINEAR_CLIENT_ID` and/or `LINEAR_CLIENT_SECRET` are not set, no usable
pair is saved in the config file, and the session isn't interactive.
Revisit [Setup](#5-provide-your-credentials) above — either export both
env vars, or run `vdt linear auth login` from a terminal to be prompted.

**Linear reports a `redirect_uri` mismatch**
Your OAuth application's redirect URI is not registered as exactly
`http://127.0.0.1:53682/callback`. Go back to your Linear OAuth
application's settings and fix it — see [step 2](#2-set-the-redirect-uri).

**"address already in use" or a callback server bind error**
Another `vdt linear auth login` process may already be running, or
something else on your machine is bound to port `53682`. Close any other
in-flight login attempt and try again.

## Security notes

- Secrets (client secret, access/refresh tokens) are held as a
  self-redacting type internally and are never logged or printed.
- The credentials file is created with mode `0600`.
- The PKCE code challenge uses the `S256` method (RFC 7636).
- The OAuth `state` parameter is validated with a constant-time comparison
  to prevent CSRF on the callback.

## Reference: Linear OAuth endpoints

For the curious, `vdt linear` talks to Linear's standard OAuth 2.0 and
GraphQL endpoints:

| Purpose   | URL                                       |
|-----------|--------------------------------------------|
| Authorize | `https://linear.app/oauth/authorize`       |
| Token     | `https://api.linear.app/oauth/token`       |
| Revoke    | `https://api.linear.app/oauth/revoke`      |
