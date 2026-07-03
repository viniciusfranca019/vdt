package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"sync"
	"time"
)

// callbackPath is the exact, and only, path the loopback OAuth callback
// server accepts. Anything else gets a 404.
const callbackPath = "/callback"

// readHeaderTimeout bounds how long the callback server waits to read a
// request's headers, mitigating Slowloris-style connection exhaustion
// (gosec G112) on the brief local listener we spin up for the OAuth
// redirect.
const readHeaderTimeout = 5 * time.Second

// shutdownTimeout bounds how long Close/shutdown waits for the callback
// server's single in-flight connection to finish before giving up.
const shutdownTimeout = 5 * time.Second

// callbackOutcome bundles the two values the HTTP handler delivers to
// wait() over resultCh. It is distinct from the test file's callbackResult
// (used only to shuttle wait()'s return values out of a test goroutine) so
// the two never collide in the same package.
type callbackOutcome struct {
	code string
	err  error
}

// callbackServer is a short-lived, loopback-only HTTP server that receives
// exactly one OAuth 2.0 authorization redirect from Linear, validates its
// state parameter (CSRF protection), and hands the authorization code back
// to whoever called wait().
type callbackServer struct {
	httpServer    *http.Server
	listener      net.Listener
	expectedState string

	resultCh    chan callbackOutcome
	deliverOnce sync.Once

	closeOnce sync.Once
	closeErr  error
}

// newCallbackServer binds a listener on 127.0.0.1:port (127.0.0.1
// literally, never "localhost", so the callback is unreachable from
// anywhere but this machine) and starts serving in the background. Passing
// port 0 lets the OS assign an ephemeral port, which redirectURI reports
// back once bound.
func newCallbackServer(port int, expectedState string) (*callbackServer, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("listen for linear oauth callback: %w", err)
	}

	c := &callbackServer{
		listener:      listener,
		expectedState: expectedState,
		resultCh:      make(chan callbackOutcome, 1),
	}

	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, c.handleCallback)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	c.httpServer = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	go func() {
		if err := c.httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			// There is no channel to surface a Serve-level failure on
			// other than resultCh, and wait() already has its own
			// context-timeout escape hatch, so a non-graceful Serve error
			// is deliberately swallowed here rather than panicking a
			// background goroutine.
			_ = err
		}
	}()

	return c, nil
}

// redirectURI returns the loopback URL Linear should redirect the user's
// browser back to once they approve (or deny) access, reflecting whatever
// port the OS actually bound (relevant when newCallbackServer was given
// port 0).
func (c *callbackServer) redirectURI() string {
	port := 0
	if addr, ok := c.listener.Addr().(*net.TCPAddr); ok {
		port = addr.Port
	}

	return fmt.Sprintf("http://127.0.0.1:%d%s", port, callbackPath)
}

// wait blocks until the callback handler has delivered a result or ctx is
// done, whichever happens first. On a context timeout/cancellation it
// returns promptly with an empty code and a wrapped ctx.Err().
func (c *callbackServer) wait(ctx context.Context) (string, error) {
	select {
	case res := <-c.resultCh:
		return res.code, res.err
	case <-ctx.Done():
		return "", fmt.Errorf("wait for linear oauth callback: %w", ctx.Err())
	}
}

// Close idempotently shuts down the callback server and its listener. It is
// safe to call multiple times (including via defer after wait() has
// already triggered a shutdown itself): only the first call performs any
// work, and subsequent calls return the same (possibly nil) result.
func (c *callbackServer) Close() error {
	c.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if err := c.httpServer.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			c.closeErr = fmt.Errorf("shutdown linear oauth callback server: %w", err)
		}
	})

	return c.closeErr
}

// handleCallback is the sole handler for callbackPath. It never logs
// r.URL.RawQuery or the full request URL, since either could carry a
// sensitive authorization code.
func (c *callbackServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Referrer-Policy", "no-referrer")

	q := r.URL.Query()

	// The OAuth "error" param (e.g. the user denied access) is checked
	// first and independently of state: we still want to reject cleanly
	// without ever depending on / echoing the raw query string.
	if errParam := q.Get("error"); errParam != "" {
		c.deliver(w, "", fmt.Errorf("linear authorization denied: %s", errParam), errorPageHTML(errParam))
		return
	}

	// Constant-time comparison is the non-negotiable CSRF defense here: a
	// timing side-channel on state comparison would let an attacker probe
	// for the expected value byte by byte.
	got := q.Get("state")
	if subtle.ConstantTimeCompare([]byte(got), []byte(c.expectedState)) != 1 {
		// On mismatch the code must never be surfaced, so it is
		// intentionally omitted from the delivered outcome even though it
		// was present on the request.
		c.deliver(w, "", errors.New("linear oauth callback: state mismatch"), errorPageHTML("state mismatch"))
		return
	}

	c.deliver(w, q.Get("code"), nil, successPageHTML)
}

// deliver hands (code, err) to wait() exactly once, via sync.Once. Any
// callback that arrives after the first delivery gets 410 Gone and its
// payload is discarded rather than overwriting the already-delivered
// result. The first (and only) successful delivery writes page to the
// browser and kicks off an async server shutdown.
func (c *callbackServer) deliver(w http.ResponseWriter, code string, err error, page string) {
	delivered := false
	c.deliverOnce.Do(func() {
		delivered = true
		c.resultCh <- callbackOutcome{code: code, err: err}
	})

	if !delivered {
		http.Error(w, "linear oauth callback already handled", http.StatusGone)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(page))

	// Shut down asynchronously: Shutdown waits for this very connection to
	// go idle, which only happens once this handler returns and the
	// response above is flushed, so running it inline here would deadlock.
	go func() { _ = c.Close() }()
}

// successPageHTML is the inline (no external resources) page shown to the
// user after a successful authorization callback.
const successPageHTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Linear Authorization</title>
<style>body{font-family:sans-serif;text-align:center;margin-top:10%}</style>
</head>
<body>
<h1>Authorization complete</h1>
<p>You may close this window.</p>
</body>
</html>`

// errorPageHTML renders the inline (no external resources) page shown to
// the user when the callback carries an OAuth error or fails the state
// check. reason is HTML-escaped since it originates from a query parameter.
func errorPageHTML(reason string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Linear Authorization Failed</title>
<style>body{font-family:sans-serif;text-align:center;margin-top:10%%}</style>
</head>
<body>
<h1>Authorization failed</h1>
<p>%s</p>
</body>
</html>`, html.EscapeString(reason))
}
