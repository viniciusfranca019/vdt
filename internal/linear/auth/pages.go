package auth

import (
	_ "embed"
	"html/template"
	"strings"
)

// successPageHTML is the static (no external resources) page shown to the
// user after a successful authorization callback. It is embedded verbatim
// at build time since it has no dynamic content.
//
//go:embed pages/success.html
var successPageHTML string

// errorPageSrc is the html/template source for the page shown to the user
// when the callback carries an OAuth error or fails the state check. The
// dynamic reason is rendered through the {{ . }} action so html/template
// performs context-aware HTML escaping automatically.
//
//go:embed pages/error.html
var errorPageSrc string

// errorPageTemplate is parsed once at package init from the embedded
// pages/error.html source.
var errorPageTemplate = template.Must(template.New("error").Parse(errorPageSrc))

// fallbackErrorPageHTML is the minimal, static, no-external-resources page
// served in the (practically unreachable) case where executing
// errorPageTemplate itself fails. It never includes the raw reason, so it
// stays safe even if the template execution failed because of the reason
// value.
const fallbackErrorPageHTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Linear Authorization Failed</title>
</head>
<body>
<h1>Authorization failed</h1>
</body>
</html>`

// successPage returns the static success page HTML.
func successPage() string {
	return successPageHTML
}

// renderErrorPage executes errorPageTemplate with reason, which
// html/template automatically HTML-escapes since reason is passed as plain
// data (never as template source). On the practically impossible execute
// error it falls back to fallbackErrorPageHTML rather than risk
// propagating reason unescaped.
func renderErrorPage(reason string) string {
	var buf strings.Builder
	if err := errorPageTemplate.Execute(&buf, reason); err != nil {
		return fallbackErrorPageHTML
	}

	return buf.String()
}
