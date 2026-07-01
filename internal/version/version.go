// Package version holds build-time metadata for the vdt CLI.
//
// The variables below are intended to be overridden at build time via
// linker flags, e.g.:
//
//	go build -ldflags "-X github.com/viniciusfranca/vdt/internal/version.Version=1.2.3 \
//	  -X github.com/viniciusfranca/vdt/internal/version.Commit=abc123 \
//	  -X github.com/viniciusfranca/vdt/internal/version.Date=2026-07-01"
package version

import "fmt"

// Version, Commit and Date are populated via -ldflags -X at build time.
// They default to placeholder values for local/dev builds.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String returns a single-line, human-readable representation of the
// current build's version metadata.
func String() string {
	return fmt.Sprintf("vdt %s (commit %s, built %s)", Version, Commit, Date)
}
