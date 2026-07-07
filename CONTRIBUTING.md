# Contributing to vdt

Thanks for considering a contribution to vdt. This guide covers setup, the
project layout, how to add a new module, and the development workflow.

## Setup

- Go 1.26.x
- [golangci-lint](https://golangci-lint.run/) pinned to `v2.12.2` (the exact
  version used by CI)

## Project layout

- `cmd/vdt/` — the entrypoint (`main.go`); wires and executes the root
  Cobra command.
- `internal/cli` — the root command plus the explicit module registry
  (`registry.go`), the single source of truth for which modules are
  compiled into the CLI.
- `internal/version` — build info (version/commit/date) injected via
  `-ldflags` at build time; exposed through `vdt version`.
- `internal/ping` — the **reference module**; copy it to bootstrap any
  new module (see "Adding a module" below).
- `internal/config` — config/secrets stub; see the note in "Adding a
  module" below for what's implemented today versus what isn't.

## Adding a module

vdt uses an explicit-registry pattern for modules — there is no `init()`
side-effect or self-registration magic. To add a new module:

1. Copy `internal/ping/ping.go` to `internal/<name>/<name>.go`.
2. Adapt `Command()` in the new file to implement your module's behavior.
3. Register it by adding exactly one line to `moduleCommands()` in
   `internal/cli/registry.go`:

   ```go
   func moduleCommands() []*cobra.Command {
       return []*cobra.Command{
           ping.Command(),
           <name>.Command(),
       }
   }
   ```

That's it — no other wiring is needed. The registry file is the single
source of truth for which modules are compiled into the CLI.

Beyond the mechanics above, a new module must:

- Live under `internal/<name>/` and expose a single constructor:
  `func Command() *cobra.Command`.
- Include table-driven tests using the standard library `testing` package
  (no `testify` or other test-assertion libraries).
- Be `gosec`-clean, i.e. it must not trip any finding from the `gosec`
  linter enabled in `.golangci.yml`.

**A note on config:** `internal/config` provides real, working config
loading. `Config` has a `Linear` section (`ClientID` plus a
self-redacting `ClientSecret`), and `Load()`/`LoadFrom()`/`SaveTo()`
actually read and write the on-disk YAML file, resolved via `Path()`
(under `os.UserConfigDir()`, XDG on Linux — `~/.config/vdt/config.yaml`).
`Load()` returns `ErrNotConfigured` only when no config file exists yet, so
callers can tell "not configured" from a genuine I/O or parse error. The
`config.Secret` type self-redacts on `fmt`/logging and JSON marshaling; on
the YAML boundary its real value is still persisted. A self-contained
module like `ping` (flags in, output out) needs none of this. A module that
needs credentials or persisted settings adds its own section to `Config`
and reads it env-first, falling back to the config file — as the `linear`
module already does for its OAuth client ID and secret.

## Development

```sh
make check
```

Runs formatting, `go vet`, `golangci-lint`, and the test suite, in that
order. This must be green before opening a PR.

### Branching

- **Never commit directly to `main`.** All work happens on a feature branch.
- Open a pull request from your feature branch targeting `main`.
- PRs are merged only after CI is green and the change has been reviewed.
