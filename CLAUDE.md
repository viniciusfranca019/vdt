# CLAUDE.md

Guidance for Claude Code (and contributors) working in this repository.

## Project

`vdt` (Vini Daily Tools) is a small, extensible Go CLI built on
[spf13/cobra](https://github.com/spf13/cobra). It ships as a single static
binary; each capability lives in its own self-contained module under
`internal/`. There is no plugin system or runtime discovery — modules are
wired together explicitly in one place (`internal/cli/registry.go`), so the
full set of available commands is always visible by reading a single file.

## Layout

- `cmd/vdt/` — the entrypoint (`main.go`); wires and executes the root
  Cobra command. This is the only `package main` in the repo.
- `internal/cli` — the root command plus the explicit module registry
  (`registry.go`). This file is the single source of truth for which
  modules are compiled into the CLI.
- `internal/version` — build info (version/commit/date) injected via
  `-ldflags` at build time; exposed through `vdt version`.
- `internal/ping` — the **reference module**. Copy it to bootstrap any new
  module; see "Adding a module" below.
- `internal/config` — config/secrets stub. Defines the `config.Secret`
  type and the XDG-based config path/loading pattern future modules should
  follow.

## Commands

- `make check` — runs `gofmt -w .`, `go vet ./...`, `golangci-lint run`,
  then `go test -race ./...`, in that order. Must be green before opening
  any PR.
- `make build` — builds the `vdt` binary from `./cmd/vdt` with version
  ldflags.
- `make test` — runs `go test -race ./...`.
  - Note: `-race` requires cgo and a working C toolchain. CI and normal
    dev machines have gcc available and run it as-is. In a sandbox
    **without** a C toolchain, use plain `go test ./...` instead — do not
    force `-race` there.
- `./install.sh` — builds `vdt` and installs it to `~/.local/bin` by
  default (override with `VDT_INSTALL_DIR`). Also supports
  `./install.sh uninstall`.

## Conventions (MUST follow)

- **Explicit module registration only.** New modules are added by listing
  `<name>.Command()` in `moduleCommands()` inside
  `internal/cli/registry.go`. NEVER use `init()`-based self-registration —
  the registry file must remain the sole, readable source of truth for the
  CLI's command set.
- **Tests**: use the standard library `testing` package, table-driven
  style. Do NOT use `testify` or any other assertion library.
- **Secrets**: any sensitive value (API keys, tokens, passwords) must be
  held as `config.Secret`, never a plain `string`, once it leaves the
  boundary where it was read. `Secret` self-redacts on `fmt`/logging
  (`String()` returns `"[REDACTED]"`) and on JSON marshaling
  (`MarshalJSON` returns `"[REDACTED]"`).
- **Config paths**: always resolve via `os.UserConfigDir()` (XDG on
  Linux: `$XDG_CONFIG_HOME` or `$HOME/.config`), never relative to the
  repository or current working directory. See `config.Path()`.
- **Secrets sourcing**: prefer env-first — read from environment
  variables before touching the on-disk config file. Fall back to the
  XDG config file only if the env var is unset.
- **Lint-clean**: new modules must be `gosec`-clean (gosec is excluded
  only on `_test.go` files, per `.golangci.yml`).

## Adding a module

1. Copy `internal/ping/ping.go` to `internal/<name>/<name>.go`.
2. Adapt `Command()` in the new file to implement the module's behavior,
   keeping the `func Command() *cobra.Command` constructor shape.
3. Register it with exactly one line added to `moduleCommands()` in
   `internal/cli/registry.go`:

   ```go
   func moduleCommands() []*cobra.Command {
       return []*cobra.Command{
           ping.Command(),
           <name>.Command(),
       }
   }
   ```

4. Add table-driven tests using stdlib `testing` (no testify).

No other wiring is needed — nothing else in the repo needs to change to
pick up a new module.

## Git golden rule

- **NEVER commit or push directly to `main`.** All work happens on a
  feature branch.
- Open a pull request from the feature branch targeting `main`; merge
  only after CI is green and the change has been reviewed.
- Use [Conventional Commits](https://www.conventionalcommits.org/) for
  commit messages.

## Linters

- `golangci-lint` is pinned to `v2.12.2` (the exact version CI uses).
- Enabled linters (see `.golangci.yml`): `errcheck`, `govet`,
  `staticcheck`, `ineffassign`, `unused`, `revive`, `gosec`. `gofmt` and
  `goimports` are configured under the `formatters:` section in v2, not as
  linters.
- `goimports` uses local-prefix grouping for `github.com/viniciusfranca/vdt`.
- `gosec` findings are excluded on `_test.go` files only — all other Go
  files must be gosec-clean.
