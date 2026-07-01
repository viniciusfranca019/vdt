# Contributing to vdt

Thanks for considering a contribution to vdt.

## Setup

- Go 1.26.x
- [golangci-lint](https://golangci-lint.run/) pinned to `v2.12.2` (the exact
  version used by CI)

## Before opening a PR

Run the full check suite locally and make sure it is green:

```sh
make check
```

This runs, in order: `gofmt -w .`, `go vet ./...`, `golangci-lint run`, and
`go test -race ./...`.

## Branching

- **Never commit directly to `main`.** All work happens on a feature branch.
- Open a pull request from your feature branch targeting `main`.
- PRs are merged only after CI is green and the change has been reviewed.

## Adding a new module

A new module must:

- Live under `internal/<name>/`.
- Expose a single constructor: `func Command() *cobra.Command`.
- Be registered explicitly by adding one line to `moduleCommands()` in
  `internal/cli/registry.go`. No `init()`-based self-registration.
- Include table-driven tests using the standard library `testing` package
  (no `testify` or other test-assertion libraries).
- Be `gosec`-clean, i.e. it must not trip any finding from the `gosec`
  linter enabled in `.golangci.yml`.

See `internal/ping/ping.go` for the reference module implementation.
