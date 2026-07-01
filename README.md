# vdt

Vini Daily Tools — a small, extensible Go CLI.

## What it is

`vdt` is a modular command-line tool for day-to-day developer tasks. It
ships as a single static binary built with [Cobra](https://github.com/spf13/cobra),
where each capability lives in its own self-contained module under
`internal/`. There is no plugin system or runtime discovery — modules are
wired together explicitly in one place, so the full set of available
commands is always visible by reading a single file.

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

## Install (Linux)

Clone the repository and run the install script:

```sh
git clone https://github.com/viniciusfranca/vdt.git
cd vdt
./install.sh
```

This builds `vdt` and installs it to `~/.local/bin` by default. Override the
destination with `VDT_INSTALL_DIR`:

```sh
VDT_INSTALL_DIR="$HOME/bin" ./install.sh
```

Alternatively, using `make`:

```sh
make install
```

Make sure the install directory is on your `PATH`.

## Usage

```sh
vdt version
vdt ping
vdt ping --count 3
```

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

**A note on config:** `internal/config` is currently a stub. What exists
today is the `config.Secret` type (self-redacts on `fmt`/logging and JSON
marshaling), `Path()` (resolves the config file location via
`os.UserConfigDir()`, XDG on Linux), and `ErrNotConfigured`. What's *not*
implemented yet is actual loading — `Config` has no fields and `Load()`
just returns `ErrNotConfigured`; nothing reads environment variables or the
on-disk YAML file yet. In practice, this means a self-contained module like
`ping` (flags in, output out) can be added right now with zero config work.
A module that needs credentials or persisted settings (e.g. a future
`linear` module needing an API token) will need real config loading
implemented first.

## Development

```sh
make check
```

Runs formatting, `go vet`, `golangci-lint`, and the test suite, in that
order. This must be green before opening a PR.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
