# vdt

Vini Daily Tools — a small, extensible Go CLI.

## What it is

`vdt` is a modular command-line tool for day-to-day developer tasks. It
ships as a single static binary built with [Cobra](https://github.com/spf13/cobra),
where each capability lives in its own self-contained module under
`internal/`. There is no plugin system or runtime discovery — modules are
wired together explicitly in one place, so the full set of available
commands is always visible by reading a single file.

Project layout, how to add a module, and the development workflow live in
[CONTRIBUTING.md](CONTRIBUTING.md).

## Modules

- **`ping`** — the reference module; prints `pong` a configurable number of
  times, useful as a liveness check and as the template for new modules.

  ```sh
  vdt ping            # prints "pong" once
  vdt ping --count 3  # prints "pong" three times
  ```

- **`linear`** — authenticate with [Linear](https://linear.app) from the CLI
  via OAuth 2.0 (authorization code flow with PKCE). Auth-related
  subcommands are grouped under `vdt linear auth`. See
  [internal/linear/README.md](internal/linear/README.md) for the full setup
  guide (creating your own OAuth application, providing credentials, and
  where tokens are stored).

  ```sh
  vdt linear auth login    # run the OAuth flow and store a token
  vdt linear auth refresh  # force-refresh the stored access token
  vdt linear auth logout   # revoke the token and delete it locally
  ```

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

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
