#!/usr/bin/env bash
# install.sh builds and installs (or uninstalls) the vdt CLI binary.
#
# Usage:
#   ./install.sh [install|uninstall]
#
# Environment:
#   VDT_INSTALL_DIR  Override the install directory (default: $HOME/.local/bin)
set -euo pipefail

VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo none)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

LDFLAGS="-X github.com/viniciusfranca/vdt/internal/version.Version=${VERSION} -X github.com/viniciusfranca/vdt/internal/version.Commit=${COMMIT} -X github.com/viniciusfranca/vdt/internal/version.Date=${DATE}"

INSTALL_DIR="${VDT_INSTALL_DIR:-$HOME/.local/bin}"

usage() {
	echo "Usage: $0 [install|uninstall]"
	echo
	echo "  install    Build vdt and install it to \$INSTALL_DIR (default action)"
	echo "  uninstall  Remove vdt from \$INSTALL_DIR"
	echo
	echo "Environment:"
	echo "  VDT_INSTALL_DIR  Override the install directory (default: \$HOME/.local/bin)"
}

cmd_install() {
	echo "==> Building vdt ${VERSION} (commit ${COMMIT}, built ${DATE})"
	mkdir -p "$INSTALL_DIR"
	go build -ldflags "$LDFLAGS" -o "$INSTALL_DIR/vdt" .
	echo "==> Installed vdt to $INSTALL_DIR/vdt"

	case ":$PATH:" in
	*":$INSTALL_DIR:"*) ;;
	*)
		echo
		echo "WARNING: $INSTALL_DIR is not in your PATH."
		echo "Add it to your shell profile, e.g.:"
		echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
		;;
	esac
}

cmd_uninstall() {
	echo "==> Removing $INSTALL_DIR/vdt"
	rm -f "$INSTALL_DIR/vdt"
	echo "==> Uninstalled vdt from $INSTALL_DIR"
}

main() {
	local action="${1:-install}"

	case "$action" in
	install)
		cmd_install
		;;
	uninstall)
		cmd_uninstall
		;;
	*)
		usage
		exit 1
		;;
	esac
}

main "$@"
