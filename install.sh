#!/bin/sh
# Stackdog Security — install script
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/trydirect/stackdog/main/install.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/trydirect/stackdog/main/install.sh | sudo bash -s -- --version v0.2.2
#
# Installs the stackdog binary to /usr/local/bin.
# Requires: curl, tar, sha256sum (or shasum), Linux x86_64 or aarch64.

set -eu

REPO="trydirect/stackdog"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="stackdog"

# --- helpers ----------------------------------------------------------------

info()  { printf '\033[1;32m▸ %s\033[0m\n' "$*"; }
warn()  { printf '\033[1;33m⚠ %s\033[0m\n' "$*"; }
error() { printf '\033[1;31m✖ %s\033[0m\n' "$*" >&2; exit 1; }

need_cmd() {
  if ! command -v "$1" > /dev/null 2>&1; then
    error "Required command not found: $1"
  fi
}

# --- detect platform --------------------------------------------------------

detect_platform() {
  OS="$(uname -s)"
  ARCH="$(uname -m)"

  case "$OS" in
    Linux)  OS="linux" ;;
    *)      error "Unsupported OS: $OS. Stackdog binaries are available for Linux only." ;;
  esac

  case "$ARCH" in
    x86_64|amd64)   ARCH="x86_64"  ;;
    aarch64|arm64)   ARCH="aarch64" ;;
    *)               error "Unsupported architecture: $ARCH. Supported: x86_64, aarch64." ;;
  esac

  PLATFORM="${OS}-${ARCH}"
}

# --- resolve version --------------------------------------------------------

resolve_version() {
  if [ -n "${VERSION:-}" ]; then
    # strip leading v if present for consistency
    VERSION="$(echo "$VERSION" | sed 's/^v//')"
    TAG="v${VERSION}"
    return
  fi

  info "Fetching latest release..."
  TAG="$(
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
      | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/' || true
  )"

  # GitHub returns 404 for /releases/latest when there are no stable releases
  # (for example only pre-releases). Fall back to the most recent release entry.
  if [ -z "$TAG" ]; then
    warn "No stable 'latest' release found, trying most recent release..."
    TAG="$(
      curl -fsSL "https://api.github.com/repos/${REPO}/releases?per_page=1" 2>/dev/null \
        | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/' || true
    )"
  fi

  if [ -z "$TAG" ]; then
    error "Could not determine latest release. Create a GitHub release, or specify one with --version (e.g. --version v0.2.2)."
  fi

  VERSION="$(echo "$TAG" | sed 's/^v//')"
}

# --- download & verify ------------------------------------------------------

download_and_install() {
  TARBALL="${BINARY_NAME}-${PLATFORM}.tar.gz"
  CHECKSUM_FILE="${TARBALL}.sha256"
  DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/${TARBALL}"
  CHECKSUM_URL="https://github.com/${REPO}/releases/download/${TAG}/${CHECKSUM_FILE}"

  TMPDIR="$(mktemp -d)"
  trap 'rm -rf "$TMPDIR"' EXIT

  info "Downloading stackdog ${VERSION} for ${PLATFORM}..."
  curl -fsSL -o "${TMPDIR}/${TARBALL}" "$DOWNLOAD_URL" \
    || error "Download failed. Check that release ${TAG} exists at https://github.com/${REPO}/releases"

  info "Downloading checksum..."
  curl -fsSL -o "${TMPDIR}/${CHECKSUM_FILE}" "$CHECKSUM_URL" \
    || warn "Checksum file not available — skipping verification"

  # verify checksum if available
  if [ -f "${TMPDIR}/${CHECKSUM_FILE}" ]; then
    info "Verifying checksum..."
    EXPECTED="$(awk '{print $1}' "${TMPDIR}/${CHECKSUM_FILE}")"
    if command -v sha256sum > /dev/null 2>&1; then
      ACTUAL="$(sha256sum "${TMPDIR}/${TARBALL}" | awk '{print $1}')"
    elif command -v shasum > /dev/null 2>&1; then
      ACTUAL="$(shasum -a 256 "${TMPDIR}/${TARBALL}" | awk '{print $1}')"
    else
      warn "sha256sum/shasum not found — skipping checksum verification"
      ACTUAL="$EXPECTED"
    fi

    if [ "$EXPECTED" != "$ACTUAL" ]; then
      error "Checksum mismatch!\n  expected: ${EXPECTED}\n  actual:   ${ACTUAL}"
    fi
  fi

  info "Extracting..."
  tar -xzf "${TMPDIR}/${TARBALL}" -C "${TMPDIR}"

  info "Installing to ${INSTALL_DIR}/${BINARY_NAME}..."
  install -m 755 "${TMPDIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
}

# --- main -------------------------------------------------------------------

main() {
  # parse args
  while [ $# -gt 0 ]; do
    case "$1" in
      --version)  VERSION="$2"; shift 2 ;;
      --help|-h)
        echo "Usage: install.sh [--version VERSION]"
        echo ""
        echo "Install stackdog binary to ${INSTALL_DIR}."
        echo ""
        echo "Options:"
        echo "  --version VERSION   Install a specific version (e.g. v0.2.2)"
        echo "  --help              Show this help"
        exit 0
        ;;
      *) error "Unknown option: $1" ;;
    esac
  done

  need_cmd curl
  need_cmd tar

  detect_platform
  resolve_version
  download_and_install

  info "stackdog ${VERSION} installed successfully!"
  echo ""
  echo "  Run:  stackdog --help"
  echo ""
}

main "$@"
