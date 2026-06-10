#!/bin/sh
# tirith install script
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/sheeki03/tirith/main/scripts/install.sh | sh
#   TIRITH_VERSION=0.1.3 curl -fsSL ... | sh
set -eu

REPO="sheeki03/tirith"
INSTALL_DIR="${TIRITH_INSTALL_DIR:-$HOME/.local/bin}"

err() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

info() {
  printf '%s\n' "$1"
}

warn() {
  printf 'warning: %s\n' "$1" >&2
}

detect_platform() {
  OS="$(uname -s)"
  ARCH="$(uname -m)"

  case "$OS" in
    Linux)  PLATFORM="unknown-linux-gnu" ;;
    Darwin) PLATFORM="apple-darwin" ;;
    *)      err "Unsupported OS: $OS" ;;
  esac

  case "$ARCH" in
    x86_64|amd64)   ARCH="x86_64" ;;
    aarch64|arm64)   ARCH="aarch64" ;;
    *)               err "Unsupported architecture: $ARCH" ;;
  esac

  TARGET="${ARCH}-${PLATFORM}"
  ARCHIVE="tirith-${TARGET}.tar.gz"
}

resolve_version() {
  if [ -n "${TIRITH_VERSION:-}" ]; then
    # Normalize: strip leading v if present, then re-add
    TIRITH_VERSION="${TIRITH_VERSION#v}"
    VERSION="v${TIRITH_VERSION}"
  else
    VERSION="latest"
  fi
}

download_url() {
  local file="$1"
  if [ "$VERSION" = "latest" ]; then
    printf 'https://github.com/%s/releases/latest/download/%s' "$REPO" "$file"
  else
    printf 'https://github.com/%s/releases/download/%s/%s' "$REPO" "$VERSION" "$file"
  fi
}

fetch() {
  local url="$1"
  local output="$2"
  if command -v curl >/dev/null 2>&1; then
    if [ -n "${GITHUB_TOKEN:-}" ]; then
      curl -fsSL -H "Authorization: token ${GITHUB_TOKEN}" -o "$output" "$url"
    else
      curl -fsSL -o "$output" "$url"
    fi
  elif command -v wget >/dev/null 2>&1; then
    if [ -n "${GITHUB_TOKEN:-}" ]; then
      wget -q --header="Authorization: token ${GITHUB_TOKEN}" -O "$output" "$url"
    else
      wget -q -O "$output" "$url"
    fi
  else
    err "Neither curl nor wget found. Install one and retry."
  fi
}

verify_sha256() {
  # Probe capability, not just presence. Apple's /sbin/sha256sum accepts `-c` as
  # a flag but does not read checksum lines from stdin, so the real invocation
  # (`sha256sum -c` with piped stdin) fails with a usage error. Feed the known
  # empty-string SHA-256 (the hash of /dev/null) through stdin to confirm the
  # binary actually validates before trusting it.
  _empty_sha=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  if command -v sha256sum >/dev/null 2>&1 && \
     printf '%s  /dev/null\n' "$_empty_sha" | sha256sum -c >/dev/null 2>&1; then
    sha256sum -c
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c
  else
    err "No GNU-compatible sha256sum or shasum found"
  fi
}

# Signature verification is MANDATORY by default: a missing cosign, an
# undownloadable signature/certificate, or a failed verification all abort the
# install. Set TIRITH_ALLOW_UNSIGNED=1 to opt out and fall back to best-effort
# (checksum-only) with a clear warning. Only do this if you understand the
# supply-chain risk.
verify_cosign() {
  local workdir="$1"
  local allow_unsigned="${TIRITH_ALLOW_UNSIGNED:-}"

  if ! command -v cosign >/dev/null 2>&1; then
    if [ -n "$allow_unsigned" ]; then
      warn "cosign not found; skipping signature verification (TIRITH_ALLOW_UNSIGNED=1; checksum only)"
      return 0
    fi
    err "cosign is required to verify the release signature but was not found. Install cosign (https://github.com/sigstore/cosign), or set TIRITH_ALLOW_UNSIGNED=1 to install with checksum-only verification (NOT recommended)."
  fi

  local sig_url
  local pem_url
  sig_url="$(download_url checksums.txt.sig)"
  pem_url="$(download_url checksums.txt.pem)"

  # Download the signature and certificate. Failure to fetch either is fatal
  # unless the caller opted out of signature verification.
  if ! fetch "$sig_url" "${workdir}/checksums.txt.sig" 2>/dev/null; then
    if [ -n "$allow_unsigned" ]; then
      warn "signature not available; skipping signature verification (TIRITH_ALLOW_UNSIGNED=1; checksum only)"
      return 0
    fi
    err "could not download the release signature (checksums.txt.sig). The release may be unsigned, or the download failed. Set TIRITH_ALLOW_UNSIGNED=1 to install with checksum-only verification (NOT recommended)."
  fi
  if ! fetch "$pem_url" "${workdir}/checksums.txt.pem" 2>/dev/null; then
    if [ -n "$allow_unsigned" ]; then
      warn "certificate not available; skipping signature verification (TIRITH_ALLOW_UNSIGNED=1; checksum only)"
      return 0
    fi
    err "could not download the release certificate (checksums.txt.pem). The release may be unsigned, or the download failed. Set TIRITH_ALLOW_UNSIGNED=1 to install with checksum-only verification (NOT recommended)."
  fi

  info "Verifying checksums signature with cosign..."
  if ! cosign verify-blob \
    --signature "${workdir}/checksums.txt.sig" \
    --certificate "${workdir}/checksums.txt.pem" \
    --certificate-identity-regexp '^https://github\.com/sheeki03/tirith/\.github/workflows/' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    "${workdir}/checksums.txt"; then
    # A FAILED verification is always fatal: even under TIRITH_ALLOW_UNSIGNED,
    # a present-but-bad signature means tampering, not a missing-tool fallback.
    err "cosign verification failed; the release signature did NOT verify. Do not trust these artifacts."
  fi
}

main() {
  detect_platform
  resolve_version

  info "Installing tirith (${VERSION}) for ${TARGET}..."

  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT

  # Download archive and checksums
  info "Downloading ${ARCHIVE}..."
  fetch "$(download_url "$ARCHIVE")" "${tmpdir}/${ARCHIVE}"

  info "Downloading checksums.txt..."
  fetch "$(download_url checksums.txt)" "${tmpdir}/checksums.txt"

  # Verify SHA256
  info "Verifying checksum..."
  CHECKSUM_LINE=$(grep -F "  ${ARCHIVE}" "${tmpdir}/checksums.txt" || true)
  if [ -z "$CHECKSUM_LINE" ]; then
    err "No checksum entry found for ${ARCHIVE} in checksums.txt"
  fi
  LINE_COUNT=$(printf '%s\n' "$CHECKSUM_LINE" | grep -c .)
  if [ "$LINE_COUNT" -ne 1 ]; then
    err "Expected exactly one checksum entry for ${ARCHIVE}, found ${LINE_COUNT}"
  fi
  (cd "$tmpdir" && printf '%s\n' "$CHECKSUM_LINE" | verify_sha256) \
    || err "Checksum verification failed"

  # Attempt cosign verification (optional)
  verify_cosign "$tmpdir"

  # Extract and install binary only
  info "Extracting..."
  tar xzf "${tmpdir}/${ARCHIVE}" -C "$tmpdir"
  mkdir -p "$INSTALL_DIR"
  if command -v install >/dev/null 2>&1; then
    install -m 755 "${tmpdir}/tirith" "${INSTALL_DIR}/tirith"
  else
    cp "${tmpdir}/tirith" "${INSTALL_DIR}/tirith"
    chmod 755 "${INSTALL_DIR}/tirith"
  fi

  info ""
  info "tirith installed to ${INSTALL_DIR}/tirith"

  # PATH advice
  case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
      info ""
      info "Add to your shell profile:"
      info "  export PATH=\"${INSTALL_DIR}:\$PATH\""
      ;;
  esac

  info ""
  info "Then activate shell integration:"
  info "  eval \"\$(tirith init)\""
  info ""
  info "To uninstall:"
  info "  rm ${INSTALL_DIR}/tirith"
}

if [ "${TIRITH_INSTALL_SH_LIB:-0}" != "1" ]; then
  main "$@"
fi
