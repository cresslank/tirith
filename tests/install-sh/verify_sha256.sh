#!/bin/sh
# Regression tests for scripts/install.sh verify_sha256.
#
# The bug: on macOS hosts where /sbin/sha256sum is first in PATH, the pre-fix
# installer tried `sha256sum -c` and died because Apple's sha256sum rejects
# stdin input. The fix: capability-probe before dispatching.
#
# These tests stub a PATH-visible sha256sum that mimics the Apple failure mode
# and assert that verify_sha256 still succeeds for valid input (falling through
# to shasum) and still fails for invalid input.
#
# Plain POSIX sh; no bats/bash dependency. Works on Linux and macOS runners.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_SH="$REPO_ROOT/scripts/install.sh"

if [ ! -f "$INSTALL_SH" ]; then
  echo "fatal: cannot locate install.sh at $INSTALL_SH" >&2
  exit 2
fi

work="$(mktemp -d 2>/dev/null || mktemp -d -t tirith-test)"
trap 'rm -rf "$work"' EXIT INT TERM

# Stub mimics macOS /sbin/sha256sum: accepts -c as a flag but emits a usage
# error when no file argument is provided (the real invocation pipes from
# stdin, which Apple's binary does not support).
stub_dir="$work/stubs"
mkdir -p "$stub_dir"
cat > "$stub_dir/sha256sum" <<'STUB'
#!/bin/sh
has_c=0
file=
for arg in "$@"; do
  case "$arg" in
    -c) has_c=1 ;;
    -*) ;;
    *) file="$arg" ;;
  esac
done
if [ "$has_c" = 1 ] && [ -z "$file" ]; then
  echo "usage: sha256sum [-bctwz] [files ...]" >&2
  exit 1
fi
echo "sha256sum-stub: unexpected invocation" >&2
exit 1
STUB
chmod +x "$stub_dir/sha256sum"

# Put the stub ahead of any real sha256sum on PATH and source install.sh as a
# library. TIRITH_INSTALL_SH_LIB=1 prevents main from running.
PATH="$stub_dir:$PATH"
export PATH
TIRITH_INSTALL_SH_LIB=1 . "$INSTALL_SH"

# Compute a real hash via shasum (always present on macOS and most Linuxes).
if ! command -v shasum >/dev/null 2>&1; then
  echo "skip: shasum not available on this runner" >&2
  exit 0
fi

sample="$work/sample.txt"
printf 'hello tirith\n' > "$sample"
good_sha=$(shasum -a 256 "$sample" | awk '{print $1}')
bad_sha=0000000000000000000000000000000000000000000000000000000000000000

fails=0

# Happy path: the probe must detect that sha256sum is broken, fall through to
# shasum, and verify a valid checksum.
if printf '%s  %s\n' "$good_sha" "$sample" | verify_sha256 >/dev/null 2>&1; then
  echo "ok  1 apple-style sha256sum: valid checksum verifies via shasum fallback"
else
  echo "not ok  1 valid checksum should have verified" >&2
  fails=$((fails + 1))
fi

# Failure path: an invalid checksum must still be rejected.
if printf '%s  %s\n' "$bad_sha" "$sample" | verify_sha256 >/dev/null 2>&1; then
  echo "not ok  2 invalid checksum should have been rejected" >&2
  fails=$((fails + 1))
else
  echo "ok  2 apple-style sha256sum: invalid checksum rejected via shasum fallback"
fi

if [ "$fails" -gt 0 ]; then
  echo "FAIL: $fails test(s) failed" >&2
  exit 1
fi

echo "PASS: verify_sha256 handles Apple-style sha256sum correctly"
