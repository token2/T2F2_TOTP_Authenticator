#!/usr/bin/env bash
#
# add-sample-profiles.sh — provision a handful of TOTP test profiles onto a
# Token2 key via the t2totp CLI, including one tagged for Auto-OTP ([A]).
#
# These use well-known RFC-style test secrets so the codes are reproducible and
# can be cross-checked against any other authenticator. They are TEST secrets —
# do not use them for real accounts.
#
# Usage:
#   ./scripts/add-sample-profiles.sh                # auto-detect transport
#   ./scripts/add-sample-profiles.sh --transport nfc
#   T2TOTP=/path/to/t2totp ./scripts/add-sample-profiles.sh
#
# Pass any extra flags (e.g. --transport nfc, --reader "NAME", --debug) and they
# are forwarded to every t2totp call.

set -euo pipefail

# Locate the binary: $T2TOTP, then PATH, then ./target/release, then debug.
T2TOTP="${T2TOTP:-}"
if [[ -z "$T2TOTP" ]]; then
  if command -v t2totp >/dev/null 2>&1; then
    T2TOTP="t2totp"
  elif [[ -x "./target/release/t2totp" ]]; then
    T2TOTP="./target/release/t2totp"
  elif [[ -x "./target/debug/t2totp" ]]; then
    T2TOTP="./target/debug/t2totp"
  else
    echo "error: t2totp binary not found. Build it (cargo build --release) or set \$T2TOTP." >&2
    exit 1
  fi
fi

# Extra args (transport/reader/debug) forwarded to every call.
COMMON_ARGS=("$@")

# add_profile <issuer> <account> <base32-secret> [extra add-flags...]
# The secret is piped on stdin, never passed on the command line.
add_profile() {
  local issuer="$1" account="$2" secret="$3"
  shift 3
  echo "  + ${issuer}:${account} $*"
  printf '%s' "$secret" | "$T2TOTP" "${COMMON_ARGS[@]}" add "$issuer" "$account" "$@"
}

echo "Using: $T2TOTP ${COMMON_ARGS[*]}"
echo "Adding sample TOTP profiles…"

# A standard SHA-1 / 30s / 6-digit profile (the classic RFC 6238 test seed
# "12345678901234567890" Base32-encoded).
add_profile "Example"  "alice@example.com" "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

# A SHA-256 variant.
add_profile "Acme"     "bob@acme.test"     "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" --sha256

# A short/long-period variant (8 digits, 60-second step).
add_profile "Widgets"  "carol"             "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" --digits 8 --period 60

# A touch-required profile (the key must be pressed to reveal/emit the code).
add_profile "Bank"     "dave"              "KRSXG5CTMVRXEZLUKRSXG5CTMVRXEZLU" --touch

# The Auto-OTP profile: tagged [A] so the global hotkey targets it. Only ONE
# profile should carry the [A] tag.
add_profile "MyAuto"   "me@auto.test"      "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" --auto

echo
echo "Done. Current profiles:"
"$T2TOTP" "${COMMON_ARGS[@]}" list
