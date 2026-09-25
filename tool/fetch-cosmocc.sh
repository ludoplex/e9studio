#!/bin/sh
# fetch-cosmocc.sh — install the pinned cosmocc toolchain, verified by sha256
# Usage: COSMOCC=DIR COSMOCC_VERSION=V COSMOCC_SHA256=HEX COSMOCC_URL=URL [COSMOCC_ZIP=local.zip] sh tool/fetch-cosmocc.sh
#        (normally invoked as `make -f Makefile.e9studio toolchain`, which passes the pins from tool/cosmocc.mk)
# Exit codes: 0 ok · 1 general · 2 usage · 3 missing dep · 4 partial state · 90+ assert failure
# Prologue follows the module template adapted to POSIX sh (set -eu; no ERR trap in POSIX sh).
set -eu

NAME=fetch-cosmocc.sh

# --- helpers ---
die() { printf '[%s] %s\n' "$NAME" "$1" >&2; exit "${2:-1}"; }
log() { printf '[%s] %s\n' "$NAME" "$*" >&2; }

# --- parameters: all pins come from the caller (tool/cosmocc.mk) ---
[ -n "${COSMOCC:-}" ] || die "COSMOCC (install directory) is not set" 2
[ -n "${COSMOCC_VERSION:-}" ] || die "COSMOCC_VERSION is not set" 2
[ -n "${COSMOCC_SHA256:-}" ] || die "COSMOCC_SHA256 is not set" 2
[ -n "${COSMOCC_URL:-}" ] || die "COSMOCC_URL is not set" 2
: "${COSMOCC_ZIP:=}"
MARK="$COSMOCC/.cosmocc-sha256"

# --- idempotency: already installed from the same verified archive ---
if [ -f "$MARK" ] && [ "$(cat "$MARK")" = "$COSMOCC_SHA256" ] && [ -x "$COSMOCC/bin/cosmocc" ]; then
  log "cosmocc $COSMOCC_VERSION already installed at $COSMOCC"
  exit 0
fi
# never clobber a directory this script did not create
if [ -e "$COSMOCC" ] && [ ! -f "$MARK" ]; then
  die "refusing to replace $COSMOCC: it exists and was not installed by $NAME" 1
fi

# --- preconditions ---
command -v unzip >/dev/null 2>&1 || die "missing dependency: unzip" 3
if command -v sha256sum >/dev/null 2>&1; then SHA='sha256sum'
elif command -v shasum >/dev/null 2>&1; then SHA='shasum -a 256'
else die "missing dependency: sha256sum or shasum" 3; fi

# --- arena: temp files live next to the destination (same filesystem) ---
parent=$(dirname -- "$COSMOCC")
mkdir -p -- "$parent"
ARENA=$(mktemp -d "$parent/.cosmocc-fetch.XXXXXX")
trap 'rm -rf "$ARENA"' EXIT

# --- fetch (or use the local archive given in COSMOCC_ZIP) ---
if [ -z "$COSMOCC_ZIP" ]; then
  command -v curl >/dev/null 2>&1 || die "missing dependency: curl" 3
  log "downloading $COSMOCC_URL"
  curl -fL --retry 3 -o "$ARENA/cosmocc.zip" "$COSMOCC_URL" || die "download failed: $COSMOCC_URL" 1
  COSMOCC_ZIP="$ARENA/cosmocc.zip"
fi
[ -r "$COSMOCC_ZIP" ] || die "cannot read archive: $COSMOCC_ZIP" 2

# --- verify before unpacking anything ---
got=$($SHA "$COSMOCC_ZIP" | cut -d' ' -f1)
[ "$got" = "$COSMOCC_SHA256" ] || die "sha256 mismatch for $COSMOCC_ZIP: got $got, want $COSMOCC_SHA256" 1
log "sha256 verified: $got"

# --- unpack, check, then swap into place ---
unzip -q "$COSMOCC_ZIP" -d "$ARENA/x"
[ -x "$ARENA/x/bin/cosmocc" ] || die "archive has no bin/cosmocc" 90
printf '%s\n' "$COSMOCC_SHA256" > "$ARENA/x/.cosmocc-sha256"
rm -rf -- "$COSMOCC"      # only reached when $COSMOCC is absent or carries our marker
mv -- "$ARENA/x" "$COSMOCC"

# --- postconditions ---
[ -x "$COSMOCC/bin/cosmocc" ] || die "install incomplete: $COSMOCC/bin/cosmocc missing" 4
log "cosmocc $COSMOCC_VERSION installed at $COSMOCC"
