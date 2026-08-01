#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# The five-minute ISSUE path (M16 Task 1). One command boots a LOCAL registrar, issues your first passport, verifies
# it, and says in plain words what just happened — and leaves you a PERSISTENT, reusable registrar (not a throwaway).
#
#   make issue-first                 # → registrar in ./my-registrar, one passport, verified   [LOCAL TESTBED]
#   DIR=./my-registrar ID=registrar-07 OPERATOR=acme LINEAGE=assistant LINEAGE_VERSION=1.0.0  make issue-first
#
# This is the registrar layer (where issuance lives), never the root. Real crypto, local only, zero telemetry.
set -uo pipefail
cd "$(dirname "$0")/.."
DIR="${DIR:-my-registrar}"; ID="${ID:-registrar-07}"
OPERATOR="${OPERATOR:-acme}"; LINEAGE="${LINEAGE:-assistant}"; VERSION="${LINEAGE_VERSION:-${VERSION:-1.0.0}}"
# `make release VERSION=vX.Y.Z` exports VERSION into every recursive recipe environment (GNU make exports
# command-line variables) — a RELEASE version is not a LINEAGE version and fails the name grammar. Guard:
case "$VERSION" in
  *[!0-9.]*|.*|*.) echo "   note: ignoring non-lineage VERSION=\"$VERSION\" from the environment (using 1.0.0; set LINEAGE_VERSION to override)"; VERSION=1.0.0;;
esac
TIER="${TIER:-L2}"; AUTH="${AUTH:-A2}"; CAP="${CAP:-read:data}"
b(){ printf '\033[1m%s\033[0m' "$1"; }; dim(){ printf '\033[2m%s\033[0m' "$1"; }

echo; b "AINRA — issue your first passport"; printf '   '; dim "[LOCAL TESTBED · real crypto · local only · zero telemetry]"; echo; echo
cargo build --release -q -p ainra-cli-rs
BIN=./target/release/ainra

if [ -f "$DIR/registrar.json" ]; then
  echo "1. $(dim "reusing your existing registrar at") $DIR $(dim "(this is the persistent, reusable one)")"
else
  echo "1. booting a local registrar $(dim "(this is the passport office — issues, revokes, renews; the root does none of that)")"
  $BIN init "$DIR" "$ID" >/dev/null && echo "   $(dim "created") $DIR $(dim "— its keys, log and status list live here and persist")"
fi

SUB="ainra:$ID:$OPERATOR:$LINEAGE@$VERSION"
echo
echo "2. issuing a passport for $(b "$SUB")"
if $BIN present "$DIR" "$SUB" >/dev/null 2>&1; then
  echo "   $(dim "already issued in a previous run — reusing it (issuance is idempotent by design; a lineage is issued once).")"
else
  $BIN issue "$DIR" --operator "$OPERATOR" --lineage "$LINEAGE" --version "$VERSION" --tier "$TIER" --auth "$AUTH" --cap "$CAP" | sed 's/^/   /'
  echo "   $(dim "what happened: the registrar dual-signed it (Ed25519 + ML-DSA-65), wrote it to its transparency log FIRST (logged-before-valid), then made it valid.")"
fi

echo
echo "3. verifying it $(dim "— the same real verifier a stranger would run, at the registrar's own clock")"
V=$($BIN verify "$DIR" "$SUB" 2>&1)
echo "   verdict: $(b "$V")"

echo
b "You now have a working registrar."; echo
echo "  $(dim "· issue more:")   $BIN issue $DIR --operator $OPERATOR --lineage <name> --version 1.0.0 --cap <cap>"
echo "  $(dim "· revoke one:")   $BIN revoke $DIR $SUB      $(dim "(watch it flip to INVALID · revoked)")"
echo "  $(dim "· see it in a UI:")  make registrar-console  $(dim "(the open registrar console — issue/renew/revoke/list)")"
echo "  $(dim "· verify anything:") make verify"
echo "  $(dim "cookbook →")        docs/quickstarts/"
echo
[ "$V" = "VALID" ] || { echo "unexpected non-VALID verdict: \"$V\" — see docs/quickstarts/cli.md"; exit 1; }
