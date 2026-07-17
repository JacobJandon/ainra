#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make doctor (M11) — check a newcomer's environment against TOOLCHAIN.md BEFORE they waste an hour on a cryptic error.
# Prints each required tool's version (or a human "how to get it"), flags version drift, and exits nonzero if anything
# required is missing. Optional tools are reported but never fail the check.
set -uo pipefail
cd "$(dirname "$0")/.."
MISS=0
ok()   { printf '  \033[32m✓\033[0m %-10s %s\n' "$1" "$2"; }
warn() { printf '  \033[33m•\033[0m %-10s %s\n' "$1" "$2"; }
bad()  { printf '  \033[31m✗\033[0m %-10s %s\n' "$1" "$2"; MISS=1; }

echo "AINRA doctor — environment check (see TOOLCHAIN.md)"
echo "──────────────────────────────────────────────────"

# Rust 1.96 (pinned). Warn on drift, don't fail (1.97+ builds; 1.96 is what's tested).
if command -v rustc >/dev/null; then
  RV="$(rustc --version 2>/dev/null | awk '{print $2}')"
  case "$RV" in 1.96*) ok rustc "$RV (pinned)";; *) warn rustc "$RV — TOOLCHAIN.md pins 1.96 (rust-toolchain.toml); install rustup so the pin is automatic";; esac
else bad rustc "missing — install Rust via https://rustup.rs (the repo pins 1.96)"; fi
command -v cargo >/dev/null && ok cargo "$(cargo --version 2>/dev/null | awk '{print $2}')" || bad cargo "missing (ships with Rust)"

# Node 18+ (CI uses 22).
if command -v node >/dev/null; then
  NV="$(node --version 2>/dev/null | tr -d v)"; NMAJ="${NV%%.*}"
  if [ "${NMAJ:-0}" -ge 18 ]; then ok node "v$NV"; else bad node "v$NV — need 18+ (CI uses 22)"; fi
else bad node "missing — install Node 18+ (CI uses 22)"; fi
command -v npm >/dev/null && ok npm "$(npm --version 2>/dev/null)" || bad npm "missing (ships with Node)"

# The rest of the required set.
command -v make >/dev/null   && ok make   "$(make --version 2>/dev/null | head -1 | awk '{print $3}')"     || bad make   "missing — install GNU Make 4.x"
command -v git  >/dev/null   && ok git    "$(git --version 2>/dev/null | awk '{print $3}')"                || bad git    "missing"
command -v bash >/dev/null   && ok bash   "$(bash --version 2>/dev/null | head -1 | awk '{print $4}')"     || bad bash   "missing (need 4+)"
command -v curl >/dev/null   && ok curl   "present (kit smokes talk to a local registrar)"                 || bad curl   "missing"
command -v tar  >/dev/null   && ok tar    "present"                                                         || bad tar    "missing (make release)"
command -v python3 >/dev/null && ok python3 "$(python3 --version 2>/dev/null | awk '{print $2}')"           || bad python3 "missing (3.8+ — a few tools/CI steps use it)"
if command -v sha256sum >/dev/null; then ok sha256sum "present"; elif command -v shasum >/dev/null; then warn sha256sum "using 'shasum -a 256' (macOS)"; else bad sha256sum "missing (coreutils — make release)"; fi

echo "── optional ──"
command -v rustup   >/dev/null && ok rustup   "makes the 1.96 pin automatic"                 || warn rustup   "not found — without it the pin isn't enforced (any recent stable is usually fine)"
command -v gitleaks >/dev/null && ok gitleaks "$(gitleaks version 2>/dev/null | head -1)"    || warn gitleaks "not found — 'make audit'/'make gitleaks' need it (CI installs it automatically)"
command -v gpg      >/dev/null && ok gpg      "present (release signing)"                     || warn gpg      "not found — only needed to SIGN a release (unsigned releases still verify by rebuild)"

echo "──────────────────────────────────────────────────"
if [ "$MISS" = "0" ]; then
  echo -e "  \033[32mREADY\033[0m — required tools present. Next: \`make preflight\`."
  exit 0
else
  echo -e "  \033[31mMISSING\033[0m — install the ✗ items above (see TOOLCHAIN.md), then re-run \`make doctor\`."
  exit 1
fi
