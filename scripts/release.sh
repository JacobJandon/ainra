#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make release [VERSION=vX.Y.Z] (M11) — produce a VERIFIABLE release, the public counterpart to reproducible builds.
# It REFUSES to run from a dirty tree or a red preflight, re-checks that the committed artifacts are reproducible
# (MANIFEST.sha256 unchanged after `make repro`, which preflight runs), builds the reference CLI, and writes a signable
# SHA256SUMS manifest. A downloader can then confirm the bytes match the committed source (see RELEASING.md).
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${VERSION:-${1:-}}"
[ -n "$VERSION" ] || VERSION="$(git describe --tags --always 2>/dev/null || echo v0.0.0-dev)"

echo "== release $VERSION =="

# 1. A release must come from a clean, committed tree — no uncommitted or untracked changes.
DIRTY="$(git status --porcelain | grep -v '^?? dist/' || true)"
if [ -n "$DIRTY" ]; then
  echo "release REFUSED: working tree is dirty — commit or stash first:"; echo "$DIRTY" | sed 's/^/   /'; exit 1
fi

# 2. A release must be green. `make preflight` runs build+test, differential, genesis-local, the kit smokes, S7,
#    license, AND `make repro` (reproducibility). A red preflight aborts here (set -e).
echo "== preflight (a release is never cut from a red tree) =="
make preflight

# 3. Reproducibility gate: `make repro` (inside preflight) regenerated MANIFEST.sha256. If it differs from what's
#    committed, the published artifacts are NOT reproducible from the committed source — refuse.
if [ -n "$(git status --porcelain -- MANIFEST.sha256)" ]; then
  echo "release REFUSED: MANIFEST.sha256 changed after 'make repro' — committed artifacts are not reproducible."
  git --no-pager diff -- MANIFEST.sha256 | head; exit 1
fi

# 4. Build the reference CLI for this host and package the platform-independent conformance corpus.
echo "== build the reference CLI (ainra) =="
cargo build --release -q -p ainra-cli-rs
HOST_TARGET="$(rustc -vV | awk '/host:/{print $2}')"
DIST="dist"; rm -rf "$DIST"; mkdir -p "$DIST"
cp target/release/ainra "$DIST/ainra-${VERSION}-${HOST_TARGET}"
# the CC0 conformance corpus + its reproducibility manifest — platform-independent, byte-reproducible via `make repro`.
tar -czf "$DIST/ainra-vectors-${VERSION}.tar.gz" vectors MANIFEST.sha256
cp MANIFEST.sha256 "$DIST/MANIFEST.sha256"

# 5. The signable checksum manifest over everything in dist/.
( cd "$DIST" && sha256sum -- * > SHA256SUMS )

echo
echo "== dist/ =="; ls -la "$DIST" | sed 's/^/   /'
echo "== SHA256SUMS (this is the file you SIGN) =="; sed 's/^/   /' "$DIST/SHA256SUMS"
echo
echo "Next (the human):"
echo "  1. Sign the manifest:  gpg --armor --detach-sign dist/SHA256SUMS   (or cosign/minisign)"
echo "  2. Tag the release:    git tag -s ${VERSION} -m \"AINRA ${VERSION}\"   (see CHANGELOG.md)"
echo "  3. Publish dist/* + dist/SHA256SUMS.asc to the GitHub release for ${VERSION}."
echo "  A downloader verifies with the steps in RELEASING.md (§ Verify a release)."
