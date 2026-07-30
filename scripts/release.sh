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

# 5. Provenance + SBOM from the REAL repo state (git commit, pinned toolchain, Cargo.lock, node deps, artifact hashes).
echo "== provenance + SBOM (M24) =="
node tools/release-attest.mjs "$DIST" "$VERSION"

# 6. The signable checksum manifest over every artifact (incl. provenance + SBOM; the .sig + verify materials are added after).
( cd "$DIST" && sha256sum -- * > SHA256SUMS )

# 7. Sign SHA256SUMS with the release key (SSH Ed25519, ssh-keygen -Y) when available — the private key is offline and
#    gitignored (.release-key/); set AINRA_RELEASE_KEY to its path. Signing SHA256SUMS transitively signs every artifact
#    (the manifest covers their hashes). The verifier needs only release/allowed_signers (committed, published on the site).
RELEASE_KEY="${AINRA_RELEASE_KEY:-.release-key/ainra-release}"
cp release/allowed_signers release/ainra-release.pub "$DIST/" 2>/dev/null || true
if [ -f "$RELEASE_KEY" ]; then
  ssh-keygen -Y sign -f "$RELEASE_KEY" -n file "$DIST/SHA256SUMS" >/dev/null 2>&1 \
    && echo "== signed: dist/SHA256SUMS.sig (SSH Ed25519 · principal release@ainra.org) =="
else
  echo "== SHA256SUMS.sig NOT written — release key absent (offline by policy). Sign on the airgapped host: =="
  echo "     ssh-keygen -Y sign -f <release-key> -n file dist/SHA256SUMS"
fi

echo
echo "== dist/ =="; ls -la "$DIST" | sed 's/^/   /'
echo
echo "Next (the human):"
echo "  1. If unsigned above, sign SHA256SUMS offline with the release key (fingerprint in release/allowed_signers)."
echo "  2. Tag the release:    git tag -s ${VERSION} -m \"AINRA ${VERSION}\"   (see RELEASING.md — pinned tag targets)"
echo "  3. Publish dist/* (incl. SHA256SUMS.sig, allowed_signers, provenance.json, sbom.json) to the GitHub release."
echo "  A downloader verifies per RELEASE-VERIFY.md: the signature, then provenance, then rebuild byte-for-byte."
