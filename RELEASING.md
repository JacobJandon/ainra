<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Releasing & verifying a release

A release is the **public counterpart to reproducible builds**: because every published artifact rebuilds byte-for-byte
from the committed source (`make repro` → `MANIFEST.sha256`), a downloader can confirm that what they fetched matches
the source they can read — trusting the bytes, not us.

## Cutting a release (maintainer)

```sh
make release VERSION=v0.1.0
```

`scripts/release.sh` **refuses** to proceed unless:
- the working tree is **clean** (all changes committed), and
- `make preflight` is **green** (build+test, differential, genesis-local, kit smokes, S7, license, **and `make repro`**), and
- `MANIFEST.sha256` is **unchanged** after that repro (i.e. the committed artifacts really are reproducible).

It then builds the reference CLI, packages the conformance corpus, and writes `dist/`:

| Artifact | What it is |
|---|---|
| `ainra-<version>-<host-target>` | the reference `ainra` CLI, built release, for the build host's platform |
| `ainra-vectors-<version>.tar.gz` | the CC0 conformance corpus + `MANIFEST.sha256` (platform-independent, reproducible) |
| `MANIFEST.sha256` | the reproducibility manifest (regenerable with `make repro`) |
| `SHA256SUMS` | SHA-256 of every file above — **the file you sign** |

Then the maintainer:
1. **Sign the manifest** — `gpg --armor --detach-sign dist/SHA256SUMS` (or `cosign sign-blob` / `minisign`). Signing
   `SHA256SUMS` transitively signs every artifact.
2. **Tag** — `git tag -s v0.1.0 -m "AINRA v0.1.0"` (annotated `-a` if not signing yet). See `CHANGELOG.md`.
3. **Publish** `dist/*` + `dist/SHA256SUMS.asc` to the GitHub release for the tag.

> Releases are cross-signed by reproducibility: anyone can re-run `make release` from the tagged commit and get the same
> `MANIFEST.sha256` and vectors tarball. The per-platform CLI binary is not bit-reproducible across toolchains, but the
> **conformance corpus that defines correctness is** — and that's what an implementer actually needs to trust.

## Verifying a release (downloader)

You do **not** need to trust the publisher. With only the release files + the public key:

```sh
# 1. the manifest signature is authentic (the key is published out of band — repo, keyserver, or a pinned fingerprint)
gpg --verify SHA256SUMS.asc SHA256SUMS

# 2. every artifact matches the signed manifest
sha256sum --check SHA256SUMS

# 3. the conformance corpus rebuilds byte-for-byte from the tagged source (the strong check)
git clone --branch v0.1.0 https://github.com/<owner>/ainra && cd ainra
make repro                                   # regenerates MANIFEST.sha256 from source
tar -xzf /path/to/ainra-vectors-v0.1.0.tar.gz  # the released corpus
diff <(sort MANIFEST.sha256) <(sort ./MANIFEST.sha256)   # released manifest == rebuilt-from-source manifest
```

Step 3 is the one that matters: it proves the released conformance corpus is exactly what the committed source
produces — no trust in the maintainer required. (Signature verification, step 1, only proves *who* published it.)

## Status of signing
Reproducibility + `SHA256SUMS` are wired now. Key management (which key signs releases, where its fingerprint is
pinned) is a maintainer/ceremony decision — until a signing key is published, releases ship `SHA256SUMS` unsigned and a
downloader relies on step 3 (rebuild-from-source), which needs no key. This is stated honestly rather than shipping a
fake trust anchor.
