<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Releasing & verifying a release

A release is the **public counterpart to reproducible builds**: the conformance corpus that defines correctness rebuilds
byte-for-byte from the committed source (`make repro` → `MANIFEST.sha256`), so a downloader can confirm that what they
fetched matches the source they can read — trusting the bytes, not us. The per-platform CLI binary and the SDKs' build
output are held to that corpus for behaviour, not rebuilt bit-for-bit (below).

## The one rule — the board runs at the release commit, or the release does not exist (M23.1)

A version is not "released" — **not tag-ready, not CHANGELOG-claimable** — until the **full preflight board runs ALL
GREEN from a clean clone at the exact release commit**, and that board is **committed as evidence** to
`docs/releases/<version>-board.md`. This is not advisory: **`make changelog-board-check`** (wired into `make ci`)
FAILS if `CHANGELOG.md` names a released version whose board evidence is absent — so the *claim* can never outrun the
*proof*. The board is the primary release artifact; signing, packaging, and the tag all build on it.

> M23 shipped v0.2.0's code without running this board and had to be re-proven afterward (M23.1). The rule exists so
> that never recurs: no board at the release commit ⇒ no release.

### Recording the board (do this first, at the release commit)

```sh
tmp="$(mktemp -d)"; git clone -q . "$tmp/clone"
( cd "$tmp/clone" && git checkout -q <release-commit> && make preflight ) | tee docs/releases/<version>-board.md
# The board names the commit it ran at. Commit docs/releases/<version>-board.md BEFORE tagging.
```

Only once the board is green + committed do you proceed to package + sign + tag below.

## Tag pins — the exact commit each release was cut at

Tagging is the maintainer's button and is never done by the agent. The pins below are the permanent record of which
commit each version's board was proven at:

| Version | Tag target (exact commit) | Board evidence | State |
|---|---|---|---|
| **v0.2.0** | **`5ae1b12`** | `docs/releases/v0.2.0-board.md` — full 17-row board ALL GREEN from a clean clone | **RELEASED** — signed tag verified (`git verify-tag v0.2.0`), artifacts on the releases page |
| **v0.3.0** | **`af3c869`** | `docs/releases/v0.3.0-board.md` — full 18-row board (incl. `conformance`, 4-way differential) ALL GREEN from a clean clone | **RELEASED** — signed tag verified, signed artifacts + provenance + SBOM on the releases page |
| **v0.5.0** | **`e6870bc`** | `docs/releases/v0.5.0-board.md` — full 44-row board ALL GREEN, no skips, from a fresh clone | **TAGGED + PUBLISHED** — signed tag verified (`git verify-tag v0.5.0`), 2026-10-31; `@ainra/sdk`, `@ainra/middleware` and PyPI `ainra` published from the tag with provenance; `@ainra/mcp` 0.5.0 published 2026-11-01 by trusted publishing (its first upload was refused); release page created by the maintainer; signed artifacts (`make release` at the tag, `SHA256SUMS.sig`) attached 2026-11-03 — the release workflow had first wanted the board inside the tagged tree, then refused on the manifest's locale order (both fixed) |
| **v0.6.0** | **`ed4cfde`** | `docs/releases/v0.6.0-board.md` — full 44-row board ALL GREEN, no skips, from a fresh clone (a first run, stopped by a full disk, was redone) | **TAGGED + PUBLISHED** — signed tag verified (`git -c gpg.ssh.allowedSignersFile=release/tag_signers verify-tag v0.6.0`), 2026-11-03; all four packages published from the tag by trusted publishing; release page created by the maintainer, the repo's Latest; signed artifacts attached 2026-11-03 by `make release` at the tag (CI's release workflow had refused on the manifest's locale order, fixed after the tag by `LC_ALL=C`) |
| **v0.7.0** | **`be0891e`** | `docs/releases/v0.7.0-board.md` — full 48-row board ALL GREEN, no skips, from a fresh clone (a first run, broken only by a temporary-directory setting the headless browser could not start in, was redone) | **TAGGED** — signed tag pushed by the maintainer 2026-11-04 (`git -c gpg.ssh.allowedSignersFile=release/tag_signers verify-tag v0.7.0`). `make release` at the tag and the tag's CI then went red on `release-state-check`, which demanded this row and the ROADMAP row inside the tagged tree — rows written after the tag, so they can never be there. The gate now exempts the tagged commit's own build (it still requires the CHANGELOG section); the tag itself cannot change, so its artifacts are built in a clone with the local tag ref removed, which leaves the same board at the same commit. The release workflow also died installing rustfmt (two board rows racing to install the toolchain); it now installs it once first. Artifacts, release page and publishing to follow |

Never rewrite tagged history: if something must change after a tag, neutralize at the tip (a new commit), never by
moving or deleting a released tag.

## Cutting a release (maintainer)

```sh
make release VERSION=v0.2.0
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
1. **Sign the manifest** — `ssh-keygen -Y sign -f <release-key> -n file dist/SHA256SUMS` (the release key is SSH
   Ed25519, offline; `scripts/release.sh` does this itself when the key is present). Signing `SHA256SUMS`
   transitively signs every artifact; anyone verifies with `release/allowed_signers` (`RELEASE-VERIFY.md`).
2. **Tag** — `git tag -s vX.Y.Z -m "AINRA vX.Y.Z"`, SSH-signed with the tag key pinned in `release/tag_signers`.
   See `CHANGELOG.md`.
3. **Publish** `dist/*` + `dist/SHA256SUMS.sig` to the GitHub release for the tag.

> Releases are cross-signed by reproducibility: anyone can re-run `make release` from the tagged commit and get the same
> `MANIFEST.sha256` and vectors tarball. The per-platform CLI binary is not bit-reproducible across toolchains, but the
> **conformance corpus that defines correctness is** — and that's what an implementer actually needs to trust.

## Publishing the packages (maintainer) — npm + PyPI

**Publishing and tagging are the maintainer's buttons. An agent never runs `npm publish`, `twine upload`, or
`git tag`.** The lists below are dry-run-verified — every artifact was packed and installed clean in a fresh
environment with its quickstart passing (M24 Task 4) — so all that remains for a human is to press the button once
the version is final.

> **Wire provenance in the SAME pass — it cannot be retrofitted.** A version published without attestation stays
> that way forever. npm takes `--provenance` (signed by the public-good Sigstore instance and logged in a public
> transparency ledger — needs `id-token: write` and a case-exact `repository` field); PyPI takes PEP 740
> attestations via Trusted Publishers; crates.io has Trusted Publishing over OIDC and owners can now *enforce* it,
> disabling token publishing entirely. All three are free and need no legal entity. See
> [`campaign/FREE-INFRASTRUCTURE.md`](campaign/FREE-INFRASTRUCTURE.md).

**Run `make publish-preflight` first.** It re-proves every one of those dry runs on the machine you are about to
publish from — versions agree across all four packages, the version is tagged, each package packs with a README and
a license and no local `file:` dependency, and the packed npm tarball *and* the built wheel each install into a
throwaway environment and reproduce all **1153** recorded conformance verdicts. It publishes nothing and holds no
credentials; when it is green it prints the exact commands below, filled in with the current version.

### npm — `@ainra/sdk`, `@ainra/middleware`, `@ainra/mcp`

Publish order matters: **`@ainra/sdk` first** (the other two resolve it by name), then `@ainra/middleware`, then
`@ainra/mcp`.

- [ ] **`npm pack` contents were dry-run-verified** — each tarball ships only its runtime (`@ainra/sdk` and
      `@ainra/middleware` ship `dist/*.js` + `dist/*.d.ts`; `@ainra/mcp` ships `src/*.mjs`) and **no** `test/`,
      `src/*.ts`, `tsconfig.json`, `node_modules`, or `package-lock.json`. This is enforced by the `files` field in
      each `package.json`; re-check before publishing with `cd packages/<pkg> && npm pack --dry-run`.
- [ ] **`@ainra/middleware` — rewrite the SDK dependency before publishing.** In the repo it is
      `"@ainra/sdk": "file:../sdk-ts"` (so the offline monorepo build resolves the sibling). **npm does NOT rewrite
      `file:` on publish** (only the `workspace:` protocol is rewritten) — a published `file:` dependency installs a
      **dangling** `@ainra/sdk` symlink and the import fails `ERR_MODULE_NOT_FOUND`. Rewrite it to the CURRENT
      SDK version at publish time — never a literal, which is how this line came to say `^0.2.0` three releases
      after 0.2.0: `npm --prefix packages/middleware pkg set dependencies.@ainra/sdk="^$(node -p "require('./packages/sdk-ts/package.json').version")"`,
      which is exactly what `.github/workflows/publish.yml` runs. Then put `file:../sdk-ts` back so the checkout
      keeps building. Do the same rewrite for any future package that depends on a sibling via `file:`.
- [x] **`@ainra/mcp` — standalone as of M33, and PUBLISHED at 0.4.1 (2026-09-19).** It was operated from a
      checkout only: `src/tools.mjs` resolved its sibling SDK build, `docs/reasons.json` and the `ainra` CLI by
      repo-relative paths, so the server would not even *start* outside the monorepo (the reasons file is read at
      import time). All three are fixed: the SDK is imported by name (`file:../sdk-ts` in the checkout, rewritten to
      a range at publish, same as `middleware`); `docs/reasons.json` is shipped as `src/reasons.json`, held
      byte-identical by `make reasons-check`; and the CLI is *located* rather than bundled — `AINRA_CLI`, then
      `ainra` on PATH, then a checkout build — because a compiled binary cannot ride in an npm tarball. Absent all
      three the read-only tools still work against a URL target; only the local-dir and write paths need a binary,
      and they say so by name. Proven by packing the tarball and running the installed server outside the repo.
      `publish.yml` has an `npm-mcp` target, which is how it went out. The only thing still parked is the MCP
      *registry* listing, on a domain that does not exist yet — [`docs/MCP-REGISTRY.md`](docs/MCP-REGISTRY.md).
- [ ] **Build fresh, from a clean tree:** `cd packages/sdk-ts && npm ci && npm run build` (and the same for
      `middleware`); `@ainra/mcp` has no build step.
- [ ] **Publish each, public scope, with provenance:**
      ```sh
      cd packages/sdk-ts    && npm publish --access public --provenance
      cd packages/middleware && npm publish --access public --provenance   # after rewriting the file: dep
      cd packages/mcp       && npm publish --access public --provenance   # only if standalone-ready (see above)
      ```
      `--access public` is required for a first-time scoped (`@ainra/*`) package. `--provenance` attaches a signed
      build-provenance attestation (run it from CI with an OIDC-enabled workflow, or locally with a supported registry).
- [ ] **2FA / OTP:** the npm account/org publishes with 2FA set to *auth-and-writes*. Pass the one-time code with
      `--otp=<code>` (or approve the interactive prompt). Prefer a **granular automation token** scoped to `@ainra/*`
      for CI, and an org publish policy that requires 2FA.
- [ ] **After publish:** confirm `npm view @ainra/sdk version` (and the others) shows the intended version, and that the
      tarball on the registry matches the local `npm pack` shasum.

### PyPI — `ainra`

The distribution name is **`ainra`** (`packages/sdk-py/pyproject.toml` → `[project] name = "ainra"`; checked
unregistered on PyPI 2026-07-30). Runtime dependency is exactly `cryptography>=48` (`pytest` is a `test` extra only).

- [ ] **Build both artifacts** from a clean tree: `python -m build packages/sdk-py` → `dist/ainra-<version>.tar.gz`
      (sdist) + `dist/ainra-<version>-py3-none-any.whl` (wheel). (Dry-run-verified: the wheel ships only the `ainra/`
      package — no `tests/`, no `__pycache__`.)
- [ ] **The wheel was dry-run-installed in a clean venv** — `python -m venv .venv && .venv/bin/pip install
      dist/ainra-<version>-py3-none-any.whl` pulls in **only** `cryptography` (+ its own `cffi`/`pycparser`), nothing
      surprising, and the README quickstart runs green under the venv's python. Re-check before publishing.
- [ ] **Check the metadata** before upload: `twine check dist/*` (long-description render, license expression,
      `Requires-Python`, `Requires-Dist: cryptography>=48`).
- [ ] **Upload** — prefer a **Trusted Publisher (OIDC)** from CI so no long-lived token is stored: configure the
      `pypi` publisher for the `ainra` project and let the GitHub Action mint a short-lived token. Otherwise, from a
      trusted machine: `twine upload dist/*` (or `--repository testpypi` for a rehearsal first). `twine` is not
      installed in every environment — `pip install twine` if `twine check`/`upload` is missing.
- [ ] **2FA:** the PyPI account has 2FA enabled (TOTP or a security key). Token/OIDC uploads still require the account
      to be 2FA-protected; never publish from an account without it.
- [ ] **After publish:** `pip install ainra==<version>` from a throwaway venv and re-run the quickstart to confirm the
      registry copy is what you built.

## Verifying a release (downloader)

You do **not** need to trust the publisher. With only the release files + the public key:

```sh
# 1. the manifest signature is authentic (allowed_signers ships with the release and is pinned in release/)
ssh-keygen -Y verify -f allowed_signers -I release@ainra.org -n file -s SHA256SUMS.sig < SHA256SUMS

# 2. every artifact matches the signed manifest
sha256sum --check SHA256SUMS

# 3. the conformance corpus rebuilds byte-for-byte from the tagged source (the strong check)
git clone --branch v0.2.0 https://github.com/JacobJandon/ainra && cd ainra
make repro                                   # regenerates MANIFEST.sha256 from source
tar -xzf /path/to/ainra-vectors-v0.2.0.tar.gz  # the released corpus
diff <(sort MANIFEST.sha256) <(sort ./MANIFEST.sha256)   # released manifest == rebuilt-from-source manifest
```

Step 3 is the one that matters: it proves the released conformance corpus is exactly what the committed source
produces — no trust in the maintainer required. (Signature verification, step 1, only proves *who* published it.)

## Status of signing
Two SSH Ed25519 keys, both pinned in the repository: the release key signs `SHA256SUMS` (`release/allowed_signers`,
`release/ainra-release.pub`) and the tag key signs tags (`release/tag_signers`); `RELEASE-VERIFY.md` checks both.
v0.5.0 and v0.6.0 carry `SHA256SUMS.sig` since 2026-11-03 (checked: a good signature from the pinned key, every
artifact matching its hash). v0.4.0 and v0.4.1 have signed tags but no release page; for those a downloader has step 3
— rebuild from source — which needs no key at all.
