<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Verifying an AINRA release

You do **not** need to trust whoever published a release. With only the release files + the pinned public key, you can
confirm (1) it was signed by the AINRA release key, (2) every artifact matches the signed manifest, (3) what built it,
and (4) — the strong check — that the conformance corpus rebuilds **byte-for-byte** from the tagged source.

Every published release directory contains:

| File | What it is |
|---|---|
| `ainra-<version>-<host-target>` | the reference `ainra` CLI, release build, for the build host |
| `ainra-vectors-<version>.tar.gz` | the CC0 conformance corpus + `MANIFEST.sha256` (platform-independent, reproducible) |
| `MANIFEST.sha256` | the reproducibility manifest (regenerable with `make repro`) |
| `provenance.json` | SLSA-style build provenance — source commit, toolchain, artifact digests, the repro claim |
| `sbom.json` | CycloneDX bill of materials — every locked crate + Node dep, from the real lockfiles |
| `SHA256SUMS` | SHA-256 of every artifact above — **the file that is signed** |
| `SHA256SUMS.sig` | the SSH (Ed25519) signature over `SHA256SUMS` |
| `allowed_signers` | the signer identity + public key, for `ssh-keygen -Y verify` |

The release signing key is an **SSH Ed25519** key (chosen over PKI/keyservers: Ed25519 by default — AINRA's own
primitive — tiny keys, detached signatures, verified with one pinned public key, no web-of-trust ceremony — D-042). The
private key is **offline**, never in the repo or CI. Its public half + fingerprint are pinned in-repo at
`release/allowed_signers` / `release/ainra-release.pub` and published on the site's status page from live data.

> **Pinned key fingerprint:** `SHA256:V1ZbCNdPDEe5plpYq07dGCsoensF4Q+MPPQQkcj5pi4` (principal `release@ainra.org`).
> Confirm it out of band before trusting a download.

## Step 1 — the signature is authentic

```sh
ssh-keygen -Y verify -f allowed_signers -I release@ainra.org -n file -s SHA256SUMS.sig < SHA256SUMS
```
Real output (this release tooling, over a v0.2.0 artifact set):
```
Good "file" signature for release@ainra.org with ED25519 key SHA256:V1ZbCNdPDEe5plpYq07dGCsoensF4Q+MPPQQkcj5pi4
```
A bad key, a tampered `SHA256SUMS`, or a forged `.sig` all fail this line. (Step 1 proves *who* signed — the strong
proof is step 4.)

## Step 2 — every artifact matches the signed manifest

```sh
sha256sum --check SHA256SUMS
```
Every line must print `OK`. Because step 1 signed `SHA256SUMS`, and `SHA256SUMS` covers each artifact's hash (including
`provenance.json` and `sbom.json`), one signature transitively covers the whole release.

## Step 3 — what built it (provenance + SBOM)

```sh
node -e 'const p=require("./provenance.json");console.log("commit",p.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit);console.log("toolchain",JSON.stringify(p.predicate.toolchain))'
```
Real output:
```
commit a2a0d72edabd…
toolchain {"rust":"1.96.1","rustc":"rustc 1.96.1 (31fca3adb 2026-06-26)","cargo":"cargo 1.96.1 (356927216 2026-06-26)","node":"v26.4.0"}
```
`sbom.json` lists every dependency with a `purl` (e.g. `pkg:npm/@noble/post-quantum@0.2.0`, `pkg:cargo/<crate>@<ver>`
with its SHA-256) — the real content of `Cargo.lock` + the Node manifests (128 components for v0.2.0: 120 cargo + 8 npm).

## Step 4 — the strong check: rebuild byte-for-byte from source

Signatures prove *who*; reproducibility proves *what*. Clone the **tagged** source and regenerate the manifest — no
trust in the builder required:

```sh
git clone --branch <version> https://github.com/JacobJandon/ainra && cd ainra
make repro                                     # rebuilds MANIFEST.sha256 from source, byte-identical ×2
tar -xzf /path/to/ainra-vectors-<version>.tar.gz   # the released corpus
diff <(sort MANIFEST.sha256) <(sort ./MANIFEST.sha256)   # released manifest == rebuilt-from-source manifest
```
No output from the final `diff` = the released conformance corpus is exactly what the committed source produces.
(v0.2.0's `make repro` is recorded green in its preflight board evidence: `docs/releases/v0.2.0-board.md`,
"reproducibility → artifacts rebuild byte-exact".)

## Verifying a platform release (from the releases page)

Releases are drafted automatically by CI on each `vX.Y.Z` tag (`.github/workflows/release.yml`): CI rebuilds the
artifacts reproducibly from the tagged source and attaches the CLI, the CC0 corpus, `MANIFEST.sha256`,
`provenance.json`, `sbom.json`, and the unsigned `SHA256SUMS`. The **detached signature is attached by the
maintainer, offline** — the release key never enters CI (D-042). So a published (non-draft) release carries
`SHA256SUMS.sig`; verify it exactly as above:

```sh
# 1. fetch a release's assets
gh release download <version> -R JacobJandon/ainra
# 2. run steps 1-4 above against them: signature, manifest, provenance/SBOM, then the strong rebuild.
```

If `SHA256SUMS.sig` is missing, the release is still a **draft** awaiting the maintainer's offline signature — the
bytes are reproducible, but do not treat it as signed until the maintainer publishes it.

## Producing a signed release (maintainer)

`make release VERSION=vX.Y.Z` runs the gates, writes `dist/` with the CLI + corpus + `MANIFEST.sha256` + `provenance.json`
+ `sbom.json` + `SHA256SUMS`, and — if the offline release key is present (`AINRA_RELEASE_KEY=<path>`, default
`.release-key/ainra-release`) — signs `SHA256SUMS` with `ssh-keygen -Y`. Absent the key, it prints the exact offline
signing command. Tagging + publishing stay the maintainer's buttons (see `RELEASING.md`).
