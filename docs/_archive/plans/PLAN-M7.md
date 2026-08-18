<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# PLAN-M7 — reproducible builds + mirrors + docs freeze (playbook wk11)

M7 makes the published artifacts **verifiable by anyone**: rebuild them byte-for-byte from source, serve them from
independent mirrors that byte-verify against a manifest, and freeze the docs so drift is detectable. The trust root
is the *source* (reproducibility), not our word. Exit (MTS §27): `make repro` rebuilds every published artifact
twice byte-identical (and matches what is committed); ≥2 mirrors byte-verify against a signed manifest; docs frozen.

Standing rules unchanged: nothing fake · fail closed · pure core (N7) · no real company names (S7) · every deviation
in `DECISIONS.md` · end with `make ci` green + honest `STATUS.md`.

## The publishable artifact set (what a mirror serves, what external builders reproduce)

Pure, seeded, path-independent — the CC0 conformance corpus + the sample book:
- `vectors/v1`, `vectors/v1-delta`, `vectors/v1-directory` — 684 + 17 + 9 vectors (seeded ChaCha20, deterministic).
- `samples/data/*.json` + `samples/*.svg` + `samples/manifest.json` — the 3-face passport book (seeded; dates derive
  from fixed claim values, no wall-clock).

**Deliberately EXCLUDED from byte-identity** (documented, not faked): the SDK `dist/` (a `tsc` build output whose
byte-identity depends on the exact TypeScript version; it is verified for *behaviour* by the differential harness,
not byte-hash) and anything timing-derived (`docs/BENCHMARKS.md`). The reproducibility claim is about the
*specification artifacts*, which are what mirrors serve and what a second implementation checks itself against.

## Thread A — `make repro` (the reproducibility proof)

`tools/repro.sh`: hash the committed artifact set; regenerate it (`make vectors samples`); hash again; regenerate
once more; hash again. Assert **committed == pass-1 == pass-2** — i.e. the toolchain reproduces exactly what is
checked in (no drift), and the build is deterministic run-to-run. Emit `MANIFEST.sha256` (sorted `sha256sum` over
the set). Any mismatch prints the drifted files and fails. `docs/REPRODUCIBILITY.md` documents the toolchain lock
(Rust `1.96` via `rust-toolchain.toml`, `Cargo.lock`, Node major, the seeded-RNG determinism) so an external builder
can reproduce byte-for-byte.

## Thread B — mirror machinery + byte-verify

A **mirror** is any host serving the artifact set. `MANIFEST.sha256` is the canonical content list; its integrity is
anchored by reproducibility (rebuild → identical manifest) + being committed to the repo. `make mirror OUT=dir`
assembles a mirror directory; `tools/mirror-verify.sh <dir>` recomputes every file's hash and diffs against the
manifest — exit 0 iff **byte-identical**, fail-closed on any missing/extra/differing byte. Demonstrate **two
independent mirror directories** each byte-verifying. (Standing up real *non-us* mirrors on external infra is
deployment; the byte-verify mechanism + the 2-mirror proof are what M7 delivers here.)

## Thread C — docs freeze + adversarial check

- **Docs freeze:** a `docs/FREEZE.sha256` manifest of the canonical spec/plan doc hashes + a `make check-freeze`
  that flags drift, so a "frozen" doc changing is caught.
- **Adversarial pass** over the M7 machinery (can a mirror pass verification while serving altered bytes? can the
  manifest be trivially forged? does repro have a false "OK"?) — fix findings.

## Sequencing (each verified)

1. **A** `repro.sh` + `MANIFEST.sha256` + `REPRODUCIBILITY.md`; run `make repro` → committed==pass1==pass2.
2. **B** `mirror-verify.sh` + `make mirror`/`make verify-mirror`; prove 2 mirrors byte-verify; a tampered mirror fails.
3. **C** `FREEZE.sha256` + `make check-freeze`; adversarial pass; fix.
4. `make ci` green; DECISIONS D-022; STATUS/PLAN updated; report. Plan M8 (`make genesis-local` + Genesis) forward.

## What M7 deliberately does NOT do (recorded, not faked)

- No real external builders / non-us mirror hosts (external coordination); the byte-verify machinery + the local
  2-mirror + rebuild-twice proofs are real and runnable.
- No manifest signature by a *persistent* published root (that root is minted at M8 Genesis); the manifest's trust is
  reproducibility + repo provenance today, with a signature hook ready for the Genesis key.
