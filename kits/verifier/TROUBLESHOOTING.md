<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Verifier kit — troubleshooting

> **`@ainra/sdk` is not published to a registry yet.** The published-SDK route below will fail with
> `E404` until it is. Use the in-repo route (`git clone` + `make verifier-kit-smoke`), which needs no
> registry at all. Publishing is prepared and parked on the maintainer's credentials — see
> [docs/_archive/plans/PLAN-M26.md](../../docs/_archive/plans/PLAN-M26.md) § PARKED.

The ten failure modes strangers actually hit, and the fix. Every check here **fails closed**: if something is wrong
the kit exits nonzero and writes no attestation — that is by design, not a bug.

### 1. `Cannot find package '@ainra/sdk'`
The kit's only dependency isn't installed. Run `npm install` inside `kits/verifier/`. As an outsider, first set
`"@ainra/sdk": "^0.3.3"` in `kits/verifier/package.json` (inside this repo it points at the local build, which you
won't have). If you cloned the whole repo, run `make sdk-build` once at the root first.

### 2. `the directory is not trust-anchored by the given roots`
Your `directory.json` and `roots.json` don't match — usually a mixed-up or partially-copied challenge folder.
Re-download the **entire** `challenge/` folder from the maintainer; don't hand-assemble it.

### 3. `--challenge <X> does not match the challenge corpus nonce <Y>`
You passed a nonce that isn't the one inside `challenge.json`. Easiest fix: use `make verify-as-external
CHALLENGE=<dir>` (it reads the nonce for you), or copy the `nonce` field out of `challenge.json` verbatim.

### 4. A sample check prints `✗ … → valid` on the forged bundle
Your SDK returned `valid` for a forged all-clear status — a **revocation bypass**. That's a real finding, not your
mistake: the kit correctly refuses to write an attestation. Please report it (repo `SECURITY.md`). Do not "work around" it.

### 5. Collector says `attestation is NOT execution-bound`
You produced a conformance-only attestation (no `--challenge-dir`). Re-run with `--challenge-dir /path/to/challenge`
so your fresh-bundle verdicts are included. A conformance-only run cannot count as an external verifier — on purpose.

### 6. Collector says `N/K challenge verdicts WRONG`
The verdicts you reported don't match the maintainer's answer key. Almost always: you verified a **different** or
**modified** corpus, or edited the attestation. Re-run the kit unmodified against the exact folder you were sent. (If
you're certain your corpus is untouched and verdicts are still wrong, that's a conformance bug — report it.)

### 7. Collector says `refuses to certify without the private answer key`
That's the maintainer's side — they must pass `--secret <answer-key.json>`. Nothing for you to do; it means they ran
the check without the key. It's fail-closed, not a rejection of your attestation.

### 8. `challenge corpus set differs from the answer key`
The set of files you hashed isn't the set that was minted — a truncated download, or an extra file dropped into the
folder. Re-download the folder; verify it has exactly `challenge.json`, `directory.json`, `roots.json`, and the
`bundle-*.json` listed in `challenge.json`.

### 9. Timestamps / freshness (`invalid:expired` or unexpected verdicts)
The kit verifies the challenge at the `now` recorded in `challenge.json` (not your wall clock), so this is rare. If you
verify **your own** live artifacts instead, pass `--now $(date +%s)`.

### 10. Corporate proxy / offline box
The kit makes **no** network calls when run against local files — verified: `grep -rIn "fetch\|http\|net" verify-kit.mjs`
finds nothing. If `npm install` is blocked, install `@ainra/sdk` from an internal mirror or copy `node_modules` in from
a machine that can reach npm. Running fully air-gapped is supported and encouraged (see `SECURITY.md`).

Still stuck? Open an issue with the exact command and the full output (it contains no secrets — your key is throwaway).
