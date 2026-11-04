<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Publishing to npm and PyPI

**Status: PUBLISHED — npm and PyPI. v0.4.0 on 2026-09-15, v0.4.1 on 2026-09-19, v0.5.0 on 2026-10-31 (`@ainra/mcp` on
2026-11-01, below), v0.6.0 on 2026-11-03, v0.7.0 on 2026-11-04 — by trusted publishing, and `@ainra/edge` for the first time.** All four artifacts are live on
the public registries **with Sigstore provenance** — built on a GitHub-hosted runner via
`.github/workflows/publish.yml`, which is the only publish path because provenance cannot be retrofitted onto a
version that is already public. v0.4.1 added `@ainra/mcp`, published for the first time once it could be installed
rather than cloned, and superseded a PyPI wheel that reported its own version wrongly.

```
packages            0.7.0 · sdk + middleware + mcp LIVE on npm — trusted publishing, attestations YES
                           @ainra/edge LIVE on npm since 0.7.0 — first publish by token from publish.yml,
                           attestation YES; trusted publishing from its next version
                           PyPI `ainra` LIVE — trusted publishing, PEP 740 attestations, no token
publish-preflight   READY — tag matches the package tree byte for byte
install smokes      npm 1153/1153 · py wheel 1153/1153
```

**What the first publish cost, recorded because the next maintainer will hit it.** Four workflow runs, each a
different gate, and the order matters: (1) the token had no *bypass-2FA* capability — npm rejects CI publishes
without it; (2) the `@ainra` **scope did not exist** — a scoped package needs an org, and npm reports this only
*after* auth passes, so it stays hidden behind any auth error; (3) a replacement token fixed the scope and lost
the 2FA bypass — both capabilities are needed at once; (4) the publish then **succeeded**, and the run still
reported failure on its last step, *confirm the attestation is on the registry*, because npm's packument endpoint
lags the version endpoint by about a minute. A red run is not proof that nothing published — check the registry
before re-running, because republishing a live version hard-fails.

**The fifth failure mode, found on v0.4.1, was the confirmation step itself.** It resolved the version with
`npm view` and then asked whether *that* version had an attestation. Because the read side lags, the step
confirmed **0.4.0's** attestation seconds after publishing 0.4.1 — a green check that never looked at what the run
had just shipped. The same lag, on `@ainra/mcp`'s first publish, returned a 404 and turned a **successful**
publish into a red run: `+ @ainra/mcp@0.4.1` and a Sigstore provenance statement are in that run's log. Failing
green and failing red for the same reason is the signature of a check that asks the wrong source. It now reads the
name and version from the manifest it just published and polls the attestation endpoint for two minutes.

**The sixth, on v0.5.0 (2026-10-31): two minutes was not enough.** `@ainra/sdk` and `@ainra/middleware` 0.5.0
published with provenance and both runs went red on the confirmation step; the attestations appeared on the
registry a few minutes later. The poll now waits up to ten minutes. Same rule as before: check the registry before
re-running anything. **And one real refusal:** `@ainra/mcp` 0.5.0 was built and its provenance statement written to
the transparency log, then the upload got `E404 … you do not have permission` — the `NPM_TOKEN` secret could publish
the other two packages but not this one. A replacement token got `EOTP` (no 2FA bypass, and npm is retiring tokens
that bypass it for publishing).

**The way through, on 2026-11-01: trusted publishing.** A Trusted Publisher on `@ainra/mcp` (GitHub Actions ·
`JacobJandon` · `ainra` · `publish.yml` · environment **blank** — the npm job declares no environment), `NPM_TOKEN`
deleted from the repo secrets, and the failed job re-run from the tag: the workflow saw no secret, authenticated by
OIDC, and published 0.5.0 with provenance. A re-run before the Trusted Publisher was saved got `ENEEDAUTH` — that is
what a missing or mismatched publisher looks like. The run still went red on the two-minute attestation poll, because a
re-run uses the workflow as it was at the tag.

**The seventh: the published range was not the written one.** The workflow sets `@ainra/sdk` to `^x.y.z` before
uploading `@ainra/mcp`, but the package also declared the SDK as a `*` peer, and npm published the dependency as `*` —
in 0.4.1 and again in 0.5.0. `peerDependencies` is gone from `packages/mcp`, and `publish-preflight` blocks any
package whose SDK peer would override the range.

**Trusted publishing on all three npm packages:** `NPM_TOKEN` is deleted, and 0.6.0 of `@ainra/sdk`,
`@ainra/middleware` and `@ainra/mcp` published by OIDC alone.

**The eighth, on v0.7.0 (2026-11-04): a brand-new package, `@ainra/edge`.** A Trusted Publisher can only be set on a
package that exists, so its first version went through `publish.yml` with a short-lived granular token (`--ref v0.7.0
-f target=npm-edge`): the WASM engine was built from the tag on the runner, the package's tests ran against it, the
tarball was checked for the engine, and it published with provenance (Sigstore log index 3691428741). Three things to
know. (1) npm printed that tokens which bypass 2FA "are being restricted for account changes and direct publishing" —
this route may not work for the next brand-new package; publishing that one from the maintainer's machine with a 2FA
code would cost its first version its provenance. (2) npm created a version `0.0.0-stage` ("Temporary package
placeholder for staged publishing") in the same second as the real one; `latest` is 0.7.0, so installs get the real
package. (3) A second run started a minute later was refused, E409 "Cannot publish over previously staged version" —
a duplicate click, not a failure. After it: the Trusted Publisher is set on `@ainra/edge`, and the token is to be
deleted from the repository secrets and from npm.

**PyPI went token-free from its very first version**, which is the difference worth remembering: its pending
publisher (project `ainra` · `JacobJandon` · `ainra` · `publish.yml` · environment **`pypi`** — this job *does*
declare one, unlike the npm job) can be registered before the project exists. npm has no equivalent, which is the
whole reason the first npm publish needed a token at all. PyPI published green on the first attempt once the
publisher was registered; npm took four.

**The remaining sequence.** The first step is the maintainer's: `RELEASING.md` states that an agent never runs
`git tag`, `npm publish` or `twine upload`.

1. `git tag -s vX.Y.Z` — maintainer
2. `make release VERSION=vX.Y.Z`
3. `make publish-preflight` — must print READY before any token is pasted
4. the two web forms — maintainer, logged-in browser

## Correcting the note this file replaces

`_archive/plans/PLAN-M26.md` § PARKED said that a token publish "would permanently forfeit attestation", and used that to
block publishing on trusted-publisher setup for both registries. **That is half wrong, and the half that is wrong
cost two milestones of parked publishing.**

Provenance (a Sigstore attestation, `--provenance`) and trusted publishing (OIDC replacing a token as the
*credential*) are two different features. A publish from a **laptop** cannot be attested — there is no CI identity
to attest to. A **token publish from this workflow** is attested perfectly well, because the runner has an OIDC
identity regardless of how the publish authenticated. The distinction matters because of an asymmetry between the
two registries, documented below.

## The asymmetry

**PyPI can be pre-registered.** A "pending publisher" exists precisely for a project that does not exist yet
(docs.pypi.org, *Creating a PyPI project with a Trusted Publisher*), so PyPI is token-free from the very first
version.

**npm cannot.** From `docs.npmjs.com/cli/v11/commands/npm-trust`:

> **Package must exist**: The package you're configuring must already exist on the npm registry.

There is no npm equivalent of a pending publisher, and nothing in the 2025–2026 changelog suggests one is coming.
So the **first** version of each npm package needs a token; every version after it can be token-free.

## The two things only the maintainer can do

### 1 · PyPI — pending publisher (no token, ever)

<https://pypi.org/manage/account/publishing/> → *Add a new pending publisher*:

| Field | Value |
|---|---|
| PyPI Project Name | `ainra` |
| Owner | `JacobJandon` |
| Repository name | `ainra` |
| Workflow name | `publish.yml` |
| Environment name | `pypi` |

The GitHub environment `pypi` already exists in the repository — it was created as part of this milestone, so
nothing else is needed on that side. The environment name must match exactly; PyPI's own troubleshooting page lists
a mismatch here as the usual cause of `invalid-pending-publisher`.

### 2 · npm — an org and one token, for the first publish only

1. Create a **free** organization named `ainra` at <https://www.npmjs.com/org/create>. The free plan covers
   unlimited **public** packages; nothing here needs a paid plan.
2. Create a **Granular Access** token scoped to `@ainra/*` with read **and write**, at
   <https://www.npmjs.com/settings/~/tokens>.
3. Put it in the repository as `NPM_TOKEN` — `gh secret set NPM_TOKEN` and paste at the prompt. **Never paste a
   token into a chat, a file, or a commit.**
4. After the first publish succeeds, configure the Trusted Publisher on each package
   (npmjs.com → package settings → Trusted Publisher → *Organization or user* `JacobJandon`, *Repository* `ainra`,
   *Workflow filename* `publish.yml`, *Environment* blank — the npm job declares no environment), then **delete
   `NPM_TOKEN`**. The workflow already prints which credential it used, and falls through to OIDC whenever the
   secret is absent, so removing it is the only step needed.

## Publishing a tagged version — one paste

```sh
cd ~/Desktop/Solvatron/ainra
make publish-preflight                          # must print READY with "tag matches tree"
gh workflow run publish.yml --ref vX.Y.Z -f target=dry-run     # publishes nothing; proves the path
gh workflow run publish.yml --ref vX.Y.Z -f target=npm-sdk     # @ainra/sdk first — the others resolve it by name
gh workflow run publish.yml --ref vX.Y.Z -f target=npm-middleware
gh workflow run publish.yml --ref vX.Y.Z -f target=npm-mcp
gh workflow run publish.yml --ref vX.Y.Z -f target=pypi

# THEN verify from the PUBLIC registries in a clean environment — never from this checkout:
npm view @ainra/sdk version
cd "$(mktemp -d)" && npm init -y >/dev/null && npm i @ainra/sdk && node -e 'console.log(Object.keys(require("@ainra/sdk")))'
python3 -m venv v && ./v/bin/pip install ainra && ./v/bin/python -c "import ainra; print(ainra.__version__)"
```

`--ref vX.Y.Z` is load-bearing. The workflow file that runs is the one at the ref you dispatch, and the release
gate compares the package tree against the tag — dispatching from `main` after `main` has moved on will block,
correctly.

## Install commands follow the registries, never the other way round

Until the first publish, registry install commands were **deliberately kept out** of the README, the site and the
verifier kit, which carried the from-the-clone route instead (a fresh public clone to a passing
`make verifier-kit-smoke` took **32 seconds**). They went in once the registries answered.

Publishing an install command before the package exists is the exact defect the Stranger Walk found (finding 5),
where the kit's troubleshooting page offered, as the remedy for a failure, the command that caused it. So the
propagation is a separate, gated step:

```sh
make outreach-check          # packets: pins, counts, install commands
make status-consistency      # every documented @ainra/sdk pin == the real package version
```

The same order holds for a new package (`@ainra/edge`): nothing names its install command until the registry
serves it, and then the kit, the site and these two gates move together, with `make stranger` against production.
