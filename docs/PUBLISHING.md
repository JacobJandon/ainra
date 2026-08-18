<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Publishing to npm and PyPI — everything that is done, and the two things that are not

**Status: READY and parked on registry identity.** `make publish-preflight` prints READY, the publish workflow's
dry run has been proven green from the tag, and every blocker that was ours to clear is cleared. What remains is
two web forms that require the maintainer's logged-in browser and cannot be done by anyone else.

```
publish-preflight   READY — "v0.3.3 is tagged AND the package tree matches it byte for byte"
publish.yml         dry-run SUCCESS from --ref v0.3.3 — @ainra/sdk@0.3.3, 8 files, 25.3 kB, provenance path proven
names               @ainra/sdk · @ainra/middleware · @ainra/mcp · PyPI ainra — all still unclaimed (404)
```

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

## Resume — one paste, once those two are done

```sh
cd ~/Desktop/Solvatron/ainra
make publish-preflight                          # must print READY with "tag matches tree"
gh workflow run publish.yml --ref v0.3.3 -f target=dry-run     # publishes nothing; proves the path
gh workflow run publish.yml --ref v0.3.3 -f target=npm-sdk     # @ainra/sdk first — the others resolve it by name
gh workflow run publish.yml --ref v0.3.3 -f target=npm-middleware
gh workflow run publish.yml --ref v0.3.3 -f target=pypi

# THEN verify from the PUBLIC registries in a clean environment — never from this checkout:
npm view @ainra/sdk version
cd "$(mktemp -d)" && npm init -y >/dev/null && npm i @ainra/sdk && node -e 'console.log(Object.keys(require("@ainra/sdk")))'
python3 -m venv v && ./v/bin/pip install ainra && ./v/bin/python -c "import ainra; print(ainra.__version__)"
```

`--ref v0.3.3` is load-bearing. The workflow file that runs is the one at the ref you dispatch, and the release
gate compares the package tree against the tag — dispatching from `main` after `main` has moved on will block,
correctly.

## Only after the registries answer

Registry install commands are **deliberately not** in the README, the site, or the verifier kit. Those surfaces
currently carry the honest banner that the packages are not published, and the from-the-clone route beside it —
which is proven to work: a fresh public clone to a passing `make verifier-kit-smoke` takes **32 seconds**.

Publishing an install command before the package exists is the exact defect the Stranger Walk found (finding 5),
where the kit's troubleshooting page offered, as the remedy for a failure, the command that caused it. So the
propagation is a separate, gated step:

```sh
make outreach-check          # packets: pins, counts, install commands
make status-consistency      # every documented @ainra/sdk pin == the real package version
```

Both currently pass **because** nothing claims an install. When the packages are live, update the kit banner and
the site together, then re-run those two gates and `make stranger` against production.
