<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Maintainers

## Current

| Role | Handle | Scope |
|---|---|---|
| Maintainer | [@JacobJandon](https://github.com/JacobJandon) | everything: merges, releases, the offline signing key, the roadmap |

That is the honest list: **one maintainer**, pre-institution. See [GOVERNANCE.md](GOVERNANCE.md) for what that means
and how it changes at the genesis ceremony (custodians) and after it (member constituencies).

The release signing key is **offline** and held by the maintainer; its public half is committed at
`release/ainra-release.pub` and pinned in `RELEASE-VERIFY.md`. No CI job and no other person can sign a release.

## What a maintainer may not do

Structural limits, enforced by the repository rather than by trust:

- **Rewrite pushed history.** Force-push and branch deletion are blocked at the platform on `main`.
- **Claim a release without proof.** `make changelog-board-check` fails the build if `CHANGELOG.md` names a version
  with no committed board evidence in `docs/releases/`.
- **Flip a Definition-of-Done row by hand.** The three real-world rows flip only when real artifacts land and the
  checker validates them — see `evidence/README.md`.
- **Weaken a gate to land a change.** A red test is fixed, never deleted or loosened (see `CONTRIBUTING.md`).

## Becoming a maintainer

There is no committee to petition. The path is the work: land substantive PRs that keep the board green, review
other people's changes usefully, and the invitation follows. After genesis this becomes a charter matter.

## Contact

- **Security findings** → the private advisory channel in [SECURITY.md](SECURITY.md). Never a public issue.
- **Everything else** → a public issue from the templates, or a pull request.

There is deliberately no email address here: the root holds no personal data, and that includes maintainers' and
reporters' (D-036).
