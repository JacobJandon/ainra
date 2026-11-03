<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# crates/ainra-cli-rs — the `ainra` command line

The reference command line over `ainra-core`. Offline and persistent, with no daemon: every command drives the real
`RegistrarBox` engine — hybrid signing, RFC 6962 log inclusion, signed status deltas — and prints what the real
verifier decides. It issues, renews and revokes (`init`, `issue`, `renew`, `revoke`), presents and
verifies (`present`, `verify`, `verify-request`, `verify-link`, `verify-decisions`, `log-verify`), links keys
(`link`, `link-revoke`, `links`), publishes status (`status`, `status-jwt`, `deltas`, `fresh-head`), and re-checks an
export with the pure core verifier (`reverify`). `ainra help` lists them.

`apps/cli-node` is a separate, independent reference CLI, kept apart for the differential harness. Build:
`cargo build --release -p ainra-cli-rs`. See [../../docs/STATUS.md](../../docs/STATUS.md).
