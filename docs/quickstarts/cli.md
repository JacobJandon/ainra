<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# CLI quickstart — `ainra`

The `ainra` command is the registrar power surface: init a registrar, issue / renew / revoke / verify. Real crypto,
local, zero telemetry. (`make issue-first` wraps the first three; this is the full set.)

```bash
cargo build --release -p ainra-cli-rs           # once; binary at ./target/release/ainra
ainra=./target/release/ainra

$ainra init my-registrar registrar-07            # a persistent registrar (keys + log + status live in the dir)
$ainra issue my-registrar --operator acme --lineage assistant --version 1.0.0 --tier L2 --cap read:data
$ainra verify my-registrar ainra:registrar-07:acme:assistant@1.0.0
$ainra revoke my-registrar ainra:registrar-07:acme:assistant@1.0.0
$ainra verify my-registrar ainra:registrar-07:acme:assistant@1.0.0
```

Real output:

```
initialized registrar 'registrar-07' at my-registrar (seed 0x5b4a2f0ac0732fb)
issued ainra:registrar-07:acme:assistant@1.0.0
VALID
revoked ainra:registrar-07:acme:assistant@1.0.0 — signed delta seq 0 → 1
INVALID (revoked)
```

More: `ainra renew <dir> <sub> --version 1.0.1` (ADR-017, add `--dry-run` to preview), `ainra list <dir>`,
`ainra events <registry.json>` (the [verdict event](../PRESENTATION.md) per record), `ainra demo` (one-process end
to end). Every error names the next command to run. Against a **network** registrar you control, the same verbs are
HTTP endpoints — see the registrar console (`make registrar-console`).

## The instance rung (ADR-019)

```sh
ainra instance issue <serial> --aud https://api.example --caps read:invoices --ttl 900
ainra instance verify <iid> --aud https://api.example
```

`issue` runs where the passport key lives and hands the container two files (both `0600`) — the credential and the
instance key. `verify` is what a receiving service does: it checks the **passport** first (revocation, then its
window), then the copy. Revoke the passport and every live copy is refused with `revoked`.
