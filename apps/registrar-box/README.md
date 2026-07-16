<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# apps/registrar-box — M2 scaffold (not yet implemented)

The org-tier "registrar in a box": an accreditation + issuance operator any registrar can self-host, built on
`crates/ainra-core` for every consensus-critical check (schema, hybrid signing, chain/mandate evaluation, log
inclusion). Empty by design — no fake issuance logic. See [../../docs/STATUS.md](../../docs/STATUS.md) and
DECISIONS D-007 (MTS §27: registrar-in-a-box is M3).
