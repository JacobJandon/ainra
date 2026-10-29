<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# kits/tsl: AINRA revocations in the IETF Token Status List form

Every AINRA registrar publishes its revocations as a hybrid-signed status list (Ed25519 and ML-DSA-65, both or
invalid). That list is authoritative. Each registrar also serves the same bits as a `statuslist+jwt`, the format of
the IETF OAuth Token Status List draft, signed with the Ed25519 half of its status key, at `GET /status-list.jwt`
(`ainra status-jwt <dir>` on the command line). The bit layout is already the draft's: one bit per entry, LSB-first,
zlib-compressed. Any Token Status List library can therefore check an AINRA passport's or link's revocation without
knowing anything about AINRA.

This kit proves it with code that is not ours, pinned by exact version in `package-lock.json`: an independent Token
Status List implementation and an independent JOSE implementation.

| Command | What it proves |
|---|---|
| `make tsl-check` | A registrar issues two passports and revokes one. The JOSE library verifies the token (EdDSA, `typ` `statuslist+jwt`) under the key in the registrar's accreditation. The Token Status List library reads the revoked passport as 1 and the valid one as 0. The bits are the same bytes as the hybrid publication. An edited payload and another key are both refused. |

**What the mirror does not change.** AINRA verifiers keep reading the hybrid publication; the mirror is for software
that speaks only the IETF format. The mirror's signature is Ed25519 alone, so it carries no post-quantum assurance; the
signer refuses any input that is not a JWS signing input, so it can never sign an AINRA object.
