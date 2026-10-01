<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# kits/signature-agent: one request, two readers (D-070)

This kit tests AINRA against a signature agent's signature. That signature uses the Web Bot Auth profile of RFC 9421:
an operator's Ed25519 key, published in a directory at its origin. The kit puts it on the same request as a running
copy's AINRA signature, and has each signature checked by its own verifier.

The other verifier is **not ours**. It is an independent open-source implementation of the signature-agent profile,
pinned by exact version in `package-lock.json`.

| | Command | What it proves |
|---|---|---|
| Offline (CI) | `make signature-agent-check` | The pinned verifier checks the `sig1` member of every vector in `vectors/v1-presentation` that has an `other_signer`. It must conclude what the vector records. AINRA's answer on the same request must stay the recorded one. Then `--negative` flips one byte of each operator signature, and every recorded-valid one must be refused. |
| Live | `make signature-agent-e2e` (after `make live-up`) | Real requests through `@ainra/middleware` and `@ainra/edge` at the real clock. See the list below. |

The live drill does the following:

1. A passport is issued for the agent's own key, plus an instance credential.
2. The operator publishes its key directory.
3. Both signatures go on one request, in either order, and also with the operator covering AINRA's signature.
4. Either signature broken or missing leaves the other verifier's answer unchanged.
5. A request moved to another path is refused by AINRA. The operator's minimal signature covers `@authority` only, so
   it still verifies.
6. After the passport is revoked, AINRA refuses a request that the operator signed.
7. The operator's withdrawn key keeps verifying until the directory is fetched again.

Read [`docs/SIGNATURE-AGENTS.md`](../../docs/SIGNATURE-AGENTS.md) for how to use this in your own setup.

This is a test root. The drill's directory runs over http on 127.0.0.1; in deployment the profile requires https. The
drill proves the mechanism. It is not evidence that any operator runs it.
