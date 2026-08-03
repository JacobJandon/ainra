<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Verifier attestation — file format

Produced for you by `make verify-as-external CHALLENGE=<dir>`; you do not hand-write it. This page explains what
the fields mean so you can read what you are signing before you sign it.

```jsonc
{
  "body": {
    "verifier_pubkey_spki_b64": "…",   // YOUR public key (throwaway is fine). The signature below is checked against this.
    "challenge": "a1b2c3…",            // the nonce WE issued you — proves this is the challenge you were given
    "execution_bound": true,           // you actually ran verification; a file without this cannot count
    "challenge_corpus_sha256": { … },  // hashes of the challenge corpus you verified, per kind
    "results": [ … ]                   // your verdict + reason for each challenge bundle
  },
  "sig_ed25519_b64": "…"               // detached Ed25519 signature over the canonical body
}
```

- **Your key is yours.** Generate a throwaway; we never see a private key, and the file carries no personal data.
- **Nothing leaves your machine but this file.** The kit makes no network calls.
- **Check it yourself first:** `node tools/intake-check.mjs verifier-attestation.json` runs exactly the public
  checks CI runs.
- **Then:** add it as `evidence/verifier/<your-id>.json` in a pull request. Keep the id short and kebab-case.

The maintainer then runs the private half (`kits/verifier/check-attestation.mjs --secret …`) against the answer key
for your challenge. Only that decides whether it counts — see [`../README.md`](../README.md).
