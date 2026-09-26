<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Personhood kit — a human behind the agent, as an AINRA principal proof

**Registrar-side.** The root issues nothing and sees none of this (D-066).

Some registries already answer one question well: *is a unique, verified human behind this wallet?* This kit turns
that answer into something an AINRA registrar accepts, the `principal_proof` in a passport's authority block. It
adds what those registries lack:

- the passport **expires**;
- it **can be revoked** with one bit;
- it names its **operator and capabilities**;
- it **verifies offline**.

The first configured registry is the AgentBook contract on World Chain. It has no revoke, no unregister and no
expiry: a wallet stays human-backed forever once registered. Registries are configuration (a chain, a contract, a
`lookup(address) → uint256` view), so a registrar can add its own.

## The chain of evidence

```
human ──(zero-knowledge proof, on chain)──▶ agent wallet ──(EIP-191 signature)──▶ AINRA holder key
```

1. **The registry says** the wallet is backed by a unique human. The lookup is pinned to a block number.
2. **The wallet signs** a readable binding naming this registrar, this agent key (holder thumbprint), the chain, a
   time and a nonce.
3. **The kit checks it:** it recovers the signer and checks every field. Only then does it return a principal proof:
   SHA-256 over the evidence. The proof is opaque and carries no identifier. The evidence stays with the registrar.

Every refusal is named: `binding_malformed`, `binding_invalid` (the signer is not the wallet), `binding_mismatch`
(another registrar, key or chain), `binding_stale` (older than 10 minutes), `not_human_backed` and `lookup_failed`.

A failed lookup is **never** read as "not registered".

## Use

```bash
cd kits/personhood && npm install
node personhood.mjs check 0x801440b7a943540872c42aA8EE2FDc505a2B12C3      # live: human-backed?
node personhood.mjs prove --message-file binding.txt --signature 0x… \
  --registrar registrar-07 --holder <sha256(ed25519 ‖ ml-dsa-65 public keys)>
```

On success, the registrar issues with `auth_class: "A1"` and `principal_proof: <the digest>`, and files the
evidence in its own store.

## Proof

- `make personhood-test`: offline, 14 tests. The Ethereum primitives are checked against vectors from other
  implementations (the EIP-55 spec examples, ERC-20 selectors, web3.js's documented signing example). Every refusal
  is forced with a stub RPC.
- `make personhood-live` needs the network. It takes a real registration from a public explorer and requires our own
  block-pinned `eth_call` to return the same human id. It then checks that a fresh wallet comes back not
  human-backed and that an unreachable RPC is `lookup_failed`.

**Not proven live:** the positive binding. That needs the key of a wallet a verified human registered, and we hold
none.
