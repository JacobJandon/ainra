<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# PLAN-M55 — The root beneath other identity systems

*Written 2026-11-14, on the operator's instruction of 13 November: AINRA is to be the root for the agent identities
other systems issue, not one more island beside them. The Standard has said so since its first section ("The
missing piece is a root"). This plan is the order in which that becomes true in code and in fact. It changes no
passport and no verdict of a recorded vector. It runs beside PLAN-M53 and PLAN-M54.*

## What "the root for other systems" means here

An agent usually already has an identity from somewhere: a directory entry in its company's identity system, a
certificate from a naming service, a token from an issuer, a key in a signature-agent directory. Each of those can be
checked and withdrawn only inside the system that issued it. AINRA does not replace any of them. A **link** (D-078)
gives a key such a system already issued an accountable owner and a status bit that anyone checks offline, under one
directory of accredited registrars. The other systems stay the issuers; AINRA is what they share. See
[LANDSCAPE.md](LANDSCAPE.md) for who those systems are.

Three things stand between that sentence and the truth. Links took only two kinds of key. A link covers one key, and
a system that issues identities to a million agents will not make a million links. And the root is a TEST root.

## Steps

**1. Links for P-256 keys** (D-108). **Done 14 November 2026.** Most other systems sign with NIST P-256 (ES256):
certificates, signed agent cards, token issuers, hardware and platform keystores. Until this step none of their keys
could be linked. WITNESS: `vectors/v1-link` l44 to l53, agreed by the three implementations (`make diff`) and the
three gates (`make link-parity`); removing the low-S rule turns l45 red.

**2. Issuer links.** One link for the key a system *issues with*, saying so, so a gate that has verified an agent's
token or certificate against that issuer key in the ordinary way can ask who stands behind the issuer and whether
that is still true. Revoking the issuer's link refuses everything it issued. A kit shows the whole path with a token
from an issuer the project does not run. Needs a decision record: what an issuer link may and may not be read to
mean (it attributes the issuer; it does not vouch for each agent the issuer names). WITNESS: a token from a linked
issuer is attributed; the same token after the issuer's link is revoked is refused; a token from an unlinked issuer
is "not linked", never "valid".

**3. RSA issuer keys.** The large identity providers sign with RSA (RS256, PS256). Needs a library choice made
against the advisory database on the day, and an answer to key size (2048 bits and up). WITNESS: link vectors for
RSA, agreed by the three implementations and the three gates; a 1024-bit key is refused by name.

**4. A kit for agents named by a certificate.** Bring the certificate an agent already has; the kit reads its key,
makes the consent, and shows the agent attributed and then switched off. It reads certificates; it issues none.
WITNESS: the kit run end to end in `make live-drills` against a certificate made by a standard tool.

**5. The root itself.** Everything above runs under a TEST root, whose key is a fixed seed (D-107, limits). Nobody
can be the root of anything real under it. A production root needs a legal entity, nine independent custodians and
three standby, five recovery-key holders, a second host for the record, a named incident deputy, and a recorded
ceremony (D-094 lists what is still undecided). This step is the operator's; code cannot shorten it. Until it is
done, every page and every answer says TEST root.

## What this plan does not do

- It does not make AINRA an identity provider. The other systems keep issuing.
- It does not vouch for another system's checks. A link says who answers for a key, not that the system that issued
  it did its work well.
- It does not add a lookup service. A gate still downloads the index and checks offline, so nobody learns which key
  it asked about.
