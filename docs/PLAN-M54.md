<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# PLAN-M54 — Global: AINRA in every country, every language, every stack

*Written 2026-11-07 at the operator's request: "we should become as global as" the most widely deployed open systems,
"in every place on this planet". The method is [GLOBAL.md](GLOBAL.md): five systems, the habit that made each one
trusted, and what AINRA still lacks. These steps close the gaps. None of them changes the passport format or the
verify path. They come after PLAN-M53's open protocol steps (R1, R2) and run beside the rest of M53.*

## Stability first

**G1. The no-break rule and long-term support.** One decision record, with three parts:
- A change that alters the verdict of a recorded vector, or breaks a published integration, is a bug.
- Deprecations are announced one full release line ahead.
- Every second minor release is a long-term-support line, kept for security fixes for two years.

WITNESS: a gate that fails when a release line marked LTS loses a vector verdict.

**G2. Maintainers per subsystem.** CODEOWNERS that name the reviewers for core, the SDKs, the services, the ceremony
and the site, so no change lands unreviewed by someone who knows that part. It starts with the founders and grows
as people earn it.

## Everyone can implement it

**G3. Verifiers in more languages.** Go and Java first, then C# and Swift, the languages most server and mobile
back-ends are written in. Each one is held to the full corpus by the differential before it is listed.

WITNESS: `make diff` names each new implementation and all of them agree.

**G4. Standards.**
- The Internet-Draft on the standards track. The I-D upload reopens 15 Nov.
- `did:ainra` registered in the public DID method registry.
- A liaison request to the international committee for identity and security techniques.
- A liaison request to the regional standards body that regulators cite for digital identity.

The operator sends every one of these requests; AINRA never initiates contact by itself.

## Anyone can trust it, everywhere

**G5. Certification and the mark.**
- An implementation that passes the full corpus publishes a signed attestation. The conformance programme already
  produces one.
- A public page lists every attestation, each with the command that re-checks it.
- A small mark may be used only alongside a current, re-checkable attestation.
- It is never sold.

**G6. A registrar per continent.**
- The onboarding kit (`tools/onboard-registrar.sh`) and the accreditation checks, published in a form a registrar
  in any country can follow.
- A regulation map per region, each line with a source.
- A dispute and liability rule for registrars, in the rulebook.

## Everyone can read it

**G7. Languages.**
- The site, the quickstarts and the Standard, translated into the world's most-spoken languages.
- Each translation reviewed by a native speaker before it is published. English stays normative.
- A gate that fails when a translated page falls behind its English source.

**G8. Low bandwidth and offline.**
- The directory, status lists and fresh heads in one compact bundle that can travel by any channel: a file, a mirror
  or a removable disk.
- A verifier that works for days on the last bundle it received, within its freshness class, and refuses when that
  class is exceeded.

## The end state

A community that runs AINRA without needing its founders: maintainers, registrars, custodians, witnesses and
implementers in many countries, under one public rulebook. That is how the systems in GLOBAL.md lasted.
