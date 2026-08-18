<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Free infrastructure — what a pre-entity, pre-revenue root can actually get

Researched 2026-08-05 against the three open rows, not against generic "free stuff" appeal. Every entry
below was checked on the issuing body's own page; the gaps are listed at the end rather than papered over.

**A convention, so this reads consistently with the rest of the campaign:** suppliers are named only where the name is
the fact (a standards body, a foundation, a registry). Where the useful fact is the *eligibility rule*, the rule is
quoted and the vendor is described by category — the S7 neutrality gate governs this directory too, and a root that
sells neutrality should not keep a list of brands it hopes will give it things. The linked pages resolve the rest.

**The finding that reframes everything:** almost every programme worth having *rewards AINRA's current
shape* — unincorporated, non-commercial, open. Several exclude commercial entities outright. See
[`JURISDICTION.md`](JURISDICTION.md), where this is now a decision input.

## Pursue now — no entity, no cost

| What | Why it matters here | Where |
|---|---|---|
| **The Witness Network** | Free third-party cosigning of our transparency log. Converts "AINRA says its log is append-only" into "AINRA **cannot lie** about its log" — and it fills `witnesses/candidates.json`, which is at 0. Apply to the **`testing`** list (`production` does not exist yet; the project self-describes as experimental). Needs C2SP `tlog-checkpoint` + `tlog-witness` and an Ed25519 vkey. | witness-network.org/participate |
| **W3C Agent Identity Registry Protocol CG** | Free, **no entity** — 21 of 40 participants are unaffiliated individuals. Its work items include **revocation lifecycle** and **post-quantum requirements**: the two things we already ship and almost nobody else does. A young CG has no test suite; we have 793 CC0 vectors. This is the "join, don't found" landing spot. | w3.org/community/agent-identity |
| **IETF** | *"There is no membership in the IETF."* Free to participate, free to submit a draft. Live WGs that touch us directly: **SCITT** (supply-chain transparency, RFC 9943), **Web Bot Auth** (we already ship an RFC 9421 adapter), **SPICE**, **KEYTRANS**, **WIMSE**. Only meetings cost; the Hackathon is free. | ietf.org |
| **NLnet / NGI Zero** | €5k–€50k, and verbatim: *"You can apply as an individual… It is not an issue if you have not yet established the entity when you apply."* **Calls open 3 Sep 2026, deadline 3 Nov 12:00 CEST.** Draft in August. | nlnet.nl/propose |
| **Vercel OSS Program** | $3,600 platform credits/yr. Both gates already met — we are on Vercel and have a `CODE_OF_CONDUCT.md`. **Applications reopen in August; check this week.** | vercel.com/open-source-program |
| **OpenSSF Scorecard + Best Practices Badge** | 23 automated checks and a free self-certification. For a project whose entire pitch is trust infrastructure, a third-party-legible score is cheap credibility — and the badge feeds Scorecard's own check, so it double-counts. Wired in this repo. | ossf/scorecard · bestpractices.dev |
| **GitHub, for public repos** | Actions, **immutable releases** (GA Oct 2025 — assets and tags can no longer be altered after publish), CodeQL **with Rust support**, secret scanning + push protection, and Artifact Attestations that use the **public-good Sigstore instance** for public repos. Mostly already paid for and switched off. | docs.github.com |
| **Registry provenance** | crates.io Trusted Publishing (OIDC, and owners can now *enforce* it), npm `--provenance`, PyPI attestations (PEP 740). **Provenance cannot be retrofitted onto a published version** — wire it in the same pass that publishes. | see `RELEASING.md` |
| **MCP Registry** | Free, self-serve, no approval: `io.github.<user>/…` namespace verified by an `mcpName` field. The most concrete free channel to actual developers we have — and `packages/mcp` already exists. Publish npm first. Registry is in preview. | registry.modelcontextprotocol.io |
| **Standards rooms, one email each** | OpenID Foundation **AI Identity Management CG** (*"open to the public, including… individuals"*), **W3C Credentials CG** (611 participants, anyone may join — where status-list and revocation semantics are argued), **OpenSSF WGs** (*"open to everyone"*). | — |
| **ClusterFuzzLite** | Continuous fuzzing on Actions, supports Rust, **no eligibility bar**. The natural upgrade from our three cargo-fuzz targets. | google.github.io/clusterfuzzlite |
| **Sundries** | JetBrains OSS licence (individual contributor, no entity) · docs.rs (automatic on publish) · a major edge provider's OSS programme, gated on *"operate solely on a non-profit basis"* — a behaviour test we pass · Anthropic Claude for OSS (*"a natural person, not a corporation"*). | — |

## Later

**Commons Conservancy** — a legal home with *no cost at all* (*"we don't interact with money"*), built for projects with no
entity; NLnet-adjacent, so it pairs with the funding route. Worth a conversation **before** incorporating anything.
**Sigstore/cosign** — free keyless signing, strictly *additive*: never let `make verify` or the stranger test shell out to
`cosign verify`, because that needs network reach to Rekor and TUF and would hand our offline onramp to someone else's
on-call rotation. Sign from Actions OIDC, never a personal identity — keyless signing writes the identity permanently and
irremovably into a public log. (Rekor v1 is **not** sunset; v2 instances shard annually, so hardcode nothing.)
**Tessera** — the prize is witness compatibility, not the Go library; emit spec-conformant checkpoints from our own log.

## Not worth it, and why

- **Palantir** — the AIP Developer Tier is genuinely free, but it is a data-ontology platform, not signing/log/CI
  infrastructure; it is geo-restricted; and building on it would put a **proprietary vendor** exactly where our
  positioning forbids one. Their ToS also bars use to build anything *"similar to Palantir's offerings"*, and their
  community registry requires the project to be built on AIP. Their open source (UI toolkits, Java/Gradle tooling) is
  irrelevant to us. **Never.**
- **OSS-Fuzz** — eligibility is *"a significant user base and/or critical to the global IT infrastructure."* We have
  neither yet. Applying would burn a first impression.
- **Certificate Transparency** — structurally impossible: CT logs accept only X.509 chaining to a browser-trusted root.
  Read RFC 9162 as design prior art, nothing more.
- **A free RFC 3161 timestamper** — the free one is run by a single unnamed individual with no SLA. Putting that in a
  neutral root's path is the worst of both worlds; take time from witness-cosigned checkpoints instead.
- **Netlify OSS** — requires a permanent vendor badge on the main page. On a project selling neutrality that is a brand
  cost, not a cosmetic one.
- **Linux Foundation hosting** ($ + member sponsors), **W3C full membership** ($953–$77,000/yr, no individual category),
  **Software Freedom Conservancy** (needs an existing vibrant community), **Alpha-Omega** (funds OpenSSL/Node/Python-scale
  projects), **CNCF Sandbox** (cloud-native — would confuse the positioning), **Microsoft for Startups** (requires being a
  B2B product), **Prototype Fund** (German tax residency), **Mozilla MOSS** (on hiatus since 2020).


## The distribution critical path — one blocker, then five free listings

The traction gap is developers, and this is the cheapest chain to them. It is **blocked on one thing**: the npm publish.

1. **Publish `@ainra/mcp` to npm** — with trusted publishing + provenance (see `RELEASING.md`).
2. **Official MCP Registry** — free, self-serve, no entity. It hosts *metadata only*, which is why npm comes first.
   Prefer **DNS verification** on the domain over GitHub-handle auth, so the namespace reads as a neutral root
   (`org.ainra/…`) rather than a personal account.
3. **PulseMCP ingests the registry daily** — free rider, no separate submission.
4. **Glama** — needs submission + a working container build; without one you are indexed but invisible.
5. **awesome-mcp-servers** (a PR) and **mcp.so** (a GitHub issue) — ~25 minutes combined. SEO plumbing; expect
   roughly zero developers from them directly, but they cost nothing.

Then, and only then, the demo-first channels: a **StackBlitz** no-install "verify a credential in 60 seconds" embed
(unlimited public projects, free) → **Show HN** (a bare repo link is a weak Show HN; a no-install verifier is a strong
one) → **Console.dev** (one email, 30k curated devtools subscribers, and it has a *beta track* built for pre-1.0
tools — the best signal-per-effort found) → **This Week in Rust** (PR to `drafts/`, one submission per contributor
per week).

**`awesome-rust` needs 50+ stars or 2,000+ downloads** — a premature PR gets closed. Check before submitting.

## Two free structural fixes worth doing regardless of funding

- **Move the repository to a GitHub organization.** It costs an hour, and it does two things: it unblocks fiscal
  hosting (Open Source Collective's criteria require *"an organizational repository, not a personal account"*), and
  it fixes an optics problem — a *neutral root* living under one person's personal account undercuts the claim
  before anyone reads a line of code.
- **Open GitHub Sponsors as an individual.** Bulgaria is a supported region, and the personal path explicitly needs
  **no legal entity** (the *organization* path does). Cleanest money route available in AINRA's current shape.

## Ready to wire, not yet wired

Free, no entity, no approval — the ones this pass did not turn on: **ClusterFuzzLite** (continuous fuzzing on
Actions, Rust supported, no eligibility bar — the honest substitute for OSS-Fuzz), **Miri** (`cargo +nightly miri
test` — cheap and pointed straight at the hand-rolled CBOR/COSE parsing), **Trivy** (vulns + secrets + SBOM across
Cargo/npm/pip — **SHA-pin the action**: third-party reporting describes a March 2026 compromise of its version tags),
**Semgrep OSS CLI**, **cargo-audit**, **deps.rs** badge, **Codecov *or* Coveralls** (pick one), and **CodSpeed**
(free for OSS, covers Rust + Python + Node — AINRA makes *speed* claims about offline verification, and those should
be regression-gated rather than asserted).

## Corrections to the first pass

- **CodeQL supports Rust** — generally available since Oct 2025, both default and advanced setup. Wired here.
- **Coverity Scan has no Rust.** Never, for the core.
- **Snyk: never** — Rust code analysis is Enterprise-gated, *and* its OSS programme requires a backlink to the vendor
  in the README and on the site. A permanent vendor badge is a brand cost this project cannot pay.
- **Travis CI** has no free tier any more; **SourceHut CI** is paid; **CodeSandbox** freezes free VMs mid-month;
  **Hugging Face Spaces** now needs a paid plan for compute Spaces and is the wrong audience anyway.
- **The Rust Playground cannot host third-party crates** — it is a popularity gate, by written policy, and there is
  no route around it. The equivalent moment is a **WASM build of the core running in our own docs page**, which needs
  nobody's permission.
- **The `modelcontextprotocol/servers` list is retired** in favour of the registry — the most common stale advice
  in MCP distribution guides.
- **OSS-Fuzz's reward programme sunset** (~May 2026); both official pages now 404.

## The soak has no clean free answer

Checked specifically because it is a DoD blocker. **Oracle Always Free is home-region only** — one account cannot give
three regions, and idle instances are reclaimed after 7 days under 20% use. GCP Always Free is one micro instance in one
US region. **Fly.io has no free tier for new customers.** Render free services **spin down after 15 minutes**, which is
fatal to a p95 < 60 s measurement. Koyeb's free tier closed to new users. The realistic free path is Oracle (home region)
+ a second provider's US free tier + an edge-worker platform, with the honest caveat that they are heterogeneous. Running three Oracle
tenancies with different home regions would likely breach their terms — don't.

## Unverified, stated plainly

Palantir's marketing pages are JS-rendered and returned nothing; the edge provider's OSS landing page, the
free-tier page of one cloud, and the Prototype Fund all returned 403. Sigstore's public-good **rate limits** are published nowhere findable.
GitHub Artifact Attestations' **SLSA level is not stated** — do not claim a level in our docs without checking. Coverity
Scan's free service may or may not expose its new Rust support. **The highest-value open question:** DIF's Trusted AI
Agents WG is the closest scope match to us outside W3C, the Contributor tier is free, but WG access is membership-gated
and signup expects an org email — **ask DIF point-blank whether an unincorporated project qualifies.**

Already missed: NIST/CAISI's RFI on *Security Considerations for AI Agents* closed 9 Mar 2026. Free, no entity, and it
produces a permanent government-hosted citation. Watch for the next one, or reach it through the OpenID AIIM CG.
