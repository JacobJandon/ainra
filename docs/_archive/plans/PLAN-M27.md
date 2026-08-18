<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# M27 — the staging network stands, and a stranger walks the whole surface

Two truths sat behind a green board.

**The network died with a session.** Four processes started by hand in a terminal. Close the laptop, log out, or let
one daemon wedge, and the demo's spine was gone with no one watching. A board that goes green on a network that only
exists while an operator is sitting at the machine is measuring the operator, not the network.

**No one had ever walked the public surface as a stranger.** Every check ran against local files or a local network.
The thing an actual visitor touches — the deployed site, its links, its claims, its downloads — had never been walked
end to end by someone with no context and no login.

This milestone closes both, and it changes what "verified" means: **every fix in the table below was re-checked on
production after deploy**, because pushing is not deploying and a fix that is only true locally is not a fix.

---

## Task 1 · The network stands on its own

`deploy/systemd/` + `tools/stage-install.sh` + `tools/stage-watchdog.sh`, documented in
[`deploy/systemd/README.md`](../../../deploy/systemd/README.md). The honest claim, which is deliberately smaller than
"always on", is:

> **The network runs whenever this machine is powered on. No more than that.**

It is not always on — the machine sleeps, reboots, travels. And it is not reachable by a stranger: every daemon binds
`127.0.0.1`, so making it stand does **not** turn the public site's minting flow on for visitors. What it does is
survive logout, reboot, and a crashed daemon.

**Two layers of recovery, because they catch different failures.** `Restart=always` catches a process that *exited*.
The watchdog catches one that is *alive and useless* — wedged, holding its port, answering nothing — by probing the
same public contract a consumer reads. Both proven, not assumed:

```
SIGKILL the artifact server → unit=active, new PID, contract answers HTTP 200 again
stop registrar-07 outright  → watchdog: "registrar-07 door not answering (HTTP 000) — restarting" → HTTP 200
```

**The always-on question is parked, not solved.** Nothing here makes the network publicly reachable, and the honest
options all cost money or a new account — both outside what this milestone may provision. The wording above is the
truth until one of them is chosen deliberately.

---

## Task 0 · The Stranger Walk — findings

Six journeys against **live production** and the public repository, by an agent with no prior context: land and
navigate; verify a passport; get a passport; read the docs and install; arrive as an AI agent via `llms.txt`; arrive
as an outsider at the repo. Severity: **BREAK** = the site told a visitor something untrue or left them stuck ·
**CONFUSE** = correct but self-contradicting · **POLISH** = cosmetic.

| # | Sev | What a stranger hit | Fixed by | Verified live |
|---|---|---|---|---|
| 1 | BREAK | The **404's own escape routes were dead in the case they exist for.** Its three links were relative, so at any nested path — `/docs/getting-started`, or `/demo/issue`, a path the site's own `llms.txt` prints — they resolved *into that directory* and were themselves 404. A visitor who took one wrong turn had no working way back. | `site/404.html` → root-absolute links | ✅ `href="/index.html"`, `/standard.html`, `/status.html` served; target 200 |
| 2 | BREAK | **Two surfaces published two different networks, and each denied the other's passports.** `verify.html` read `/data/registry.json` (13 lineages, 3 registrars); `get.html` and `foundation.html` read `/net/registry.json` (8, 2) — the *same* registrar-07 carrying a *different root key* in each, so they could not be two snapshots of one network. A stranger could verify "a live lineage" on one page and find it flatly absent from the record browser that claims to hold *every passport the network has issued*, under a banner reading NUMBERS ARE MEASURED OR THEY ARE ABSENT. | `site/verify.html` → reads `net/registry.json` | ✅ picker 13→8 lineages, registrar-02 absent from both, matching AINRAscan's 2/8 |
| 3 | BREAK | **`llms.txt` — the file that tells agents "this is your map" — stated the wrong release**: "two signed releases; current: v0.3.0" when three exist and v0.3.1 is current, a *security* release at that. Stale at source, not a stale deploy. It survived every board because the status-honesty gate only ever compared README against `docs/STATUS.md`. | `site/llms.txt` + `tools/status-consistency.mjs` derives count and current version from git tags | ✅ live `llms.txt` reads "three signed, board-proven releases; current: v0.3.1" |
| 4 | BREAK | **`docs#install` sent strangers to the releases page** for "the one-file reference CLI… it runs with just node". No release has ever contained a node CLI — all three ship a Linux x86_64 Rust binary. Anyone on macOS, Windows or ARM following the homepage's main call to action left with an unrunnable file, or nothing. | `site/docs.html` → `ainra-cli-v0.3.1.zip`, and the releases page described as what it is | ✅ link present, zip serves HTTP 200 |
| 5 | BREAK | **The verifier kit's documented outsider route installs a package that does not exist.** QUICKSTART, README and TROUBLESHOOTING all say to `npm install @ainra/sdk` — never published, so it dies with E404, and the remedy TROUBLESHOOTING offers for failure #1 *is itself the cause of failure*. The project already had the honest pattern (`packages/mcp/README.md` carries a "not published to a registry" banner); it simply was not applied on the verifier path. | `kits/verifier/{QUICKSTART,README,TROUBLESHOOTING}.md` → banner added, stale `^0.1.0` → `^0.3.1` | ✅ in the public repo at HEAD; 0 stale pins remain |
| 6 | BREAK | **A registrar that ACCEPTS and never answers hung the page forever.** `?reg=<url>` is documented on `get.html`; a *refused* port always failed correctly in milliseconds, which is why this was never caught. A host that *drops* instead of resetting — a firewall, a wedged daemon, a laptop that closed its lid mid-request — never rejects the fetch at all, so `boot()` never reached its `unavailable()` branch, the honest note never appeared, the handlers were never attached, and "Mint my passport →" sat there enabled and looking ready. | new `site/js/net.mjs` — all 17 site reads through one gateway that cannot be called without a deadline; button disabled until its listener is attached | ✅ see the proof below |
| 7 | BREAK | **"The published record is 110 days old" was wrong — and the fix reporting it was mine.** The date came from `generated_window.verified_at`, which is not a publication time: it is `seed.rs::VERIFY_NOW`, the pinned instant staging computes validity against, *identical* in a record published today and one published a year from now. The live network serves that same value right now, and the committed copy is byte-identical to what the running network serves this second. The panel was announcing "110 days ago" over a current record. | `make site-net` stamps `published.json` at copy time; `make site-net-check` proves the copy still matches the network; panels read the stamp | ✅ `published record · published 2026-08-08 (today)` on foundation and get |
| 8 | BREAK | **`foundation.html` declared `canonical=/foundation.html` and `og:url=/status.html`.** Every share of the page whose entire job is to state what exists today produced a card resolving to a *different page*. Both tags were individually well-formed — which is exactly why nothing caught it. | `site/foundation.html` + `tools/link-check.mjs` now compares the two on every page | ✅ no mismatch on any of 12 pages |
| 9 | BREAK | **"a reference CLI, two signed releases"** — the identical stale sentence from #3, in `foundation.html`'s meta description *and* its share card. The gate written for #3 looked only at `site/llms.txt`, and only for a parenthesised `(two signed`, so it walked past both. | `site/foundation.html` + the gate now checks every release-count claim in every `.html/.txt/.md` under `site/` | ✅ 7 claims across site/, all agreeing with the 3 real tags |
| 10 | CONFUSE | `verify.html` claimed "all **nine** checks passed" and "· 9 checks ·" while rendering **seven** rows — on the page whose whole pitch is that you can count it yourself. | count derived from the rows | ✅ 0 hardcoded "nine checks" left; rows=7 |
| 11 | CONFUSE | "the live network" / "the live record" survived in `get.html`'s `<title>` and eyebrow and throughout the `scan.html` stub, after the heading above that same panel was corrected. A title promising "live" contradicts the page under it. | titles and stub reworded to "the record" | ✅ live titles carry no "live network" claim |

### Proof for #6 — the black hole

A TCP server that accepts the connection and then says nothing, ever:

```
pre-fix   honest note NEVER APPEARED (still waiting at 25s) · mint enabled, label "Mint my passport →"
post-fix  settles in 8168 ms · "no answer from http://127.0.0.1:4999 within 8s" · mint disabled
refused   166 ms · "could not reach …"  ← the case that always worked, unregressed
```

One caveat stated rather than hidden: on the **https** production origin, an `http://` registrar URL is refused by
the browser's mixed-content rule at ~1.4 s, before the deadline is ever reached. The 8 s deadline is what covers an
`https` host that black-holes; that path is proven on the local http origin above.

### Deliberately not fixed

| What | Why |
|---|---|
| Headless Chromium repeatedly died with `ERR_INSUFFICIENT_RESOURCES` mid-walk | The **machine**, not the site: ~1.4 GB free with swap exhausted, and the "crashing" pages were nine-line meta-refresh stubs. The walking agent reached the same judgement independently. Recorded as a non-finding rather than manufactured into one. |
| `docs.html` → "Use the live network →" (link label to `get.html`) | Accurate in context: that page *is* where you point at a live network. The corrected claims were the ones asserting the **published copy** is live. |
| `@ainra/sdk` still not installable from a registry | A publish needs the maintainer's trusted-publisher setup and a tag containing the package bump — a human step, parked by design. #5 makes the docs honest about it; it does not pretend the package exists. |
| The network is not reachable by strangers | Architecture, not a defect: daemons bind `127.0.0.1`, and issuance happens at a registrar, never at the root. `get.html` says so in its own words rather than degrading silently. |

---

## Task 3 · The walk becomes a schedule

A walk done once is an anecdote. [`tools/stranger-journeys.mjs`](../../../tools/stranger-journeys.mjs) replays five
journeys against the **deployed** site, daily and on demand
([`.github/workflows/stranger.yml`](../../../.github/workflows/stranger.yml)), needing no secrets and touching nothing:

| Journey | What it refuses to let rot |
|---|---|
| `land-and-navigate` | every page loads, every internal link a stranger can click resolves |
| `lost-and-found` | the 404's own escape routes are root-absolute and work (finding #1) |
| `browse-the-record` | the record parses, is non-empty, its stamp is readable, and **every page reads the same one** (finding #2) |
| `read-and-install` | the download the docs offer actually serves (finding #4) |
| `agent-arrival` | `llms.txt`'s links resolve and its `current:` matches the newest **public** release, read from the releases API — where a stranger stands, not from our own tags (finding #3) |

**Three verdicts, kept apart on purpose.** Reaching NETWORK DOWN took a real correction: several pages link straight
into `/net`, so deleting the record also breaks links, and the first version collapsed to SITE BROKEN — meaning that
verdict could never have been reached at all, and a served-but-empty site would have been misfiled forever. Failures
are now classified by *what* is missing, not by *who* linked to it.

```
pages missing            → SITE BROKEN
pages fine, record gone  → NETWORK DOWN
production, right now    → ALL UP   (5/5 journeys)
```

It refuses to report success it did not earn: a journey that cannot complete yields `INCOMPLETE`, never ALL UP, and
CI fails on that too — a monitor that reports "we didn't look" as green is worse than no monitor. Plain HTTP, no
browser, because CI must not be able to fail this by running out of memory, which is exactly what defeated the
browser walk on this machine.

**The workflow runs its own negative control first, every run, in the same job as the real walk** — a deliberately
broken surface that must not pass. A monitor that cannot fail is not a monitor, and the only way to know this one
still can is to watch it fail right next to the green we intend to believe. First CI run:

```
negative control — a deliberately broken surface must NOT pass   ✓   VERDICT: SITE BROKEN
walk production as a stranger                                    ✓   VERDICT: ALL UP
```

`make campaign-status` carries it as a row — `PUBLIC SURFACE   checked <when> → <verdict>`. It reports the last walk
**this machine** did, never CI's (which it cannot see) and never a guess; with nothing on record it says "never
walked from this machine", not nothing and not OK.

---

### What the walk actually taught

Every one of #1–#11 was a **claim nothing checked**. Not one was a broken build, a failing test, or a crash — each
was a sentence, a link, or a number that was true once and then quietly stopped being true while a green board said
otherwise. So the fixes are paired with gates, and each gate is negative-controlled by restoring the defect and
watching the board go red:

| Gate | Now catches | Negative control |
|---|---|---|
| `tools/status-consistency.mjs` | every release-count and current-version claim across `site/`, derived from git tags | restoring "two signed releases" → 2 named failures, red |
| `tools/link-check.mjs` | `canonical` vs `og:url` disagreement on every page | restoring the mismatch → named failure, build fails |
| `tools/site-net.sh check` | the published record drifting from the running network | mutating one file → "DRIFT — site/net/registry.json differs", non-zero exit |
| `site/js/net.mjs` | any site fetch without a deadline (there is no other way to call one) | pre-fix code vs the same black hole → never settled |
