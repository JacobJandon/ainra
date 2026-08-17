# AINRA — the acceptance bar (MTS §28, brief §8): a stranger clones, runs `make test && make vectors && make diff`,
# and everything is green in under 10 minutes on a laptop.
.PHONY: one-decode-path bench-gate all test vectors vectors-check diff cli-check suite-migration-drill ceremony-rehearsal-multi witness-check push-advisory-check changelog-board-check fmt clippy fuzz-smoke bench sdk-build sdk-test ci clean status console samples drill explorer demo scale ceremony testbed wedge-build wedge-test repro mirror verify-mirror check-freeze freeze genesis-local verifier-kit-smoke ceremony-dry-run soak-smoke drill-networked preflight s7 license gitleaks audit verify-as-external verifier-triple-drill soak-verify genesis-status verify-transcript genesis-board-demo release doctor verifier-operator-drill site site-up site-down site-check stage-all stage-all-down explorer-up explorer-down ainrascan stage-up stage-down stage-status stage-smoke demo-walkthrough three-clients genesis-verify config-diff declaration genesis-rehearsal site-demo verify issue-first registrar-console mcp-test skills-replay presentation-diff conformance campaign-status campaign-init campaign-gates campaign-check publish-preflight stage-install stage-uninstall stage-health stranger probe-drill site-net site-net-check lockfile-sync soak-ingest outreach-check names-check interop interop-negative

all: fmt clippy test vectors diff

# Rust core + workspace tests (property tests + size-conformance asserts run here).
# Release profile: SLH-DSA-SHA2-128s signing is ~seconds/op unless SHA-2 is inlined via LTO; the release build does
# that (signs in ms) AND shares its compiled artifacts with `make vectors` (also release), so the heavy compile is
# paid once for both targets — the fastest path to the <10-minute acceptance bar.
test:
	cargo test --release --workspace --all-features

# (Re)generate the CC0 conformance vectors deterministically (seeded), then verify the count.
# Release build: SLH-DSA-SHA2-128s signing is the slow FIPS variant (~seconds/op in debug); release keeps the
# whole corpus well inside the 10-minute acceptance budget.
vectors:
	cargo run --release -q -p ainra-vector-gen -- --out vectors/v1 --min 500
	cargo run --release -q -p ainra-vector-gen -- --delta-out vectors/v1-delta
	cargo run --release -q -p ainra-vector-gen -- --directory-out vectors/v1-directory
	@echo "vectors present:" && ls vectors/v1/*.json 2>/dev/null | wc -l
	@echo "delta vectors:" && ls vectors/v1-delta/*.json 2>/dev/null | wc -l
	@echo "directory vectors:" && ls vectors/v1-directory/*.json 2>/dev/null | wc -l

# Replay every vector back through ainra-core (the generator holding itself honest).
vectors-check:
	cargo run --release -q -p ainra-vector-gen -- --check vectors/v1 --min 500
	cargo run --release -q -p ainra-vector-gen -- --check-delta vectors/v1-delta
	cargo run --release -q -p ainra-vector-gen -- --check-directory vectors/v1-directory

# 3-way differential: same vectors through ainra-core, sdk-ts, and the P0 cli-node. Nonzero unless 100% agreement.
diff: sdk-build
	node tools/diff-harness/run.mjs

# M24 Task 2 — the conformance programme: the language-agnostic runner drives the FULL public corpus against ANY
# implementation. Proves BOTH ways offline — the 3 in-repo verdict impls (Rust core, TS SDK, Python) each pass CLEAN
# with the SAME corpus hash, a deliberately broken impl FAILS with named divergences, and the self-attestation
# roundtrip verifies (implementer signs own results, a re-checker re-runs). The root certifies no one. See
# docs/conformance/PROGRAMME.md + tools/conformance/CONTRACT.md.
conformance: sdk-build
	cargo build --release -q -p ainra-vector-gen
	bash tools/conformance/conformance.sh

# The DOWNLOADABLE CLI reaches the core/SDK hybrid standard: Ed25519 + ML-DSA-65 both-or-invalid, with a legacy
# credential (alg_downgrade — overlap-only) distinguished from a tampered one (sig_invalid — always closed). Runs the
# exact source that ships bundled on a live testbed (@noble resolved from the SDK install via NODE_PATH).
cli-check: sdk-build
	node tools/cli-hybrid-check.mjs

# Suite Migration Drill 01 (M23 / ADR-017 trap ii): a REAL Ed25519 → hybrid migration over a running network —
# REISSUE + prev_leaf continuity, auto-expiring policy epoch (D-037), legacy-fails / hybrid-passes — asserting every
# claim (add nothing fake). The staging half (network already hybrid, 0 stragglers) skips cleanly when staging is down.
suite-migration-drill: sdk-build
	node tools/suite-migration-drill.mjs --quiet
	node tools/staging-suite-audit.mjs

# M23 Task 3 — the DISTRIBUTABLE genesis ceremony: FROST 5-of-9 across NINE ISOLATED OS processes, every round
# message couriered through a shared postbox dir (the air-gap shape). Proves one group key emerges from nine
# independent processes, five shares threshold-sign / four cannot, and the transcript is reproducible. TEST-ROOT.
ceremony-rehearsal-multi:
	bash tools/ceremony-rehearsal-multi.sh

# M23 Task 4 — witness kit v2: single-binary witnessd from a ONE-FILE config, self-declared /meta (verified by no
# one), /root alias, bare-address back-compat, and a quorum that still refuses a fork. Times the <10-min onboarding.
witness-check:
	bash tools/witness-kit-smoke.sh

# M23 Task 5 — ADR-018 threat proof: PUSH IS ADVISORY, PULL IS SOVEREIGN. Over the real conformance vectors + the
# real sdk-ts verifier: a suppressed push still fails closed on freshness (stale_status); a forged push is ignored
# (checkpoint_invalid). Push can accelerate revocation, never subvert it.
push-advisory-check: sdk-build
	node tools/push-advisory-threat.mjs

# M23.1 — the CHANGELOG cannot claim a released version whose preflight-board evidence is absent (docs/releases/
# <version>-board.md). The claim can never outrun the proof. See RELEASING.md, "The one rule".
changelog-board-check:
	node tools/changelog-board-guard.mjs

# One target the board can call: exactly what CI gates on for style/lints, so a green board implies a green CI
# on this axis. Split out after CI failed on `cargo fmt --check` while `make preflight` reported ALL GREEN.
lint-check:
	@cargo fmt --all -- --check
	@cargo clippy --workspace --all-targets -- -D warnings

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

fuzz-smoke:
	./tools/fuzz-smoke.sh

bench:
	cargo run --release -q -p ainra-vector-gen -- --bench > docs/BENCHMARKS.md
	@echo "wrote docs/BENCHMARKS.md"

# The site claims verification takes milliseconds. This makes that claim a gate, using the measurement we
# already produce — no third-party service, no new dependency, no vendor in the path of our own proof.
bench-gate: bench
	@node tools/bench-gate.mjs

sdk-build:
	cd packages/sdk-ts && [ -d node_modules ] || npm install --prefer-offline --no-audit --no-fund --silent
	cd packages/sdk-ts && npm run build

sdk-test: sdk-build
	cd packages/sdk-ts && npm test

# The full local gate mirror of .github/workflows/ci.yml.
ci: fmt clippy lockfile-sync soak-ingest test vectors diff conformance cli-check suite-migration-drill ceremony-rehearsal-multi witness-check push-advisory-check changelog-board-check sdk-test site site-check
	node tools/s7-lint.mjs
	node tools/license-check.mjs
	./tools/fuzz-smoke.sh
	@grep -rnE "std::net|std::fs|reqwest|tokio|SystemTime|Instant|std::env" crates/ainra-core/src/ && (echo "ainra-core must be pure (N7)"; exit 1) || echo "no-network: ainra-core clean"
	@echo "== CI local pass =="

# Local test console: passport book viewer + LIVE verify API (real sdk-ts verifier + tamper switches).
console: sdk-build samples
	node apps/console/server.mjs

# M3 registrar explorer: build the fictional registry (real crypto + real verdicts) and serve the explorer.
explorer:
	cargo run --release -q -p ainra-cli-rs -- seed apps/registrar-explorer/data
	@echo "serving http://127.0.0.1:8099/  (Ctrl-C to stop)"
	cd apps/registrar-explorer && python3 -m http.server 8099

# The M3 end-to-end lifecycle demo (issue → verify → revoke → re-verify), one process, real crypto.
demo:
	cargo run --release -q -p ainra-cli-rs -- demo

# M16 — the sixty-second VERIFY path: one command, no account/server/config. Verifies bundled sample credentials
# ROOT DARK (LOCAL TESTBED); set AINRA_NET=http://host:8091 to verify a live network's public record (STAGING·TEST-ROOT).
verify: sdk-build
	@node tools/verify-60s.mjs

# M16 — the five-minute ISSUE path: boot a LOCAL registrar, issue your first passport, verify it, keep the registrar.
issue-first:
	@bash tools/issue-first.sh

# M16 — the MCP server's wrapper-fidelity differential: ainra_verify ≡ @ainra/sdk byte-for-byte over sampled vectors,
# plus safety-annotation + confirm-gate checks. Proves the MCP verify tool stays a thin wrapper, never a fork.
mcp-test: sdk-build
	node --test packages/mcp/test/*.test.mjs

# M16 — the one-verdict-event-shape differential: the `ainra` CLI (Rust), the middleware, and the MCP server all
# serialize the SAME verdict event byte-identically over a seeded registry (docs/PRESENTATION.md). Fails on any drift.
presentation-diff: sdk-build wedge-build
	cargo build --release -q -p ainra-cli-rs
	node tools/presentation-diff.mjs

# M16 — replay skills.md end to end: prove the agent-onboarding file is executable exactly as written (CI gate).
skills-replay: sdk-build
	@bash tools/skills-replay.sh

# M16 — the OPEN registrar console (neutral open-core, D-034): start a registrar-in-a-box and serve its lifecycle UI.
# Also served by every staging registrar at /console. DIR/PORT/ID override; write path is open locally, token on staging.
registrar-console:
	cargo build --release -q -p ainra-services --bin registrar-box
	@echo "→ open the registrar console:  http://127.0.0.1:$(or $(PORT),4899)/console   (Ctrl-C to stop)"
	@AINRA_STAGE=1 ./target/release/registrar-box 127.0.0.1:$(or $(PORT),4899) $(or $(ID),registrar-07) $(or $(DIR),stage/console-registrar)

# The M4 genesis ceremony rehearsal: FROST 5-of-9 DKG + SLH-DSA dual root → signed directory → mint+verify a real
# passport → revoke the delegate (passport goes checkpoint_invalid) → rotate (VALID again) → replayable transcript.
ceremony:
	cargo run --release -q -p ainra-ceremony --bin ceremony -- ceremony-out

# M5 the wedge: compose the LIVE registrar-box + ceremony `accredit` + the 5-line `ainra-verify` step end to end —
# issue → present bundle → VALID; revoke → INVALID; + verify-latency. Proves local, offline, ~5-line verification.
testbed:
	bash tools/testbed.sh

# M5 build the verifier SDK + middleware packages (the npm wedge a verifier estate installs).
wedge-test: wedge-build
	cd packages/middleware && npm test

wedge-build: sdk-build
	cd packages/middleware && [ -d node_modules ] || npm install --prefer-offline --no-audit --no-fund --silent
	cd packages/middleware && npm run build

# The billion-device scale proof: builds a REAL 1-billion-lineage status list, 16M-leaf RFC 6962 trees, sharded
# issuance — measures everything and writes the honest report (measured vs structural, labeled).
scale:
	bash tools/scale.sh

# The M2 transparency pipeline end-to-end (logd → witness catches an injected fork → statusd), in-process.
drill:
	cargo run --release -q -p ainra-services --bin pipeline-demo

# Regenerate the illustrative sample passports (real crypto) + render the 3-side book SVGs.
samples:
	cargo run --release -q -p ainra-core --example sample_passport -- valid     > samples/data/sample-valid.json
	cargo run --release -q -p ainra-core --example sample_passport -- delegated > samples/data/sample-delegated.json
	cargo run --release -q -p ainra-core --example sample_passport -- revoked   > samples/data/sample-revoked.json
	node tools/render-samples.mjs

status:
	@cat docs/STATUS.md

# M8 — boot the whole AINRA world on one laptop (MTS §29 / N9): ceremony → 2 registrars → issue+log → external
# verify → revoke → forged rejected → witness-quorum fork caught → transcript. Artifacts land in genesis-out/.
genesis-local:
	bash tools/genesis-local.sh "$(or $(OUT),genesis-out)"

# M9 — External Verifier Kit smoke: a stranger verifies root-dark + rejects revoked/forged with ONLY the
# published @ainra/sdk, and emits a signed attestation we collect without trusting them.
verifier-kit-smoke:
	bash tools/verifier-kit-smoke.sh

# M10 — the ONE command a stranger runs to become external verifier #N (CHALLENGE=<dir the maintainer sent>).
verify-as-external:
	bash tools/verify-as-external.sh

# M10 — the §29 "≥3 external verifiers" flow at smoke scale: 3 distinct challenges → 3 distinct execution-bound
# attestations accepted, a hand-authored one rejected. A dry run (simulated on one host) — proves the machinery.
verifier-triple-drill:
	bash tools/verifier-triple-drill.sh

# M11 — the OPERATOR loop for real external verifiers: mint per-party → party verifies → check → durable evidence →
# `make genesis-status` counts it. 3 dry-run parties (not counted) + a forgery rejected. See kits/verifier/OPERATOR.md.
verifier-operator-drill:
	bash tools/verifier-operator-drill.sh

# M9 — Ceremony dry-run: rehearse the operator choreography on N 'machines', run the real dual-root ceremony
# (TEST-ROOT), and an independent witness recomputes the transcript hash + verifies every custodian; fails loud.
ceremony-dry-run:
	bash tools/ceremony-dry-run.sh $(or $(N),5)

# M10 — an outsider recomputes a PUBLISHED ceremony transcript's hash from public bytes alone (TRANSCRIPT=, SHA256=).
verify-transcript:
	node kits/ceremony/verify-transcript.mjs --transcript "$(or $(TRANSCRIPT),transcript.json)" --sha256 "$(or $(SHA256),transcript.sha256)" $(if $(CHECKLIST),--checklist "$(CHECKLIST)",)

# M9 — Soak instrument smoke: real registrar, issue+revoke, measure propagation from 3 vantage points into a
# hash-chained log, signed report + SLO flag (fail closed). Real soak = same instrument, --duration-sec + regions.
soak-smoke:
	bash tools/soak-smoke.sh $(or $(CYCLES),20)

# M10 — re-check a FINISHED soak run's signature + tamper-evident structure (OUT=<dir>). Add SLO=60 CHALLENGE=<n> to gate.
soak-verify:
	bash tools/soak-verify.sh

# M9 — Networked witness quorum (D-021 transport): N witnessd processes over HTTP; relying party collects
# cosignatures + refuses a fork; k stays the relying party's argument.
drill-networked:
	bash tools/drill-networked.sh $(or $(N),5) $(or $(K),3)

# M7 — reproducibility + mirrors + docs freeze.
# Prove the published artifact set rebuilds byte-for-byte (twice, and == committed); emit MANIFEST.sha256.
repro:
	bash tools/repro.sh

# Assemble a mirror directory from the published artifacts (OUT=dir, default build/mirror).
mirror:
	bash tools/mirror.sh "$(or $(OUT),build/mirror)"

# Byte-verify a mirror directory against MANIFEST.sha256 (MIRROR=dir). Fail-closed on any differing byte.
verify-mirror:
	bash tools/mirror-verify.sh "$(or $(MIRROR),build/mirror)"

# Docs freeze: hash the canonical spec/plan docs into docs/FREEZE.sha256.
freeze:
	bash tools/freeze.sh write

# Fail if any frozen doc drifted from docs/FREEZE.sha256.
check-freeze:
	bash tools/freeze.sh check

# M11 — cut a VERIFIABLE release: refuse a dirty tree / red preflight, re-check reproducibility, build the reference
# CLI, write a signable SHA256SUMS manifest (VERSION=vX.Y.Z). The public counterpart to reproducible builds.
release:
	bash scripts/release.sh

# M10 — the honest DoD board: ingest collected verifier attestations + ceremony transcript + soak reports, verify each,
# render the §29 table (✅ only with a valid artifact). EVIDENCE=<dir> (default genesis-evidence/ — absent = all ⏳).
genesis-status:
	node tools/genesis-board/board.mjs $(if $(EVIDENCE),--evidence "$(EVIDENCE)",)

# M10 — prove the board: real evidence (3 attestations + ceremony + soak) drives rows to ✅, soak stays honest, fakes refused.
genesis-board-demo:
	bash tools/genesis-board/demo.sh

# L3 — the human half. The three real-world DoD rows move only when strangers act; this is the schedule for asking
# them, the tracker (LOCAL — people never enter this repo, D-036), and an honest scoreboard read from the registries.
# It can read every row and move none of them. campaign/README.md.
campaign-status:
	@node tools/campaign.mjs status
campaign-init:
	@node tools/campaign.mjs init
campaign-gates:
	@node tools/campaign.mjs gates
campaign-check:
	@node tools/campaign.mjs check

# L3 — everything that can be checked before the maintainer pastes an npm/PyPI token. Publishes NOTHING, holds no
# credentials: versions agree, each package packs, the packed artifact installs into a throwaway env and verifies a
# real vector, no local file: deps. Prints the exact publish commands when it is green.
publish-preflight:
	@bash tools/publish-preflight.sh

# M11 — check a newcomer's environment against TOOLCHAIN.md before they waste an hour on a cryptic error.
doctor:
	bash tools/doctor.sh

# M11+ — build the public static site (site/): refresh its derived downloads from canonical sources. SERVE=1 to serve.
site:
	bash tools/site.sh
site-up:
	bash tools/site.sh up
site-down:
	bash tools/site.sh down
site-check:
	node tools/site-includes.mjs --check
	node tools/link-check.mjs

# M17 — the full staging deploy profile: network (registrars + witness + artifacts + console) + site + explorer, one cmd.
stage-all:
	$(MAKE) stage-up
	$(MAKE) site-up
	$(MAKE) explorer-up
	@echo ""
	@echo "  AINRA STAGING · GENESIS ROOT — FULL DEPLOY:"
	@echo "    site        http://127.0.0.1:8088/            (make site-down)"
	@echo "    demo        http://127.0.0.1:8088/demo.html"
	@echo "    public API  http://127.0.0.1:8091/            (CORS · X-AINRA-Network: staging)"
	@echo "    console     http://127.0.0.1:4907/console"
	@echo "    AINRAscan   http://127.0.0.1:8090/?net=http://127.0.0.1:8091"
	@echo "    → make stage-all-down stops everything"
explorer-up:
	bash tools/explorer.sh up
explorer-down:
	bash tools/explorer.sh down
stage-all-down:
	$(MAKE) site-down
	$(MAKE) explorer-down
	$(MAKE) stage-down
	@echo "full staging deploy stopped."

# The independent AINRAscan explorer, built against a real seeded network + the real SDK bundled for the browser.
ainrascan:
	bash tools/ainrascan.sh

# The AINRA STAGING network on one host (real deployment, real crypto, TEST-ROOT, honest labels).
stage-up:
	bash tools/stage.sh up
stage-down:
	bash tools/stage.sh down
stage-status:
	bash tools/stage.sh status
stage-smoke:
	bash tools/stage-smoke.sh

# M17 Task 2 — headless full-lifecycle walkthrough against the live public demo door (needs `make stage-up`).
demo-walkthrough:
	node tools/demo-walkthrough.mjs

# M17 Task 4 — prove 'any agent': the full lifecycle through 3 independent clients (HTTP/MCP/curl). Needs stage-up.
three-clients:
	node tools/three-clients.mjs

# M19 — prove the LIVE network runs under the real genesis root (root-dark verify against the published
# dual-root-signed directory + roots). Needs `make stage-up`.
genesis-verify:
	node tools/genesis-verify.mjs

# Genesis (M15): production≡staging parity gate · the fail-closed founding-declaration pipeline · the dress rehearsal.
config-diff:
	node tools/config-diff.mjs
declaration:
	node tools/declaration.mjs $(if $(EVIDENCE),--evidence "$(EVIDENCE)",)
genesis-rehearsal:
	bash tools/genesis-rehearsal.sh

# M10 — the "clone it and it works" promise: run every gate a stranger runs, print a green/red board (QUICK=1 skips repro).
preflight:
	bash tools/preflight.sh

# S7 neutrality: no product impersonation in fixtures/code + no commercial-brand names in public prose or commit messages.
# L5 — exactly ONE Rust path turns external bytes into core verify types (crates/ainra-adapter).
# A duplicate parser is how a verifier quietly stops agreeing with itself; this fails the build if one appears.
one-decode-path:
	@node tools/one-decode-path.mjs

s7:
	node tools/s7-lint.mjs

# Every authored source file carries the dual-license SPDX header.
license:
	node tools/license-check.mjs

# Secret scan over the FULL git history (config .gitleaks.toml allowlists only the CC0 vector public keys). Needs gitleaks.
gitleaks:
	gitleaks detect --source . --config .gitleaks.toml --no-banner --redact

# M10 — publish-readiness audit: neutral + licensed + zero secrets in history. See docs/PUBLISH-AUDIT.md.
audit: s7 license gitleaks
	@echo "AUDIT OK — neutral, licensed, no secrets in history"

clean:
	cargo clean
	rm -rf packages/sdk-ts/node_modules packages/sdk-ts/dist build/mirror

# M16+ — refresh the public site's in-browser demo assets (the real SDK bundle + a real seeded registry).
# The site is fully static and self-contained; these two derived files make demo.html verify in any browser.
site-demo: ainrascan
	cp ainrascan/vendor/ainra-sdk.js site/vendor/ainra-sdk.js
	cargo run --release -q -p ainra-cli-rs -- seed site/data
	@rm -rf site/data/registrar-*
	@echo "stripped site/data/registrar-* — the browser demo reads only registry.json; registrar key-seed material must never ship"
	@echo "site/demo.html is ready — open site/index.html → 'Try it live'"

# ── L5: the browser surface ────────────────────────────────────────────────────────────────────────────────
wasm: ## build the browser verifier into site/assets/wasm (size ceiling enforced)
	@bash tools/build-wasm.sh

wasm-diff: wasm ## run the FULL conformance corpus through the WASM in a headless browser; must be N/N
	@node tools/wasm-differential.mjs

wasm-diff-negative: wasm ## prove the browser differential can fail (one flipped signature bit)
	@NEGATIVE_CONTROL=1 node tools/wasm-differential.mjs && (echo "NEGATIVE CONTROL DID NOT FAIL"; exit 1) || echo "negative control OK: the harness reports mismatches."


# M26 (d) — freshly-signed material checked by two INDEPENDENT ML-DSA implementations (noble + OpenSSL).
interop: sdk-build ## cross-implementation interop on material that has never existed before
	@node tools/interop-verify.mjs

interop-negative: sdk-build ## prove the interop harness can fail (one corrupted signature byte)
	@NEGATIVE_CONTROL=1 node tools/interop-verify.mjs && (echo "NEGATIVE CONTROL DID NOT FAIL"; exit 1) || echo "negative control OK: corruption is caught."

# M27 — the staging network as a STANDING service: systemd user units, restart-on-failure, start-on-boot,
# journal logging, and a watchdog that probes the public contract. Honest claim: runs whenever this machine is
stranger:        ## walk the DEPLOYED site as a stranger — SITE BROKEN / NETWORK DOWN / ALL UP
	@node tools/stranger-journeys.mjs $(if $(BASE),--base $(BASE),)

lockfile-sync:   ## every committed lockfile must state its package's version
	@node tools/lockfile-sync.mjs

soak-ingest:     ## the declaration must read what kits/soak/soak.mjs actually writes
	@node tools/soak-ingest-check.mjs

outreach-check:  ## packets say only what is true today (LOCAL — outreach/ready/ is gitignored, D-036)
	@node tools/outreach-check.mjs

names-check:     ## no tracked candidate's name may appear in any git-tracked file (LOCAL, D-036)
	@node tools/names-check.mjs

# D-046 — measure a registrar's accreditation invariants from OUTSIDE, holding nothing it issued, and prove the
# instrument can observe a dishonest one (four sabotage controls). Compliance by self-report is compliance until
# the day it isn't.
probe-drill:     ## the compliance probe: passes an honest registrar, catches four dishonest ones
	bash tools/probe-drill.sh

site-net:        ## publish the running network's read contract into site/net/ and stamp when
	bash tools/site-net.sh publish

site-net-check:  ## is the committed site/net/ still byte-identical to what the network serves?
	bash tools/site-net.sh check

# on — it binds 127.0.0.1, so it is not reachable from the internet.
stage-install:   ## install the staging network as user services (survives logout + reboot)
	@bash tools/stage-install.sh install
stage-uninstall: ## remove the units (state in stage/ is left alone)
	@bash tools/stage-install.sh uninstall
stage-health:    ## probe the public read contract + unit state; exits non-zero when degraded
	@bash tools/stage-install.sh health
