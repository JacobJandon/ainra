# AINRA — the acceptance bar (MTS §28, brief §8): a stranger clones, runs `make test && make vectors && make diff`,
# and everything is green in under 10 minutes on a laptop.
.PHONY: all test vectors vectors-check diff fmt clippy fuzz-smoke bench sdk-build sdk-test ci clean status console samples drill explorer demo scale ceremony testbed wedge-build wedge-test repro mirror verify-mirror check-freeze freeze genesis-local verifier-kit-smoke ceremony-dry-run soak-smoke drill-networked

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

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

fuzz-smoke:
	./tools/fuzz-smoke.sh

bench:
	cargo run --release -q -p ainra-vector-gen -- --bench > docs/BENCHMARKS.md
	@echo "wrote docs/BENCHMARKS.md"

sdk-build:
	cd packages/sdk-ts && [ -d node_modules ] || npm install --prefer-offline --no-audit --no-fund --silent
	cd packages/sdk-ts && npm run build

sdk-test: sdk-build
	cd packages/sdk-ts && npm test

# The full local gate mirror of .github/workflows/ci.yml.
ci: fmt clippy test vectors diff sdk-test
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
	cargo run --release -q -p ainra-services --bin scale-proof > docs/SCALE.md
	@echo "wrote docs/SCALE.md"

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

clean:
	cargo clean
	rm -rf packages/sdk-ts/node_modules packages/sdk-ts/dist build/mirror
