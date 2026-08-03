<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# L2 closing board — 2026-08-03

The full preflight board from a **clean clone at HEAD** (`f9bfe02`) — the closing evidence for L2. ALL GREEN,
including `skills replay` after the fix (an illustrative intake command block in `skills.md` was ````bash`
and skills-replay runs every bash block; changed to ````sh`). Reproduce: clone, `cargo fmt --all -- --check && make preflight`.

```text
== clean clone at HEAD: f9bfe02 ==
== fmt-clean under the pinned toolchain ==
fmt: 0 diffs ✓
== make preflight (full board) ==
bash tools/preflight.sh
AINRA preflight — clone-and-it-works board
toolchain: rustc 1.96.1 (31fca3adb 2026-06-26) · v26.5.0
────────────────────────────────────────────────────────────────
  … build + tests          
  [PASS] build + tests          release test suite (68s)
  … differential           
  [PASS] differential           4 impls agree over vectors (28s)
  … conformance            
  [PASS] conformance            runner: 3 clean, broken caught (31s)
  … CLI hybrid             
  [PASS] CLI hybrid             download: Ed25519+ML-DSA both (2s)
  … genesis-local          
  [PASS] genesis-local          whole stack boots on 1 host (21s)
  … verifier kit           
  [PASS] verifier kit           execution-bound attestation (3s)
  … ceremony dry-run       
  [PASS] ceremony dry-run       witness-reproducible (27s)
  … ceremony multi         
  [PASS] ceremony multi         FROST 5-of-9 across processes (13s)
  … soak instrument        
  [PASS] soak instrument        measured p95, signed report (18s)
  … witness quorum         
  [PASS] witness quorum         fork refused over HTTP (8s)
  … S7 neutrality          
  [PASS] S7 neutrality          no brands / no impersonation (1s)
  … license headers        
  [PASS] license headers        SPDX on every source file (0s)
  … status honesty         
  [PASS] status honesty         README == STATUS claim (0s)
  … doc freeze             
  [PASS] doc freeze             normative docs unchanged (0s)
  … MCP fidelity           
  [PASS] MCP fidelity           ainra_verify ≡ SDK on vectors (4s)
  … presentation shape     
  [PASS] presentation shape     CLI≡middleware≡MCP event (25s)
  … skills replay          
  [PASS] skills replay          skills.md runs as written (8s)
  … reproducibility        
  [PASS] reproducibility        artifacts rebuild byte-exact (372s)
────────────────────────────────────────────────────────────────
  ALL GREEN — a stranger can clone this repo and every gate passes.
== BOARD EXIT: 0 ==
```
