<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# The Stranger Test — 2026-07-31 (L1, first public contact)

The first run of the clone-and-it-works promise from OUTSIDE: a pristine `rust:1.96` container with **no
credentials of any kind** (no `.ssh`, no `.netrc`, no hosting-CLI config) cloned the PUBLIC repository over
anonymous https and ran the full 18-row board. Reproduce it yourself — the container line is in the log.

```text
== STRANGER CONTAINER: "Debian GNU/Linux 13 (trixie)" · rustc 1.96.1 (31fca3adb 2026-06-26) ==
== no credentials: HOME has no .ssh/.netrc/.config/gh ==
ls: cannot access '/root/.ssh': No such file or directory
ls: cannot access '/root/.netrc': No such file or directory
ls: cannot access '/root/.config/gh': No such file or directory
== node v20.19.2 · python Python 3.13.5 ==
== cloning the PUBLIC URL (anonymous https) ==
== HEAD: aac68e6895a48cd0912c0feb46bba7fbe5024eb7 ==
tr: extra operand '"'
Try 'tr --help' for more information.
== tags visible:  ==
== fmt-clean under the pinned toolchain ==
info: syncing channel updates for 1.96.1-x86_64-unknown-linux-gnu
info: latest update on 2026-06-30 for version 1.96.1 (31fca3adb 2026-06-26)
info: downloading component clippy
fmt: 0 diffs ✓

== make preflight (full 18-row board) ==
bash tools/preflight.sh
AINRA preflight — clone-and-it-works board
toolchain: rustc 1.96.1 (31fca3adb 2026-06-26) · v20.19.2
────────────────────────────────────────────────────────────────
  … build + tests          
  [PASS] build + tests          release test suite (66s)
  … differential           
  [PASS] differential           4 impls agree over vectors (36s)
  … conformance            
  [PASS] conformance            runner: 3 clean, broken caught (36s)
  … CLI hybrid             
  [PASS] CLI hybrid             download: Ed25519+ML-DSA both (3s)
  … genesis-local          
  [PASS] genesis-local          whole stack boots on 1 host (23s)
  … verifier kit           
  [PASS] verifier kit           execution-bound attestation (5s)
  … ceremony dry-run       
  [PASS] ceremony dry-run       witness-reproducible (11s)
  … ceremony multi         
  [PASS] ceremony multi         FROST 5-of-9 across processes (6s)
  … soak instrument        
  [PASS] soak instrument        measured p95, signed report (4s)
  … witness quorum         
  [PASS] witness quorum         fork refused over HTTP (5s)
  … S7 neutrality          
  [PASS] S7 neutrality          no brands / no impersonation (1s)
  … license headers        
  [PASS] license headers        SPDX on every source file (0s)
  … status honesty         
  [PASS] status honesty         README == STATUS claim (0s)
  … doc freeze             
  [PASS] doc freeze             normative docs unchanged (0s)
  … MCP fidelity           
  [PASS] MCP fidelity           ainra_verify ≡ SDK on vectors (3s)
  … presentation shape     
  [PASS] presentation shape     CLI≡middleware≡MCP event (17s)
  … skills replay          
  [PASS] skills replay          skills.md runs as written (6s)
  … reproducibility        
  [PASS] reproducibility        artifacts rebuild byte-exact (361s)
────────────────────────────────────────────────────────────────
  ALL GREEN — a stranger can clone this repo and every gate passes.
== STRANGER BOARD EXIT: 0 ==
STRANGER_DONE
container-exit: 0
```

Notes for the record: the empty "tags visible" line is a quoting bug in the session's probe script (the tags are
on the remote — `git ls-remote` shows both, dereferencing to the pinned commits); the clone ran at `aac68e6`,
the public tip at clone time.
