<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# The AINRA conformance contract

The conformance runner (`tools/conformance/run.mjs`) drives the full public corpus against **any** executable that
follows this contract. The contract is deliberately tiny: an implementation reads vectors on stdin and prints its
verdicts on stdout. Nothing else — no files, no network, no AINRA-specific harness to link against.

## The executable

The **implementation under test** is any executable (a binary, a script, `node x.mjs`, `python3 x.py`, …). The runner
invokes it **once per corpus part**, passing the part's **kind** as the final command-line argument:

```
<your-command> <kind>          kind ∈ { passport, delta, directory }
```

- **stdin** — the runner writes that part's vectors as **JSON Lines**: one published vector object per line, exactly as
  it appears in `vectors/…` (each line carries the vector's `name`). Numbers are passed verbatim — a vector can hold a
  `u64` near 2⁶⁴, so parse integers exactly (don't round-trip through a lossy float).
- **stdout** — for each input line, print **one line**: `<name>\t<result-json>` (the vector's `name`, a TAB, then your
  verdict as JSON). Key order and insignificant whitespace do not matter; the runner canonicalises before comparing.
- **exit 0**. Read no files; open no sockets. Everything you need is on stdin.

### The result JSON, per kind

| kind | valid / accept | invalid / reject |
|---|---|---|
| `passport` | `{"verdict":"valid"}` | `{"verdict":"invalid","reason":"<reason>"}` |
| `delta` | `{"accept":true}` | `{"accept":false,"reason":"<reason>"}` |
| `directory` | `{"accept":true,"registrars":<n>}` | `{"accept":false}` |

`<reason>` is one of the 15 frozen reason strings (`docs/reasons.json`). This is the SAME shape every AINRA surface
already emits (`docs/PRESENTATION.md`; `ainra._vector_runner` prints exactly `<name>\t<result-json>`), so an existing
verifier needs only a thin wrapper — see `tools/conformance/adapters/`.

A minimal conformant implementation, in full:

```python
import sys, json
kind = sys.argv[1]
for line in sys.stdin:
    v = json.loads(line)
    result = my_verifier(kind, v)          # -> {"verdict": "..."} / {"accept": ...}
    print(f"{v['name']}\t{json.dumps(result)}")
```

## What the runner does

1. Loads the corpus from `vectors/v1` (passport), `vectors/v1-delta`, `vectors/v1-directory` (`manifest.json`
   excluded). Point `AINRA_CONFORMANCE_ROOT` at another tree to check a downloaded corpus tarball.
2. **Corpus hash** — `sha256` over the sorted `\<relpath\>\0\<sha256(file-bytes)\>` lines of every vector file. This
   pins the *exact* corpus set + contents in the report, so two parties can confirm they ran the identical corpus and a
   partial/empty corpus is visibly different.
3. **Count guard (fail closed)** — every part must clear a minimum count (`passport ≥ 500`, `delta ≥ 15`,
   `directory ≥ 9`). An empty or partial corpus **FAILS** even with zero divergences on the vectors present — no vacuous
   pass (the M9 verifier-collector lesson).
4. Streams each part to the executable, compares each verdict to the vector's recorded `expect` (the ainra-core
   verdict, already in the result shape above), and writes a machine-readable JSON **report**.

### The report

```
node tools/conformance/run.mjs --impl "<command...>" --name NAME --version VER --out report.json
```

```json
{
  "report_version": "1", "runner_version": "1", "generated_at": "…Z",
  "implementation": { "name": "…", "version": "…" },
  "corpus": { "hash": "sha256:…", "parts": {"passport":745,"delta":17,"directory":9}, "total": 771,
              "required_minimums": {"passport":500,"delta":15,"directory":9} },
  "totals": { "checked": 771, "passed": 771, "failed": 0 },
  "guard_failures": [], "result": "pass",
  "divergences": [ { "part": "passport", "vector": "…", "expected": {…}, "got": {…} } ]
}
```

`result` is `pass` iff the count guard is clear **and** `divergences` is empty. Exit code mirrors it. Every failing
vector is named with `expected` vs `got`, so a diverging implementation learns exactly which class it gets wrong.

## The runner is Node

Node, not Python, for the runner itself: the repo's tooling is already Node (`diff-harness`, `s7-lint`,
`license-check`, `release-attest`, the genesis board), Node is a documented toolchain dependency (`TOOLCHAIN.md`), and
the runner needs only the standard library (`node:crypto`, `node:child_process`, `node:fs`) — a stranger runs it with
zero `npm install`. The runner is language-agnostic about the *implementation*; only the ~250-line driver is Node.

## The in-repo adapters

`tools/conformance/adapters/` holds thin wrappers proving the contract against the reference implementations:

| adapter | implementation | how it verifies |
|---|---|---|
| `core.sh` | Rust core (`crates/ainra-core`) | execs `ainra-vector-gen --emit <kind>`, which runs the real core verify path |
| `sdk.mjs` | TS SDK (`packages/sdk-ts`) | `runVector` / `runDeltaVector` / `runDirectoryVector` from `dist` |
| `py.py` | Python (`packages/sdk-py`) | the same `verify` / `verify_delta_vector` / `verify_directory` as `make diff` |
| `broken.mjs` | *deliberately broken* | a verifier that skips the validity-window check — the runner MUST catch it |

> The fourth reference tool, the self-contained lifecycle CLI `apps/cli-node`, is **not** a corpus adapter. It verifies
> credentials it issued into its own store; it does not implement corpus-vector verification (no SLH-DSA checkpoint
> verification, no status/Merkle/chain/mandate/name/ceiling/schema over the vector bundle format), so it cannot produce
> verdicts for these vectors. Its role in `make diff` is the **canonical-JSON encoding** cross-check, not verdicts.
> Adding vector verification to it would be a verifier-logic change, out of scope here — so it is honestly excluded
> rather than wrapped in an adapter that could not pass. The three adapters above are the genuine corpus verifiers.
