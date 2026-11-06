<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# The AINRA conformance contract

The conformance runner (`tools/conformance/run.mjs`) drives the public corpus against **any** executable that
follows this contract. This is contract **v2** (PLAN-M50): v1's three kinds, plus the five corpora a gate, a link check
and a decision log are held to. The contract is deliberately tiny: an implementation reads vectors on stdin and prints its
verdicts on stdout. Nothing else — no files, no network, no AINRA-specific harness to link against.

## The executable

The **implementation under test** is any executable (a binary, a script, `node x.mjs`, `python3 x.py`, …). The runner
invokes it **once per corpus part**, passing the part's **kind** as the final command-line argument:

```
<your-command> <kind>
```

| profile | kinds | what passing it says |
|---|---|---|
| `core` | `passport`, `delta`, `directory` | the v1 contract: the nine-step verify, deltas, directories |
| `full` (default) | `core` plus `presentation`, `gate`, `link`, `decision`, `directory-epoch`, `currency` | also decides as a gate does: status only if the registrar signed it, a link, a decision log, no older directory |

`core` is still a valid claim, and a v1 adapter still passes it unchanged (`--profile core`). It is not the claim a
gate needs: the `core` kinds hand a verifier its status list as a trusted input, so a verifier that believes the
presenter's status passes every one of them. That is the hole of D-072, D-074 and D-075, and
`adapters/broken_status.py` is it, kept on purpose: it passes `core` and fails `full`.

- **stdin** — the runner writes that part's vectors as **JSON Lines**: one published vector object per line, exactly as
  it appears in `vectors/…` (each line carries the vector's `name`). Numbers are passed verbatim — a vector can hold a
  `u64` near 2⁶⁴, so parse integers exactly (don't round-trip through a lossy float).
- **stdout** — for each input line, print **one line**: `<name>\t<result-json>` (the vector's `name`, a TAB, then your
  verdict as JSON). Key order and insignificant whitespace do not matter; the runner canonicalises before comparing.
- **exit 0**. Read no files; open no sockets. Everything you need is on stdin.

### The result JSON, per kind

| kind | corpus | valid / accept | invalid / reject |
|---|---|---|---|
| `passport` | `vectors/v1` | `{"verdict":"valid"}` | `{"verdict":"invalid","reason":"<reason>"}` |
| `delta` | `vectors/v1-delta` | `{"accept":true}` | `{"accept":false,"reason":"<reason>"}` |
| `directory` | `vectors/v1-directory` | `{"accept":true,"registrars":<n>}` | `{"accept":false}` |
| `presentation` | `vectors/v1-presentation` | `{"ok":true,"created":<t>,"nonce":"…"}` | `{"ok":false,"reason":"<reason>"}` |
| `gate` | `vectors/v1-gate` | `{"verdict":"valid"}` | `{"verdict":"invalid","reason":"<reason>"}` or `{"verdict":"no_gate"}` |
| `link` | `vectors/v1-link` | `{"verdict":"valid","registrar","operator","passport","scope"}` | `{"verdict":"invalid","reason":"<reason>"}` or `{"verdict":"no_gate"}` |
| `decision` | `vectors/v1-decision` | `{"ok":true,"count":<n>}` or `{"ok":true,"head":"…"}` | `{"ok":false,"index":<i>,"problem":"…"}` |
| `directory-epoch` | `vectors/v1-directory-epoch` | an array, one `{"accept":true,"epoch","registrars"}` per directory offered | `{"accept":false,"refusal":"…"}` in that array |
| `currency` | `vectors/v1-currency` | an array, one `{"verdict":"valid"}` per step of ONE currency gate | `{"verdict":"invalid","reason":"<reason>"}` in that array, or `{"verdict":"no_gate"}` |

Each vector carries what it means in `description` and the exact answer in `expect`; the per-kind specifications are
`docs/PRESENTATION.md`, `docs/DECISIONS.md` (D-073, D-078, D-079, D-081, D-083) and `docs/LINKS.md`.

`<reason>` is one of the 21 frozen reason strings (`docs/reasons.json`: the 20 the verify returns, and `denied_by_policy`, which only a gate with its own policy returns, D-100). This is the SAME shape every AINRA surface
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

1. Loads the profile's corpora (the table above; `manifest.json` excluded). Point `AINRA_CONFORMANCE_ROOT` at another
   tree to check a downloaded corpus tarball.
2. **Corpus hash** — `sha256` over the sorted `\<relpath\>\0\<sha256(file-bytes)\>` lines of every vector file. This
   pins the *exact* corpus set + contents in the report, so two parties can confirm they ran the identical corpus and a
   partial/empty corpus is visibly different.
3. **Count guard (fail closed)** — every part must clear a minimum count (`passport ≥ 500`, `delta ≥ 15`,
   `directory ≥ 9`, `presentation ≥ 40`, `gate ≥ 27`, `link ≥ 40`, `decision ≥ 30`, `directory-epoch ≥ 9`,
   `currency ≥ 18`). An empty
   or partial corpus **FAILS** even with zero divergences on the vectors present — no vacuous pass (the M9
   verifier-collector lesson).
4. Streams each part to the executable, compares each verdict to the vector's recorded `expect` (the ainra-core
   verdict, already in the result shape above), and writes a machine-readable JSON **report**.

### The report

```
node tools/conformance/run.mjs --impl "<command...>" [--profile full|core] --name NAME --version VER --out report.json
```

```json
{
  "report_version": "2", "runner_version": "2", "generated_at": "…Z", "profile": "full",
  "implementation": { "name": "…", "version": "…" },
  "corpus": { "hash": "sha256:…", "parts": {"passport":…,"delta":…,"directory":…,"presentation":…,"gate":…,
              "link":…,"decision":…,"directory-epoch":…}, "total": …, "required_minimums": {…} },
  "totals": { "checked": …, "passed": …, "failed": 0 },
  "guard_failures": [], "result": "pass",
  "divergences": [ { "part": "passport", "vector": "…", "expected": {…}, "got": {…} } ]
}
```

`result` is `pass` iff the count guard is clear **and** `divergences` is empty. Exit code mirrors it. The corpus hash
covers the profile's corpora only, so a `core` and a `full` report never share one. A v1 report (`report_version`
"1", no `profile`) is a `core` report. Every failing
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
| `core.sh` | Rust core (`crates/ainra-core`) | execs `ainra-vector-gen --emit <kind>`, the functions each `--check-*` uses |
| `sdk.mjs` | TS SDK (`packages/sdk-ts`) | the `@ainra/sdk/conformance` entry from `dist`, as `make diff` runs it |
| `py.py` | Python (`packages/sdk-py`) | `ainra.conformance`, as the `make diff` fourth column runs it |
| `broken.mjs` | *deliberately broken* | a verifier that skips the validity-window check — the runner MUST catch it |
| `broken_status.py` | *deliberately broken* | the Python verifier believing the presenter's status — passes `core`, MUST fail `full` |

> The fourth reference tool, the self-contained lifecycle CLI `apps/cli-node`, is **not** a corpus adapter. It verifies
> credentials it issued into its own store; it does not implement corpus-vector verification (no SLH-DSA checkpoint
> verification, no status/Merkle/chain/mandate/name/ceiling/schema over the vector bundle format), so it cannot produce
> verdicts for these vectors. Its role in `make diff` is the **canonical-JSON encoding** cross-check, not verdicts.
> Adding vector verification to it would be a verifier-logic change, out of scope here — so it is honestly excluded
> rather than wrapped in an adapter that could not pass. The first three adapters above are the genuine corpus verifiers.
