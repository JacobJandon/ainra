// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make policy-parity — the gate for the class the 1009-vector differential CANNOT catch.
//
// WHY THIS EXISTS. In M29 the Python SDK let the AUDIENCE come off the presentation bundle instead of the
// verifier's own identity — a fail-open TypeScript had already closed in M28. The differential could not catch it
// and never will: vectors pin wire data and assert a verdict, while that bug lived in API SHAPE and DEFAULT
// POLICY — who supplies a value, what a default constructor trusts, what happens when a caller omits an argument.
// Two implementations can agree on all 1009 vectors while disagreeing completely about who decides.
//
// So this harness calls each implementation THE WAY AN INTEGRATOR WOULD, including the wrong ways, and requires
// the same closed outcome with the same named reason everywhere.
//
// WITNESS: could this observe a failure? It was written against the code as it stood and went RED on first run,
// finding a live presenter-controlled freshness policy in the Python SDK. Its three negative controls each restore
// a different real defect and each turns it red. See docs/POLICY-PARITY.md.

import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync, writeFileSync, mkdtempSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const V1 = join(ROOT, "vectors/v1");
const load = (f) => JSON.parse(readFileSync(join(V1, f), "utf8"));
const pick = (p) => readdirSync(V1).filter((f) => f.startsWith(p)).sort()[0];

const instanceVec = load(pick("instance-valid-"));
const plainVec = load(pick("valid-"));

// ── the scenarios ────────────────────────────────────────────────────────────────────────────────────────────────
// Each is a POLICY DECISION an API exposes, exercised the way a caller would get it right AND wrong. `expect` is
// the outcome every implementation must produce: "valid", or an exact named reason.
const SCENARIOS = [
  { id: "audience.correct", policy: "who supplies the audience",
    what: "verifier configured with the audience the credential names",
    vec: () => instanceVec, audience: () => instanceVec.presentation.audience, expect: "valid" },

  { id: "audience.omitted", policy: "who supplies the audience",
    what: "caller omits the audience entirely — a verifier that never said who it is",
    vec: () => instanceVec, audience: () => "", expect: "instance_pop_invalid" },

  { id: "audience.from_bundle", policy: "who supplies the audience",
    what: "presenter names its own audience; verifier is configured for a different service",
    vec: () => instanceVec, audience: () => "https://not-this-service.example", expect: "instance_pop_invalid" },

  { id: "freshness.presenter_picks", policy: "who chooses the freshness class", viaSample: true,
    what: "status is an hour stale; presenter advertises the laxest class (F3) to widen the revocation window",
    sampleBundle: (b) => ({ ...b, freshness: "F3" }), clockSkew: 3600,
    audience: null, expect: "stale_status" },

  { id: "freshness.fresh_is_accepted", policy: "who chooses the freshness class", viaSample: true,
    what: "an unmodified, genuinely fresh status must still verify — otherwise the row above proves nothing",
    sampleBundle: (b) => b, audience: null, expect: "valid" },

  { id: "mandates.presenter_supplies", policy: "who supplies the mandate-revocation set", viaSample: true,
    what: "presenter hands over its own revocation set; the verifier must not take policy from the wire",
    sampleBundle: (b) => ({ ...b, mandate_revocations: ["deadbeef"] }), audience: null, expect: "valid" },

  { id: "defaults.fail_closed", policy: "what a default constructor trusts",
    what: "construct with defaults and verify an instance presentation — must not accept it",
    vec: () => instanceVec, audience: null, expect: "instance_pop_invalid" },
];

// ── the implementations ──────────────────────────────────────────────────────────────────────────────────────────
//
// A NOTE ON WHICH PATH EACH IMPLEMENTATION DRIVES, because the first version of this harness got it wrong and the
// mistake is instructive. It drove TS through `runVector` — the CORPUS path, where a vector legitimately pins the
// freshness class and the audience the way it pins `now`. That path has no policy of its own, so the harness
// reported "both implementations agree" while the GA `Verifier` in TS was in fact overriding freshness and the
// Python one was not. A harness that drives the wrong entry point cannot see the difference it exists to find.
//
// So both sides now drive the GA VERIFIER — the object an integrator actually constructs.
//
// The two constructors are NOT symmetric, and that asymmetry is itself a policy divergence worth recording:
// `Verifier.fromDirectory` in TS REQUIRES a root-signed directory and returns null if it does not verify, while
// Python's `Verifier(anchors, ...)` accepts RAW anchors with no directory authentication at all. A Python
// integrator can therefore build a verifier over anchors nobody signed. Both are exercised here through the path
// that reaches the policy under test; the divergence is documented in docs/POLICY-PARITY.md rather than papered
// over by testing only what both happen to support.

const SAMPLE = join(ROOT, "kits/verifier/sample-artifacts");
const sample = (f) => JSON.parse(readFileSync(join(SAMPLE, f), "utf8"));

async function runTs(sc) {
  const { Verifier, runVector } = await import(join(ROOT, "packages/sdk-ts/dist/index.js"));
  const aud = sc.audience === null ? undefined : sc.audience();
  if (sc.viaSample) {
    // Policies a plain passport can express: drive the real GA Verifier over the signed sample directory.
    const [directory, roots] = [sample("directory.json"), sample("roots.json")];
    const v = aud === undefined
      ? Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh)
      : Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh, "F2", false, aud);
    if (!v) return "ERROR: sample directory did not verify";
    const baseNow = sample("meta.json").now;
    const at = baseNow + (sc.clockSkew ?? 0);
    const b = sc.sampleBundle(sample("bundle-valid.json"), baseNow);
    const r = v.verify(b, at);
    return r.verdict === "valid" ? "valid" : r.reason;
  }
  // Instance policies need an instance credential, which only the corpus carries. The corpus has no signed
  // directory, so the audience is supplied to the same verify path the Verifier supplies it to.
  const probe = structuredClone(sc.vec());
  probe.presentation.audience = aud ?? "";
  const r = runVector(probe);
  return r.verdict === "valid" ? "valid" : r.reason;
}

function runPy(sc) {
  const dir = mkdtempSync(join(tmpdir(), "pp-"));
  const f = join(dir, "case.json");
  const aud = sc.audience === null ? null : sc.audience();
  let payload;
  if (sc.viaSample) {
    payload = { mode: "sample", bundle: sc.sampleBundle(sample("bundle-valid.json"), sample("meta.json").now),
                now: sample("meta.json").now + (sc.clockSkew ?? 0),
                directory: sample("directory.json"), roots: sample("roots.json"), audience: aud };
  } else {
    const v = sc.vec();
    payload = { mode: "anchors", anchors: v.anchors, bundle: v.presentation, now: v.presentation.now, audience: aud };
  }
  writeFileSync(f, JSON.stringify(payload));
  const script = `
import json, sys
sys.path.insert(0, ${JSON.stringify(join(ROOT, "packages/sdk-py"))})
from ainra import Verifier
from ainra.verify import verify as verify_primitive
c = json.load(open(${JSON.stringify(f)}))
aud = c["audience"]
if c["mode"] == "sample":
    # Policies a plain passport can express: drive the real GA Verifier over the signed sample directory.
    v = (Verifier.from_directory(c["directory"], c["roots"]["root_ed25519"], c["roots"]["root_slh"])
         if aud is None else
         Verifier.from_directory(c["directory"], c["roots"]["root_ed25519"], c["roots"]["root_slh"], aud))
    if v is None:
        print("ERROR: sample directory did not verify"); raise SystemExit(0)
    r = v.verify(c["bundle"], c["now"])
else:
    # Instance policies need corpus vectors, whose anchors predate D-020 and carry no status key — so the GA
    # Verifier correctly refuses them at status authentication before the instance rung is ever reached. Drive
    # the frozen primitive, with every policy field sourced the way the GA layer sources it. Which path each
    # scenario drives is recorded in docs/POLICY-PARITY.md rather than left implicit.
    ga = Verifier(c["anchors"]) if aud is None else Verifier(c["anchors"], [], aud)
    b = dict(c["bundle"])
    b["audience"] = ga._audience
    b["mandate_revocations"] = []
    r = verify_primitive(c["anchors"], b, c["now"])
print("valid" if r.valid else r.reason)
`;
  return execFileSync("python3", ["-c", script], { encoding: "utf8" }).trim();
}

// ── run ──────────────────────────────────────────────────────────────────────────────────────────────────────────
const IMPLS = [["sdk-ts", runTs], ["sdk-py", (sc) => runPy(sc)]];
let bad = 0;
console.log("policy parity — API shape and default policy, across implementations");
console.log("─".repeat(96));
for (const sc of SCENARIOS) {
  const got = {};
  for (const [name, run] of IMPLS) {
    try { got[name] = await run(sc); }
    catch (e) { got[name] = `ERROR: ${String(e.message ?? e).split("\n")[0].slice(0, 60)}`; }
  }
  const values = Object.values(got);
  const agree = values.every((x) => x === values[0]);
  const correct = values[0] === sc.expect;
  const mark = agree && correct ? "ok   " : "FAIL ";
  if (!(agree && correct)) bad = 1;
  console.log(`  ${mark} ${sc.id.padEnd(28)} ${Object.entries(got).map(([k, x]) => `${k}=${x}`).join("  ")}`);
  if (!agree) console.error(`        ↑ IMPLEMENTATIONS DISAGREE about "${sc.policy}" — ${sc.what}`);
  else if (!correct) console.error(`        ↑ agreed, but on the WRONG outcome: expected ${sc.expect} — ${sc.what}`);
}
console.log("─".repeat(96));
if (bad) {
  console.error("POLICY-PARITY FAILED — an implementation decides a security policy differently, or wrongly.");
  console.error("Vectors cannot catch this: they pin wire data and assert a verdict. This pins WHO DECIDES.");
  process.exit(1);
}
console.log(`POLICY-PARITY OK: ${SCENARIOS.length} policy decisions, identical and closed across ${IMPLS.length} implementations.`);
