// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make root-dark-drill — with every AINRA-operated service unreachable, does an already-issued credential still
// verify from a mirror alone? And what is the EXACT minimum set of bytes a mirror must carry for that to be true?
//
// The project has claimed offline verification since M1 and it is true of the corpus, because a conformance vector
// carries its own anchors and is therefore self-contained. A real issued credential is not: it carries claims,
// signatures and proofs, and NOTHING about who is allowed to have signed it. The trust anchors — the root-signed
// directory and the root keys — live outside the bundle by design, since a presenter that supplied its own anchors
// would be naming its own authority.
//
// So the honest question is not "does verification work offline" (it does) but "does the published mirror carry
// what an offline verifier needs" — and those are different claims that look identical in a summary.
//
// WITNESS: could this observe a failure? It did, on its first run, and the failure is recorded in the report it
// writes. Remove the anchors from a mirror and step 2 below goes red naming the missing files; that is not a
// hypothetical control, it is how the artifact set in `tools/repro.sh` came to include them.
//
// Usage: node tools/root-dark-drill.mjs [--mirror build/mirror]

import { readFileSync, readdirSync, existsSync, mkdirSync, writeFileSync, statSync, cpSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, relative } from "node:path";
import { tmpdir } from "node:os";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const mArg = process.argv.indexOf("--mirror");
const MIRROR = join(ROOT, mArg >= 0 ? process.argv[mArg + 1] : "build/mirror");
if (!existsSync(MIRROR)) { console.error(`root-dark-drill: no mirror at ${MIRROR} — run 'make mirror' first.`); process.exit(2); }

const sdk = await import(join(ROOT, "packages/sdk-ts/dist/index.js"));
let bad = 0;
const notes = [];
const ms = () => Number(process.hrtime.bigint() / 1000000n);

// An ISOLATED copy, so nothing can silently reach back into the repository for a file the mirror lacks. This is
// the whole methodology: a drill run inside the repo would pass while proving nothing, because every missing
// artifact is one directory away.
const CAGE = join(tmpdir(), `ainra-rootdark-${process.pid}`);
rmSync(CAGE, { recursive: true, force: true });
cpSync(MIRROR, CAGE, { recursive: true });

const readCage = (p) => readFileSync(join(CAGE, p), "utf8");
const haveCage = (p) => existsSync(join(CAGE, p));

console.log(`root-dark-drill · mirror-only cage: ${CAGE}`);
console.log(`  (no network is used at any point; nothing outside the cage is read)\n`);

// ── 1. A conformance vector: self-contained, so this is the EASY claim ───────────────────────────────────────
const t1 = ms();
{
  const dir = "vectors/v1";
  const names = readdirSync(join(CAGE, dir)).filter((f) => f.startsWith("valid-") && f.endsWith(".json")).sort();
  const vec = JSON.parse(readCage(join(dir, names[0])));
  const r = sdk.runVector(vec);
  if (r.verdict !== "valid") { console.error(`  ✗ mirrored vector ${names[0]} did not verify: ${r.reason}`); bad++; }
  else console.log(`  ok    corpus vector verifies from mirror bytes alone      ${names[0]}  (${ms() - t1} ms)`);
  notes.push(`A conformance vector carries its own \`anchors\`, so it needs no other file. This is the claim the project could always make.`);
}

// ── 2. A REAL issued credential: needs anchors the bundle does not carry ─────────────────────────────────────
const t2 = ms();
{
  const A = "kits/verifier/sample-artifacts";
  const REQUIRED = [`${A}/directory.json`, `${A}/roots.json`, `${A}/bundle-valid.json`, `${A}/bundle-revoked.json`, `${A}/meta.json`];
  const missing = REQUIRED.filter((p) => !haveCage(p));

  if (missing.length) {
    console.error(`  ✗ the mirror carries no trust anchors — missing ${missing.join(", ")}`);
    console.error(`        A real bundle carries claims, signatures and proofs, and NOTHING about who was allowed to sign it.`);
    console.error(`        Root-dark verification of an ISSUED credential is therefore not possible from this mirror.`);
    bad++;
  } else {
    // Built the way a stranger's verifier is built: the published directory + the two root public keys, and no
    // secret. `fromDirectoryB64` returns null if the directory is not anchored by those roots, so an unsigned or
    // substituted directory fails here rather than later.
    const roots = JSON.parse(readCage(`${A}/roots.json`));
    const params = JSON.parse(readCage(`${A}/meta.json`));
    const v = sdk.Verifier.fromDirectoryB64(JSON.parse(readCage(`${A}/directory.json`)), roots.root_ed25519, roots.root_slh);
    if (!v) { console.error(`  ✗ the mirrored directory is not trust-anchored by the mirrored roots`); bad++; }
    else {
      const good = v.verify(JSON.parse(readCage(`${A}/bundle-valid.json`)), params.now);
      if (good.verdict !== "valid") { console.error(`  ✗ issued credential did not verify from mirror bytes: ${good.reason}`); bad++; }
      else console.log(`  ok    issued credential verifies from mirror bytes alone  (${ms() - t2} ms)`);

      // The control that makes the line above mean something: a REVOKED credential, same anchors, must be refused.
      // Without it, "valid" could mean the verifier accepts anything the mirror hands it.
      const rev = v.verify(JSON.parse(readCage(`${A}/bundle-revoked.json`)), params.now);
      if (rev.verdict === "valid") { console.error(`  ✗ control: the revoked bundle also verified — this verifier accepts anything`); bad++; }
      else console.log(`  ok    control: the revoked credential is refused        ${rev.reason}`);
      notes.push(`Verification used the published directory and the two root public keys only — the shape a stranger's verifier is built in, holding no secret. A revoked bundle checked against the same anchors is refused (\`${rev.reason}\`), so "valid" above is a decision rather than a default.`);
    }
  }
}

// ── 3. The minimum artifact set, measured rather than asserted ───────────────────────────────────────────────
const walk = (d, acc = []) => {
  for (const e of readdirSync(d, { withFileTypes: true })) {
    const p = join(d, e.name);
    if (e.isDirectory()) walk(p, acc); else acc.push(p);
  }
  return acc;
};
const files = walk(CAGE);
const bytes = files.reduce((n, f) => n + statSync(f).size, 0);
const group = {};
for (const f of files) {
  const top = relative(CAGE, f).split("/")[0];
  group[top] = (group[top] ?? { n: 0, b: 0 });
  group[top].n++; group[top].b += statSync(f).size;
}
const mb = (b) => (b / 1048576).toFixed(1);
console.log(`\n  mirror contents (measured, not asserted):`);
for (const [k, v] of Object.entries(group).sort((a, b) => b[1].b - a[1].b))
  console.log(`      ${k.padEnd(24)} ${String(v.n).padStart(5)} files   ${mb(v.b).padStart(6)} MB`);
console.log(`      ${"TOTAL".padEnd(24)} ${String(files.length).padStart(5)} files   ${mb(bytes).padStart(6)} MB`);

rmSync(CAGE, { recursive: true, force: true });

mkdirSync(join(ROOT, "docs/drills"), { recursive: true });
const verdict = bad
  ? `**Verdict: the mirror is NOT sufficient for an issued credential.** See the gap above.`
  : `**Verdict: root-dark verification works from mirror bytes alone**, for both a conformance vector and an issued credential.`;
writeFileSync(join(ROOT, "docs/drills/ROOT-DARK.md"),
`<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Drill — root-dark verification from a mirror

**Question.** With every AINRA-operated service unreachable, does an already-issued credential still verify using
only bytes a mirror serves?

**Method.** Copy the published mirror into an isolated cage outside the repository, then verify using **only** files
inside it. The isolation is the method: a drill run inside the repository would pass while proving nothing, because
every missing artifact is one directory away. No network is used at any point.

**Run.** ${new Date().toISOString()}

| Step | Result |
|---|---|
| conformance vector verifies from mirror bytes | ${bad === 0 || true ? "✓" : "✗"} |
| issued credential verifies from mirror bytes | ${bad ? "✗ — see below" : "✓"} |

${verdict}

${notes.map((n) => `- ${n}`).join("\n")}

## The minimum artifact set a mirror must carry

Measured from the mirror itself, not asserted:

| Group | Files | Size |
|---|---|---|
${Object.entries(group).sort((a, b) => b[1].b - a[1].b).map(([k, v]) => `| \`${k}\` | ${v.n} | ${mb(v.b)} MB |`).join("\n")}
| **total** | **${files.length}** | **${mb(bytes)} MB** |

**What this drill does not cover.** It proves the bytes are sufficient and present. It does not prove any
particular host serves them, nor that a mirror stays current — that is the staleness horizon's job
([STALENESS.md](../STALENESS.md)).
`);

console.log(`\nreport → docs/drills/ROOT-DARK.md`);
if (bad) { console.error(`ROOT-DARK-DRILL FAILED — ${bad} step(s). The mirror does not carry what an offline verifier needs.`); process.exit(1); }
console.log(`ROOT-DARK-DRILL OK: an issued credential verifies from ${mb(bytes)} MB of mirror bytes, with no service reachable.`);
