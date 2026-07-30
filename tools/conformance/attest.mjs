// SPDX-License-Identifier: Apache-2.0 OR MIT
// Self-attestation for the AINRA conformance programme (M24 Task 2c). The root does NOT certify implementations —
// anyone attests their OWN results with their OWN key; anyone else re-runs the runner to check. This is the exact
// SSH-Ed25519 mechanism as release signing (ssh-keygen -Y, D-042), but the signer is the IMPLEMENTER, not the root.
//
// A conformance attestation is a signed statement binding {implementation name+version, corpus_hash, report_hash,
// result, date}. It carries no root endorsement; its whole value is that it is RE-RUNNABLE — "self-attested
// conformant, re-runnable". See docs/conformance/PROGRAMME.md.
//
//   generate:  node tools/conformance/attest.mjs generate --report <report.json> --key <ssh-priv> \
//                     --identity <you@example> [--out <attestation.json>]
//   verify:    node tools/conformance/attest.mjs verify --attestation <a.json> --allowed-signers <file> \
//                     --identity <you@example> --impl "<command...>" [--report <their-report.json>]
//
// The signing namespace is `ainra-conformance` (distinct from the release namespace `file`, so signatures cannot be
// replayed across purposes). `verify` (1) checks the signature, (2) RE-RUNS the runner against the named
// implementation and confirms the fresh corpus_hash + result match the signed statement — trust the re-run, not us.

import fs from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { runConformance } from "./run.mjs";

const NAMESPACE = "ainra-conformance";
const sha256File = (p) => "sha256:" + createHash("sha256").update(fs.readFileSync(p)).digest("hex");

function parseArgs(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) o[a.slice(2)] = argv[++i];
    else o._ = a;
  }
  return o;
}

function generate(a) {
  for (const k of ["report", "key", "identity"]) {
    if (!a[k]) { console.error(`generate: missing --${k}`); process.exit(2); }
  }
  const report = JSON.parse(fs.readFileSync(a.report, "utf8"));
  if (report.result !== "pass") {
    console.error(`generate: refusing to attest a report whose result is "${report.result}" — attest a clean run only.`);
    process.exit(1);
  }
  const statement = {
    statement_version: "1",
    implementation: report.implementation,
    corpus_hash: report.corpus.hash,
    report_hash: sha256File(a.report),
    result: report.result,
    totals: report.totals,
    runner_version: report.runner_version,
    date: new Date().toISOString(),
    signer: a.identity,
    note: "self-attested conformant, re-runnable — no root certifies this; re-run the runner to check.",
  };
  const out = a.out || "attestation.json";
  fs.writeFileSync(out, JSON.stringify(statement, null, 2) + "\n");

  // Sign the statement bytes with the implementer's OWN key. ssh-keygen writes <out>.sig alongside.
  execFileSync("ssh-keygen", ["-Y", "sign", "-f", a.key, "-n", NAMESPACE, out], { stdio: ["ignore", "ignore", "inherit"] });

  // Convenience: emit an allowed_signers line (the implementer publishes this out of band; a re-checker verifies with it).
  const pub = fs.readFileSync(`${a.key}.pub`, "utf8").trim();
  const allowed = `${a.identity} namespaces="${NAMESPACE}" ${pub}\n`;
  fs.writeFileSync(`${out}.allowed_signers`, allowed);

  console.log(`  attestation → ${out}`);
  console.log(`  signature   → ${out}.sig  (SSH Ed25519 · namespace ${NAMESPACE} · signer ${a.identity})`);
  console.log(`  publish     → ${out}.allowed_signers  (your public key, for anyone to re-check)`);
  console.log(`  corpus_hash ${statement.corpus_hash}`);
  console.log(`  report_hash ${statement.report_hash}`);
}

function verify(a) {
  for (const k of ["attestation", "allowed-signers", "identity", "impl"]) {
    if (!a[k]) { console.error(`verify: missing --${k}`); process.exit(2); }
  }
  const sig = a.sig || `${a.attestation}.sig`;
  const statement = JSON.parse(fs.readFileSync(a.attestation, "utf8"));

  // Step 1 — the signature is authentic (signed by the implementer's key, this namespace, this identity).
  try {
    execFileSync("ssh-keygen", ["-Y", "verify", "-f", a["allowed-signers"], "-I", a.identity, "-n", NAMESPACE, "-s", sig], {
      input: fs.readFileSync(a.attestation),
      stdio: ["pipe", "inherit", "inherit"],
    });
  } catch {
    console.error("  ✗ REJECTED — signature did not verify (wrong key, tampered statement, or forged signature).");
    process.exit(1);
  }

  // Step 2 (optional) — the attester's report artifact is the exact one they signed.
  if (a.report) {
    const rh = sha256File(a.report);
    if (rh !== statement.report_hash) {
      console.error(`  ✗ REJECTED — report_hash mismatch: statement ${statement.report_hash}, provided report ${rh}.`);
      process.exit(1);
    }
    console.log(`  ✓ report_hash matches the signed statement (${rh})`);
  }

  // Step 3 — the CLAIM reproduces: re-run the runner against the named implementation and confirm the corpus hash
  // and result match what was signed. This is the substance — we trust the re-run, not the attester and not any root.
  const implArgv = a.impl.split(/\s+/).filter(Boolean);
  const fresh = runConformance(implArgv, { name: statement.implementation.name, version: statement.implementation.version });
  const problems = [];
  if (fresh.corpus.hash !== statement.corpus_hash)
    problems.push(`corpus_hash: signed ${statement.corpus_hash}, re-run ${fresh.corpus.hash} (different corpus)`);
  if (fresh.result !== statement.result)
    problems.push(`result: signed ${statement.result}, re-run ${fresh.result}`);
  if (fresh.result !== "pass")
    problems.push(`re-run is not a clean pass (${fresh.divergences.length} divergence(s))`);

  if (problems.length) {
    console.error("  ✗ REJECTED — the attested claim did not reproduce:");
    for (const p of problems) console.error(`      ${p}`);
    process.exit(1);
  }
  console.log(`  ✓ signature authentic (signer ${a.identity})`);
  console.log(`  ✓ re-run reproduces: corpus ${fresh.corpus.hash}  result ${fresh.result}  (${fresh.totals.passed}/${fresh.totals.checked})`);
  console.log(`  ✓ ACCEPTED — ${statement.implementation.name}@${statement.implementation.version} is self-attested conformant, and it re-ran clean here.`);
}

function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  const a = parseArgs(rest);
  if (cmd === "generate") generate(a);
  else if (cmd === "verify") verify(a);
  else {
    console.error("usage: attest.mjs <generate|verify> …  (see the header of this file)");
    process.exit(2);
  }
}

main();
