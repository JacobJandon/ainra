// SPDX-License-Identifier: Apache-2.0 OR MIT
// Example: verify a passport, then ACT only if it's valid — the pattern for an agent that must prove authority before
// doing something. Run: node examples/verify-then-act.mjs   (self-contained; placeholder operators only.)
import { readFileSync } from "node:fs";
import { Verifier } from "../packages/sdk-ts/dist/index.js";

const j = (f) => JSON.parse(readFileSync(new URL("../kits/verifier/sample-artifacts/" + f, import.meta.url), "utf8"));
const roots = j("roots.json");
const NOW = j("meta.json").now;
const verifier = Verifier.fromDirectoryB64(j("directory.json"), roots.root_ed25519, roots.root_slh);

// The action we only perform for a verified agent (here: a stand-in "release the payment" side effect).
function act(name) { console.log(`  ✓ ACTED: released the invoice for ${name}`); }

for (const file of ["bundle-valid.json", "bundle-revoked.json"]) {
  const bundle = j(file);
  const verdict = verifier.verify(bundle, NOW);
  if (verdict.verdict === "valid") {
    const claims = JSON.parse(Buffer.from(bundle.claims, "base64url").toString("utf8"));
    console.log(`${file}: VALID`);
    act(claims.sub);
  } else {
    console.log(`${file}: INVALID (${verdict.reason}) — refusing to act, failing closed`);
  }
}
