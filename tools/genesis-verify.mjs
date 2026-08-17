// SPDX-License-Identifier: Apache-2.0 OR MIT
// M19 — prove the LIVE network runs under the real genesis root. Fetch the dual-root-SIGNED directory + roots from
// the public contract, fetch a live passport, and verify it ROOT-DARK: trust only the root keys, chain the directory
// to them, then the passport to the accredited registrar. Fails closed if the directory isn't root-signed or the
// passport doesn't chain. Negative control: a tampered root must reject the directory. Needs `make stage-up`.
import { Verifier } from "../packages/sdk-ts/dist/index.js";

const ART = process.env.AINRA_ART || "http://127.0.0.1:8091";
const REG = process.env.AINRA_REG || "http://127.0.0.1:4907";
const NOW = Number(process.env.AINRA_NOW || 1776729600);
const SUB = process.env.AINRA_SUB || "ainra:registrar-07:acme:invoicing@4.2.1";
const j = async (u) => (await fetch(u)).json();

const main = async () => {
  const directory = await j(`${ART}/directory.json`).catch(() => null);
  const roots = await j(`${ART}/roots.json`).catch(() => null);
  if (!directory || !roots?.root_ed25519) { console.error("  ✗ no genesis directory/roots on the contract — run: make stage-up"); process.exit(2); }
  const fp = roots.root_ed25519.slice(0, 16);
  console.log(`AINRA genesis-root verification · ${ART} · root ${fp}…\n`);

  const verifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh);
  if (!verifier) { console.log("  ✗ the published directory is NOT signed by the published roots"); process.exit(1); }
  console.log("  ✓ directory is dual-root-signed by the published genesis root");

  // A FETCH failure is not a VERIFICATION verdict, and conflating the two is how this target spent days reporting
  // "INVALID:schema_violation" for a passport that simply did not exist on the running registrar. The verifier was
  // being handed {"error":"unknown subject"} and dutifully rejecting it as malformed — a true statement about the
  // bytes and a completely misleading statement about the network. Separate the two before verifying anything.
  const bundle = await j(`${REG}/present?sub=${encodeURIComponent(SUB)}&now=${NOW}`).catch((e) => ({ error: String(e) }));
  if (!bundle || bundle.error || !bundle.presentation) {
    console.log(`  ✗ ${SUB} could NOT BE FETCHED from the registrar: ${bundle?.error ?? "no presentation in response"}`);
    console.log(`     This is a NETWORK/STATE problem, not a cryptographic one — the registrar does not have this`);
    console.log(`     subject. If the published record lists it, the registrar has regressed behind the record.`);
    console.log(`     Check: curl ${ART}/registry.json | grep sub    ·    make stage-health`);
    process.exit(1);
  }
  const v = verifier.verify(bundle, NOW);
  const ok = v.verdict === "valid";
  console.log(`  ${ok ? "✓" : "✗"} ${SUB} verifies ROOT-DARK → ${v.verdict.toUpperCase()}${v.reason ? ":" + v.reason : ""}`);

  const bad = [...roots.root_ed25519].reverse().join("");
  const rejected = !Verifier.fromDirectoryB64(directory, bad, roots.root_slh);
  console.log(`  ${rejected ? "✓" : "✗"} a wrong root rejects the directory (fails closed)`);

  console.log(ok && rejected
    ? `\n✓ the live network runs under a REAL genesis root — passports chain to it, root-dark, trusting only the root`
    : `\n✗ genesis-root verification failed`);
  process.exit(ok && rejected ? 0 : 1);
};
main().catch((e) => { console.error("genesis-verify error:", e.message); process.exit(2); });
