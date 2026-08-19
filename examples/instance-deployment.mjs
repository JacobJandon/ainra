// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// THE REAL DEPLOYMENT SHAPE (ADR-019 / D-047), end to end, in one file you can run:
//
//   node examples/instance-deployment.mjs
//
// Three roles, deliberately kept in separate scopes so the boundary is visible in the code and not just in prose:
//
//   OPERATOR   holds the passport's control key. Mints a short, narrowed credential for one running copy.
//              The control key NEVER crosses into the container scope below.
//   CONTAINER  holds its own instance key and the credential it was handed. Nothing else. It proves possession
//              at presentation time.
//   SERVICE    holds a directory + root keys and ITS OWN AUDIENCE. It verifies. It is told nothing by the
//              presenter that it is willing to believe about who it is.
//
// Why this example exists: before ADR-019 the answer to "what does a running copy carry?" was "the lineage's
// private key and a bearer token good for 366 days". Everything below is the difference.
//
// Operators here are placeholder names (`acme`), per the project's neutrality rule — no real party appears.

import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
// Relative in-repo path so this runs from a clone with no install; the published form is the commented line.
import {
  INSTANCE_CRED_DEFAULT_SECS,
  instanceSigningBytes,
  popSigningBytes,
  runVector,
} from "../packages/sdk-ts/dist/index.js"; // published: import { … } from "@ainra/sdk";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const V1 = ROOT + "vectors/v1/";

// The corpus already contains a genuine, accepted instance presentation built by the vector generator with real
// hybrid keys. Using it keeps this example HONEST: every signature below is real and was produced by the same code
// path a registrar uses, rather than mocked for the demonstration.
const name = readdirSync(V1).filter((f) => f.startsWith("instance-valid-")).sort()[0];
const vec = JSON.parse(readFileSync(V1 + name, "utf8"));
const { presentation } = vec;

const line = (s = "") => console.log(s);
const b64len = (s) => `${String(s).length} chars`;

line("AINRA · the deployment shape for a running copy (ADR-019)");
line("═".repeat(78));

// ── OPERATOR ─────────────────────────────────────────────────────────────────────────────────────────────────
// What the operator has, and what it hands over. `mintInstanceCredential` is the SDK call; this example shows the
// RESULT of that call as it appears on the wire, because the signing key itself must not appear in an example.
line();
line("OPERATOR — holds the passport control key (stays here, never ships)");
{
  const ic = presentation.instance;
  line(`  passport            ${ic.sub}`);
  line(`  control key         keys[0] of the passport — NOT in the credential below`);
  line(`  mints               iid=${ic.iid}  ttl=${ic.exp - ic.nbf}s (ceiling ${INSTANCE_CRED_DEFAULT_SECS}s)`);
  line(`  narrowed to         ${JSON.stringify(ic.capabilities)}`);
  line(`  addressed to        ${ic.aud}`);
  line(`  bound to leaf       ${ic.passport_leaf.slice(0, 16)}…  (the passport's already-logged leaf)`);
  line(`  signed over         ${b64len(instanceSigningBytes(decodeIc(ic)))} of canonical bytes`);
}

// ── CONTAINER ────────────────────────────────────────────────────────────────────────────────────────────────
line();
line("CONTAINER — holds its own instance key + the credential. That is the entire inventory.");
{
  const { pop } = presentation.instance;
  line(`  instance key        the ONLY secret in here`);
  line(`  proves possession   nonce=${pop.nonce} ts=${pop.ts}`);
  line(`  signed over         ${b64len(popSigningBytes({ aud: pop.aud, nonce: pop.nonce, ts: pop.ts }))} of canonical bytes`);
  line(`  sends               the passport bundle + the instance object, in one header`);
  const header = Buffer.from(JSON.stringify(presentation)).toString("base64url");
  line(`  x-ainra-passport:   ${header.slice(0, 40)}…  (${header.length} bytes)`);
}

// ── SERVICE ──────────────────────────────────────────────────────────────────────────────────────────────────
// The service supplies its own audience and its own clock. Both are refusals waiting to happen if the presenter
// disagrees, which is the point.
line();
line("SERVICE — verifies with ITS OWN audience and clock");

function check(label, mutate) {
  const v = structuredClone(vec);
  mutate(v);
  const verdict = runVector(v);
  const mark = verdict.verdict === "valid" ? "ALLOW" : "DENY ";
  line(`  ${mark}  ${label.padEnd(46)} ${verdict.verdict === "valid" ? "" : verdict.reason}`);
  return verdict;
}

check("presented to the service it was addressed to", () => {});
check("presented to a different service", (v) => { v.presentation.audience = "https://other-service.example"; });
check("a service that has not said who it is", (v) => { v.presentation.audience = ""; });
check("the credential's window has closed", (v) => { v.presentation.instance.exp = v.presentation.now; });

line();
line("And the one that matters most — the operator revokes the PASSPORT:");
{
  const revoked = readdirSync(V1).filter((f) => f.startsWith("instance-passport-revoked-")).sort()[0];
  const rv = JSON.parse(readFileSync(V1 + revoked, "utf8"));
  const verdict = runVector(rv);
  line(`  DENY   every live copy under it dies                 ${verdict.reason}`);
  line(`         ↑ note the reason: the LINEAGE failed, not the container. A debugging integrator`);
  line(`           is sent to the passport, not to the process.`);
}

line();
line("What an attacker gets from reading this container: that copy's key, and a credential that is");
line(`narrower than the passport, expires in ${presentation.instance.exp - presentation.instance.nbf}s, works at one audience, and dies on revocation.`);
line("The lineage's key was never in here to steal.");

// The wire carries base64url; `instanceSigningBytes` wants bytes. Local, and deliberately not exported: an example
// should not grow an API surface of its own.
function decodeIc(ic) {
  const dec = (s) => Buffer.from(s, "base64url");
  return {
    sub: ic.sub, iid: ic.iid,
    ikey: { ed25519: dec(ic.ikey.ed25519), mldsa65: dec(ic.ikey.mldsa65) },
    nbf: ic.nbf, exp: ic.exp, capabilities: ic.capabilities, aud: ic.aud,
    passportLeaf: dec(ic.passport_leaf),
    sig: { ed25519: dec(ic.sig.ed25519), mldsa65: dec(ic.sig.mldsa65) },
  };
}
