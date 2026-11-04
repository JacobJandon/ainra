// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// @ainra/edge/conformance — replay the public test vectors through the edge engine.
//
// These answer what a VECTOR says: each one carries its own clock, directory and lists, which is what lets the corpus
// pin every reason. That is exactly why none of them may decide whether to trust a request — the gate in the package
// root does that, with the deployment's own directory, clock and freshness class. Keeping them here puts the
// difference in the import path, as @ainra/sdk/conformance and ainra.conformance do (D-074, D-075).
//
//   import { initAinra } from "@ainra/edge";
//   import { runGateVector } from "@ainra/edge/conformance";

import { engineReady, core } from "./_engine.mjs";

/** The same corpus entry the core runs — so a deployment can prove which engine answers it. */
export function runPresentationVector(vector) {
  if (!engineReady()) throw new Error("@ainra/edge: call initAinra(wasm) first");
  return JSON.parse(core.run_presentation_vector(JSON.stringify(vector)));
}

/** One `vectors/v1-currency` vector through the edge engine: one currency gate's life, step by step (PLAN-M51). */
export function runCurrencyVector(vector) {
  if (!engineReady()) throw new Error("@ainra/edge: call initAinra(wasm) first");
  return JSON.parse(core.run_currency_vector(JSON.stringify(vector)));
}

/** One `vectors/v1-gate` entry, answered by the core (D-073): the directory against its roots, then the bundle under
 *  the gate's policy. `{verdict:"no_gate"}` when the directory does not verify. */
export function runGateVector(vector) {
  if (!engineReady()) throw new Error("@ainra/edge: call initAinra(wasm) first");
  return JSON.parse(core.run_gate_vector(JSON.stringify(vector)));
}

/** One `vectors/v1-link` entry, answered by the core. */
export function runLinkVector(vector) {
  if (!engineReady()) throw new Error("@ainra/edge: call initAinra(wasm) first");
  return JSON.parse(core.run_link_vector(JSON.stringify(vector)));
}

/** One `vectors/v1-decision` entry, answered by the core. */
export function runDecisionVector(vector) {
  if (!engineReady()) throw new Error("@ainra/edge: call initAinra(wasm) first");
  return JSON.parse(core.run_decision_vector(JSON.stringify(vector)));
}
