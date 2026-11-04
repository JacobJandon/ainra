// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The one WASM core an isolate loads, shared by the gate (index.mjs) and the corpus runners (conformance.mjs).

import init, * as core from "../wasm/ainra_wasm.js";

export { core };

let ready = null;
/** Load the core once per isolate. `wasm` is whatever the runtime hands you for the module: a WebAssembly.Module
 *  (Workers), the bytes (Node), or a URL/Response (browsers, Deno). */
export function initAinra(wasm) {
  ready ??= init({ module_or_path: wasm });
  return ready;
}

/** The pending or settled load, or null before initAinra. */
export const engineReady = () => ready;
