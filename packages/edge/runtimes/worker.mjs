// SPDX-License-Identifier: Apache-2.0 OR MIT
// A minimal Worker-style module: the gate in front of an origin. `workerd.mjs` runs it inside the workerd runtime.
import { initAinra, createAinraEdgeGate } from "../src/index.mjs";
import wasm from "../wasm/ainra_wasm_bg.wasm";

let gate;
export default {
  async fetch(request, env) {
    await initAinra(wasm);
    gate ??= createAinraEdgeGate({ directory: env.DIRECTORY, roots: env.ROOTS, audience: "https://api.example", now: () => env.NOW });
    const g = await (await gate)(request);
    return g.allow ? new Response("forwarded to origin", { status: 200 }) : g.response;
  },
};
