#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make personhood-live — the personhood kit against the REAL chain (D-066). Needs the network; not part of CI.
//
//   1. take the most recent AgentRegistered event from a public block explorer — an agent a real person registered;
//   2. ask the registry ourselves (our own eth_call, pinned to a block) and require the SAME human id the event
//      carries: two independent sources, one answer;
//   3. a fresh wallet nobody registered must come back NOT human-backed, from the same chain;
//   4. the full binding path for that fresh wallet must refuse `not_human_backed` — a real answer, not a stub;
//   5. an unreachable RPC must be `lookup_failed`, never "not registered".
//
// What it cannot do, said plainly: finish the positive binding path live. That needs the private key of a wallet a
// verified human registered, and we hold none — no one here has been through the registry's verification. The
// binding is proven offline in test/ with vectors from other implementations; this proves the chain half is real.

import { randomBytes } from "node:crypto";
import { lookupHuman, provePersonhood, bindingMessage, signPersonal, addressFromPrivateKey, checksumAddress, holderThumbprint, SOURCES } from "./personhood.mjs";

const SRC = SOURCES["agentbook-worldchain"];
const EXPLORER = process.env.AINRA_EXPLORER ?? "https://worldchain-mainnet.explorer.alchemy.com";
let bad = 0;
const ok = (m) => console.log(`  ok    ${m}`);
const fail = (m) => { console.error(`  ✗     ${m}`); bad = 1; };

console.log(`personhood-live · ${SRC.id} · chain ${SRC.chainId} · ${SRC.contract}`);

// 1 · a real registration, from an independent source
let agent, eventHuman, eventBlock;
try {
  const r = await fetch(`${EXPLORER}/api/v2/addresses/${SRC.contract}/logs`, { signal: AbortSignal.timeout(20000) });
  const items = (await r.json()).items ?? [];
  const ev = items.find((it) => /^AgentRegistered\(/.test(it.decoded?.method_call ?? ""));
  if (!ev) throw new Error("no AgentRegistered event on the first page");
  const p = Object.fromEntries(ev.decoded.parameters.map((x) => [x.name, x.value]));
  agent = checksumAddress(p.agent); eventHuman = BigInt(p.humanId); eventBlock = ev.block_number;
  ok(`explorer: ${agent} registered at block ${eventBlock}`);
} catch (e) { fail(`could not read a registration from the explorer: ${e.message}`); process.exit(2); }

// 2 · our own read must agree with it
try {
  const { humanId, block } = await lookupHuman(agent, SRC);
  humanId === eventHuman && humanId !== 0n
    ? ok(`our eth_call at block ${block} returns the SAME human id as the event — two sources, one answer`)
    : fail(`eth_call says ${humanId}, the event says ${eventHuman}`);
} catch (e) { fail(`lookup of a registered agent failed: ${e.message}`); }

// 3 · a wallet nobody registered
const freshKey = randomBytes(32);
const fresh = addressFromPrivateKey(freshKey);
try {
  const { humanId, block } = await lookupHuman(fresh, SRC);
  humanId === 0n ? ok(`a fresh wallet ${fresh.slice(0, 10)}… → not human-backed (block ${block})`) : fail(`a fresh wallet came back backed: ${humanId}`);
} catch (e) { fail(`lookup of a fresh wallet failed: ${e.message}`); }

// 4 · the whole binding path, answered by the real chain
{
  const holder = holderThumbprint({ ed25519: randomBytes(32).toString("base64url"), mldsa65: randomBytes(1952).toString("base64url") });
  const now = Math.floor(Date.now() / 1000);
  const message = bindingMessage({ registrar: "registrar-07", holder, address: fresh, chainId: SRC.chainId, issuedAt: now, nonce: randomBytes(8).toString("hex") });
  const r = await provePersonhood({ message, signature: signPersonal(message, freshKey), registrar: "registrar-07", holder, now });
  !r.ok && r.reason === "not_human_backed"
    ? ok(`a correctly signed binding for an unregistered wallet → refused ${r.reason} (the real chain said no)`)
    : fail(`binding for an unregistered wallet: ${JSON.stringify(r).slice(0, 120)}`);
}

// 5 · an RPC that cannot be reached is a failure to ask, not a "no"
try { await lookupHuman(agent, { ...SRC, rpc: "http://127.0.0.1:9" }); fail("an unreachable RPC answered"); }
catch (e) { ok(`unreachable RPC → lookup_failed ("${e.message.slice(0, 40)}"), never read as "not registered"`); }

console.log(bad ? "\nPERSONHOOD-LIVE FAILED" : "\nPERSONHOOD-LIVE OK: the kit reads the real registry, agrees with an independent source, and refuses by name.");
process.exit(bad);
