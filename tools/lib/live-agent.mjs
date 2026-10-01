// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// One agent on the live network, for drills that need a real one: its own hybrid key, a passport from the registrar's
// public door, an instance credential for one running copy, and the pieces a request is made of. Everything is real —
// the registrar, the keys, the signatures — and TEST-ROOT. `make live-up` must be running.
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import {
  canonicalize, mintInstanceCredential, proveInstancePossession, signPresentation, PRESENTATION_HEADER, POP_HEADER,
} from "../../packages/sdk-ts/dist/index.js";

// The SDK's own copies of the libraries — the exact versions the verifier checks with.
const sdkRequire = createRequire(new URL("../../packages/sdk-ts/package.json", import.meta.url));
const load = async (m) => import(pathToFileURL(sdkRequire.resolve(m)).href);
const { ml_dsa65 } = await load("@noble/post-quantum/ml-dsa");
const { ed25519 } = await load("@noble/curves/ed25519");

export const REG = process.env.AINRA_REGISTRAR ?? "http://127.0.0.1:4970";
export const now = () => Math.floor(Date.now() / 1000);
export const b64u = (u) => Buffer.from(u).toString("base64url");
const wireSig = (s) => ({ ed25519: b64u(s.ed25519), mldsa65: b64u(s.mldsa65) });

export function hybridKey() {
  const edSk = ed25519.utils.randomPrivateKey();
  const ml = ml_dsa65.keygen(randomBytes(32));
  return {
    raw: { ed25519: ed25519.getPublicKey(edSk), mldsa65: ml.publicKey },
    wire: { ed25519: b64u(ed25519.getPublicKey(edSk)), mldsa65: b64u(ml.publicKey) },
    sign: (msg) => ({ ed25519: ed25519.sign(msg, edSk), mldsa65: ml_dsa65.sign(ml.secretKey, msg) }),
  };
}

// The registrar's public door allows 30 writes a minute and answers 429 beyond that. A drill that mints several
// agents waits its turn rather than failing: up to 70 s, a little longer than the door's window.
async function j(url, init) {
  for (let attempt = 0; ; attempt++) {
    const r = await fetch(url, init);
    if (r.status === 429 && attempt < 14) { await new Promise((ok) => setTimeout(ok, 5000)); continue; }
    const t = await r.text();
    try { return { status: r.status, body: JSON.parse(t) }; } catch { return { status: r.status, body: t }; }
  }
}

/** A passport and a running copy's credential, minted now. Throws if the registrar is not there or refuses. */
export async function liveAgent({ lineage, audience }) {
  const accred = await j(`${REG}/accreditation`);
  const registrar = accred.body?.id ?? accred.body?.registrar ?? "registrar-07";
  const holder = hybridKey(), instance = hybridKey();
  const proof = wireSig(holder.sign(new TextEncoder().encode(canonicalize({ holder: holder.wire, purpose: "ainra-holder-pop-v1", registrar }))));
  const issued = await j(`${REG}/demo/issue`, { method: "POST", body: JSON.stringify({ operator: "specimen", lineage, holder_key: holder.wire, holder_pop: proof }) });
  if (issued.status !== 200) throw new Error(`issue failed: ${issued.status} ${JSON.stringify(issued.body)}`);
  const sub = issued.body.sub;
  const fetchBundle = async () => (await j(`${REG}/present?sub=${encodeURIComponent(sub)}&now=${now()}`)).body;
  const bundle = await fetchBundle();
  const ic = await mintInstanceCredential({
    passportClaimsB64: bundle.claims, instancePublic: instance.raw, capabilities: ["demo:specimen"], audience,
    now: now(), lifetimeSecs: 900, iid: "i-" + randomBytes(4).toString("hex"), controlSign: holder.sign,
  });
  /** The full presentation: the bundle, the credential, and a FRESH proof of possession. */
  async function presentation(b = bundle) {
    const pop = await proveInstancePossession({ audience, credential: ic, nonce: "p-" + randomBytes(6).toString("hex"), now: now(), instanceSign: instance.sign });
    return {
      ...b,
      instance: {
        sub: ic.sub, iid: ic.iid, ikey: wireSig(ic.ikey), nbf: ic.nbf, exp: ic.exp, capabilities: ic.capabilities,
        aud: ic.aud, passport_leaf: b64u(ic.passportLeaf), sig: wireSig(ic.sig),
        pop: { aud: pop.aud, nonce: pop.nonce, ts: pop.ts, sig: wireSig(pop.sig) },
      },
    };
  }
  /** The fresh-proof header value a request carries next to the digest reference. */
  const popHeader = async () => b64u(JSON.stringify((await presentation()).instance.pop));
  /** RFC 9421 headers for one request, signed by `key` (default: this copy's instance key). */
  const sign = ({ method, authority, path, headers, body, created = now(), key = instance, keyid = ic.iid }) =>
    signPresentation({ req: { method, authority, path, headers, body }, keyid, nonce: "r-" + randomBytes(6).toString("hex"), created, instanceSign: key.sign });
  const revoke = () => j(`${REG}/demo/revoke`, { method: "POST", body: JSON.stringify({ sub, now: now() }) });
  return { sub, bundle, ic, instance, presentation, popHeader, sign, revoke, fetchBundle, PRESENTATION_HEADER, POP_HEADER };
}
