// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// A WIMSE workload and a WIMSE verifier built ONLY from independent open-source libraries — `jose` for the Workload
// Identity Token, `http-message-sig` for RFC 9421, `structured-headers` to find the signature by its tag — pinned in
// package-lock.json. Nothing here imports AINRA. It is what a service that speaks WIMSE and has never heard of AINRA
// would run: given a trust domain and that trust domain's authorized issuer key ("configured out of band", in the
// draft's words), it checks the token and the request signature, and nothing more. It has no notion of revocation;
// the draft names a short token lifetime as the mitigation.
//
// Profile: draft-ietf-wimse-workload-creds-02 (WIT) and draft-ietf-wimse-http-signature-07 (request signature).
import { createHash } from "node:crypto";
import { SignJWT, importJWK, jwtVerify } from "jose";
import { createSignature, verifySignature, webcrypto } from "http-message-sig";
import { parseDictionary } from "structured-headers";

export const TAG = "wimse-workload-to-workload";
const COVERED_IF_PRESENT = ["content-type", "content-digest", "authorization", "txn-token", "workload-identity-token"];

export const digestOf = (body) => `sha-256=:${createHash("sha256").update(body).digest("base64")}:`;
const okpJwk = (x) => ({ kty: "OKP", crv: "Ed25519", x });
const verifyKey = (x) => crypto.subtle.importKey("jwk", okpJwk(x), { name: "Ed25519" }, false, ["verify"]);

/** The WIMSE-only verifier. Throws with the library's own message on any failure; returns the workload's `sub`. */
export async function wimseOnlyVerify(request, { trustDomain, issuerX, audience, now, body }) {
  const wit = request.headers.get("workload-identity-token");
  if (!wit) throw new Error("no Workload-Identity-Token");
  const { payload } = await jwtVerify(wit, await importJWK({ ...okpJwk(issuerX), alg: "EdDSA" }, "EdDSA"), {
    typ: "wit+jwt", algorithms: ["EdDSA"], currentDate: new Date(now * 1000), requiredClaims: ["sub", "exp", "cnf"],
  });
  if (typeof payload.sub !== "string" || !payload.sub.startsWith(`wimse://${trustDomain}/`)) throw new Error(`sub ${payload.sub} is not in ${trustDomain}`);
  const jwk = payload.cnf?.jwk;
  if (jwk?.kty !== "OKP" || jwk?.crv !== "Ed25519" || jwk?.alg !== "EdDSA") throw new Error("cnf.jwk is not an EdDSA Ed25519 key");

  // "the recipient selects the signature by its tag, and rejects the request if more than one carries it"
  const tagged = [...parseDictionary(request.headers.get("signature-input") ?? "")].filter(([, [, params]]) => params.get("tag") === TAG);
  if (tagged.length !== 1) throw new Error(`${tagged.length} signatures carry tag="${TAG}"`);
  const [label, [, params]] = tagged[0];
  if (params.has("keyid") || params.has("alg")) throw new Error("keyid and alg are prohibited in this profile");
  if (body?.length && request.headers.get("content-digest") !== digestOf(body)) throw new Error("content-digest does not match the body");

  const required = ["@method", "@path", "@query", ...COVERED_IF_PRESENT.filter((h) => request.headers.has(h))];
  await verifySignature(request, {
    label,
    policy: {
      algorithms: ["ed25519"], requiredComponents: required, requiredParameters: ["created", "expires", "nonce", "tag", "wimse-aud"],
      now, clockSkew: 30, maxAge: 300,
      validate: (s) => {
        if (s.parameters["wimse-aud"] !== audience) throw new Error(`wimse-aud ${s.parameters["wimse-aud"]} is not ${audience}`);
        if (s.parameters.expires - s.parameters.created > 300) throw new Error("expires is more than minutes after created");
      },
    },
    resolveVerifier: async () => webcrypto.verifier(await verifyKey(jwk.x)),
  });
  return payload.sub;
}

/** The WIMSE-only workload: mints a WIT with the trust domain's issuer key and signs one request with its own key. */
export async function wimseOnlySign({ url, method, headers = {}, body, issuerJwkPrivate, workloadJwkPrivate, sub, audience, now, nonce, iss }) {
  const issuer = await importJWK({ ...issuerJwkPrivate, alg: "EdDSA" }, "EdDSA");
  const wit = await new SignJWT({ cnf: { jwk: { ...okpJwk(workloadJwkPrivate.x), alg: "EdDSA" } } })
    .setProtectedHeader({ alg: "EdDSA", typ: "wit+jwt" })
    .setSubject(sub).setIssuer(iss).setIssuedAt(now).setExpirationTime(now + 3600).setJti(nonce)
    .sign(issuer);
  const h = new Headers(headers);
  h.set("workload-identity-token", wit);
  if (body?.length) h.set("content-digest", digestOf(body));
  const request = new Request(url, { method, headers: h, body });
  const signer = webcrypto.signer(await crypto.subtle.importKey("jwk", { ...okpJwk(workloadJwkPrivate.x), d: workloadJwkPrivate.d }, { name: "Ed25519" }, false, ["sign"]));
  const components = ["@method", "@path", "@query", ...COVERED_IF_PRESENT.filter((n) => h.has(n))];
  const fields = await createSignature(request, {
    label: "wimse",
    components,
    parameters: { created: now, expires: now + 120, nonce, tag: TAG, "wimse-aud": audience },
    signer,
  });
  h.set("signature-input", fields.signatureInput);
  h.set("signature", fields.signature);
  return h;
}
