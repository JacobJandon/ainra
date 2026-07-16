// SPDX-License-Identifier: Apache-2.0 OR MIT
// Regression guard for the M5 review CRITICAL — the status-list revocation bypass (D-020). These are REAL artifacts
// captured from the live registrar-box + ceremony (tools/testbed.sh path): a dual-root-signed directory, its roots,
// and two presentation bundles (a valid credential and a revoked one). The verifier authenticates the presented
// status list against the registrar's directory-published status key, so a presenter cannot forge an all-clear
// status to un-revoke a passport. This runs hermetically in CI (no daemon), unlike the end-to-end testbed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { deflateSync } from "node:zlib";
import { Verifier } from "@ainra/sdk";

const fx = (name) => JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8"));
const NOW = 1776729600; // the instant the fixtures were stamped (status issued_at = NOW - 1, well inside F2)

const directory = fx("directory.json");
const roots = fx("roots.json");
const valid = fx("bundle-valid.json");
const revoked = fx("bundle-revoked.json");

const verifier = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh);

test("the captured directory trust-anchors (both roots) and carries a status key", () => {
  assert.ok(verifier, "directory.json must verify under its published roots");
});

test("a real valid passport verifies VALID; the same passport revoked verifies INVALID(revoked)", () => {
  assert.equal(verifier.verify(valid, NOW).verdict, "valid");
  const v = verifier.verify(revoked, NOW);
  assert.equal(v.verdict, "invalid");
  assert.equal(v.reason, "revoked", "an honestly-presented revoked passport is revoked");
});

// ── The bypass itself: a hostile presenter rewrites the revoked bundle's status to lie "nobody is revoked" ─────────
test("FORGE clear: an all-clear bitmap + fresh issued_at (unsigned) is REJECTED, not un-revoked", () => {
  const forged = structuredClone(revoked);
  // A genuinely-decodable all-zero (nobody-revoked) list of the SAME declared length, zlib-compressed exactly like
  // the real codec — so it is NOT a malformed-status rejection; it is rejected purely because it is not SIGNED.
  forged.status_list = deflateSync(Buffer.alloc(Math.ceil(revoked.status_len / 8))).toString("base64url");
  forged.status_issued_at = NOW; // re-stamp fresh so no freshness window can save us
  forged.freshness = "F1";
  const v = verifier.verify(forged, NOW);
  assert.equal(v.verdict, "invalid", "a forged all-clear status must NOT verify VALID — that is the bypass");
  assert.equal(v.reason, "stale_status", "an unauthenticated status list fails closed to stale_status");
});

test("FORGE strip: removing the status signature entirely is REJECTED (no authenticated status ⇒ fail closed)", () => {
  const forged = structuredClone(valid); // even a VALID (non-revoked) bundle must carry an authenticated status
  delete forged.status_sig_ed25519;
  delete forged.status_sig_mldsa65;
  const v = verifier.verify(forged, NOW);
  assert.equal(v.verdict, "invalid");
  assert.equal(v.reason, "stale_status");
});

test("FORGE swap-uri: pointing the signed publication at a different URI breaks the binding ⇒ REJECTED", () => {
  const forged = structuredClone(valid);
  forged.status_uri = `${forged.status_uri}-attacker`;
  const v = verifier.verify(forged, NOW);
  assert.equal(v.verdict, "invalid");
  assert.equal(v.reason, "stale_status");
});

test("FORGE tamper-bits: flipping the signed bitmap under the original signature is REJECTED", () => {
  const forged = structuredClone(revoked);
  // Take the real (signed) revoked list but corrupt one compressed byte — the signature no longer covers these bits.
  const raw = Buffer.from(revoked.status_list, "base64url");
  raw[Math.floor(raw.length / 2)] ^= 0xff;
  forged.status_list = raw.toString("base64url");
  const v = verifier.verify(forged, NOW);
  assert.equal(v.verdict, "invalid");
  assert.equal(v.reason, "stale_status");
});

test("nothing throws on any forged input — a security gate must never 500", () => {
  for (const b of [valid, revoked, {}, { ...valid, status_list: "!!!" }, { ...valid, status_len: 1e12 }]) {
    assert.doesNotThrow(() => verifier.verify(b, NOW));
  }
});

// ── DoS: a compression-amplification bundle whose declared length sits AT the cap must NOT decompress (adversarial
//    review HIGH). status_len = 2^24 with a tiny blob that inflates to exactly the cap used to build a ~360 MB
//    boolean[] BEFORE authentication → process OOM. Now the signature is checked first (over the compressed bytes),
//    so an unauthenticated bundle fails cheap; and the list is kept packed (≤ 2 MiB) even when authenticated. ──────
test("DoS: an unauthenticated status list at the size cap fails closed cheaply — no decompress, no OOM", () => {
  const atCap = { ...valid, status_len: 1 << 24, status_list: deflateSync(Buffer.alloc((1 << 24) / 8)).toString("base64url") };
  const t0 = process.hrtime.bigint();
  const v = verifier.verify(atCap, NOW);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  assert.equal(v.verdict, "invalid");
  assert.equal(v.reason, "stale_status", "authentication over the compressed bytes fails BEFORE any inflate");
  assert.ok(ms < 200, `must reject without decompressing the 2 MiB list (took ${ms.toFixed(1)}ms)`);
  // one above the cap is rejected too; and neither crashes the process
  assert.equal(verifier.verify({ ...valid, status_len: (1 << 24) + 1 }, NOW).verdict, "invalid");
});

// ── Freshness bounds revocation LATENCY, not currency (adversarial review, honest semantics). An offline verifier
//    trusts a genuine registrar-signed status SNAPSHOT within its freshness window — so a holder can replay a
//    pre-revocation snapshot until it ages out. The control is the WINDOW: verifier-owned, unforgeable, hard-stop. ─
test("freshness window is enforced: a genuine snapshot is accepted within the class and fails closed past it", () => {
  const f1 = Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh, "F1"); // 30 s
  const issued = valid.status_issued_at;
  assert.equal(f1.verify(valid, issued + 10).verdict, "valid", "within 30 s the stapled snapshot is trusted");
  assert.equal(f1.verify(valid, issued + 31).verdict, "invalid", "past the window it fails closed");
  assert.equal(f1.verify(valid, issued + 31).reason, "stale_status");
});

// ── Currency mode (D-021, M6): the fresh head + monotonic head-sequence CLOSE genuine-snapshot replay for a verifier
//    that has observed the head advance. `valid` (fresh-head seq 0) and `revoked` (seq 1) are the SAME passport. ────
const currency = () => Verifier.fromDirectoryB64(directory, roots.root_ed25519, roots.root_slh, "F1", true);

test("currency mode: a genuine current bundle (fresh head binds, seq unseen) verifies VALID", () => {
  assert.equal(currency().verify(valid, valid.status_issued_at + 5).verdict, "valid");
});

test("currency mode: a monotonic fresh-head seq rejects a REPLAYED pre-revocation snapshot", () => {
  const cur = currency();
  const issued = valid.status_issued_at;
  // the verifier OBSERVES the revocation (revoked bundle, fresh-head seq 1) → INVALID(revoked); seq 1 is recorded
  const rv = cur.verify(revoked, issued + 5);
  assert.equal(rv.verdict, "invalid");
  assert.equal(rv.reason, "revoked");
  // the holder now REPLAYS the genuine pre-revocation snapshot (all-clear list, fresh-head seq 0) — still fresh and
  // genuinely signed, but its seq is BEHIND the head this verifier has seen → rejected as a superseded replay
  const replay = cur.verify(valid, issued + 6);
  assert.equal(replay.verdict, "invalid");
  assert.equal(replay.reason, "stale_status", "a superseded fresh head must not re-validate a revoked lineage");
});

test("currency mode REQUIRES the fresh head — a stripped one fails closed (no downgrade)", () => {
  const noHead = { ...valid };
  delete noHead.fresh_head;
  assert.equal(currency().verify(noHead, valid.status_issued_at + 5).reason, "stale_status");
});

test("currency mode: a fresh head that does not name the presented list is rejected (head-hash binding)", () => {
  // present the valid (all-clear) list but splice in the REVOKED bundle's fresh head (which names the revoked list)
  const mismatched = { ...valid, fresh_head: revoked.fresh_head, status_delegate_cert: revoked.status_delegate_cert };
  const v = currency().verify(mismatched, valid.status_issued_at + 5);
  assert.equal(v.verdict, "invalid");
  assert.equal(v.reason, "stale_status");
});

test("the DEFAULT verifier ignores the fresh head — currency is strictly opt-in (M5 behaviour preserved)", () => {
  // default (non-currency) verifier: valid → VALID, revoked → INVALID(revoked), fresh head untouched
  assert.equal(verifier.verify(valid, NOW).verdict, "valid");
  assert.equal(verifier.verify(revoked, NOW).reason, "revoked");
});
