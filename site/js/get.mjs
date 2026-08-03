// SPDX-License-Identifier: Apache-2.0 OR MIT
// M18 — "Get your agent an AINRA passport." A real, three-step issuance flow against a registrar's public door on a
// TEST-ROOT: NAME your agent → GET the passport (minted + logged, with real crypto) → USE it (verify locally, carry
// it, or revoke it). If no registrar is reachable (a public static deploy), the flow degrades to an honest note.
import { runVector, verdictEvent, serializeVerdictEvent } from "../vendor/ainra-sdk.js";

const qs = new URLSearchParams(location.search);
const meta = (n) => document.querySelector(`meta[name="${n}"]`)?.content?.trim();
const onLocal = /^(localhost|127\.|0\.0\.0\.0|\[::1\])/.test(location.hostname);
const REG = (qs.get("reg") || meta("ainra-registrar") || (onLocal ? "http://127.0.0.1:4907" : "")).replace(/\/$/, "");
const REGID = qs.get("regid") || "registrar-07";
const CONTRACT = (qs.get("net") || meta("ainra-contract") || (onLocal ? "http://127.0.0.1:8091" : "")).replace(/\/$/, "");
const EXPLORER = (qs.get("scan") || (onLocal ? "http://127.0.0.1:8090" : "")).replace(/\/$/, "");
const NOW = 1776729600;

const $ = (s) => document.querySelector(s);
let rec = null, anchors = null;

const clean = (s, d) => { const c = [...(s || "")].filter((ch) => /[a-z0-9-]/i.test(ch)).join("").toLowerCase().replace(/^-+|-+$/g, "").slice(0, 24); return c || d; };
const preview = () => { const sub = `ainra:${REGID}:${clean($("#g-op").value, "specimen")}:${clean($("#g-lin").value, "demo")}@1.0.x`; $("#g-preview").textContent = sub; };
const step = (n) => { document.querySelectorAll("[data-step]").forEach((s) => (s.hidden = +s.dataset.step !== n)); document.querySelectorAll(".g-dot").forEach((d) => (d.dataset.on = +d.dataset.i <= n ? "1" : "0")); };

async function boot() {
  if (!$("#get")) return;
  // No registrar configured — the ordinary case on a static host. This is architecture, not a missing feature:
  // issuance happens at a registrar, never at the root, so a published site has nothing to issue with. Say that
  // plainly, point at the two things that DO work everywhere, and give the one command that makes minting local.
  if (!REG) return unavailable(
    "<b>Issuance happens at a registrar, never at the root</b> — so this page has nothing to mint with until you " +
    "point it at one. Everything that does not need a signing key works right here: <a href=\"#browse\">browse the " +
    "record below</a>, and <a href=\"verify.html#try\">run the verifier</a> on real bundles. " +
    "To mint: <code>make stage-all</code> in the repository, then reload — or pass <code>?reg=&lt;url&gt;</code> " +
    "for a registrar you already run.");
  let health;
  try { health = await (await fetch(REG + "/health", { cache: "no-store" })).json(); } catch { return unavailable(`No registrar reachable at <code>${REG}</code>. Run <code>make stage-all</code>.`); }
  if (!health?.ok) return unavailable("A registrar answered but isn't ready.");
  try { const a = await (await fetch(REG + "/accreditation")).json(); anchors = { [REGID]: { issuer_key: a.issuer_key, log_root_key: a.log_root_key } }; } catch { return unavailable("Couldn't read the registrar's accreditation."); }
  let netRoot = health.root || "test-root";
  if (CONTRACT) { try { netRoot = (await (await fetch(CONTRACT + "/index.json", { cache: "no-store" })).json()).root || netRoot; } catch {} }
  $("#g-badge").textContent = (health.network || "staging").toUpperCase() + " · " + netRoot.toUpperCase();
  $("#g-op").addEventListener("input", preview); $("#g-lin").addEventListener("input", preview); preview();
  $("#g-mint").addEventListener("click", mint);
  $("#g-verify").addEventListener("click", verify);
  $("#g-download").addEventListener("click", download);
  $("#g-revoke").addEventListener("click", revoke);
  $("#g-again").addEventListener("click", () => { rec = null; step(1); $("#g-verdict").textContent = "—"; $("#g-verdict").className = "g-verdict pend"; });
  $("#g-copyprompt")?.addEventListener("click", () => { const p = $("#g-prompt"); navigator.clipboard?.writeText(p.textContent).then(() => { $("#g-copyprompt").textContent = "COPIED"; setTimeout(() => ($("#g-copyprompt").textContent = "COPY"), 1400); }, () => {}); });
  step(1);
}

async function mint() {
  $("#g-mint").disabled = true; $("#g-mint").textContent = "Minting…";
  try {
    rec = await (await fetch(REG + "/demo/issue", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ operator: $("#g-op").value, lineage: $("#g-lin").value }) })).json();
    if (!rec.sub) throw new Error(rec.error || "issue failed");
    renderCard(rec);
    step(2);
  } catch (e) { alert("Could not mint: " + e.message); }
  finally { $("#g-mint").disabled = false; $("#g-mint").textContent = "Mint my passport →"; }
}

function renderCard(r) {
  const did = "did:ainra:" + r.sub.replace(/^ainra:/, "").replace(/@.*$/, "");
  $("#c-name").textContent = r.sub;
  $("#c-number").textContent = did;
  $("#c-op").textContent = r.operator;
  $("#c-lineage").textContent = r.lineage + " @ " + r.version;
  $("#c-tier").textContent = r.tier + " · SPECIMEN";
  $("#c-auth").textContent = r.auth_class + " · ORG-DELEGATED";
  $("#c-height").textContent = "checkpoint height " + r.checkpoint_size + " · logged before valid";
  $("#c-key").textContent = "ED25519 + ML-DSA-65";
  { const a = $("#c-scan"); if (a) { a.href = "#browse"; a.hidden = false; } } // browse the record: the section below on this same page
  // fill the self-onboard prompt with the real name
  const p = $("#g-prompt"); if (p) p.textContent = `Verify the AINRA passport ${r.sub} locally with @ainra/sdk against ${REG}. Fetch its presentation from ${REG}/present?sub=${encodeURIComponent(r.sub)} and confirm the verdict-event. This is a staging TEST-ROOT specimen.`;
}

async function verify() {
  step(3);
  const v = $("#g-verdict"); v.textContent = "…"; v.className = "g-verdict pend";
  try {
    const pres = await (await fetch(`${REG}/present?sub=${encodeURIComponent(rec.sub)}&now=${NOW}`)).json();
    const r = runVector({ name: rec.sub, expect: {}, anchors, presentation: pres });
    const ev = serializeVerdictEvent(verdictEvent(pres, r, NOW));
    const ok = r.verdict === "valid";
    v.textContent = ok ? "VALID" : "INVALID · " + (r.reason || ""); v.className = "g-verdict " + (ok ? "ok" : "no");
    $("#g-event").textContent = ev;
  } catch (e) { v.textContent = "ERROR"; v.className = "g-verdict no"; $("#g-event").textContent = e.message; }
}

async function download() {
  try {
    const pres = await (await fetch(`${REG}/present?sub=${encodeURIComponent(rec.sub)}&now=${NOW}`)).json();
    const bundle = { name: rec.sub, anchors, presentation: pres, note: "AINRA passport bundle (STAGING · TEST-ROOT specimen). Verify with @ainra/sdk runVector(this)." };
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = rec.sub.replace(/[:@]/g, "_") + ".passport.json"; a.click();
  } catch (e) { alert("Download failed: " + e.message); }
}

async function revoke() {
  if (!confirm("Revoke this specimen? It will fail closed on re-verify — that's the point.")) return;
  try {
    const rv = await (await fetch(REG + "/demo/revoke", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ sub: rec.sub, now: NOW }) })).json();
    if (rv.revoked !== rec.sub) throw new Error(rv.error || "revoke failed");
    await verify(); // re-verify → INVALID·revoked
  } catch (e) { alert("Revoke failed: " + e.message); }
}

function unavailable(html) { const u = $("#g-unavailable"); if (u) { u.innerHTML = html; u.hidden = false; } const f = $("#g-flow"); if (f) f.hidden = true; }

boot();
