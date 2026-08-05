// SPDX-License-Identifier: Apache-2.0 OR MIT
// AINRAscan — browse the live AINRA record in your browser. Reads the public artifact contract (registry + the
// genesis directory + roots), lists every passport, and verifies any of them locally with the real SDK: VALID /
// INVALID + the one verdict-event. Works whenever a contract is reachable; degrades to an honest note otherwise.
// Everything is client-side against the same read contract mirrors use (CORS from M14). Zero telemetry.
import { runVector, verdictEvent, serializeVerdictEvent, verifyDirectory } from "../vendor/ainra-sdk.js";

const qs = new URLSearchParams(location.search);
const meta = (n) => document.querySelector(`meta[name="${n}"]`)?.content?.trim();
const onLocal = /^(localhost|127\.|0\.0\.0\.0|\[::1\])/.test(location.hostname);
const CONTRACT = (qs.get("net") || meta("ainra-contract") || (onLocal ? "http://127.0.0.1:8091" : "")).replace(/\/$/, "");

const $ = (s) => document.querySelector(s);
const enc = (u) => btoa(String.fromCharCode(...u)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const dec = (s) => { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; const b = atob(s); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; };
let REG = null, NOW = 0, ROWS = [];

function toWire(rec, R) {
  return { name: rec.sub, expect: {},
    anchors: { [R.registrar]: { issuer_key: R.accreditation.issuer_key, log_root_key: R.accreditation.log_root_key } },
    presentation: {
      claims: enc(new TextEncoder().encode(rec.claims)),
      issuer_sig: { ed25519: rec.issuer_sig_ed25519, mldsa65: rec.issuer_sig_mldsa65 },
      now: NOW, chain_keys: rec.chain_keys, hop_proofs: rec.hop_proofs,
      status_list: R.status_list.status_list_b64, status_len: R.status_list.bit_len, status_issued_at: R.status_list.issued_at,
      freshness: "F3", checkpoint: { origin: rec.log_origin, size: rec.checkpoint_size, root: rec.checkpoint_root },
      checkpoint_sig: rec.checkpoint_sig, leaf_index: rec.leaf_index, inclusion_proof: rec.inclusion_proof,
      mandate_revocations: [], revoked_delegates: [],
    } };
}

async function boot() {
  if (!$("#scan")) return;
  if (!CONTRACT) return down("This reads a live AINRA network. Start one — <code>make stage-all</code> — then reload, or pass <code>?net=&lt;contract-url&gt;</code>.");
  let res;
  try { res = await fetch(CONTRACT + "/registry.json", { cache: "no-store" }); if (!res.ok) throw 0; REG = await res.json(); }
  catch { return down(`No AINRA contract reachable at <code>${CONTRACT}</code>. Run <code>make stage-all</code>.`); }
  NOW = REG.generated_window?.verified_at ?? 0;
  const root = (res.headers.get("X-AINRA-Root") || "test-root");

  $("#s-root").textContent = root.split(":")[0].toUpperCase(); // the TYPE (GENESIS / TEST-ROOT); the full fingerprint is in the note below
  $("#s-regs").textContent = REG.totals?.registrars ?? "—";
  $("#s-issued").textContent = REG.totals?.issued ?? "—";
  $("#s-revoked").textContent = REG.totals?.revoked ?? "—";
  let h = 0; for (const R of REG.registrars || []) for (const e of R.records || []) { const c = e.record?.checkpoint_size || 0; if (c > h) h = c; }
  $("#s-height").textContent = h || "—";

  // root-dark chain: is the published directory dual-root-signed by the published root?
  try {
    const DIR = await (await fetch(CONTRACT + "/directory.json")).json();
    const ROOTS = await (await fetch(CONTRACT + "/roots.json")).json();
    if (DIR && ROOTS?.root_ed25519) {
      const acc = verifyDirectory(DIR, dec(ROOTS.root_ed25519), dec(ROOTS.root_slh));
      const rd = $("#s-rootdark"); rd.hidden = false;
      rd.innerHTML = acc ? `✓ the directory is dual-root-signed by <b>${root}</b> — every record below chains to it root-dark`
                         : `the published directory is not verifiable against the published root`;
      rd.className = "s-rootdark " + (acc ? "ok" : "no");
    }
  } catch {}

  for (const R of REG.registrars || []) for (const e of R.records || []) ROWS.push({ rec: e.record, R });

  // Suite mix — honest, straight from the live records: a hybrid credential carries the ML-DSA-65 half, a legacy one
  // does not. During a suite migration this shows both; a legacy credential fails closed by default (see the drill).
  const hy = ROWS.filter((r) => r.rec.issuer_sig_mldsa65).length, lg = ROWS.length - hy;
  const su = $("#s-suite");
  if (su && ROWS.length) {
    su.hidden = false; su.className = "s-rootdark " + (lg ? "" : "ok");
    su.innerHTML = lg
      ? `suite mix — <b>${hy}</b> hybrid (Ed25519 + ML-DSA-65) · <b>${lg}</b> legacy Ed25519-only, which fails closed by default during migration`
      : `cryptographic suite — every live record is <b>hybrid Ed25519 + ML-DSA-65</b> (post-quantum) · <b>0</b> legacy stragglers`;
  }
  // Witness diversity — self-declared, from live data: how many independent operators (and regions) cosign the log.
  // A checkpoint is certified only when a relying-party quorum of these witnesses agrees; a fork needs the quorum to
  // collude. The metadata is the operators' own claim (verified by no one); the count and keys are the live facts.
  const W = REG.witnesses || [];
  const wel = $("#s-witnesses");
  if (wel && W.length) {
    const regions = [...new Set(W.map((w) => (w.region || "").trim()).filter(Boolean))];
    wel.hidden = false; wel.className = "s-rootdark";
    wel.innerHTML = `witnesses — <b>${W.length}</b> cosigning the log` +
      (regions.length ? ` · ${regions.map((r) => `<em>${r}</em>`).join(" · ")}` : "") +
      ` · self-declared, verified by no one — a fork must out-collude the relying party's quorum`;
  }

  render(ROWS);
  $("#s-search").addEventListener("input", () => {
    const q = $("#s-search").value.toLowerCase();
    render(ROWS.filter((r) => r.rec.sub.toLowerCase().includes(q) || (r.rec.operator || "").toLowerCase().includes(q) || r.rec.tier.toLowerCase().includes(q)));
  });
}

function render(rows) {
  const t = $("#s-rows"); t.innerHTML = "";
  if (!rows.length) { t.innerHTML = `<div class="s-empty">No passports match.</div>`; return; }
  for (const { rec, R } of rows) {
    const wrap = document.createElement("div"); wrap.className = "s-item";
    const row = document.createElement("div"); row.className = "s-row";
    row.innerHTML = `<div class="s-main"><div class="s-name">${rec.sub}</div><div class="s-meta">${rec.tier} · ${rec.auth_class} · ${rec.registrar}${rec.hops?.length ? " · delegated" : ""}</div></div>
      <span class="s-chip ${rec.revoked ? "no" : "ok"}">${rec.revoked ? "REVOKED" : "ACTIVE"}</span>
      <button class="s-verify" type="button">Verify ↧</button>`;
    const detail = document.createElement("div"); detail.className = "s-detail"; detail.hidden = true;
    row.querySelector(".s-verify").addEventListener("click", () => { if (!detail.hidden) { detail.hidden = true; return; } verifyRow(rec, R, detail); });
    wrap.appendChild(row); wrap.appendChild(detail); t.appendChild(wrap);
  }
}

function verifyRow(rec, R, detail, btn) {
  detail.hidden = false;
  if (btn) { btn.setAttribute("aria-expanded", "true"); btn.textContent = "Hide ↥"; } detail.innerHTML = `<div class="s-verd pend">running the verifier in your browser…</div>`;
  setTimeout(() => {
    const wire = toWire(rec, R);
    let v; try { v = runVector(wire); } catch (e) { detail.innerHTML = `<div class="s-verd no">ERROR — ${e.message}</div>`; return; }
    const ok = v.verdict === "valid";
    let ev = ""; try { ev = serializeVerdictEvent(verdictEvent(wire.presentation, v, NOW)); } catch {}
    detail.innerHTML = `<div class="s-verd ${ok ? "ok" : "no"}">${ok ? "VALID" : "INVALID · " + (v.reason || "")}</div>
      <div class="s-fields">
        <div><span>AINRA Number</span>did:ainra:${rec.sub.replace(/^ainra:/, "").replace(/@.*/, "")}</div>
        <div><span>Version</span>${rec.version}</div>
        <div><span>Keys</span>ED25519 + ML-DSA-65</div>
        <div><span>Checkpoint</span>height ${rec.checkpoint_size} · root ${String(rec.checkpoint_root).slice(0, 18)}…</div>
      </div>
      ${ev ? `<div class="s-event">${ev}</div>` : ""}
      <div class="s-note">Verified locally — the record's own inclusion proof recomputed in this tab, not taken on trust.</div>`;
  }, 120);
}

function down(html) { const u = $("#s-down"); if (u) { u.innerHTML = html; u.hidden = false; } const f = $("#s-flow"); if (f) f.hidden = true; }
boot();
