// SPDX-License-Identifier: Apache-2.0 OR MIT
// Conway's Game of Life as the site's background — the AINRA doctrine made visible: simple rules build complex
// systems. Three rules (B3/S23) on a toroidal grid, and everything that happens on screen emerges from them.
//
// Design: a fixed, full-viewport canvas at z-index 0 behind the page (content is lifted to z-index 1); cells are
// 7px pixels drawn 6×6 for the site's pixel-art grain, in the brand green, with age-faded alpha so newborn cells
// shimmer and old colonies settle into faint texture. A random classic pattern (glider, r-pentomino, LWSS, acorn)
// is stamped every 30 generations so the field never dies out. On the landing the field starts BELOW the hero
// (drawing is clipped to the hero's live bottom edge, with a short fade ramp), taking over as you scroll; on other
// pages it runs behind the whole page. Zero interaction cost: pointer-events none, rAF-gated to one generation per
// 120 ms, paused by the browser when the tab is hidden, and fully static under prefers-reduced-motion (one seeded
// generation drawn once — texture, no motion).

const CS = 9;            // cell size (px) — drawn CS-1 so the 1px gap keeps the pixel grid visible
const TICK = 150;        // ms per generation
const DENSITY = 0.07;    // initial random seed density
const STAMP_EVERY = 50;  // generations between pattern injections
const FADE_PX = 48;      // alpha ramp below the hero clip edge
const ALPHA = 0.16;      // global visibility factor — the field is texture, never a subject

const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

// ── the three rules (B3/S23), cells carry their AGE (0 = dead, ≥1 = generations alive, capped) ───────────────────
const alloc = (w, h) => new Uint8Array(w * h);
const seed = (g, density) => { for (let i = 0; i < g.length; i++) g[i] = Math.random() < density ? 1 : 0; };
function neighbours(g, w, h, x, y) {
  let n = 0;
  for (let dy = -1; dy <= 1; dy++) for (let dx = -1; dx <= 1; dx++) {
    if (!dx && !dy) continue;
    if (g[((y + dy + h) % h) * w + ((x + dx + w) % w)] > 0) n++;
  }
  return n;
}
function step(cur, next, w, h) {
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const i = y * w + x, n = neighbours(cur, w, h, x, y);
    next[i] = cur[i] > 0 ? (n === 2 || n === 3 ? Math.min(cur[i] + 1, 255) : 0) : (n === 3 ? 1 : 0);
  }
}
// classic still-breeding patterns, stamped at a random spot to keep the field alive
const PATTERNS = [
  [[0, 1], [1, 2], [2, 0], [2, 1], [2, 2]],                                     // glider
  [[0, 1], [0, 2], [1, 0], [1, 1], [2, 1]],                                     // r-pentomino
  [[0, 1], [0, 4], [1, 0], [2, 0], [2, 4], [3, 0], [3, 1], [3, 2], [3, 3]],     // lightweight spaceship
  [[0, 1], [1, 3], [2, 0], [2, 1], [2, 4], [2, 5], [2, 6]],                     // acorn
];
function stamp(g, w, h) {
  const x = Math.floor(Math.random() * (w - 10)) + 5, y = Math.floor(Math.random() * (h - 10)) + 5;
  const p = PATTERNS[Math.floor(Math.random() * PATTERNS.length)];
  for (const [dy, dx] of p) g[((y + dy + h) % h) * w + ((x + dx + w) % w)] = 1;
}

// ── the field ────────────────────────────────────────────────────────────────────────────────────────────────────
// Lift the page above the canvas once (nav/main/footer are the only direct body children that hold content).
const style = document.createElement("style");
style.textContent = `#life-field{position:fixed;inset:0;z-index:0;pointer-events:none}
body>nav,body>main,body>header,body>footer{position:relative;z-index:1}`;
document.head.appendChild(style);

const canvas = document.createElement("canvas");
canvas.id = "life-field";
canvas.setAttribute("aria-hidden", "true");
document.body.prepend(canvas);
const ctx = canvas.getContext("2d");
const hero = document.getElementById("hero"); // landing only — the field starts below it

let W = 0, H = 0, cols = 0, rows = 0, cur, next, gen = 0, last = 0;

function size() {
  const dpr = window.devicePixelRatio || 1;
  W = window.innerWidth; H = window.innerHeight;
  canvas.width = W * dpr; canvas.height = H * dpr;
  canvas.style.width = W + "px"; canvas.style.height = H + "px";
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  const c = Math.ceil(W / CS), r = Math.ceil(H / CS);
  const g = alloc(c, r);
  if (cur) { // preserve the overlapping region across resizes instead of restarting the world
    for (let y = 0; y < Math.min(rows, r); y++) for (let x = 0; x < Math.min(cols, c); x++) g[y * c + x] = cur[y * cols + x];
  } else seed(g, DENSITY);
  cols = c; rows = r; cur = g; next = alloc(c, r);
}

// age → colour: newborn cells are brighter and more present, old colonies fade into the paper
function fill(age, ramp) {
  const t = Math.min(age, 40) / 40;
  return `rgba(26,${Math.round(160 - t * 56)},${Math.round(92 - t * 32)},${((0.5 - t * 0.35) * ALPHA * ramp).toFixed(3)})`;
}

function draw() {
  ctx.clearRect(0, 0, W, H);
  // clip above the hero's live bottom edge (landing); elsewhere clipY is 0 and the whole viewport is field
  const clipY = hero ? Math.max(0, hero.getBoundingClientRect().bottom) : 0;
  const firstRow = Math.floor(clipY / CS);
  for (let y = firstRow; y < rows; y++) {
    const py = y * CS;
    const ramp = FADE_PX ? Math.min(1, Math.max(0, (py - clipY) / FADE_PX)) : 1;
    if (ramp <= 0) continue;
    for (let x = 0; x < cols; x++) {
      const age = cur[y * cols + x];
      if (age > 0) { ctx.fillStyle = fill(age, ramp); ctx.fillRect(x * CS, py, CS - 1, CS - 1); }
    }
  }
}

function frame(t) {
  requestAnimationFrame(frame);
  if (t - last < TICK) return;
  last = t; gen++;
  if (gen % STAMP_EVERY === 0) stamp(cur, cols, rows);
  step(cur, next, cols, rows);
  [cur, next] = [next, cur];
  draw();
}

size();
window.addEventListener("resize", size);
if (reduced) draw();               // one seeded generation, drawn once — texture without motion
else requestAnimationFrame(frame);
