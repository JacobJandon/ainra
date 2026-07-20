// SPDX-License-Identifier: Apache-2.0 OR MIT
// The AINRA public artifact server — the CDN-shaped read surface of a staging network. It serves a static
// directory of public artifacts (directory, checkpoints, status lists, fresh heads, exports) with the exact HTTP
// behaviour docs/ARTIFACT-CONTRACT.md specifies, so any browser SDK / mirror / verifier can read them at
// planet-scale caching correctness. It holds NO keys, issues nothing, verifies nothing — dumb static transport.
//
//   node tools/artifact-server.mjs <root-dir> [port]
//
// Contract, per class (decided by path):
//   * immutable, content/height-addressed  (…/checkpoints/<n>.json, …/tiles/…, *.immutable.*):
//       Cache-Control: public, max-age=31536000, immutable
//   * mutable heads/deltas/directory/exports (everything else):
//       Cache-Control: public, max-age=5, must-revalidate  + strong ETag (sha256 of the bytes)
//   * every response: Access-Control-Allow-Origin: * (+ OPTIONS preflight), correct Content-Type, gzip when asked,
//       and the STAGING banner headers  X-AINRA-Network: staging  /  X-AINRA-Root: test-root.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import crypto from "node:crypto";

const ROOT = path.resolve(process.argv[2] || "stage/public");
const PORT = parseInt(process.argv[3] || "8091", 10);
const NETWORK = process.env.AINRA_STAGE === "0" ? "dev" : "staging";

const CT = { ".json": "application/json", ".txt": "text/plain; charset=utf-8", ".html": "text/html; charset=utf-8", ".js": "text/javascript" };
const isImmutable = p => /\/checkpoints\/|\/tiles\/|\.immutable\./.test(p);

function bannerHeaders(h = {}) {
  h["Access-Control-Allow-Origin"] = "*";
  h["Access-Control-Expose-Headers"] = "ETag, X-AINRA-Network, X-AINRA-Root";
  h["X-AINRA-Network"] = NETWORK;   // machine-readable: this is a staging network…
  h["X-AINRA-Root"] = "test-root";  // …on a TEST-ROOT. No trust migrates to the future production root.
  return h;
}

const server = http.createServer((req, res) => {
  const url = decodeURIComponent((req.url || "/").split("?")[0]);
  if (req.method === "OPTIONS") {
    res.writeHead(204, bannerHeaders({ "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS", "Access-Control-Allow-Headers": "*", "Content-Length": 0 }));
    return res.end();
  }
  if (req.method !== "GET" && req.method !== "HEAD") {
    return res.writeHead(405, bannerHeaders({ "Content-Type": "application/json" })).end('{"error":"read-only"}');
  }
  // resolve inside ROOT (no traversal); "/" → index.json
  let rel = url === "/" ? "/index.json" : url;
  const abs = path.join(ROOT, rel);
  if (!abs.startsWith(ROOT + path.sep) && abs !== ROOT) {
    return res.writeHead(403, bannerHeaders()).end();
  }
  fs.readFile(abs, (err, buf) => {
    if (err) return res.writeHead(404, bannerHeaders({ "Content-Type": "application/json" })).end('{"error":"not found"}');
    const ext = path.extname(abs);
    const etag = '"' + crypto.createHash("sha256").update(buf).digest("hex").slice(0, 32) + '"';
    const h = bannerHeaders({ "Content-Type": CT[ext] || "application/octet-stream" });
    if (isImmutable(rel)) h["Cache-Control"] = "public, max-age=31536000, immutable";
    else { h["Cache-Control"] = "public, max-age=5, must-revalidate"; h["ETag"] = etag; }
    // conditional GET on mutable artifacts
    if (!isImmutable(rel) && req.headers["if-none-match"] === etag) return res.writeHead(304, h).end();
    let body = buf;
    if (/\bgzip\b/.test(req.headers["accept-encoding"] || "") && buf.length > 256) { body = zlib.gzipSync(buf); h["Content-Encoding"] = "gzip"; h["Vary"] = "Accept-Encoding"; }
    h["Content-Length"] = body.length;
    res.writeHead(200, h);
    res.end(req.method === "HEAD" ? undefined : body);
  });
});
server.listen(PORT, "0.0.0.0", () => console.error(`artifact-server [${NETWORK}·test-root] root=${ROOT} → http://0.0.0.0:${PORT}`));
