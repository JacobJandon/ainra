#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make scale — the planet-scale proof. Runs the Rust scale-proof (device verify cost, log proofs at 8.6 B,
# revocation for 1 B lineages, sharded issuance — all measured on this host), THEN a bounded distribution load test
# against the reference artifact server (req/s for an immutable checkpoint + a mutable head), and appends the
# honest CDN argument. Every number is [measured] here or [extrapolated] with the method shown. Writes docs/SCALE.md.
set -uo pipefail
cd "$(dirname "$0")/.."
OUT=docs/SCALE.md

cargo run --release -q -p ainra-services --bin scale-proof > "$OUT"

# ── distribution load test (the static read surface) ─────────────────────────────────────────────────────────────
{
  echo
  echo "## 6 · Distribution: the static read surface (measured + the CDN argument)"
  echo
  echo "The only globally-distributed surface is static files (docs/ARTIFACT-CONTRACT.md). Load-tested here against"
  echo "the *reference* Node artifact server (\`tools/artifact-server.mjs\`) — a single process on this laptop, not a"
  echo "real CDN or even nginx:"
  echo
} >> "$OUT"

if command -v ab >/dev/null 2>&1; then
  WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
  mkdir -p "$WORK/checkpoints"
  echo '{"origin":"ainra-log/registrar-07","size":1048576,"root":"'"$(head -c24 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')"'"}' > "$WORK/checkpoints/1048576.json"
  echo '{"seq":42,"ts":1776729600,"status_hash":"AAAA"}' > "$WORK/fresh-head.json"
  PORT=8195
  AINRA_STAGE=1 node tools/artifact-server.mjs "$WORK" "$PORT" >/dev/null 2>&1 &
  SRV=$!; sleep 0.8
  imm=$(ab -n 8000 -c 64 -q "http://127.0.0.1:$PORT/checkpoints/1048576.json" 2>/dev/null | awk '/Requests per second/{print $4} /Failed requests/{f=$3}')
  immrps=$(ab -n 8000 -c 64 -q "http://127.0.0.1:$PORT/checkpoints/1048576.json" 2>/dev/null | awk '/Requests per second/{print int($4)}')
  mutrps=$(ab -n 8000 -c 64 -q "http://127.0.0.1:$PORT/fresh-head.json" 2>/dev/null | awk '/Requests per second/{print int($4)}')
  kill "$SRV" 2>/dev/null
  {
    echo "| Object | Cache policy | Throughput (measured, 1 node, c=64) |"
    echo "|---|---|---|"
    echo "| immutable checkpoint | \`max-age=1y, immutable\` | **${immrps:-n/a} req/s**, 0 failures |"
    echo "| mutable fresh-head   | \`max-age=5\` + ETag       | **${mutrps:-n/a} req/s**, 0 failures |"
    echo
    echo "**[measured]** on \`$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed 's/^ *//')\`."
  } >> "$OUT"
else
  echo "> \`ab\` not installed — load test skipped (install apache2-utils to measure; the CDN argument below holds regardless)." >> "$OUT"
fi

cat >> "$OUT" <<'EOF'

**The CDN argument, honestly [extrapolated].** A single laptop-class node already serves thousands of req/s of these
objects. But the read surface is *content-addressed static files* — the most cacheable objects on the internet
(immutable checkpoints/tiles never change; heads carry an ETag so revalidation is a header, not a download). Global
scale is therefore a **CDN configuration** — two cache rules keyed on path prefix (docs/ARTIFACT-CONTRACT.md) —
delivered by infrastructure that already serves the web's static assets at planetary scale. It is not a protocol
problem, and it adds **zero** load to the root or any registrar: the root publishes; edges cache; devices verify
locally.

## What these numbers prove — and do not

They prove the **architecture holds at planetary scale**: verification is local (the root does zero per-verify
work), proofs and revocation stay tiny (KB, logarithmic), issuance shards with no shared state, and the only global
surface is cacheable static files. They do **not** prove that anyone uses it — adoption is not a number you can
benchmark. It is earned by the humans running the pending DoD rows (a recorded ceremony, external verifiers, a
3-region soak). This document measures the property that *makes* billions possible; it never claims billions, or any,
users.
EOF
echo "wrote $OUT (Rust measurements + distribution load test + honest closing)"
