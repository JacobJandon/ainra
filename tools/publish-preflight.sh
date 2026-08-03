#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# PUBLISH PREFLIGHT — everything that can be checked before the maintainer pastes a token.
#
# Publishing is the maintainer's button: this script NEVER runs `npm publish` or `twine upload`, and it holds no
# credentials. What it does is remove every reason the button could fail — versions agree, each package packs, the
# packed artifact installs into a throwaway environment and actually verifies a real conformance vector, and no
# package carries a local `file:` dependency that would break the moment a stranger installs it.
#
#   bash tools/publish-preflight.sh
#
# Exit 0 = ready to publish, and the exact commands are printed at the end. Exit 1 = something would have broken.
# Steps that genuinely need the network degrade to SKIP with the reason stated; correctness checks never degrade.
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

FAIL=0; SKIP=0; TODO=0
pass() { printf '  \033[32m[PASS]\033[0m %-24s %s\n' "$1" "$2"; }
block(){ printf '  \033[31m[BLOCK]\033[0m %-24s %s\n' "$1" "$2"; FAIL=$((FAIL+1)); }
skip() { printf '  \033[33m[SKIP]\033[0m %-24s %s\n' "$1" "$2"; SKIP=$((SKIP+1)); }
# a step the maintainer performs AT publish time — correct to leave undone in the repo, wrong to leave undone at upload
todo() { printf '  \033[36m[TODO]\033[0m %-24s %s\n' "$1" "$2"; TODO=$((TODO+1)); }
have() { command -v "$1" >/dev/null 2>&1; }
online() { [ -n "${PREFLIGHT_OFFLINE:-}" ] && return 1; curl -fsS --max-time 6 -o /dev/null https://registry.npmjs.org/-/ping 2>/dev/null; }

echo "AINRA publish preflight — npm + PyPI, everything short of the button"
echo "toolchain: $(node --version) · $(python3 --version 2>&1) · npm $(npm --version 2>/dev/null || echo '?')"
echo "────────────────────────────────────────────────────────────────"

# ── 1. one version across every package ──────────────────────────────────────────────────────────────────────────
V_SDK=$(node -p "require('$ROOT/packages/sdk-ts/package.json').version")
V_MW=$(node -p "require('$ROOT/packages/middleware/package.json').version")
V_MCP=$(node -p "require('$ROOT/packages/mcp/package.json').version")
V_PY=$(grep -m1 '^version' packages/sdk-py/pyproject.toml | sed 's/.*"\(.*\)".*/\1/')
if [ "$V_SDK" = "$V_MW" ] && [ "$V_SDK" = "$V_MCP" ] && [ "$V_SDK" = "$V_PY" ]; then
  pass "version agreement" "all four packages at $V_SDK"
else
  block "version agreement" "sdk=$V_SDK middleware=$V_MW mcp=$V_MCP py=$V_PY — they must match before a release goes out"
fi
if git rev-parse "v$V_SDK" >/dev/null 2>&1; then
  pass "tag exists" "v$V_SDK is tagged — publishing this version is publishing tagged source"
else
  block "tag exists" "no tag v$V_SDK — a package must never be published from untagged source (D-040)"
fi
if [ -z "$(git status --porcelain)" ]; then pass "clean tree" "nothing uncommitted"; else
  skip "clean tree" "working tree is dirty — publish from a clean checkout of the tag, not from here"; fi

# ── 2. npm package hygiene (what a stranger receives) ────────────────────────────────────────────────────────────
for pkg in sdk-ts middleware mcp; do
  dir="packages/$pkg"
  name=$(node -p "require('$ROOT/$dir/package.json').name")
  # a local file: dependency resolves on this machine and nowhere else — it is the classic broken first publish
  filedeps=$(node -p "const d=require('$ROOT/$dir/package.json').dependencies||{};Object.entries(d).filter(([,v])=>/^(file|link):/.test(v)).map(([k,v])=>k+'@'+v).join(', ')||''")
  if [ -n "$filedeps" ]; then
    # correct in the repo (local development resolves against the checkout), fatal on the registry — so it is a
    # publish-time step with an exact command, not a repository defect to "fix" by breaking the dev loop.
    todo "$name deps" "rewrite $filedeps → ^$V_SDK at upload time (command printed below); revert after"
  else
    pass "$name deps" "no local file:/link: dependencies"
  fi
  if [ -f "$dir/README.md" ]; then pass "$name readme" "README.md ships with the package"; else
    block "$name readme" "no README.md — the registry page would be blank for the package that is the front door"; fi
  lic=$(node -p "require('$ROOT/$dir/package.json').license||''")
  [ -n "$lic" ] && pass "$name license" "$lic" || block "$name license" "no license field"
done

# ── 3. build + pack + install the real tarball, and make it verify a real vector ──────────────────────────────────
if (cd packages/sdk-ts && npm run build) >"$WORK/build.log" 2>&1; then
  pass "sdk build" "tsc clean"
else
  block "sdk build" "npm run build failed — see $WORK/build.log"; sed -n '1,15p' "$WORK/build.log"
fi
TARBALL=""
if (cd packages/sdk-ts && npm pack --pack-destination "$WORK") >"$WORK/pack.log" 2>&1; then
  TARBALL=$(ls "$WORK"/ainra-sdk-*.tgz 2>/dev/null | head -1)
  N=$(tar tzf "$TARBALL" | wc -l)
  pass "sdk pack" "$(basename "$TARBALL") · $N files · $(du -h "$TARBALL" | cut -f1)"
  if tar tzf "$TARBALL" | grep -qE 'package/(src|test)/'; then
    block "sdk tarball" "source or tests leaked into the published tarball"
  else
    pass "sdk tarball" "dist/ + metadata only — no src, no tests"
  fi
else
  block "sdk pack" "npm pack failed — see $WORK/pack.log"
fi

if [ -n "$TARBALL" ] && online; then
  mkdir -p "$WORK/consumer"
  if (cd "$WORK/consumer" && npm init -y >/dev/null 2>&1 && npm install "$TARBALL" >"$WORK/install.log" 2>&1); then
    # The smoke that matters: the tarball a STRANGER downloads reproduces the recorded verdict on the WHOLE corpus —
    # the same runVector/expectedVerdict pair the 4-way differential uses, so a passing install is a conformant one.
    cat > "$WORK/consumer/smoke.mjs" <<'JS'
import { readFileSync, readdirSync } from "node:fs";
import { runVector, expectedVerdict } from "@ainra/sdk";
const stable = (o) => o === null || typeof o !== "object" ? JSON.stringify(o)
  : Array.isArray(o) ? `[${o.map(stable).join(",")}]`
  : `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${stable(o[k])}`).join(",")}}`;
const dir = process.argv[2];
const files = readdirSync(dir).filter((f) => f.endsWith(".json") && f !== "manifest.json");
let ok = 0, first = "";
for (const f of files) {
  const v = JSON.parse(readFileSync(`${dir}/${f}`, "utf8"));
  const got = stable(runVector(v)), want = stable(expectedVerdict(v));
  if (got === want) ok++; else if (!first) first = `${v.name}: got=${got} want=${want}`;
}
console.log(`${ok}/${files.length} vectors agree`);
if (ok !== files.length) { console.error(`first mismatch — ${first}`); process.exit(1); }
JS
    if (cd "$WORK/consumer" && node smoke.mjs "$ROOT/vectors/v1") >"$WORK/smoke.log" 2>&1; then
      pass "sdk install smoke" "packed tarball installs clean and $(cat "$WORK/smoke.log") with the recorded verdicts"
    else
      block "sdk install smoke" "the packed tarball does NOT reproduce the recorded verdicts"; sed -n '1,4p' "$WORK/smoke.log"
    fi
  else
    block "sdk install" "the packed tarball failed to install — see $WORK/install.log"
  fi
else
  skip "sdk install smoke" "${TARBALL:+no network —}${TARBALL:-nothing packed —} re-run online before publishing"
fi

# ── 4. PyPI artifacts ────────────────────────────────────────────────────────────────────────────────────────────
if python3 -c "import build" 2>/dev/null; then
  rm -rf "$WORK/pydist"
  if python3 -m build --outdir "$WORK/pydist" packages/sdk-py >"$WORK/pybuild.log" 2>&1; then
    WHL=$(ls "$WORK/pydist"/*.whl 2>/dev/null | head -1); SDIST=$(ls "$WORK/pydist"/*.tar.gz 2>/dev/null | head -1)
    if [ -n "$WHL" ] && [ -n "$SDIST" ]; then
      pass "py build" "$(basename "$SDIST") + $(basename "$WHL")"
      if python3 -c "
import zipfile,sys
bad=[n for n in zipfile.ZipFile(sys.argv[1]).namelist() if n.startswith('tests/') or '__pycache__' in n]
sys.exit(1 if bad else 0)" "$WHL"; then
        pass "py wheel" "ships only the ainra/ package — no tests, no caches"
      else
        block "py wheel" "tests or __pycache__ leaked into the wheel"
      fi
    else
      block "py build" "python -m build produced no wheel/sdist — see $WORK/pybuild.log"
    fi
  else
    block "py build" "python -m build failed — see $WORK/pybuild.log"; tail -5 "$WORK/pybuild.log"
  fi
else
  block "py build" "the 'build' module is missing — python3 -m pip install --user build"
fi
# twine is needed for both the metadata check and the upload. Most system Pythons are PEP 668 externally-managed, so
# `pip install --user twine` fails — provision it in a throwaway venv instead of telling anyone to
# --break-system-packages their OS Python.
TWINE=""; TWINE_HOW=""
if python3 -c "import twine" 2>/dev/null; then TWINE="python3 -m twine"; TWINE_HOW="system"
elif have twine; then TWINE="twine"; TWINE_HOW="on PATH"
elif online && python3 -m venv "$WORK/tw" >/dev/null 2>&1 && "$WORK/tw/bin/pip" install --quiet twine >"$WORK/tw.log" 2>&1; then
  TWINE="$WORK/tw/bin/twine"; TWINE_HOW="provisioned in a throwaway venv"
fi
if [ -n "$TWINE" ] && [ -n "${WHL:-}" ]; then
  if $TWINE check "$WORK/pydist"/* >"$WORK/twine.log" 2>&1; then
    pass "py metadata" "twine check passed ($TWINE_HOW) — long description renders, license + requires-python well formed"
  else
    block "py metadata" "twine check failed"; cat "$WORK/twine.log"
  fi
else
  skip "py metadata" "twine unavailable and could not be provisioned — see the venv recipe below"
fi
if [ -n "${WHL:-}" ] && online; then
  if python3 -m venv "$WORK/venv" >/dev/null 2>&1 && "$WORK/venv/bin/pip" install --quiet "$WHL" >"$WORK/pyinstall.log" 2>&1; then
    # Same bar as the TS side, via the wheel's OWN vector runner (the one the differential drives): every recorded
    # verdict reproduced from a clean venv that has never seen this checkout.
    cat > "$WORK/pycmp.mjs" <<'JS'
import { readFileSync, readdirSync } from "node:fs";
const stable = (o) => o === null || typeof o !== "object" ? JSON.stringify(o)
  : Array.isArray(o) ? `[${o.map(stable).join(",")}]`
  : `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${stable(o[k])}`).join(",")}}`;
const [dir, out] = process.argv.slice(2);
const got = new Map(readFileSync(out, "utf8").split("\n").filter(Boolean).map((l) => { const t = l.indexOf("\t"); return [l.slice(0, t), l.slice(t + 1)]; }));
const files = readdirSync(dir).filter((f) => f.endsWith(".json") && f !== "manifest.json");
let ok = 0, first = "";
for (const f of files) {
  const v = JSON.parse(readFileSync(`${dir}/${f}`, "utf8"));
  if (got.get(v.name) === stable(v.expect)) ok++; else if (!first) first = `${v.name}: got=${got.get(v.name)} want=${stable(v.expect)}`;
}
console.log(`${ok}/${files.length} vectors agree`);
if (ok !== files.length) { console.error(`first mismatch — ${first}`); process.exit(1); }
JS
    if "$WORK/venv/bin/python" -m ainra._vector_runner passport "$ROOT/vectors/v1" >"$WORK/pyrun.txt" 2>"$WORK/pysmoke.log" \
       && node "$WORK/pycmp.mjs" "$ROOT/vectors/v1" "$WORK/pyrun.txt" >>"$WORK/pysmoke.log" 2>&1; then
      pass "py install smoke" "wheel installs clean in a fresh venv and $(tail -1 "$WORK/pysmoke.log") with the recorded verdicts"
    else
      block "py install smoke" "the wheel does NOT reproduce the recorded verdicts"; sed -n '1,4p' "$WORK/pysmoke.log"
    fi
  else
    block "py install" "the wheel failed to install into a clean venv — see $WORK/pyinstall.log"
  fi
else
  skip "py install smoke" "no network — re-run online before publishing"
fi

# ── 5. the button ────────────────────────────────────────────────────────────────────────────────────────────────
echo "────────────────────────────────────────────────────────────────"
if [ "$FAIL" -gt 0 ]; then
  echo -e "  \033[31m$FAIL BLOCKER(S)\033[0m — fix these before pasting any token. Nothing was published."
  exit 1
fi
cat <<EOF
  $([ "$SKIP" -gt 0 ] && echo -e "\033[33mREADY (with $SKIP skipped check(s) above — read them)\033[0m" || echo -e "\033[32mREADY\033[0m") — nothing left but the button and the $TODO step(s) below. This script has published nothing.

  npm   (2FA on; use --otp=<code> if prompted)
    npm login
    cd packages/sdk-ts && npm publish --access public --provenance && cd ../..

    # @ainra/middleware depends on the sdk by path for local development; point it at the published version,
    # publish, then put the path back so the checkout keeps working:
    npm --prefix packages/middleware pkg set dependencies.@ainra/sdk=^$V_SDK
    cd packages/middleware && npm publish --access public --provenance && cd ../..
    npm --prefix packages/middleware pkg set dependencies.@ainra/sdk=file:../sdk-ts

    # @ainra/mcp stays unpublished until it is standalone-ready (RELEASING.md)

  PyPI  (prefer a Trusted Publisher from CI; a token only from a trusted machine)
    python3 -m venv ~/.venvs/ainra-publish && ~/.venvs/ainra-publish/bin/pip install build twine
    ~/.venvs/ainra-publish/bin/python -m build packages/sdk-py
    TWINE_USERNAME=__token__ TWINE_PASSWORD=<token> ~/.venvs/ainra-publish/bin/twine upload packages/sdk-py/dist/*
    # (a venv because this system Python is PEP 668 externally-managed — never --break-system-packages for this)

  after both:  npm view @ainra/sdk version   ·   pip install ainra==$V_PY   (throwaway venv, re-run the quickstart)
EOF
