#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# make skills-replay — LITERALLY follow skills.md. Extract every ```bash block and run it, in document order, in one
# shell, asserting exit 0. This is the test that the agent-onboarding file is executable exactly as written — if an
# edit breaks a step, CI goes red. (The one self-referential block, `make skills-replay`, is skipped to avoid recursion.)
set -uo pipefail
cd "$(dirname "$0")/.."
STEPS="$(mktemp)"
node -e '
const fs = require("node:fs");
const md = fs.readFileSync("skills.md", "utf8");
const blocks = [...md.matchAll(/```bash\n([\s\S]*?)```/g)].map((m) => m[1]);
const runnable = blocks.filter((b) => !/skills-replay/.test(b)); // skip the self-referential block
fs.writeFileSync(process.argv[1], "set -e\n" + runnable.join("\necho \"--- next step ---\"\n"));
process.stderr.write(`extracted ${runnable.length} runnable step(s) (skipped ${blocks.length - runnable.length} self-referential) from skills.md\n`);
' "$STEPS"
echo "== replaying skills.md =="
if bash "$STEPS"; then
  rm -f "$STEPS"
  echo
  echo "✓ skills.md replays green — every step executed exactly as written"
else
  rc=$?
  echo "✗ a skills.md step failed (exit $rc) — the onboarding file is not executable as written; fix skills.md" >&2
  rm -f "$STEPS"; exit "$rc"
fi
