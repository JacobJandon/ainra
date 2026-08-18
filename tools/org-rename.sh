#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Propagate a repository-owner change through every hand-authored reference, then regenerate what is derived
# and re-run the gates. Prepared for the move off a personal account — see docs/ORG-MOVE.md.
#
#   bash tools/org-rename.sh <new-owner>            # DRY RUN — prints every change, writes nothing
#   bash tools/org-rename.sh <new-owner> --apply    # writes, regenerates the site, runs the gates
#
# Deliberately NOT rewritten: CHANGELOG.md, docs/PLAN-L*.md and docs/releases/* are historical records of what was
# true when they were written. A record that silently rewrites itself is not a record — and the platform keeps the
# old URLs resolving anyway. Generated files are not touched either; `make site` regenerates them from the includes.
set -euo pipefail
cd "$(dirname "$0")/.."

OLD="${AINRA_OLD_OWNER:-JacobJandon}"
NEW="${1:-}"
APPLY="${2:-}"
[ -n "$NEW" ] || { echo "usage: bash tools/org-rename.sh <new-owner> [--apply]"; exit 2; }
[ "$NEW" != "$OLD" ] || { echo "new owner is the same as the old one ($OLD) — nothing to do"; exit 2; }

# Hand-authored files only. Everything here is a reference a human wrote and a human would expect to change.
FILES=(
  README.md ROADMAP.md SECURITY.md RELEASING.md RELEASE-VERIFY.md MAINTAINERS.md skills.md
  site/llms.txt evidence/README.md campaign/TEMPLATES.md docs/_archive/PUBLISH-AUDIT.md docs/ORG-MOVE.md
  .github/ISSUE_TEMPLATE/config.yml .github/ISSUE_TEMPLATE/verifier_divergence.yml
  packages/sdk-ts/package.json packages/middleware/package.json packages/mcp/package.json
  packages/sdk-py/pyproject.toml packages/sdk-ts/README.md packages/mcp/README.md
  site/_includes/header.html site/_includes/footer.html
  tools/export-site.sh tools/link-check.mjs
)
SKIP=(CHANGELOG.md docs/_archive/plans/PLAN-L1.md docs/_archive/plans/PLAN-L2.md docs/releases)

echo "owner: $OLD → $NEW"
echo "mode : $([ "$APPLY" = "--apply" ] && echo APPLY || echo 'DRY RUN (pass --apply to write)')"
echo "────────────────────────────────────────────────────────────────"

total=0; touched=0
for f in "${FILES[@]}"; do
  [ -f "$f" ] || { echo "  · $f — absent, skipped"; continue; }
  n=$(grep -c "$OLD" "$f" 2>/dev/null || true); n=${n:-0}
  [ "$n" -gt 0 ] || continue
  touched=$((touched+1)); total=$((total+n))
  printf "  %-52s %2d reference(s)\n" "$f" "$n"
  [ "$APPLY" = "--apply" ] && sed -i "s|$OLD|$NEW|g" "$f"
done
echo "────────────────────────────────────────────────────────────────"
echo "  $total reference(s) across $touched file(s)"
echo "  untouched by design (historical records): ${SKIP[*]}"

if [ "$APPLY" != "--apply" ]; then
  echo; echo "DRY RUN — nothing written. Re-run with --apply."; exit 0
fi

echo; echo "== regenerate everything derived =="
make site >/dev/null
echo "== gates =="
make site-check
node tools/s7-lint.mjs | tail -1
node tools/license-check.mjs | tail -1
node tools/status-consistency.mjs | tail -1

echo
echo "REMAINING references to $OLD (expected: only historical records):"
grep -rn "$OLD" --include="*.md" --include="*.json" --include="*.toml" --include="*.yml" --include="*.html" \
  --include="*.txt" --include="*.sh" --include="*.mjs" . 2>/dev/null \
  | grep -v node_modules | grep -v "^./target" | sed 's/^/  /' | head -20 || echo "  none"

cat <<EOF

NEXT, and none of it is automatic (docs/ORG-MOVE.md has the full list):
  · re-point trusted publishing on EVERY registry — each binds to an exact owner/repo + workflow path
  · restore branch protection on main; confirm Actions are enabled and secrets present
  · make preflight from a CLEAN CLONE of the new URL, not this checkout
EOF
