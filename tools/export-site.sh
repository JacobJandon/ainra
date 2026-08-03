#!/usr/bin/env bash
# Rebuild the site and push it to the dedicated static website repo (JacobJandon/ainra-website), which Vercel
# auto-deploys. Source of truth stays THIS monorepo; the website repo is a generated static export.
#   bash tools/export-site.sh
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_URL="https://github.com/JacobJandon/ainra-website.git"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

echo "== rebuild site =="
make site >/dev/null

echo "== clone the website repo =="
git clone -q "$REPO_URL" "$WORK/site-repo"

echo "== sync built site → repo (preserve .git, README, vercel.json) =="
find "$WORK/site-repo" -mindepth 1 -maxdepth 1 ! -name .git ! -name README.md ! -name vercel.json -exec rm -rf {} +
cp -r site/. "$WORK/site-repo"/
rm -rf "$WORK/site-repo/_includes" "$WORK/site-repo/DEPLOY.md" 2>/dev/null || true
# keep the website README (not the build-internal one that make site emits)
git -C "$WORK/site-repo" checkout -q -- README.md vercel.json 2>/dev/null || true

cd "$WORK/site-repo"
if git diff --quiet && git diff --cached --quiet; then echo "no changes — website already current"; exit 0; fi
git add -A
git -c user.name="AINRA" -c user.email="dev@ainra.local" commit -q \
  -m "sync: static export from ainra @ $(git -C "$OLDPWD" rev-parse --short HEAD 2>/dev/null || echo local)"
git push -q origin main
echo "== pushed — Vercel redeploys ainra-website on push =="
