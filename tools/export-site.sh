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

echo "== films and clips: copied in from outside the repository, then checked against site/media/MEDIA.sha256 =="
# The video files are not kept in git (size); MEDIA.sha256 in the repository pins their exact bytes. Missing or
# changed files stop the export before anything is pushed.
MEDIA="${AINRA_MEDIA:-$PWD/../ainra-private/site-media}"
while read -r sum path; do
  [ -n "$path" ] || continue
  if [ ! -f "$MEDIA/$path" ]; then echo "missing $MEDIA/$path (set AINRA_MEDIA to the folder that holds media/)" >&2; exit 1; fi
  mkdir -p "$WORK/site-repo/$(dirname "$path")"
  cp "$MEDIA/$path" "$WORK/site-repo/$path"
done < site/media/MEDIA.sha256
( cd "$WORK/site-repo" && sha256sum --quiet -c "$OLDPWD/site/media/MEDIA.sha256" ) || { echo "film bytes do not match site/media/MEDIA.sha256" >&2; exit 1; }
rm -f "$WORK/site-repo/media/MEDIA.sha256"
# keep the website README (not the build-internal one that make site emits)
git -C "$WORK/site-repo" checkout -q -- README.md vercel.json 2>/dev/null || true

cd "$WORK/site-repo"
if git diff --quiet && git diff --cached --quiet; then echo "no changes — website already current"; exit 0; fi
git add -A
git -c user.name="AINRA" -c user.email="dev@ainra.local" commit -q \
  -m "sync: static export from ainra @ $(git -C "$OLDPWD" rev-parse --short HEAD 2>/dev/null || echo local)"
git push -q origin main
echo "== pushed — Vercel redeploys ainra-website on push =="
