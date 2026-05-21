#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Resume-Database — safe deploy
#
#  Verifies the baseline THEN deploys. Render auto-deploys on push to main,
#  so "deploy" here means: pass verifier → push to origin/main.
#
#  (The original spec mentioned `wrangler pages deploy` for Cloudflare; this
#  project explicitly stayed on Render, so the wrangler step is omitted.
#  If you ever migrate to Cloudflare Pages or Workers, this script is the
#  single place to add the wrangler call after the verifier passes.)
#
#  Usage:
#      sh scripts/safe-deploy.sh
#
#  Intentional-baseline-change bypass (only after updating CLAUDE.md and
#  scripts/verify-baseline.py to reflect the new rule):
#      FORCE=1 sh scripts/safe-deploy.sh
# ─────────────────────────────────────────────────────────────────────────────
set -e

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    echo "✗ Not inside a git repository." >&2
    exit 1
}
cd "$REPO_ROOT"

# ── 1. Branch + working tree sanity ─────────────────────────────────────────
BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$BRANCH" != "main" ]; then
    echo "✗ Safe-deploy only ships from the main branch (currently: $BRANCH)." >&2
    echo "  Switch first:  git checkout main" >&2
    exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "✗ Working tree has uncommitted changes. Commit or stash first:" >&2
    git status --short >&2
    exit 1
fi

# ── 2. Baseline verifier (skippable with FORCE=1) ───────────────────────────
if [ "${FORCE:-0}" = "1" ]; then
    echo "⚠️  FORCE=1 — skipping baseline verifier."
    echo "    You MUST have updated CLAUDE.md and scripts/verify-baseline.py"
    echo "    if you are intentionally changing the baseline."
else
    echo "▶ Running baseline verifier before deploy…"
    if ! python3 scripts/verify-baseline.py; then
        cat <<'EOF' >&2

✗ Deploy refused — baseline invariants drifted.

If this is intentional (you're updating the locked baseline):
  1. Update CLAUDE.md
  2. Update scripts/verify-baseline.py
  3. Commit those changes, then retry
  — or as a last resort —
  FORCE=1 sh scripts/safe-deploy.sh

EOF
        exit 1
    fi
fi

# ── 3. Check there's actually something to push ─────────────────────────────
git fetch origin main --quiet 2>/dev/null || true
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main 2>/dev/null || echo "")
if [ "$LOCAL" = "$REMOTE" ]; then
    echo "ℹ  origin/main is already up to date with HEAD — nothing to deploy."
    exit 0
fi

# ── 4. Push (Render auto-deploys) ───────────────────────────────────────────
echo
echo "▶ Pushing to origin/main — Render will auto-deploy."
git push origin main

cat <<'EOF'

✓ Push complete. Render is now building.
   • Dashboard:    https://dashboard.render.com
   • Live URL:     https://resume-database-ocwa.onrender.com
   • Typical deploy time: ~90 seconds for new CSS/HTML to be served.

To verify the new code is live, hard-refresh the site (Cmd+Shift+R / Ctrl+F5)
once the build completes.
EOF
