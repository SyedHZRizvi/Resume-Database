#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Resume-Database — install repo-versioned git hooks
#
#  Git stores hooks in .git/hooks/, which is per-clone and NOT versioned.
#  This script copies our versioned hooks from scripts/git-hooks/ into
#  the local .git/hooks/ so the baseline-verifier runs on every commit.
#
#  Run once after cloning, or any time scripts/git-hooks/ changes:
#      sh scripts/install-hooks.sh
# ─────────────────────────────────────────────────────────────────────────────
set -e

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    echo "✗ Not inside a git repository." >&2
    exit 1
}

SRC_DIR="$REPO_ROOT/scripts/git-hooks"
DST_DIR="$REPO_ROOT/.git/hooks"

if [ ! -d "$SRC_DIR" ]; then
    echo "✗ Missing $SRC_DIR — nothing to install." >&2
    exit 1
fi
if [ ! -d "$DST_DIR" ]; then
    echo "✗ Missing $DST_DIR — .git not initialised here?" >&2
    exit 1
fi

installed=0
for src in "$SRC_DIR"/*; do
    [ -e "$src" ] || continue
    name="$(basename "$src")"
    dst="$DST_DIR/$name"

    # If a non-symlink hook already exists, back it up before replacing
    if [ -f "$dst" ] && [ ! -L "$dst" ]; then
        backup="$dst.backup-$(date +%Y%m%d-%H%M%S)"
        mv "$dst" "$backup"
        echo "  ℹ  backed up existing $name → $(basename "$backup")"
    elif [ -L "$dst" ]; then
        rm "$dst"
    fi

    # Copy (not symlink — more portable across OSes and works in worktrees)
    cp "$src" "$dst"
    chmod +x "$dst"
    chmod +x "$src"
    echo "  ✓ installed $name"
    installed=$((installed + 1))
done

echo
echo "Installed $installed hook(s) into $DST_DIR"
echo "The baseline verifier now runs automatically on every git commit."
echo
echo "Bypass for intentional baseline changes:  git commit --no-verify"
