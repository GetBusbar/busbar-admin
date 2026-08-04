#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# rc-promote.sh — shared "one-push fleet release" helper for busbar downstream
# repos. Called by .github/workflows/release-on-upstream.yml. Three subcommands:
#
#   gate     rc-GATE: is THIS repo staged for the incoming version? i.e. does it
#            carry any  v${VERSION}-rc.*  staging tag. Emits  staged=yes|no  to
#            $GITHUB_OUTPUT. A repo with no rc tag (unchanged this train) is not
#            staged → the caller skips everything cleanly.
#
#   promote  PROMOTE qa→main by FAST-FORWARD ONLY. Never --force. If main is not
#            an ancestor of qa (someone diverged main) it FAILS LOUD — a human
#            must reconcile. If main already == qa it is a no-op (idempotent).
#            Honors DRY_RUN: when "true" it only LOGS what it would do.
#
#   cleanup  Best-effort delete of this repo's v${VERSION}-rc.* staging tags after
#            a successful final release. Non-fatal; honors DRY_RUN.
#
# Config (env, all optional except where noted):
#   VERSION      shared train version X, e.g. "1.5.2" (leading v tolerated).
#                REQUIRED for gate/cleanup.
#   DRY_RUN      "true" (default) → log only, never push/tag. "false" → armed.
#   REMOTE       default "origin"
#   QA_BRANCH    default "qa"
#   MAIN_BRANCH  default "main"
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REMOTE="${REMOTE:-origin}"
QA_BRANCH="${QA_BRANCH:-qa}"
MAIN_BRANCH="${MAIN_BRANCH:-main}"

notice() { echo "::notice::$*"; }
warn()   { echo "::warning::$*"; }
die()    { echo "::error::$*" >&2; exit 1; }
emit()   { if [ -n "${GITHUB_OUTPUT:-}" ]; then printf '%s\n' "$1" >> "$GITHUB_OUTPUT"; fi; }

cmd="${1:-}"; shift || true

case "$cmd" in
  gate)
    ver="${VERSION:-}"; ver="${ver#v}"
    [ -n "$ver" ] || die "gate: VERSION is empty — cannot rc-gate"
    pat="v${ver}-rc.*"
    # Authoritative first: ask the remote (staging tags may have been pushed by
    # another actor and not be in this shallow-ish local view).
    found="$(git ls-remote --tags "$REMOTE" "$pat" 2>/dev/null || true)"
    # Fallback to locally-known tags (release-on-upstream checks out fetch-depth:0
    # so tags are present) in case the remote query is unavailable.
    if [ -z "$found" ]; then
      found="$(git tag -l "$pat" 2>/dev/null || true)"
    fi
    if [ -n "$found" ]; then
      n="$(printf '%s\n' "$found" | grep -c . || true)"
      notice "staged for ${ver}: found ${n} ${pat} tag(s) — proceeding"
      emit "staged=yes"
    else
      notice "not staged for ${ver} (no ${pat} tag) — skipping"
      emit "staged=no"
    fi
    ;;

  promote)
    dry="${DRY_RUN:-true}"
    git fetch --quiet "$REMOTE" "$MAIN_BRANCH" "$QA_BRANCH"
    main_sha="$(git rev-parse "refs/remotes/${REMOTE}/${MAIN_BRANCH}")"
    qa_sha="$(git rev-parse "refs/remotes/${REMOTE}/${QA_BRANCH}")"
    if [ "$main_sha" = "$qa_sha" ]; then
      notice "promote: ${MAIN_BRANCH} already == ${QA_BRANCH} (${qa_sha:0:7}) — no-op (idempotent)"
      exit 0
    fi
    # FF-ONLY guard: main MUST be an ancestor of qa. If not, main has diverged
    # from qa → a fast-forward is impossible → refuse loudly (never --force).
    if ! git merge-base --is-ancestor "$main_sha" "$qa_sha"; then
      die "promote: ${MAIN_BRANCH} (${main_sha:0:7}) is NOT an ancestor of ${QA_BRANCH} (${qa_sha:0:7}) — not a fast-forward. Refusing to promote (never --force). A human must reconcile the divergence."
    fi
    if [ "$dry" = "true" ]; then
      notice "[dry-run] would fast-forward ${MAIN_BRANCH} ${main_sha:0:7} -> ${QA_BRANCH} ${qa_sha:0:7} and push ${REMOTE} ${MAIN_BRANCH} (nothing pushed)"
      exit 0
    fi
    git checkout "$MAIN_BRANCH"
    git merge --ff-only "refs/remotes/${REMOTE}/${QA_BRANCH}"
    git push "$REMOTE" "$MAIN_BRANCH"
    notice "promoted ${MAIN_BRANCH} -> ${qa_sha:0:7} (fast-forward from ${QA_BRANCH}); pushed ${REMOTE} ${MAIN_BRANCH}"
    ;;

  cleanup)
    dry="${DRY_RUN:-true}"
    ver="${VERSION:-}"; ver="${ver#v}"
    if [ -z "$ver" ]; then notice "cleanup: no VERSION — skipping"; exit 0; fi
    pat="v${ver}-rc.*"
    tags="$(git ls-remote --tags "$REMOTE" "$pat" 2>/dev/null \
              | awk '{print $2}' | sed 's#refs/tags/##; s/\^{}//' | sort -u || true)"
    if [ -z "$tags" ]; then
      notice "cleanup: no ${pat} staging tags to remove"; exit 0
    fi
    for t in $tags; do
      if [ "$dry" = "true" ]; then
        notice "[dry-run] would delete staging tag ${t} on ${REMOTE}"
      elif git push "$REMOTE" ":refs/tags/${t}"; then
        notice "deleted staging tag ${t}"
      else
        warn "cleanup: failed to delete ${t} (non-fatal)"
      fi
    done
    ;;

  *)
    die "usage: rc-promote.sh {gate|promote|cleanup}"
    ;;
esac
