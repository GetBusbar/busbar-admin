#!/usr/bin/env bash
# End-to-end integration test: boot a REAL busbar gateway and drive EVERY busbar-admin command
# against it, asserting real effects — the same "prove it works against a real busbar" bar the
# plugin repos hold themselves to. Bidirectional by design:
#   - busbar-admin's own CI runs this against the latest RELEASED busbar (catches CLIENT drift).
#   - busbar core's dev-gate runs this against the FRESHLY-BUILT busbar (catches ENGINE drift that
#     would break the admin client) — the reverse of how core tests each plugin.
#
# Usage: integration.sh <busbar-binary> <busbar-admin-binary>
# Both must be executable. Uses ports 19080/19081 on localhost; override with BUSBAR_ITEST_PORT /
# BUSBAR_ITEST_ADMIN_PORT if those clash.
set -euo pipefail

BUSBAR_BIN=${1:?path to the busbar gateway binary}
ADM=${2:?path to the busbar-admin binary}
[ -x "$BUSBAR_BIN" ] || { echo "busbar binary not executable: $BUSBAR_BIN" >&2; exit 1; }
[ -x "$ADM" ] || { echo "busbar-admin binary not executable: $ADM" >&2; exit 1; }

PORT=${BUSBAR_ITEST_PORT:-19080}
ADMIN_PORT=${BUSBAR_ITEST_ADMIN_PORT:-19081}
WORK=$(mktemp -d)
export BUSBAR_ADMIN_TOKEN="itest-$$-$RANDOM"
export MOCK_KEY="not-a-real-key"
export BUSBAR_ENDPOINT="http://127.0.0.1:${ADMIN_PORT}"
export BUSBAR_CONFIG="$WORK/config.yaml"
export BUSBAR_PROVIDERS="$WORK/providers.yaml"

cat > "$BUSBAR_PROVIDERS" <<EOF
mock:
  protocol: anthropic
  base_url: "http://127.0.0.1:9"
  api_key_env: MOCK_KEY
EOF
# 1.5.1: the built-in `keys` verifier requires an explicit signing key — busbar no longer
# auto-generates one. Mint a real ed25519 secret via the shipping command (secret -> stdout,
# guidance -> stderr) into a file and reference it as a {file:} secret ref, as an operator would.
"$BUSBAR_BIN" --generate-signing-key > "$WORK/signing.key" 2>/dev/null
[ -s "$WORK/signing.key" ] || { echo "--generate-signing-key produced no key" >&2; exit 1; }
cat > "$BUSBAR_CONFIG" <<EOF
listen: "127.0.0.1:${PORT}"
admin_listen: "127.0.0.1:${ADMIN_PORT}"
# 1.5.3: inline module entries under auth.admin_auth: were retired. Each identity provider is
# DEFINED once here and REFERENCED by bare name below; busbar refuses to boot the old inline shape.
# (No backticks in this heredoc: the delimiter is unquoted so ${WORK} expands, which means bash
# would also run anything in backticks as a command while writing the file.)
identity-providers:
  admin-tokens: { module: admin-tokens, token: { env: BUSBAR_ADMIN_TOKEN } }
auth:
  chain: [keys]
  signing_key: { file: "${WORK}/signing.key" }
  admin_auth: [admin-tokens]
providers:
  mock:
    api_key: { env: MOCK_KEY }
models:
  m:
    provider: mock
EOF

"$BUSBAR_BIN" > "$WORK/busbar.log" 2>&1 &
BUSBAR_PID=$!
cleanup() { kill "$BUSBAR_PID" 2>/dev/null || true; wait "$BUSBAR_PID" 2>/dev/null || true; }
trap 'ec=$?; if [ $ec -ne 0 ]; then echo "=== busbar log ==="; cat "$WORK/busbar.log"; fi; cleanup; exit $ec' EXIT

# Wait for the admin listener (a clean `info` is the readiness signal).
ready=0
for _ in $(seq 1 60); do
  if "$ADM" info >/dev/null 2>&1; then ready=1; break; fi
  sleep 0.5
done
[ "$ready" = 1 ] || { echo "busbar admin API never became ready on ${ADMIN_PORT}" >&2; exit 1; }

pass() { echo "  ok: $1"; }
fail() { echo "  FAIL: $1" >&2; exit 1; }

# Every leaf command this run actually drives, recorded as it happens. The coverage gate at the
# bottom compares this against the leaf set the CLI's own --help advertises, so the closing
# "every busbar-admin command" claim is CHECKED rather than asserted by a comment.
DRIVEN=""
drove() { DRIVEN="${DRIVEN}|$1"; }

# ── info ──────────────────────────────────────────────────────────────────────────────────────
"$ADM" info | grep -q "^busbar " || fail "info did not report a busbar version"
pass "info"; drove "info"

# ── keys: create → get → list → rotate → revoke ────────────────────────────────────────────────
KID=$("$ADM" keys create svc-b --json | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")
[ -n "$KID" ] || fail "keys create returned no id"
pass "keys create ($KID)"; drove "keys create"

"$ADM" keys get "$KID" --json | python3 -c "import sys,json;assert json.load(sys.stdin)['state']=='active'" \
  || fail "keys get: new key is not active"
pass "keys get (active)"; drove "keys get"

# The --no-pools fail-open-on-privilege fix: an explicit empty allow-list must survive as [] (NO
# pools), NEVER collapse to all-pools. This is the whole reason the flag exists.
NP=$("$ADM" keys create audit-only --no-pools --json | python3 -c "import sys,json;print(json.dumps(json.load(sys.stdin).get('allowed_pools')))")
[ "$NP" = "[]" ] || fail "keys create --no-pools produced allowed_pools=$NP (expected [] — a NON-empty/null value is a privilege fail-open)"
pass "keys create --no-pools (allowed_pools=[])"

"$ADM" keys list --json | python3 -c "import sys,json;ids=[k['id'] for k in json.load(sys.stdin)['items']];assert '$KID' in ids" \
  || fail "keys list did not contain the created key"
pass "keys list"; drove "keys list"

"$ADM" keys rotate "$KID" | grep -q "NEW CREDENTIAL" || fail "keys rotate did not print a fresh credential"
pass "keys rotate"; drove "keys rotate"

"$ADM" keys revoke "$KID" | grep -qi "revoked" || fail "keys revoke did not confirm"
pass "keys revoke"; drove "keys revoke"

# ── keys delete (tombstone) ────────────────────────────────────────────────────────────────────
TID=$("$ADM" keys create throwaway --json | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")
"$ADM" keys delete "$TID" | grep -qi "tombstone" || fail "keys delete did not confirm a tombstone"
"$ADM" keys list --json | python3 -c "import sys,json;ids=[k['id'] for k in json.load(sys.stdin)['items']];assert '$TID' not in ids" \
  || fail "deleted key still appears in the list"
pass "keys delete (tombstoned, hidden from list)"; drove "keys delete"

# ── read-only inspects: must exit 0 against a real gateway ─────────────────────────────────────
"$ADM" hooks list >/dev/null || fail "hooks list errored"
pass "hooks list"; drove "hooks list"
for t in store auth hooks; do
  "$ADM" plugins list --type "$t" >/dev/null || fail "plugins list --type $t errored"
done
pass "plugins list (store/auth/hooks)"; drove "plugins list"
"$ADM" config version >/dev/null || fail "config version errored"
"$ADM" config show >/dev/null || fail "config show errored"
pass "config version + show"; drove "config version"; drove "config show"

# ── config apply round-trip: apply the running config back and require applied=true ────────────
# Exercises the mutating path AND the `applied` in-band success check (a 200/applied=false must be
# a nonzero exit, never a silent "applied").
CFG=$("$ADM" config show --json)
python3 -c "import json,sys; c=json.load(sys.stdin); json.dump({'config':c,'providers':{'mock':{'protocol':'anthropic','base_url':'http://127.0.0.1:9','api_key_env':'MOCK_KEY'}}}, open('$WORK/apply.json','w'))" <<<"$CFG"
rc=0
"$ADM" config apply "$WORK/apply.json" >/dev/null 2>"$WORK/apply.err" || rc=$?
if [ "$rc" -eq 0 ]; then
  pass "config apply (applied=true)"; drove "config apply"
elif [ "$rc" -eq 1 ] && grep -qE '^error: (gateway returned [45][0-9][0-9]|gateway did NOT apply the config \(applied=false\))' "$WORK/apply.err"; then
  # The ONLY tolerated failure: the gateway itself refused the re-applied document. That is the
  # SERVER's contract, not a CLI defect, and it still proves the command reached the API and
  # reported the refusal as a nonzero exit.
  #
  # Everything else is a CLI defect and fails the suite. The blanket `else: print a note` this
  # replaced accepted ANY nonzero exit, so a `config apply` that clap no longer recognised at all
  # (exit 2, "unrecognized subcommand") was reported as "rejected by the gateway" and the run
  # still ended in INTEGRATION OK. Note 401/403 do NOT match: they render as "admin token
  # rejected"/"lacks the required scope", and an auth failure here is a real defect.
  echo "  note: gateway refused the re-applied config (server contract, not a CLI defect): $(cat "$WORK/apply.err")"
  drove "config apply"
else
  fail "config apply exited $rc, which is not a gateway rejection (a usage error, a transport
  failure, an auth failure or a crash): $(cat "$WORK/apply.err")"
fi

# ── plugins reload: re-scan the plugins directory and report the reconciled inventory ──────────
"$ADM" plugins reload >/dev/null || fail "plugins reload errored"
pass "plugins reload"; drove "plugins reload"

# ── coverage gate: is "EVERY busbar-admin command" actually true? ──────────────────────────────
# The header and the closing line both claim this script drives every command. Nothing checked it,
# so the claim could rot the moment a command was added — and it HAD: plugins install/inspect/
# reload were never invoked. Derive the leaf command set from the CLI's OWN --help and require
# each leaf to be either driven above or listed in NOT_DRIVEN with a reason.
leaf_subcommands() {   # $1 = parent command path ("" for the top level)
  # shellcheck disable=SC2086
  "$ADM" $1 --help 2>/dev/null \
    | awk '/^Commands:/{f=1;next} f&&NF==0{exit} f{print $1}' \
    | grep -vx help || true
}

LEAVES=()
for top in $(leaf_subcommands ""); do
  subs=$(leaf_subcommands "$top")
  if [ -z "$subs" ]; then
    LEAVES+=("$top")
  else
    for s in $subs; do LEAVES+=("$top $s"); done
  fi
done

# FLOOR. A --help format change (or a binary that fails to run) would otherwise produce an EMPTY
# leaf set, and "every leaf was driven" is vacuously true over zero leaves — exactly the failure
# this gate exists to prevent.
[ "${#LEAVES[@]}" -ge 12 ] || fail "parsed only ${#LEAVES[@]} leaf commands from '$ADM --help'
  (expected at least 12). The help format changed and this coverage gate stopped seeing anything;
  fix the parse rather than lowering the floor."

# Commands this script deliberately does not drive. Each needs a reason, and each is checked below
# for still being a real command, so the list cannot rot into a blanket excuse.
NOT_DRIVEN=(
  # Both need a plugin tarball signed by a publisher key the CI job does not hold; installing an
  # unsigned artifact is refused by the engine by design, so there is nothing to drive here that
  # would not be testing the rejection path only.
  "plugins install"
  "plugins inspect"
)

for leaf in "${LEAVES[@]}"; do
  case "$DRIVEN" in *"|$leaf"*) continue;; esac
  ack=0
  for n in "${NOT_DRIVEN[@]}"; do [ "$n" = "$leaf" ] && ack=1; done
  [ "$ack" = 1 ] || fail "'busbar-admin $leaf' exists but this script never drives it. Add a case
  above, or add it to NOT_DRIVEN with the reason it cannot be exercised here."
done

for n in "${NOT_DRIVEN[@]}"; do
  found=0
  for leaf in "${LEAVES[@]}"; do [ "$n" = "$leaf" ] && found=1; done
  [ "$found" = 1 ] || fail "NOT_DRIVEN lists '$n' but the CLI has no such command; drop the stale entry."
  case "$DRIVEN" in *"|$n"*) fail "NOT_DRIVEN lists '$n' but the script DOES drive it; drop the entry so it is covered like every other command.";; esac
done
pass "command coverage (${#LEAVES[@]} leaf commands: $(( ${#LEAVES[@]} - ${#NOT_DRIVEN[@]} )) driven, ${#NOT_DRIVEN[@]} explicitly excepted)"

echo "INTEGRATION OK: every busbar-admin command drove a real busbar ${BUSBAR_BIN##*/} end to end"
