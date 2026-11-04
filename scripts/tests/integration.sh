#!/usr/bin/env bash
# Exercise the shipping integration caller against a deterministic CLI fixture. Refusal, a stale
# acknowledgement and an acknowledgement without the installed effect must all fail the suite.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cat > "$WORK/busbar" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  --version) echo 'busbar 1.6.0' ;;
  --generate-signing-key) echo 'fixture-signing-key' ;;
  --validate) exit 0 ;;
  '') exec sleep 120 ;;
  *) exit 2 ;;
esac
SH
cat > "$WORK/admin" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "$1 ${2:-}" in
  'info ') echo 'busbar 1.6.0' ;;
  'keys create')
    case "$3" in
      throwaway) echo '{"id":"key2"}' ;;
      audit-only) echo '{"id":"audit","allowed_pools":[]}' ;;
      *) echo '{"id":"key1"}' ;;
    esac ;;
  'keys get') echo '{"state":"active"}' ;;
  'keys list') echo '{"items":[{"id":"key1"}]}' ;;
  'keys rotate') echo 'NEW CREDENTIAL' ;;
  'keys revoke') echo 'revoked' ;;
  'keys delete') echo 'tombstone' ;;
  'hooks list'|'plugins list') echo '{}' ;;
  'config version')
    version=1
    [ ! -f "$CALLER_STATE" ] || version=2
    printf '{"config_version":%s}\n' "$version" ;;
  'config show')
    version=1; model=''
    if [ -f "$CALLER_STATE" ]; then
      version=2
      [ "$CALLER_CASE" = no-effect ] || model=',{"model":"apply-proof","provider":"mock"}'
    fi
    printf '{"version":%s,"models":[{"model":"m","provider":"mock"}%s]}\n' "$version" "$model" ;;
  'config apply')
    touch "$CALLER_STATE.invoked"
    # Check that the caller passed deploy input, including secret REFERENCES, instead of GET's
    # redacted response. This fake does not accept an invalid request just to make the test green.
    python3 - "$3" <<'PY'
import json, sys
body = json.load(open(sys.argv[1]))
config = body['config']
assert 'version' not in config
assert config['auth']['signing_key']['file']
assert config['identity-providers']['admin-tokens']['token'] == {'env': 'BUSBAR_ADMIN_TOKEN'}
assert config['models']['apply-proof'] == {'provider': 'mock'}
assert body['providers']['mock']['protocol'] == 'anthropic'
assert body['providers']['mock']['api_key'] == {'env': 'MOCK_KEY'}
assert 'api_key_env' not in body['providers']['mock']
PY
    case "$CALLER_CASE" in
      refuse) echo 'fixture: apply always fails' >&2; exit 27 ;;
      false-ack) echo '{"applied":false,"config_version":1}'; exit 0 ;;
      stale) echo '{"applied":true,"config_version":1}'; exit 0 ;;
      success|no-effect) touch "$CALLER_STATE"; echo '{"applied":true,"config_version":2}' ;;
      *) exit 2 ;;
    esac ;;
  *) echo "unexpected admin call: $*" >&2; exit 2 ;;
esac
SH
chmod +x "$WORK/busbar" "$WORK/admin"
mkdir "$WORK/fixture-tmp"
export TMPDIR="$WORK/fixture-tmp"
mkdir "$WORK/bin"
cat > "$WORK/bin/mktemp" <<'SH'
#!/usr/bin/env bash
exec /usr/bin/mktemp -d "$TMPDIR/integration.XXXXXXXX"
SH
chmod +x "$WORK/bin/mktemp"
export PATH="$WORK/bin:$PATH"
for scenario in refuse false-ack stale no-effect success; do
  export CALLER_CASE=$scenario CALLER_STATE="$WORK/$scenario.applied"
  if bash "$ROOT/scripts/integration.sh" "$WORK/busbar" "$WORK/admin" >"$WORK/$scenario.log" 2>&1; then
    [ "$scenario" = success ] || { cat "$WORK/$scenario.log"; echo "$scenario passed unexpectedly" >&2; exit 1; }
    grep -q 'INTEGRATION OK' "$WORK/$scenario.log"
  else
    [ "$scenario" != success ] || { cat "$WORK/$scenario.log"; exit 1; }
    if grep -q 'INTEGRATION OK' "$WORK/$scenario.log"; then
      echo "$scenario claimed integration success after refusing the apply" >&2; exit 1
    fi
  fi
  [ -f "$CALLER_STATE.invoked" ] || { cat "$WORK/$scenario.log"; echo 'apply was never exercised' >&2; exit 1; }
done

[ -z "$(ls -A "$TMPDIR")" ] || { echo 'integration leaked temporary credentials' >&2; exit 1; }
# A failure before the daemon starts must also remove the generated signing key.
cat > "$WORK/invalid-busbar" <<'SH'
#!/usr/bin/env bash
case "${1:-}" in
  --version) echo 'busbar 1.6.0' ;;
  --generate-signing-key) echo 'fixture-signing-key' ;;
  --validate) exit 1 ;;
  *) exit 2 ;;
esac
SH
chmod +x "$WORK/invalid-busbar"
if bash "$ROOT/scripts/integration.sh" "$WORK/invalid-busbar" "$WORK/admin" >"$WORK/early-failure.log" 2>&1; then
  echo 'invalid config unexpectedly passed' >&2; exit 1
fi
[ -z "$(ls -A "$TMPDIR")" ] || { echo 'early failure leaked temporary credentials' >&2; exit 1; }
