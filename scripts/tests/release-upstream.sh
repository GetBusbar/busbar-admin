#!/usr/bin/env bash
# Run the production upstream-release caller with a local download and inert Git. The contract
# command remains REAL: removing a consumed field must be the reason no tag/push is reached.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export REAL_CARGO
REAL_CARGO=$(command -v cargo)
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
export RELEASE_CALLS="$WORK/calls"
mkdir -p "$WORK/bin" "$WORK/client" "$WORK/core/crates/busbar-core-admin/src/v1/json"
cp "$ROOT/Cargo.toml" "$ROOT/Cargo.lock" "$ROOT/rust-toolchain.toml" \
  "$ROOT/.busbar-core" "$ROOT/openapi.json" "$WORK/client/"
cp -R "$ROOT/src" "$ROOT/scripts" "$WORK/client/"
cat > "$WORK/bin/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
while [ "$#" -gt 0 ]; do
  if [ "$1" = --output ]; then
    [ ! -e "$2" ] || { echo 'download output already exists' >&2; exit 2; }
    cp "$RELEASE_SPEC" "$2"; exit 0
  fi
  shift
done
exit 2
SH
cat > "$WORK/bin/git" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[ "$1" != -C ] || shift 2
printf 'git %s\n' "$*" >> "$RELEASE_CALLS"
case "$1" in
  diff) exit 1 ;;
  tag) echo v0.2.3 ;;
esac
SH
cat > "$WORK/bin/cargo" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'cargo %s\n' "$*" >> "$RELEASE_CALLS"
case "$*" in
  'test --locked spec_contract -- --nocapture') exec "$REAL_CARGO" "$@" ;;
  *) [ "$RELEASE_CASE" = integration-refusal ] || exit 28 ;;
esac
SH
chmod +x "$WORK/bin/gh" "$WORK/bin/git" "$WORK/bin/cargo"
export PATH="$WORK/bin:$PATH"
export RELEASE_SPEC="$WORK/download.json"

# Establish the positive control before interpreting any nonzero result as a contract refusal.
(cd "$WORK/client" && BUSBAR_SPEC="$ROOT/openapi.json" "$REAL_CARGO" test --locked spec_contract -- --nocapture)
for scenario in downloaded-field-removed paired-field-removed integration-refusal; do
  export RELEASE_CASE=$scenario
  : > "$RELEASE_CALLS"
  python3 - "$ROOT/openapi.json" "$RELEASE_SPEC" "$WORK/core/crates/busbar-core-admin/src/v1/json/openapi.json" "$scenario" <<'PY'
import copy, json, pathlib, sys
source, download, paired, scenario = sys.argv[1:]
spec = json.load(open(source))
spec['info']['version'] = '99.0.1'
core = copy.deepcopy(spec)
if scenario == 'downloaded-field-removed':
    del spec['components']['schemas']['ConfigApplyView']['properties']['applied']
if scenario == 'paired-field-removed':
    del core['components']['schemas']['ConfigApplyView']['properties']['applied']
pathlib.Path(download).write_text(json.dumps(spec))
pathlib.Path(paired).write_text(json.dumps(core))
PY
  if [ "$scenario" = integration-refusal ]; then
    cat > "$WORK/client/scripts/integration.sh" <<'SH'
#!/usr/bin/env bash
echo 'integration fixture refused' >> "$RELEASE_CALLS"
exit 29
SH
  fi
  if (cd "$WORK/client" && bash scripts/release-upstream.sh v99.0.1 "$WORK/core") >"$WORK/$scenario.log" 2>&1; then
    cat "$WORK/$scenario.log"; echo "$scenario created a release unexpectedly" >&2; exit 1
  fi
  if [ "$scenario" = integration-refusal ]; then
    grep -q '^integration fixture refused$' "$RELEASE_CALLS"
  else
    grep -q 'ConfigApplyView: this client models.*applied' "$WORK/$scenario.log" || {
      cat "$WORK/$scenario.log"; echo 'failure was not the actual removed-field contract' >&2; exit 1;
    }
  fi
  # The refreshed files must agree even when qualification refuses the candidate.
  [ "$(cat "$WORK/client/.busbar-core")" = 99.0.1 ]
  [ "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["info"]["version"])' "$WORK/client/openapi.json")" = 99.0.1 ]
  if grep -Eq '^git (tag|push|commit|add)( |$)' "$RELEASE_CALLS"; then
    cat "$RELEASE_CALLS"; echo 'release mutation reached after qualification refusal' >&2; exit 1
  fi
done
