#!/usr/bin/env bash
# Retry an interrupted publication without invoking cargo or a remote service.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin" "$WORK/client/scripts" "$WORK/core"
cp "$ROOT/scripts/release-upstream.sh" "$WORK/client/scripts/"
printf '[package]\nversion = "0.2.4"\n' > "$WORK/client/Cargo.toml"
printf '{"info":{"version":"1.6.0"}}\n' > "$WORK/spec.json"
export RETRY_WORK="$WORK"
cat > "$WORK/bin/gh" <<'EOF'
#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
  if [ "$1" = --output ]; then cp "$RETRY_WORK/spec.json" "$2"; exit 0; fi
  shift
done
exit 2
EOF
cat > "$WORK/bin/git" <<'EOF'
#!/usr/bin/env bash
[ "$1" != -C ] || shift 2
printf '%s\n' "$*" >> "$RETRY_WORK/calls"
case "$1" in
  diff) exit 0 ;;
  log) echo 'release: v0.2.4 — refresh openapi.json to busbar v1.6.0' ;;
  rev-parse) exit 1 ;;
  tag|push) exit 0 ;;
  *) exit 2 ;;
esac
EOF
cat > "$WORK/client/scripts/qualify-release.sh" <<'EOF'
#!/usr/bin/env bash
echo qualified >> "$RETRY_WORK/calls"
EOF
chmod +x "$WORK/bin/gh" "$WORK/bin/git"
export PATH="$WORK/bin:$PATH"
(cd "$WORK/client" && bash scripts/release-upstream.sh v1.6.0 "$WORK/core")
grep -qx 'qualified' "$WORK/calls"
grep -qx 'tag v0.2.4' "$WORK/calls"
grep -qx 'push --atomic origin HEAD:main refs/tags/v0.2.4' "$WORK/calls"
