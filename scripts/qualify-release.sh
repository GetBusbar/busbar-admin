#!/usr/bin/env bash
# Shared by upstream refresh and tag publication. Every failure must stop the caller before it
# creates a tag or a draft release. Run from the busbar-admin checkout with the exact core sibling.
set -euo pipefail
CORE=${1:?path to the paired busbar checkout}
CORE=$(cd "$CORE" && pwd)
pin=$(tr -d ' \t\r\n' < .busbar-core)
[[ "$pin" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "invalid .busbar-core: $pin" >&2; exit 1; }
[ "$(jq -er .info.version openapi.json)" = "$pin" ] || {
  echo "openapi.json and .busbar-core disagree" >&2; exit 1;
}
paired="$CORE/crates/busbar-core-admin/src/v1/json/openapi.json"
[ -f "$paired" ] || paired="$CORE/crates/busbar/src/admin/v1/json/openapi.json"
[ -f "$paired" ] || { echo "paired core OpenAPI document is absent" >&2; exit 1; }
[ "$(jq -er .info.version "$paired")" = "$pin" ] || {
  echo "paired core spec does not match .busbar-core" >&2; exit 1;
}

# These tests read the refreshed JSON; compiling the hand-written client does not.
BUSBAR_SPEC="$PWD/openapi.json" cargo test --locked spec_contract -- --nocapture
BUSBAR_SPEC="$paired" cargo test --locked spec_contract -- --nocapture
cargo test --locked

cargo build --release --locked
if [ -f "$CORE/dist/default/Cargo.toml" ]; then
  (cd "$CORE/dist/default" && cargo build --release --locked --bin busbar)
  engine="$CORE/dist/default/target/release/busbar"
else
  (cd "$CORE" && cargo build --release --locked --bin busbar)
  engine="$CORE/target/release/busbar"
fi
bash scripts/integration.sh "$engine" "$PWD/target/release/busbar-admin"
