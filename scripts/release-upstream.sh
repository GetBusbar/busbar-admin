#!/usr/bin/env bash
# Refresh and qualify the exact upstream release before any commit, push or tag.
set -euo pipefail
unset GIT_INDEX_FILE GIT_DIR GIT_WORK_TREE
CORE_TAG=${1:?core release tag}
CORE=${2:?path to the paired core checkout}
[[ "$CORE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "core release tag must be vX.Y.Z: $CORE_TAG" >&2; exit 1;
}
CORE_VER=${CORE_TAG#v}
ROOT=$(pwd)
fresh_dir=$(mktemp -d)
fresh="$fresh_dir/openapi.json"
trap 'rm -f "$fresh"; rmdir "$fresh_dir"' EXIT
gh release download "$CORE_TAG" --repo GetBusbar/busbar \
  --pattern "busbar-openapi-v${CORE_VER}.json" --output "$fresh"
[ "$(jq -er .info.version "$fresh")" = "$CORE_VER" ] || {
  echo "downloaded spec does not match $CORE_TAG" >&2; exit 1;
}
mv "$fresh" openapi.json
printf '%s\n' "$CORE_VER" > .busbar-core
publish_release() {
  local release=$1
  if git -C "$ROOT" rev-parse -q --verify "refs/tags/$release" >/dev/null; then
    [ "$(git -C "$ROOT" rev-parse "refs/tags/$release^{commit}")" = "$(git -C "$ROOT" rev-parse HEAD)" ] || {
      echo "$release already points to a different revision" >&2; exit 1;
    }
  else
    git -C "$ROOT" tag "$release"
  fi
  git -C "$ROOT" push --atomic origin HEAD:main "refs/tags/$release"
}
if git -C "$ROOT" diff --quiet -- openapi.json .busbar-core; then
  current=$(sed -nE 's/^version = "([0-9]+\.[0-9]+\.[0-9]+)"/v\1/p' Cargo.toml | head -n1)
  if [ -n "$current" ] && [ "$(git -C "$ROOT" log -1 --format=%s)" = "release: $current — refresh openapi.json to busbar $CORE_TAG" ]; then
    bash scripts/qualify-release.sh "$CORE"
    publish_release "$current"
    echo "::notice::ensured publication of $current"
  else
    echo "::notice::spec and core pin already current -> idempotent no-op"
  fi
  exit 0
fi

bash scripts/qualify-release.sh "$CORE"

latest=$(git -C "$ROOT" tag -l 'v*' --sort=-v:refname | head -1)
[[ "$latest" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || {
  echo "cannot derive a patch release from tag $latest" >&2; exit 1;
}
next="v${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.$((10#${BASH_REMATCH[3]} + 1))"
if git -C "$ROOT" rev-parse -q --verify "refs/tags/$next" >/dev/null; then
  echo "::notice::$next already exists -> idempotent no-op"
  exit 0
fi
nver=${next#v}
sed -i -E "s/^version = \"[^\"]*\"/version = \"${nver}\"/" Cargo.toml
# Re-sync the root package entry in Cargo.lock after the version-only change.
cargo build
cargo test --locked
git -C "$ROOT" add openapi.json .busbar-core Cargo.toml Cargo.lock
git -C "$ROOT" commit -m "release: $next — refresh openapi.json to busbar $CORE_TAG"
publish_release "$next"
echo "::notice::pushed $next — release.yml will qualify and build the binaries"
