#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

publish=true
allow_dirty=false

usage() {
  cat <<'USAGE'
Usage: ./release.sh [--no-publish] [--allow-dirty]

Runs the complete STEF release pipeline:
  * Rust/toolchain preflight
  * rustfmt, clippy and tests
  * optimized native binary build
  * Debian package build
  * RPM package build
  * crates.io package verification and dry-run
  * crates.io publish (unless --no-publish)
  * SHA-256 checksums in dist/

Authentication for crates.io is handled by Cargo. Prefer either:
  export CARGO_REGISTRY_TOKEN='...'
or an already configured Cargo credential provider / `cargo login`.

Options:
  --no-publish   Build and validate everything but do not upload to crates.io.
  --allow-dirty  Permit running from a Git working tree with uncommitted changes.
  -h, --help     Show this help.
USAGE
}

while (($#)); do
  case "$1" in
    --no-publish)
      publish=false
      ;;
    --allow-dirty)
      allow_dirty=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if [[ "$allow_dirty" != true ]] && [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
    echo "error: refusing to release from a dirty Git working tree" >&2
    echo "commit/stash changes first, or use --allow-dirty deliberately" >&2
    exit 1
  fi
fi

./packaging/build-packages.sh

name="$(sed -n 's/^name = "\([^"]*\)"/\1/p' Cargo.toml | head -n1)"
version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n1)"
crate="target/package/${name}-${version}.crate"

cargo_package_args=(--locked)
cargo_publish_args=(--locked)
if [[ "$allow_dirty" == true ]]; then
  cargo_package_args+=(--allow-dirty)
  cargo_publish_args+=(--allow-dirty)
fi

printf '\nVerifying crates.io package...\n'
cargo package "${cargo_package_args[@]}"
cargo publish --dry-run "${cargo_publish_args[@]}"

cp "$crate" dist/
(
  cd dist
  rm -f SHA256SUMS
  sha256sum -- * > SHA256SUMS
)

if [[ "$publish" == true ]]; then
  printf '\nPublishing %s %s to crates.io...\n' "$name" "$version"
  cargo publish "${cargo_publish_args[@]}"
else
  printf '\n--no-publish selected: crates.io upload skipped.\n'
fi

printf '\nRelease artifacts:\n'
ls -lh dist/
printf '\nChecksums:\n'
cat dist/SHA256SUMS
