#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: required build command '$1' is not installed" >&2
    exit 1
  }
}

CARGO_DEB_VERSION="3.7.0"
CARGO_GENERATE_RPM_VERSION="0.21.0"

ensure_cargo_tool() {
  local command_name="$1"
  local crate_name="$2"
  local version="$3"
  if ! cargo "$command_name" --version 2>/dev/null | grep -Fq "$version"; then
    echo "Installing ${crate_name} ${version}..."
    cargo install "$crate_name" --version "$version" --locked
  fi
}

need cargo
need rustc
need sha256sum

./packaging/check-rust-version.sh
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked

ensure_cargo_tool deb cargo-deb "$CARGO_DEB_VERSION"
ensure_cargo_tool generate-rpm cargo-generate-rpm "$CARGO_GENERATE_RPM_VERSION"

cargo build --release --locked
cargo deb --no-build
cargo generate-rpm

name="$(sed -n 's/^name = "\([^"]*\)"/\1/p' Cargo.toml | head -n1)"
version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n1)"
host="$(rustc -vV | awk '/^host:/ { print $2 }')"

if [[ -z "$name" || -z "$version" || -z "$host" ]]; then
  echo "error: could not determine package name/version/host" >&2
  exit 1
fi

rm -rf dist
mkdir -p dist
cp "target/release/${name}" "dist/${name}-${version}-${host}"
cp target/debian/*.deb dist/
cp target/generate-rpm/*.rpm dist/

(
  cd dist
  sha256sum -- * > SHA256SUMS
)

printf 'Built artifacts:\n'
ls -lh dist/
