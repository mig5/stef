#!/usr/bin/env bash
set -euo pipefail

required_major=1
required_minor=88

if ! command -v rustc >/dev/null 2>&1; then
  echo "error: rustc is not installed; stef requires Rust >= ${required_major}.${required_minor}" >&2
  echo "hint: install Rust with rustup, then run: rustup toolchain install 1.88.0 --profile minimal --component rustfmt --component clippy" >&2
  exit 1
fi

version=$(rustc --version | awk '{print $2}')
major=${version%%.*}
rest=${version#*.}
minor=${rest%%.*}

if [ "$major" -lt "$required_major" ] || { [ "$major" -eq "$required_major" ] && [ "$minor" -lt "$required_minor" ]; }; then
  echo "error: stef requires Rust >= ${required_major}.${required_minor}; found rustc ${version}" >&2
  echo "hint: with rustup:" >&2
  echo "  rustup toolchain install 1.88.0 --profile minimal --component rustfmt --component clippy" >&2
  echo "  rustup override set 1.88.0" >&2
  exit 1
fi

printf 'Rust toolchain OK: rustc %s\n' "$version"
