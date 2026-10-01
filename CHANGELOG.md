# Changelog

## 0.1.1

### Changed
- `.rgignore` renamed to `.stefignore` (ripgrep has no such file, so the old name was misleading)

### Added
- Directory operands matching an ancestor `.stefignore` or `.ignore` file are now skipped before the
  walk starts, so `stef -r pattern repo/*` respects a repo-root `.stefignore` without having to pass
  `repo` as a single root. Ignored by `--no-ignore` and `--no-ignore-parent`.

### Fixed
- SOPS stderr is now captured instead of inherited: successful decrypts are silent (no more
  "Found possibly unencrypted comment" noise), and failed decrypts surface sops's output inside
  stef's own `sops --decrypt failed for <path>` error message.


## 0.1.0

Initial release.
