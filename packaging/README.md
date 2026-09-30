# Packaging stef

The project carries metadata for both `cargo-deb` and `cargo-generate-rpm`.
The runtime package contains a single native `/usr/bin/stef` binary plus the
README, license and man page.

Build prerequisites:

```sh
cargo install cargo-deb
cargo install cargo-generate-rpm
```

Build both package formats:

```sh
./packaging/build-packages.sh
```

Artifacts are copied into `dist/` with `SHA256SUMS`.

`sops` and `gpg` are intentionally not hard package dependencies. `stef`
works as a normal recursive search tool without them. `sops` is required only
when a searched file is actually SOPS-encrypted; `gpg` is required only when
a GPG-wrapped history key is selected or auto-detected.
