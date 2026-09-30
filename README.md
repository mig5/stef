# stef

`stef` is a standalone grep-style search tool for ordinary files **and SOPS-encrypted files**, with encrypted history that can answer a second question grep normally cannot:

> **What used to match, but does not match now?**

It is a native Rust program. It does **not** shell out to `grep` or `rg` and does not require ripgrep to be installed. Its search core is built from the same reusable Rust crates used by ripgrep: `grep-regex`, `grep-searcher`, `grep-matcher`, and `ignore`.

When stef encounters a SOPS-encrypted file it invokes the user's existing `sops` command as:

```sh
sops --decrypt FILE
```

and searches the decrypted stdout stream. Decrypted file contents are never written to a stef temporary file.

## Highlights

- one native `stef` executable; no `rg`, Python, pipx, or Poetry runtime dependency;
- searches explicit files directly and recurses into directories only with `-r` or `-R`;
- respects `.gitignore`, `.ignore`, `.git/info/exclude`, global Git ignores and `.rgignore`;
- familiar grep/ripgrep-style regex, fixed-string, case, word, line, context, glob and file-type controls;
- transparent SOPS detection and decryption inside mixed plaintext/encrypted directory trees;
- exact matching text highlighted in green on terminals;
- encrypted match history containing matched records, **not copies of whole files**;
- `stef -p` shows matches that disappeared in red and newly appearing matches in green;
- `stef -p 7d` compares current matches with everything stef saw for the same search during the last seven days;
- history master key can be wrapped to the user's local GPG secret key when PGP-backed SOPS files are searched;
- `.deb` and `.rpm` packaging metadata included.

## Installation

### From source

You need **Rust 1.88 or newer** for this release. The ripgrep-core crate versions used by stef are pinned in `Cargo.toml` so a future `ignore` update cannot silently raise that requirement. A distro-provided Rust 1.50-era toolchain is too old even to parse the manifest.

The repository includes `rust-toolchain.toml`, pinned to Rust 1.88.0 with `rustfmt` and Clippy. With rustup, install that toolchain once:

```bash
rustup toolchain install 1.88.0 --profile minimal --component rustfmt --component clippy
```

Then, from the stef checkout, rustup will select it automatically. You can verify the toolchain before building:

```bash
./packaging/check-rust-version.sh
rustc --version
cargo --version
```

On Debian 13 or another system whose packaged Rust is older, rustup is the simplest development-toolchain option:

From a stef source checkout:

```sh
cargo build --release
sudo install -m 0755 target/release/stef /usr/local/bin/stef
```

Or install the crate directly from a local checkout:

```sh
cargo install --path .
```

Plaintext searching then needs no other program.

To search SOPS-encrypted files, install [`sops`](https://github.com/getsops/sops) and configure whichever key backend those files already use. GnuPG is needed only for PGP-backed SOPS decryption or GPG-wrapped stef history.

### Debian package

The repository contains `cargo-deb` metadata:

```sh
cargo install cargo-deb
cargo build --release
cargo deb --no-build
sudo apt install ./target/debian/stef_0.1.0_*.deb
```

### RPM package

The repository also contains `cargo-generate-rpm` metadata:

```sh
cargo install cargo-generate-rpm
cargo build --release
cargo generate-rpm
sudo rpm -Uvh target/generate-rpm/stef-0.1.0-*.rpm
```

Or build both formats, the optimized standalone binary, and checksums:

```sh
./packaging/build-packages.sh
```

The helper installs the pinned packaging tools (`cargo-deb` 3.7.0 and `cargo-generate-rpm` 0.21.0) automatically when the required versions are missing. Artifacts are copied into `dist/`.

### Full release and crates.io publish

`release.sh` is the complete local release path. It refuses a dirty Git tree by default, runs the toolchain preflight, rustfmt, Clippy and tests, builds the optimized binary, DEB and RPM, validates the crates.io package with a dry-run, and only then performs the irreversible crates.io upload:

```sh
export CARGO_REGISTRY_TOKEN='your-crates-io-token'
./release.sh
```

Cargo's normal credential configuration also works, so the token does not need to be placed in the script. To exercise the entire release pipeline without uploading anything:

```sh
./release.sh --no-publish
```

The resulting `dist/` contains the native binary named with its host target triple, the `.deb`, the `.rpm`, the `.crate` source package, and `SHA256SUMS`. Published crates.io versions cannot be replaced, so the actual `cargo publish` step deliberately comes last.

`sops` and `gpg` are intentionally **not hard package dependencies**. A user who wants stef only as a fast plaintext search tool should not have to install either.

## Quick start

Search one file:

```sh
stef forgejo README.md
```

Search a directory recursively:

```sh
stef -r forgejo ~/git/mig5-devops/
```

Like GNU grep, directory recursion is opt-in. `-r` recurses without following discovered symbolic links; `-R` recurses and follows symbolic links:

```sh
stef -r forgejo inventory/
stef -R forgejo inventory/
```

Search a SOPS file exactly the same way:

```sh
stef forgejo inventory/host_vars/ashpool.mig5.net/forgejo.sops.yml
```

Given decrypted content such as:

```yaml
forgejo_postgres_password: xxxxxxxxxx
forgejo_postgres_user: forgejo
forgejo_postgres_db: forgejo
forgejo_domain: git.mig5.net
```

stef prints the matching decrypted lines while the original file remains encrypted on disk.

Search a tree containing both plaintext and encrypted files:

```sh
stef -r 'password|token' inventory/
```

## SOPS behaviour

### Detection

stef does not run SOPS over every YAML file it encounters. It first considers likely configuration formats and probes candidates for SOPS ciphertext and metadata.

Default candidate globs are:

```text
*.yaml
*.yml
*.json
*.env
.env
*.env.*
*.ini
*.sops
*.sops.*
```

Names containing `.sops.` are always candidates.

Add another candidate pattern with:

```sh
stef -r --sops-glob '*.enc' secret .
```

Disable SOPS handling completely with:

```sh
stef -r --no-sops secret .
```

### Decryption

For compatibility with old and new SOPS releases, stef uses only the longstanding interface:

```sh
sops --decrypt FILE
```

The encrypted source file is read by SOPS; its decrypted stdout is piped directly into the same native search engine used for plaintext files. stef does not create a decrypted temporary file.

Override the SOPS executable for testing or unusual installations:

```sh
STEF_SOPS=/opt/sops/bin/sops stef -r password .
```

### stdin

`-` is supported as plaintext stdin:

```sh
journalctl | stef error -
```

Transparent SOPS detection is deliberately file-oriented because using the real filename gives the broadest compatibility with older SOPS versions. For encrypted stdin, decrypt explicitly:

```sh
sops --decrypt secrets.sops.yml | stef password -
```

## Search syntax

Basic form:

```text
stef [OPTIONS] PATTERN [PATH ...]
stef [OPTIONS] -e PATTERN ... [PATH ...]
```

With no path, stef reads standard input. When `-r` or `-R` is supplied without a path, stef searches `.`. Passing a directory without `-r`/`-R` is an error, matching traditional grep-style expectations.

### Patterns and matching

| Flag | Meaning |
| --- | --- |
| `-e, --regexp PATTERN` | Add a pattern. May be repeated. |
| `-f, --file FILE` | Read one pattern per line from a file. May be repeated. |
| `-F, --fixed-strings` | Treat patterns literally instead of as regexes. |
| `-i, --ignore-case` | Case-insensitive matching. |
| `-s, --case-sensitive` | Explicitly use case-sensitive matching. |
| `-S, --smart-case` | Ignore case unless the pattern contains an uppercase literal. |
| `-w, --word-regexp` | Require matches at word boundaries. |
| `-x, --line-regexp` | Require a pattern to match the entire line. |
| `-v, --invert-match` | Report non-matching lines. |
| `-U, --multiline` | Permit a match to span lines. |
| `--multiline-dotall` | With `-U`, make `.` match newlines. |
| `--ignore-whitespace` | Enable regex extended/whitespace-insensitive mode. |
| `--swap-greed` | Swap greedy and lazy repetition behaviour. |
| `--no-unicode` | Use byte/ASCII-oriented regex behaviour where applicable. |
| `--octal` | Permit octal regex escapes. |
| `--crlf` | Use CRLF-aware line matching. |
| `--regex-size-limit BYTES` | Limit compiled regex program size. |
| `--dfa-size-limit BYTES` | Limit regex DFA cache size. |
| `--regex-nest-limit N` | Limit regex AST nesting depth. |

Examples:

```sh
# Case-insensitive
stef -r -i 'authorization' config/

# Smart case: "forgejo" ignores case, "Forgejo" does not
stef -r -S forgejo .

# Literal brackets, not regex syntax
stef -r -F 'service[0]' .

# Whole words only
stef -r -w token inventory/

# Multiple alternatives without writing one large regex
stef -r -e password -e token -e private_key .

# Patterns from a file
stef -r -f interesting-patterns.txt logs/

# Multiline search
stef -r -U 'BEGIN.*END' generated/
```

The default regex engine is Rust's regex engine through ripgrep's `grep-regex` crate. It provides Unicode-aware regular expressions and linear-time searching for its supported syntax. PCRE2-only constructs such as look-around and backreferences are not part of stef 0.1.0; see **Differences from the `rg` CLI** below.

### Context and searcher controls

| Flag | Meaning |
| --- | --- |
| `-A, --after-context N` | Show N lines after each match. |
| `-B, --before-context N` | Show N lines before each match. |
| `-C, --context N` | Show N lines before and after. |
| `--passthru` | Print matching and non-matching lines from searched files. |
| `-m, --max-count N` | Stop after N matches per file. |
| `-a, --text` | Search binary-looking input as text. |
| `-E, --encoding ENCODING` | Transcode from a named encoding before searching. |
| `--no-bom` | Disable automatic BOM-based UTF-16 detection/transcoding. |
| `--stop-on-nonmatch` | After a match, stop at the next non-match; useful for sorted data. |
| `--heap-limit BYTES` | Limit heap use in the searcher. |

Examples:

```sh
stef -r -C 3 'failed login' /var/log/
stef -A 10 '^panic:' application.log
stef -r --encoding windows-1252 café old-data/
stef -a 'magic' binary-ish-dump
```

### Recursive traversal and ignore rules

Recursive directory traversal comes from ripgrep's `ignore` crate.

By default stef:

- searches files named explicitly;
- does not descend into directory operands unless `-r` or `-R` is supplied;
- skips hidden files/directories;
- honours `.ignore`;
- honours `.gitignore`;
- honours `.git/info/exclude`;
- honours the user's global Git ignore file;
- honours `.rgignore` as a high-precedence custom ignore file;
- does not follow symbolic links.

| Flag | Meaning |
| --- | --- |
| `-r, --recursive` | Recurse into directory operands. |
| `-R` | Recursive search and follow symbolic links (GNU grep-compatible behaviour). |
| `-u, --unrestricted` | Reduce filtering. Repeat it; see below. |
| `--hidden` | Include hidden files/directories. |
| `--no-ignore` | Disable ignore-file filtering. |
| `--no-ignore-vcs` | Ignore neither `.gitignore` nor `.git/info/exclude`. |
| `--no-ignore-global` | Ignore the user's global Git ignore file. |
| `--no-ignore-parent` | Do not read ignore rules from parent directories. |
| `--no-ignore-dot` | Do not read `.ignore`. |
| `--ignore-file PATH` | Add an explicit global ignore file. May be repeated. |
| `--ignore-file-case-insensitive` | Match ignore-file globs case-insensitively. |
| `--follow` | Follow symbolic links while recursively walking (use with `-r`; `-R` enables both). |
| `--max-depth N` | Limit recursion depth. |
| `--max-filesize BYTES` | Skip files larger than the given byte count. |
| `--one-file-system` | Do not descend across filesystem boundaries. |
| `--sort path` | Return traversal/results in path order. |

`-u` follows ripgrep's useful escalating convention:

```text
-u     disable ignore rules
-uu    also include hidden files
-uuu   also search binary-looking data as text
```

Examples:

```sh
# Search ignored/vendor files too
stef -r -u FIXME .

# Include .git/, dotfiles, etc.
stef -r -uu credential .

# Search absolutely everything as text
stef -r -uuu marker .

# Follow symlinks explicitly
stef -r --follow domain /srv/config/
```

### Globs and file types

| Flag | Meaning |
| --- | --- |
| `-g, --glob GLOB` | Include/exclude using an override glob. Repeatable. Prefix with `!` for exclusion. |
| `--iglob GLOB` | Case-insensitive override glob. |
| `-t, --type TYPE` | Search a built-in/custom file type. Repeatable. |
| `-T, --type-not TYPE` | Exclude a file type. Repeatable. |
| `--type-add TYPE:GLOB` | Add or extend a file-type definition. |
| `--type-clear TYPE` | Clear an existing type definition before redefining it. |
| `--type-list` | Print available type definitions. |

Examples:

```sh
# YAML only
stef -r -g '*.yml' -g '*.yaml' password .

# Everything except generated YAML
stef -r -g '*.yaml' -g '!*.generated.yaml' token .

# Python type from the ignore crate's defaults
stef -r -t py TODO .

# Define an Ansible-ish type
stef -r --type-add 'ansible:*.yml' -t ansible become_user .

# Replace a built-in type definition
stef -r --type-clear yaml --type-add 'yaml:*.yaml' -t yaml secret .

# Inspect all current definitions
stef --type-list
```

## Output

In a terminal, exact matched substrings are highlighted in green. Context lines are visually subdued. Multiple matching files use headings by default.

| Flag | Meaning |
| --- | --- |
| `-n, --line-number` | Show line numbers; this is the normal stef presentation. |
| `-N, --no-line-number` | Hide line numbers. |
| `-H, --with-filename` | Always show filenames on each non-heading line. |
| `-I, --no-filename` | Suppress filenames on result lines. |
| `--heading` / `--no-heading` | Force grouped headings on/off. |
| `-o, --only-matching` | Print only matched substrings. |
| `-b, --byte-offset` | Include absolute byte offsets. |
| `--column` | Include first-match column. |
| `--vimgrep` | Print `path:line:column:text`. |
| `-c, --count` | Print matching-line count per file. |
| `--count-matches` | Print submatch count per file. |
| `-l, --files-with-matches` | Print only filenames containing matches. |
| `-L, --files-without-match` | Print only filenames without matches. |
| `-q, --quiet` | Suppress normal output; use exit status. |
| `--files` | List files that traversal would search. |
| `--json` | Emit newline-delimited match/summary JSON. |
| `--stats` | Print search statistics on stderr. |
| `--no-messages` | Suppress non-fatal diagnostics. |
| `--color auto|always|never` | Control ANSI colour. |

Examples:

```sh
stef -r --no-heading forgejo inventory/
stef -r -l password .
stef -r -c TODO src/
stef -r --vimgrep FIXME .
stef -r --json 'ERROR|WARN' logs/ > matches.jsonl
stef -r --files -t yaml inventory/
```

Exit codes follow grep convention:

```text
0   at least one match
1   no matches
2   an error occurred
```

## Match history

Every normal search is remembered unless `--no-history` is supplied.

The important security property is that stef does **not** snapshot files. It stores only the records the search returned, together with enough command metadata to identify and replay that search.

Pure presentation switches such as colour, headings, line-number display, JSON/count modes and `--stats` are excluded from the remembered search identity, so changing how results are displayed does not create a different historical search.

Suppose this is currently present:

```yaml
database_password: alpha
```

Run:

```sh
stef -r database_password inventory/
```

Later the file becomes:

```yaml
database_password: beta
```

Now run:

```sh
stef -p -r database_password inventory/
```

The output is diff-like:

```diff
@@ inventory/group_vars/all/secrets.sops.yml @@
-     12 │ database_password: alpha
+     12 │ database_password: beta
```

The removed historical match is red and the current addition is green on a colour terminal.

### Repeat the last remembered search

You do not need to type the pattern/path again:

```sh
stef -p
```

This loads the most recent search, returns to the working directory in which it originally ran, reruns it, and compares its current result with the most recent **distinct** earlier match state.

That “distinct” detail means this remains useful:

```sh
stef -r password .
# files change
stef -r password .        # accidentally refresh history first
stef -p                # still finds the older distinct state
```

### Time windows

Pass a duration directly to `-p`:

```sh
stef -p 30m -r password .
stef -p 12h -r token config/
stef -p 7d -r forgejo inventory/
stef -p 2w -r credential .
```

Units are:

```text
m   minutes
h   hours
d   days
w   weeks
```

`stef -p 7d` considers **all remembered snapshots of that exact search during the last seven days**. It builds the historical set of matches seen anywhere in that window and compares that with the current state.

For example, if the week contained:

```text
password: alpha
password: beta
password: gamma
```

and today contains only:

```text
password: delta
```

then the pass can show the old values as removals and `delta` as an addition.

If the literal pattern you want to search is itself duration-like, terminate option parsing:

```sh
stef -p -r -- 7d .
```

### Line movement is not a change

Historical identity is based on **path + matched line text**, not line number. If an unchanged match moves from line 12 to line 97 because unrelated content was inserted above it, stef does not report a false removal/addition.

### History commands

```sh
# Search but do not retain this run
stef -r --no-history password .

# Show recent commands and metadata; stored match text is not printed
stef --history

stef --history --history-limit 50

# Put history/state somewhere else
stef -r --state-dir /secure/state password .

# Remove all snapshots and compact the SQLite DB
stef --clear-history
```

`--state-dir DIR` overrides the history/state directory for that invocation. `STEF_STATE_DIR` provides the same setting through the environment.

## History encryption

Default state directory:

```text
$STEF_STATE_DIR                     if set
$XDG_STATE_HOME/stef               otherwise, if set
~/.local/state/stef                otherwise
```

The directory is created mode `0700` on Unix. History files are mode `0600`.

The database contains encrypted payloads. Match text, paths, working directories and remembered commands are serialized then encrypted with ChaCha20-Poly1305 using a random 256-bit master key. Search identities stored outside the ciphertext are keyed BLAKE3 hashes, so the regex/pattern is not left as a plaintext index column.

### GPG-backed master key

When stef searches a PGP-backed SOPS file, it can read the PGP fingerprints from the **encrypted SOPS metadata** without exposing values. stef checks those fingerprints against the local GPG secret keyring. If a matching local secret key exists, the random stef history master key is stored only as:

```text
history.key.gpg
```

The SQLite records remain ChaCha20-Poly1305 ciphertext. GPG wraps the one small master key rather than being invoked for every match record.

This gives efficient database access while removing a plaintext history key from disk.

If a previous local `history.key` exists and a usable SOPS PGP recipient is later discovered, stef wraps that same key with GPG and removes the local plaintext key. Existing history remains readable.

Select a history key explicitly:

```sh
stef -r --history-gpg-recipient 0123456789ABCDEF... password .
```

or by any selector GPG accepts that resolves to a local secret key:

```sh
stef -r --history-gpg-recipient me@example.net password .
```

Environment equivalent:

```sh
export STEF_HISTORY_GPG_RECIPIENT='me@example.net'
```

Multiple explicit recipients may be supplied.

Override the GPG executable with:

```sh
STEF_GPG=/usr/local/bin/gpg stef -r password .
```

### age-only SOPS users

A user decrypting SOPS with age does not necessarily have a GPG key. In that case stef keeps a random local `history.key` with mode `0600` inside the mode-`0700` state directory.

This local key protects the SQLite history if the DB is copied independently. Like any local application secret, it does not protect against an attacker who can read both the database and the key as the user.

A future backend can wrap the same master key with age without changing the database format.

## Why not just use `sops -d | grep`?

For one file, this works:

```sh
sops -d secrets.sops.yml | grep password
```

The purpose of stef is the larger workflow:

```sh
stef -r password infrastructure/
```

where the tree might contain hundreds of ordinary files plus several encrypted SOPS files, ignore rules should work naturally, context and type/glob controls are useful, and historical matching should still work.

## Relationship to ripgrep

The first stef prototype drove the `rg` executable as a subprocess. That gave excellent searching immediately, but it also meant asking users to install a second search program and created CLI conflicts—most notably GNU grep's `-r` means recursive while ripgrep's `-r` means replacement text.

0.1.0 removes that runtime dependency.

The native implementation embeds reusable crates from the ripgrep project:

- **`grep-regex`** — construction of the default regex matcher;
- **`grep-matcher`** — common matcher interface and exact submatch ranges;
- **`grep-searcher`** — efficient line-oriented search, line numbers, context, inversion, binary detection, transcoding and multiline search;
- **`ignore`** — recursive traversal, ignore files, globs and file types.

So stef is not reimplementing a regex engine or filesystem walker from scratch, while the user still receives one `stef` binary.

## Differences from the `rg` CLI

The crates expose the underlying machinery; they do not automatically provide every option in ripgrep's command-line program. stef 0.1.0 deliberately implements the subset that fits its purpose and documents it above.

Notable `rg` CLI features **not** currently implemented include:

- `-P/--pcre2` and automatic PCRE2 switching;
- replacement output (`-r/--replace`) — in stef, `-r` is intentionally recursive;
- arbitrary external `--pre` preprocessors — SOPS is a first-class stef integration instead;
- compressed-file searching (`-z/--search-zip`);
- ripgrep configuration files and every formatting switch;
- parallel search worker controls such as `--threads`;
- every ripgrep sorting/preprocessing/engine-selection option.

Those omissions are intentional rather than silently forwarded somewhere: there is no `rg` process underneath stef.

## Security notes

SOPS-aware searching can print secrets to your terminal, shell scrollback, terminal recording, CI log, redirected file, clipboard, or another process. stef protects its own persisted history; it cannot make displayed secrets non-secret.

Useful controls include:

```sh
# One-off search without persisted match history
stef -r --no-history password secrets/

# Machine check without displaying a value
stef -r -q 'known-marker' secrets/

# Remove stef history
stef --clear-history
```

The SOPS child process inherits the user's normal SOPS/GPG/age/KMS environment. stef does not copy private keys or implement SOPS cryptography itself.

## Environment variables

| Variable | Purpose |
| --- | --- |
| `STEF_STATE_DIR` | Override the history state directory. |
| `STEF_HISTORY_GPG_RECIPIENT` | Comma-separated GPG history-key recipients. |
| `STEF_SOPS` | Override the `sops` executable. |
| `STEF_GPG` | Override the `gpg` executable. |
| `NO_COLOR` | Disable automatic ANSI colour. |
| `XDG_STATE_HOME` | Standard fallback base for history. |

## Forgejo Actions

Two Forgejo workflows are included under `.forgejo/workflows/`:

- **`test.yml`** runs on `docker.io/library/debian:13`, installs Debian's `rustup`, selects Rust 1.88.0, runs `make check`, builds the release binary, verifies the opt-in `-r`/`-R` recursion behaviour, and performs a real SOPS+age decrypt/search smoke test.
- **`build.yml`** builds and install-tests a DEB natively on Debian 13 and an RPM natively on AlmaLinux 9. Building each package on its target distribution avoids accidentally shipping an AlmaLinux RPM containing a binary linked against a newer Debian glibc. Each job uploads its native binary plus package as a Forgejo artifact.

The workflows use `runs-on: docker`, the same Debian/AlmaLinux container names as the Enroll project, and `actions/checkout@v4`. Artifact upload deliberately uses `actions/upload-artifact@v3` for Forgejo compatibility.

## Packaging and development

Useful targets:

```sh
make build
make test
make check
make release
make deb
make rpm
make packages
```

`make check` runs formatting, Clippy and tests. `make packages` produces DEB/RPM artifacts after a release build.

Project layout:

```text
src/cli.rs       CLI and grep/ripgrep compatibility parsing
src/search.rs    native matcher/searcher/traversal integration
src/sops.rs      SOPS detection, PGP metadata discovery and decryption pipe
src/history.rs   encrypted SQLite history and GPG-wrapped master key
src/diffing.rs   previous/window comparison logic
src/render.rs    normal, JSON and red/green diff output
src/model.rs     search/history data structures
```

## License

GPL 3.0 or later.
