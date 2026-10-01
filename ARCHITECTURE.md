# How stef Works - A Code-Level Guide

This document explains the **entire Rust codebase** of `stef`, piece by piece, intended for
someone familiar with Python more so than Rust (like me!)

## What is stef?

stef is a grep-like search tool that:

1. Searches plaintext files **and** SOPS-encrypted files (by shelling out to `sops --decrypt`),
2. Remembers what matched in an **encrypted local SQLite history**,
3. Can answer *"what used to match this search, but doesn't anymore?"* (`stef -p`).

---

## Table of Contents

1. [The 30-second project map](#1-the-30-second-project-map)
2. [`src/model.rs` - the data types](#4-modelrs)
3. [`src/cli.rs` - command-line parsing](#5-clirs)
4. [`src/sops.rs` - detecting and decrypting SOPS files](#6-sopsrs)
5. [`src/search.rs` - the search engine](#7-searchrs)
6. [`src/diffing.rs` - comparing two searches](#8-diffingrs)
7. [`src/history.rs` - the encrypted history database](#9-historyrs)
8. [`src/render.rs` - printing output](#10-renderrs)
9. [`src/main.rs` - tying it all together](#11-mainrs)
10. [Two complete run-throughs](#12-two-complete-run-throughs)
11. [Rust glossary (quick reference)](#13-glossary)

---

## 1. The 30-second project map

```
src/
├── main.rs        orchestrator: decides what the user asked for and calls the others
├── cli.rs         parses command-line flags (like Python's argparse, but declarative)
├── model.rs       plain data structures: what a match/result looks like
├── sops.rs        detects SOPS-encrypted files, extracts PGP fingerprints, runs `sops --decrypt`
├── search.rs      the actual search engine (walks dirs, runs the regex, collects matches)
├── diffing.rs     compares "old matches" vs "new matches" → added/removed lists
├── history.rs     encrypted SQLite storage + GPG key wrapping + GPG helpers
└── render.rs      all terminal output: colors, JSON, counts, diffs, history tables
```

Dependency flow (who imports whom):

```
main ──► cli ──► (clap crate)
 │       ▲
 │       │
 ├─► search ──► model, cli, sops
 │       │
 ├─► render ──► model, cli, diffing, history
 ├─► diffing ─► model
 └─► history ─► model
```

Everything else is third-party "crates" (Rust's name for packages - like pip
packages or composer packages).

---

## 2. model.rs

The smallest file - pure data definitions, no logic. Three structs shared by every
other module.

```rust
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MatchRecord {
    pub path: String,
    pub line_number: u64,
    pub byte_offset: u64,
    pub text: String,
    pub spans: Vec<(usize, usize)>,
}
```

One **match**: which file (`path`), what line (`line_number`), where in the file
(`byte_offset`), the whole line's text (`text`), and `spans` - a list of
`(start, end)` byte ranges within `text` where the pattern actually matched
(a line can match several times; `spans` is used for green highlighting).

The derives mean: match records can be copied, printed for debugging, compared with
`==` (used by the differ to detect change), and serialized to/from JSON (this is
exactly what gets encrypted into the history DB - serde turns each `MatchRecord`
into JSON first).

```rust
pub struct DisplayLine { ..., pub is_match: bool, ... }
```

A line to *print*: same data as `MatchRecord` plus `is_match` - because with
context lines (`-A`/`-B`/`-C`) or `--passthru`, printed output contains both
matching and non-matching lines. Context lines get a `-` separator and dim
color; matches get `:` and highlight.

```rust
pub struct FileResult {
    pub path: String,
    pub matches: Vec<MatchRecord>,
    pub display_lines: Vec<DisplayLine>,
    pub match_lines: u64,   // how many lines matched (for -c / --count)
    pub submatches: u64,    // how many individual pattern hits (for --count-matches)
}
```

Everything the searcher found in **one file**.

```rust
pub struct SearchResult {
    pub files: Vec<FileResult>,
    pub matches: Vec<MatchRecord>,        // flattened across all files
    pub searched_paths: Vec<String>,
    pub pgp_recipients: BTreeSet<String>, // GPG fingerprints discovered in SOPS metadata
    pub errors: Vec<String>,
    pub bytes_searched: u64,
    pub elapsed_millis: u128,
}

impl SearchResult {
    pub fn any_match(&self) -> bool {
        !self.matches.is_empty()
    }
}
```

The aggregate of a whole run. `any_match()` decides the process exit code
(0 = found, 1 = not found - grep convention).

`Default` derive gives `SearchResult::default()` - all fields empty/zero, like
`{}` in Python with defaults. That's why `run_search` starts with
`let mut result = SearchResult::default();` and fills it as it goes.

---

## 3. cli.rs

### 3.1 Declarative argument parsing with clap

```rust
#[derive(Parser, Clone, Debug)]
#[command(name = "stef", version, about = "SOPS-aware grep with encrypted match history", ...)]
pub struct Cli {
    #[arg(short = 'p', long = "pass", help = "Compare with the most recent distinct previous result")]
    pub pass: bool,
    ...
}
```

The `derive(Parser)` is the star here: clap reads the struct at compile time and
generates a complete argument parser, `--help` text, and error messages. Compare
Python's `argparse`, where you write ~40 lines of `add_argument` calls manually -
here each field *is* a flag:

- `pass: bool` → boolean flag `-p` / `--pass`
- `history_limit: usize` with `#[arg(long, default_value_t = 20)]` → `--history-limit` defaulting to 20
- `state_dir: Option<PathBuf>` with `env = "STEF_STATE_DIR"` → `--state-dir DIR`, also readable from that environment variable
- `regexp: Vec<String>` with `action = ArgAction::Append` → repeatable `-e PAT -e PAT` collects into a list
- `unrestricted: u8` with `action = ArgAction::Count` → count repetitions: `-u`, `-uu`, `-uuu` (like rg's escalating freedom levels)
- `ignore_case: bool` with `conflicts_with_all = [...]` → clap itself rejects `-i -s` combos with a nice error
- `positional: Vec<String>` → everything not starting with `-` (the PATTERN and PATHs)

`Option<String>` means the flag is optional; `Vec<...>` means repeatable.

Two hand-made enums restrict values:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ColorChoice { Auto, Always, Never }
```

`ValueEnum` makes clap accept `--color auto|always|never` and reject anything else.

### 3.2 `SearchInvocation` - separating "what to search" from "how"

```rust
pub struct SearchInvocation {
    pub patterns: Vec<String>,
    pub paths: Vec<String>,
}
```

`Cli` holds *every possible flag*; `invocation()` distills it into just patterns
and paths, applying grep-style defaults:

```rust
pub fn invocation(&self) -> Result<SearchInvocation> {
    let mut patterns = self.regexp.clone();
    for path in &self.pattern_files {
        let text = fs::read_to_string(path)
            .with_context(|| format!("reading pattern file {}", path.display()))?;
        patterns.extend(text.lines().map(ToOwned::to_owned));
    }
    ...
}
```

- Patterns come from `-e PAT` flags **plus** any `-f FILE` pattern files (one
  pattern per line - `text.lines()` is a string-splitting iterator,
  `ToOwned::to_owned` converts each borrowed `&str` line into an owned `String`).
- If no pattern was given and we're doing a real search, the **first positional
  argument becomes the pattern** and is removed from the list
  (`positional.remove(0)` - like `list.pop(0)`):
  `stef password config/` → pattern `password`, remaining positionals are paths.
- Path defaults: grep-style - if none given, `-r`-style modes search `"."`
  (current directory), otherwise `"-"` (stdin). Those are just strings at this point.

Also in the `impl Cli` block: small helper methods that resolve flag
interactions, e.g.

```rust
pub fn before_context_lines(&self) -> usize {
    self.before_context.or(self.context).unwrap_or(0)
}
```

Python: `self.before_context if self.before_context is not None else (self.context or 0)`.

`-u` expansion:

```rust
pub fn effective_hidden(&self) -> bool { self.hidden || self.unrestricted >= 2 }
pub fn effective_no_ignore(&self) -> bool { self.no_ignore || self.unrestricted >= 1 }
pub fn effective_text(&self) -> bool { self.text || self.unrestricted >= 3 }
```

(`-u` ignores ignore-files, `-uu` also searches hidden files, `-uuu` also searches binary files.)

And `validate()` for cross-flag rules clap can't easily express, e.g. "at most one
of `--count`, `--json`, `--quiet`, ..." - it counts the true booleans in an array
literal and `bail!`s if > 1.

### 3.3 The `-p 7d` duration trick

User ergonomics: `stef -p 7d password config/` should mean "pass mode with a
7-day window." But clap would see `7d` as the *pattern*, since `-p` is a boolean
flag. So `parse_compat()` rewrites argv *before* parsing:

```rust
pub fn parse_compat() -> Self {
    let raw: Vec<OsString> = std::env::args_os().collect();  // raw OS arguments
    let cooked = rewrite_pass_duration(raw);
    Self::parse_from(cooked)
}
```

`OsString` is a raw OS string (may not be valid UTF-8; `to_string_lossy()` gives a
best-effort `String` view). `rewrite_pass_duration` walks the argv list and, when
it sees `-p`, `--pass`, `-p7d`, or `--pass=7d` followed by (or containing) something
that parses as a duration, injects `--pass-window`:

```
["stef", "-p", "7d", "password", "."]
 →  ["stef", "--pass", "--pass-window", "7d", "password", "."]
```

`looks_like_duration` simply tries `parse_duration` and checks if it succeeded
(`is_ok()`), so a user searching for the literal string `7d` must use
`stef -p -- 7d .` (the `--` means "everything after this is positional" - same
convention as grep and Python's argv parsers).

`parse_duration` itself:

```rust
let (number, unit) = value.split_at(value.len() - 1);   // "7d" → ("7", "d")
let n: i64 = number.parse().with_context(...)?;         // "7" → 7, or error via ?
let seconds = match unit { "m" => 60, "h" => 3600, "d" => 86400, "w" => 604800, _ => bail!(...) };
n.checked_mul(seconds).context("duration is too large") // overflow-safe multiply
```

`checked_mul` returns `Option<i64>` (None on overflow), and anyhow's
`.context()` accepts an `Option` too, converting it into an `Err` - so overflow
becomes an error message instead of silent garbage.

### 3.4 History identity: `strip_history_controls`

For history, stef records "the same search" as *(cwd + argv)*. But two runs that
differ only in *display* options (`--json`, `--color always`, `-n`, `--stats`...)
should count as the same search. So before storing/comparing, control flags are
stripped:

```rust
pub fn history_argv_from_current() -> Vec<String> {
    strip_history_controls(std::env::args().skip(1).collect())   // skip argv[0] = program name
}
```

`strip_history_controls` is a hand-rolled loop over args (the only argv-level
parsing in the codebase that isn't clap):

- respects `--` (everything after is kept verbatim),
- removes pass-mode flags (including consuming a duration value after `-p`),
- removes output/display flags (`--json`, `-n`, `-H`, `--color always` - note it
  consumes the *value* too: `i += 2` for `--color X`),
- keeps everything else (the pattern, the paths, `-r`, `-i`, ...).

Result: `stef -p 7d secret .` and `stef --json secret .` share one history entry
stream, while `stef secret ./other` is a different search.

### 3.5 The tests at the bottom

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duration_parser() {
        assert_eq!(parse_duration("7d").unwrap(), 604800);
    }
}
```

`use super::*` imports the parent module (everything above), `unwrap()` crashes on
error which is fine in tests. `Cli::parse_from(["stef", "needle"])` builds a `Cli`
from a fake argv - clap's test-friendly entry point.

---

## 4. sops.rs

### 4.1 What is being detected

A SOPS-encrypted file is a normal YAML/JSON/ini file whose *values* were replaced
by `ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]` blobs, with a `sops:` metadata
section at the bottom. stef detects that *without parsing* - pure byte sniffing.

### 4.2 The detector

```rust
pub struct SopsDetector { globs: GlobSet }

impl SopsDetector {
    pub fn new(extra_globs: &[String]) -> Result<Self> {
        let mut builder = GlobSetBuilder::new();
        for pattern in DEFAULT_GLOBS.iter().copied()
            .chain(extra_globs.iter().map(String::as_str)) { ... }
    }
}
```

- `DEFAULT_GLOBS` is `&[&str]` - a fixed-size array of string literals. `.iter().copied()`
  yields `&str` items; `.chain(...)` glues the user's `--sops-glob` patterns onto
  the iterator (Python's `itertools.chain`).
- `String::as_str` as a function argument means "map each String to its &str view."
- `GlobSet` is a compiled matcher for many globs at once (like `fnmatch` for a
  whole list of patterns).

`is_candidate(path)` checks the whole path *and* the bare filename against the
globs, plus a special case: any filename containing `.sops.` is a candidate.

### 4.3 `probe()` - the sniffing

```rust
pub fn probe(&self, path: &Path) -> Result<SopsProbe> {
    if !self.is_candidate(path) {
        return Ok(SopsProbe { encrypted: false, pgp_fingerprints: BTreeSet::new() });
    }
    let bytes = read_probe_bytes(path)?;
    let has_enc = bytes.windows(b"ENC[AES256_GCM".len()).any(|w| w == b"ENC[AES256_GCM");
    ...
    let encrypted = has_enc && has_sops_metadata;
```

- `bytes` is `Vec<u8>` - raw bytes, not a string (files may not be UTF-8).
- `windows(n)` is a sliding-window iterator (like looking at every n-byte
  substring); `.any(...)` is Python's `any()`. Equivalent to
  `b"ENC[AES256_GCM" in data` in Python, expressed iterator-style.
- Both signals must be present (the `ENC[` marker **and** `sops:` metadata) -
  a file that merely contains the literal text `ENC[AES256_GCM` (e.g. documentation
  about SOPS!) is not treated as encrypted.
- The metadata check looks for `\nsops:`, `"sops"`, `sops_`, `[sops]`, or a
  `.sops.` filename - covering YAML, JSON, env and ini SOPS formats.

`read_probe_bytes` reads the **first 256 KiB and the last 256 KiB** of the file:

```rust
let first_len = len.min(PROBE_CHUNK as u64) as usize;   // Python: min(len, CHUNK)
file.read_exact(&mut out)?;                            // fill buffer exactly
if len > PROBE_CHUNK as u64 {
    file.seek(SeekFrom::End(-(tail_len as i64)))?;     // seek to end-minus-tail
    ...
}
```

Because SOPS metadata lives at the end of the file, and encrypted values appear
at the top. `read_exact` (not `read`) insists on filling the whole buffer -
short reads are an error.

### 4.4 PGP fingerprint harvesting

```rust
fn fp_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(...).expect("..."))
}
```

- `OnceLock` = compile-once lazy global (a thread-safe memoization). First call
  builds the regex; all later calls reuse it. Python analogue: a module-level
  lazily-initialized global.
- `'static` lifetime means the value lives for the whole program run.
- `.expect(...)` = `unwrap()` with a custom panic message (safe because the regex
  is a hard-coded constant).

The regex (`regex::bytes::Regex` - works on `&[u8]`, not just strings) captures
40–64 hex chars after `fp:`/`fp =`/`sops_pgp..._fp =` - i.e. GPG fingerprints from
the SOPS metadata, in any of the YAML/JSON/env/ini layouts. `pgp_fingerprints()`
returns them uppercased in a `BTreeSet` (sorted, deduplicated).

**Why?** These fingerprints tell stef which GPG keys the *user* already uses for
SOPS - used later to optionally wrap the history key (see history.rs).

### 4.5 Running `sops --decrypt` as a subprocess

```rust
pub struct DecryptReader {
    child: std::process::Child,     // the running process handle
    stdout: Option<ChildStdout>,    // its stdout pipe, taken out exactly once
    path: PathBuf,
}
```

`spawn_decrypt` runs `sops --decrypt FILE` with stdout piped, stderr inherited
(so SOPS's own error messages reach the user's terminal), stdin nulled.

The subtle bit - `Option<ChildStdout>` + `.take()`:

```rust
pub fn stdout(&mut self) -> Result<ChildStdout> {
    self.stdout.take().context("internal error: SOPS stdout already consumed")
}
```

`.take()` moves the value out of the `Option`, leaving `None` behind. Rust's
ownership rules make it *impossible* to read the same pipe handle twice or to
forget which component owns it - the type system encodes "this can only be taken
once." Python would need runtime checks for this; Rust gets it at compile time.

`wait()` consumes `self` (`mut self`, not `&self` or `&mut self`!): after waiting
you can never use the reader again, because it no longer exists. It returns an
error if `sops` exited non-zero.

---

## 5. search.rs

The heart. `run_search` builds three objects, then walks files:

1. `build_matcher` - the compiled regex(es)
2. `build_searcher` - *how* to search a stream (context lines, binary detection, ...)
3. `build_walker` - *which* files to visit (recursion, gitignore, globs, types)

### 5.1 `build_matcher`

```rust
let mut builder = RegexMatcherBuilder::new();
builder
    .case_insensitive(cli.ignore_case)
    .case_smart(cli.smart_case)          // case-insensitive only if pattern has no uppercase
    .fixed_strings(cli.fixed_strings)    // -F: treat pattern literally, not as regex
    ...
builder.build_many(patterns).context("building search pattern")
```

A straight mapping of CLI flags onto builder methods - every grep flag becomes one
builder call. `build_many` compiles *all* `-e` patterns into one matcher that
matches if any pattern matches. Line terminator handling: `--multiline` disables
the line concept entirely; otherwise the terminator is `\n` (or CRLF with `--crlf`).

Size limits (`--regex-size-limit` etc.) are guarded with `if let Some(limit) = ...`
- "if the user set it, apply it; else skip."

### 5.2 `build_searcher`

```rust
builder
    .invert_match(cli.invert_match)      // -v
    .line_number(true)                   // always track line numbers internally
    .before_context(...)/.after_context(...)
    .passthru(cli.passthru)              // --passthru: print every line
    .max_matches(cli.max_count)          // -m NUM
    .binary_detection(if cli.effective_text() { BinaryDetection::none() }
                      else { BinaryDetection::quit(b'\x00') });
```

`BinaryDetection::quit(b'\x00')` means "stop searching a file once a NUL byte
appears" - grep's classic binary-file behavior; `-a/--text` (or `-uuu`) disables
it. `b'\x00'` is a byte literal.

`cli.max_matches(cli.max_count)` takes an `Option<u64>` directly - "no limit" is
expressed as `None`.

### 5.3 `build_walker` - the ripgrep `ignore` crate

```rust
let mut walk = WalkBuilder::new(first);
for path in paths.iter().skip(1) { walk.add(path); }   // additional roots
walk.add_custom_ignore_filename(".rgignore");
walk.hidden(!cli.effective_hidden());
```

The walker handles recursion, symlink policy (`follow_links`), `max_depth`,
`.gitignore`/`.ignore`/global git ignores, `.rgignore`, size caps, and
same-filesystem constraints. The `--no-ignore-*` flags selectively disable each
ignore source (note the inversions: `walk.git_ignore(!cli.no_ignore_vcs)`).

Globs and file types:

```rust
let mut overrides = OverrideBuilder::new(cwd);
for glob in &cli.glob { overrides.add(glob)...? }
walk.overrides(overrides.build()?);
```

`-g/--glob` whitelist patterns; `-t/--type rust` selects file-type definitions
(`rust: *.rs`) from `TypesBuilder::add_defaults()` plus user `--type-add` rules.

One subtlety:

```rust
.max_depth(if cli.recursive_requested() { cli.max_depth } else { Some(0) })
```

Without `-r`, depth 0 = "don't descend into directories" - grep's non-recursive
behavior, implemented via the walker rather than special-casing.

### 5.4 `run_search` - the orchestration

```rust
pub fn run_search(cli: &Cli, invocation: &SearchInvocation) -> Result<SearchResult> {
    let started = Instant::now();                        // for --stats timing
    let matcher = build_matcher(cli, &invocation.patterns)?;
    let detector = SopsDetector::new(&cli.sops_glob)?;
    ...
```

**Stdin first** (searched as plaintext - SOPS decryption needs a real filename):

```rust
if paths.iter().any(|p| p == Path::new("-")) {
    let mut sink = CollectSink::new("<stdin>".to_owned(), &matcher);
    let stdin = io::stdin();
    if let Err(err) = searcher.search_reader(&matcher, stdin.lock(), &mut sink) { ... }
    result.files.push(sink.finish());
}
```

- `searcher.search_reader(&matcher, reader, &mut sink)` - the grep-searcher API:
  feed any `Read` (a file, a pipe, stdin) plus the matcher; matched lines are
  delivered to the sink's methods.
- `stdin.lock()` locks the shared stdin handle for fast reading.
- `if let Err(err) = ...` - "if the search failed, record it but keep going"
  (one unreadable file must not abort the whole run; errors accumulate in
  `result.errors` and become exit code 2).

**Then filesystem paths** via the walker:

```rust
for entry in walker.build() {
    let entry = match entry { Ok(e) => e, Err(err) => { result.errors.push(...); continue; } };
    if !entry.file_type().is_some_and(|ft| ft.is_file()) { continue; }
```

- `match entry { ... }` unpacks each walk result (walking can yield errors, e.g.
  unreadable directories) - `continue` skips to the next entry.
- `is_some_and(|ft| ft.is_file())` - `file_type()` is an `Option`; `is_some_and`
  runs the closure only if it's `Some`. Python: `ft and ft.is_file()`.

**Per-file SOPS decision:**

```rust
let probe = if cli.no_sops { None } else { Some(detector.probe(path)?) };
if let Some(probe) = &probe {
    result.pgp_recipients.extend(probe.pgp_fingerprints.iter().cloned());
}
let search_result = if probe.as_ref().is_some_and(|p| p.encrypted) {
    // encrypted → stream from `sops --decrypt`
    match spawn_decrypt(path) {
        Ok(mut decrypt) => match decrypt.stdout() {
            Ok(stdout) => {
                let searched = searcher.search_reader(&matcher, stdout, &mut sink);
                let waited = decrypt.wait();
                match (searched, waited) {
                    (Err(err), _) => Err(anyhow::anyhow!(err)),
                    (_, Err(err)) => Err(err),
                    _ => Ok(()),
                }
            }
            ...
```

Key point: for encrypted files, stef **streams `sops`'s stdout directly into the
searcher** - plaintext never touches a temp file or a full in-memory buffer.
It then checks *both* the search result and the child process's exit status,
combining either failure into one error (`anyhow::anyhow!(err)` wraps a plain
`io::Error` into anyhow's type).

Plaintext files use `searcher.search_path(&matcher, path, &mut sink)` directly.

**Finally**, sort (if `--sort path`), flatten all per-file matches into
`result.matches`, record elapsed time, return.

### 5.5 `CollectSink` - collecting results

The `grep-searcher` crate calls *your* code for each hit through the `Sink` trait
(an "observer"/callback interface):

```rust
struct CollectSink<'m> {
    path: String,
    matcher: &'m RegexMatcher,   // borrowed reference to the matcher, kept for span extraction
    result: FileResult,
}
```

The `<'m>` lifetime ties the borrowed matcher to the sink's existence.

`matched()` runs per matching line:

```rust
fn matched(&mut self, _searcher: &Searcher, mat: &SinkMatch<'_>) -> Result<bool, Self::Error> {
    let bytes = mat.bytes();
    let text = Self::clean_text(bytes);            // strip trailing \n / \r
    let spans = self.spans(bytes);                 // re-run matcher to find exact hit positions
    ...
    self.result.match_lines += 1;
    self.result.submatches += spans.len() as u64;  // usize → u64 cast
    self.result.matches.push(record);              // full record (kept for history/diffing)
    self.result.display_lines.push(DisplayLine { ..., is_match: true, ... });
    Ok(true)                                       // true = keep searching
}
```

`context()` (the trait method - not the anyhow error helper!) captures
non-matching lines shown for context, marked `is_match: false`. `binary_data()`
returns `Ok(false)` = "stop at binary data."

`spans()` re-runs the matcher over the line's bytes:

```rust
fn spans(&self, bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let _ = self.matcher.find_iter(bytes, |m| {
        spans.push((m.start(), m.end()));
        true                       // true = keep iterating matches
    });
    spans
}
```

`let _ = ...` discards the return value deliberately ("I know this returns
something and I don't need it").

`finish(self)` **consumes** the sink (takes `self`, not `&self`) and hands back the
accumulated `FileResult` - after this call the sink cannot be reused, by construction.

---

## 6. diffing.rs

Answers: "given old matches and new matches, what appeared / disappeared?"

### 6.1 Grouping by identity

```rust
fn grouped(items: &[MatchRecord]) -> BTreeMap<(String, String), Vec<MatchRecord>>
```

Groups matches by `(path, text)` - file + full line text. Line *numbers* are
deliberately excluded: if a secret moves from line 12 to line 50, that's **not a
change** (there's even a test: `movement_is_not_a_change`).

### 6.2 `diff_matches`

```rust
let common = old_items.len().min(new_items.len());  // Python: min(len(a), len(b))
old_items.drain(0..common);                         // drop the first `common` items (like del a[:common])
new_items.drain(0..common);
removed.extend(old_items);
added.extend(new_items);
```

For each identity (path+text), pair up min(count) occurrences as "unchanged";
any surplus on the old side = **removed**, surplus on the new side = **added**.
If a password's value changed, the line text differs → old text is "removed",
new text is "added". That's how changed *values* get detected, even though
SOPS hides the old ciphertext from comparison (we compare decrypted lines).

The union of keys is collected via a `BTreeMap::<(String, String), ()>::new()` -
the `()` unit type (Rust's `None`/`null`-ish placeholder value) used as a sorted
set. Then results are sorted by `(path, line_number, text)` for stable output.

### 6.3 `snapshots_equal`

```rust
let mut a: Vec<_> = left.iter().map(|m| (m.path.as_str(), m.text.as_str())).collect();
a.sort_unstable();
a == b
```

Two match sets are equal if their (path, text) multisets are equal - again
ignoring line numbers. `sort_unstable` = faster in-place sort that doesn't
preserve equal-element order (doesn't matter here).

### 6.4 `window_baseline` - for `-p 7d` windows

With a time window you compare against *many* snapshots at once. The baseline is:
**for each (path, text) identity, the maximum count ever seen in the window.**

```rust
for (identity, matches) in groups {
    if matches.len() > best.get(&identity).map_or(0, Vec::len) {
        best.insert(identity, matches);
    }
}
best.into_values().flatten().collect()
```

- `map_or(0, Vec::len)` - the count currently stored, or 0 if absent.
- `into_values().flatten()` - take all the per-identity Vecs and concatenate them
  (Python: `list(itertools.chain.from_iterable(d.values()))`).

Why "max multiplicity"? If a key appeared 3 times last week and once today,
comparing today against "one previous" would show nothing; comparing against the
historical maximum shows the 2 disappearances. The first snapshot (newest) wins
ties so line numbers stay recent.

---

## 7. history.rs

The security-critical module. It stores *matched secret lines* on disk, so it
encrypts them at rest. Architecture:

```
~/.local/state/stef/            (or $STEF_STATE_DIR / $XDG_STATE_HOME/stef)
├── history.key                 32 random bytes, chmod 600          (local mode)
├── history.key.gpg             the same key, GPG-encrypted         (gpg mode)
└── history.sqlite3             table `runs(id, created_at, signature, nonce, payload)`
```

- `signature` = BLAKE3 keyed hash of (cwd, argv) - lets us group runs of "the same
  search" *without storing the search command in plaintext*. Keyed by the same
  32-byte master key, so it's a MAC: unforgeable, and leaks only an equality
  fingerprint.
- `payload` = ChaCha20-Poly1305-encrypted JSON of `{cwd, argv, matches}`.
- `nonce` = fresh random 12 bytes per row (stored alongside).

### 7.1 Key management: `load_or_create_key`

Priority: existing `.gpg` key → existing raw key → create new.

```rust
if gpg_key_path.exists() {
    check_private_key_permissions(gpg_key_path)?;   // refuse if group/other can read
    let key = decrypt_gpg_key(gpg_key_path)?;       // run `gpg --quiet --decrypt FILE`
    if !recipients.is_empty() { write_gpg_key(gpg_key_path, &key, recipients)?; }  // re-wrap for new recipients
    return Ok(key);
}
```

- Raw key mode: read 32 bytes, verify length, chmod 600 enforced.
- **Safety check:** if a non-empty database exists but *no key file at all* -
  `bail!` "history database exists but its key is missing." Without this, a fresh
  random key would silently fail to decrypt old rows (or worse, mask the loss).
- **Upgrade path:** if a raw key exists and GPG recipients are configured, the key
  is re-wrapped to GPG and the raw file **deleted** (`fs::remove_file`).
- New key: 32 bytes from `getrandom` (a CSPRNG), written per mode.

`check_private_key_permissions` is the "paranoid chmod" check:

```rust
let mode = fs::metadata(path)?.permissions().mode() & 0o777;
if mode & 0o077 != 0 { bail!("refusing to use history key with permissions {:o}; run: chmod 600 {}", ...) }
```

`{:o}` prints the mode in octal (like `ls -l`).

### 7.2 GPG subprocess plumbing (`write_gpg_key` / `decrypt_gpg_key`)

`write_gpg_key` pipes the 32-byte key into `gpg --encrypt --recipient ...`:

```rust
let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()...;
child.stdin.as_mut().context("capturing gpg stdin")?.write_all(key)?;
drop(child.stdin.take());        // close stdin → signals gpg "input finished"
let output = child.wait_with_output()?;
```

- `child.stdin` is `Option<ChildStdin>`; `.as_mut()` converts to
  `Option<&mut ChildStdin>`, `?` unwraps it.
- `drop(...)` explicitly closes the pipe - the equivalent of closing a `Popen.stdin`
  file in Python, which gpg needs before it finishes encrypting.
- Writes to a `.tmp` file then `fs::rename` (atomic on POSIX) so a crash mid-write
  can't corrupt the key file.

`decrypt_gpg_key` is simply `gpg --quiet --decrypt PATH` with output capture;
verifies exactly 32 bytes came back.

`secret_key_fingerprint(selector)` resolves a user-supplied recipient (`--history-gpg-recipient`)
to a real **secret key** fingerprint by parsing `gpg --with-colons --list-secret-keys`
output - colon-separated fields, `sec` row followed by `fpr` row, field index 9.
This ensures the recipient is a key *this machine can decrypt with* (otherwise the
history would be unwritable-back).

`resolve_secret_gpg_recipients` maps that over a list, deduping; note the generic
signature (`I: IntoIterator<Item = S>, S: AsRef<str>`) lets callers pass Vec<String>,
slices, or iterators of either string type.

### 7.3 Encryption (`encrypt` / `decrypt`)

```rust
const AAD: &[u8] = b"stef-history-v1";
...
let mut nonce = [0u8; 12];
getrandom::getrandom(&mut nonce).context("generating history nonce")?;
let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
let encrypted = cipher.encrypt(
    Nonce::from_slice(&nonce),
    Payload { msg: &raw, aad: AAD },
).map_err(|_| anyhow::anyhow!("failed to encrypt stef history payload"))?;
```

- ChaCha20-Poly1305 is an AEAD: encryption + authentication in one. If anyone
  tampers with a row, `decrypt` fails instead of returning garbage.
- `AAD` ("additional authenticated data") is *not* encrypted but is authenticated -
  a version tag so payloads can't be silently repurposed across formats.
- `map_err(|_| ...)` maps the library's opaque error into a readable message
  (`|_|` = closure ignoring its argument).
- Encryption happens in `add()` before any SQL; decryption in `row_to_snapshot()`
  right after each row is read. The database file never sees plaintext
  (there's a test that literally greps the raw sqlite bytes for the secret string).

### 7.4 Query methods

- `add(cwd, argv, matches)` → hash signature, encrypt payload, `INSERT`, return rowid.
- `latest()` → `query_row(...).optional()?` then `.map(...).transpose()`:
  `optional()` turns "no row" from an error into `Ok(None)`; `transpose()`
  swaps `Option<Result<...>>` into `Result<Option<...>>` so `?` works. This
  two-step is the idiomatic rusqlite single-row pattern.
- `for_command(cwd, argv, limit, since)` → all snapshots for one search identity,
  newest first, optionally time- or count-limited. The `match (since, limit)`
  matches on the *tuple* of two Options - four combinations, four SQL variants
  (hand-written instead of dynamic SQL string building).
- `list_recent(limit)` → for `--history` (decrypts each row but `render_history`
  only prints counts and commands, never match text).
- `clear()` → `DELETE FROM runs` + `VACUUM` (the VACUUM matters: SQLite otherwise
  keeps deleted data in freed pages, which for a secrets database is exactly
  what you don't want).

Note `connect()` creates the DB file with `create_new(true)` + mode 0o600 and
handles the race where another stef process created it first
(`Err if err.kind() == AlreadyExists => {}` - the empty match arm means "this
error is fine, do nothing").

### 7.5 Misc helpers

- `default_state_dir()` - env var precedence: `STEF_STATE_DIR` → `XDG_STATE_HOME/stef` → `$HOME/.local/state/stef`.
- `now_unix()` - seconds since epoch; `unwrap_or_default()` (0 on clock error) keeps a broken clock from crashing the tool.
- `recipients_from_env()` - parses comma-separated `STEF_HISTORY_GPG_RECIPIENT`:
  `ok()` converts the missing-env `Err` to `Option::None`, `.into_iter().flat_map(...)`
  = "if unset, iterate nothing" then split/trim/filter per value.

---

## 8. render.rs

All printing lives here. Nothing else writes to stdout.

### 8.1 Color handling

```rust
const GREEN: &str = "\x1b[32m";
...
pub fn color_enabled(choice: ColorChoice) -> bool {
    match choice {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
    }
}
```

`is_terminal()` (from the standard `IsTerminal` trait) is the `isatty()` check -
"are we attached to a TTY or being piped?" Plus respect for the `NO_COLOR`
convention.

### 8.2 `render_search` - the mode dispatch

Early returns per output mode, in priority order: `--quiet` (nothing),
`--json`, `--files-with-matches`/`--files-without-match` (just paths),
`--count`/`--count-matches` (`path:count` lines), `--vimgrep`
(`path:line:col:text`), `--only-matching` (each hit separately).

Then the big "normal output" path, deciding **heading mode** (like `rg`:
filename as a header line when >1 file, or `path:line:text` prefixes otherwise):

```rust
let heading = if cli.no_filename { false }
    else if cli.heading { true }
    else if cli.no_heading || cli.with_filename { false }
    else { result.files.len() > 1 };
```

### 8.3 `render_line` and `highlight`

```rust
let sep = if line.is_match { ':' } else { '-' };    // grep convention: : for match, - for context
```

Prefixes are printed conditionally (path / line number / byte offset / column),
then:

```rust
fn highlight(text: &str, spans: &[(usize, usize)], color: bool) -> String
```

Walks the spans, splicing `\x1b[32m` ... `\x1b[0m` around each hit. The
defensive checks (`is_char_boundary`, `start < at` for overlapping spans) exist
because byte offsets from a matcher may not align with UTF-8 character
boundaries - slicing a Rust `&str` at a non-boundary index is a *panic*, so the
code validates instead of slicing blindly.

### 8.4 `render_diff`

```rust
let mut by_path: BTreeMap<String, (Vec<&MatchRecord>, Vec<&MatchRecord>)> = BTreeMap::new();
for m in &diff.removed { by_path.entry(m.path.clone()).or_default().0.push(m); }
```

- Groups removed/added records by path (BTreeMap keeps files alphabetically).
- `.entry(k).or_default()` - Python's `d.setdefault(k, [])`: get-or-create the
  entry; `.0`/`.1` index into the tuple.
- Output mimics `diff`: `@@ path @@` header, red `-` lines (removed), green `+`
  lines (added), line numbers right-aligned in 6 columns (`{:>6}`).

### 8.5 The rest

- `render_history` - TSV table: run id, unix time, match *count* (never text), cwd, command.
- `render_errors` / `render_stats` - stderr only, gated by `--no-messages` / `--stats`.
- `render_json` - one JSON object per match plus a final summary object,
  via `serde_json::json!({...})` (a macro building JSON values inline - like
  Python dict literals) and `serde_json::to_string`.
- `shellish_join` - quote args for display only (single-quote escaping à la POSIX shell).
- `safe_slice` - bounds- and boundary-checked substring, `None` on any doubt
  (used by `--only-matching`).

---

## 9. main.rs

The orchestrator. Small because everything is delegated.

### 9.1 `main` → `run`

```rust
fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(err) => { eprintln!("stef: {err:#}"); ExitCode::from(2) }
    }
}
```

- `main` returning a value (not `()`, Rust's "unit"/void) sets the process exit
  code. `ExitCode::from(u8)` wraps it.
- `{err:#}` prints an anyhow error with its full context chain ("context: cause").
- Unhandled errors exit **2** (grep convention: 0 found / 1 not found / 2 trouble).

### 9.2 `run()` - the decision tree

```
run():
  1. cli = Cli::parse_compat(); cli.validate()
  2. state_dir, explicit_recipients (env + --history-gpg-recipient, resolved via gpg)
  3. if --clear-history:  open store, clear, exit
     if --history:        open store, render recent snapshots, exit
     if --type-list:      print type definitions, exit
  4. pass-mode bookkeeping (below)
  5. invocation = cli.invocation()
  6. if --files: list files and exit
  7. result = search::run_search(...)   ← THE SEARCH
  8. render errors / stats
  9. if pass mode:  compare, render diff, maybe save snapshot, exit
 10. otherwise:     render matches, maybe save snapshot, exit
```

### 9.3 Pass mode's "remembered search" feature

`stef -p` with **no pattern** replays your *previous* search from history:

```rust
if cli.is_pass_mode() && !has_explicit_search {
    let latest = store.latest()?.context("no remembered stef search exists yet")?;
    history_cwd = PathBuf::from(&latest.cwd);
    std::env::set_current_dir(&history_cwd)...;     // cd back to where it ran
    let mut args = vec!["stef".to_owned()];
    args.extend(latest.argv.clone());
    let mut remembered = Cli::parse_from(args);     // re-parse the old command line!
    remembered.pass = true;
    ...
    cli = remembered;                               // adopt it wholesale
}
```

It decrypts the latest snapshot's stored argv, reconstructs the original command
line, re-parses it through clap (parsing is cheap; no need to persist a `Cli`),
overrides the current run's pass/history/color settings onto it, and swaps it in
as `cli`. So `stef -p` alone re-runs (in effect) your last search and diffs it.

### 9.4 The pass-mode comparison

```rust
let prior = if let Some(window) = cli.pass_window.as_deref() {
    let seconds = parse_duration(window)?;
    let since = now_unix().saturating_sub(seconds);
    store.for_command(&history_cwd_string, &history_argv, None, Some(since))?
} else {
    store.for_command(&history_cwd_string, &history_argv, None, None)?
};
```

- `as_deref()` turns `Option<String>` into `Option<&str>` (borrow the inner string).
- `saturating_sub` - clock can't go negative.
- Window mode → all snapshots within N seconds; plain mode → *all* history for
  this search identity.

Then three cases:

```rust
if let Some(window) = ... {
    let baseline = window_baseline(prior.iter().map(|s| s.matches.as_slice()));
    render::render_diff(&diff_matches(&baseline, &result.matches), cli.color)?;
} else if let Some(previous) = prior.iter().find(|s| !snapshots_equal(&s.matches, &result.matches)) {
    render::render_diff(&diff_matches(&previous.matches, &result.matches), cli.color)?;
} else if prior.is_empty() {
    println!("No previous snapshot for this search.");
} else {
    println!("No distinct previous match state for this search.");
}
```

- **Window mode:** baseline = historical maximum per identity, diff against now.
- **Plain mode:** `prior` is newest-first, so `.find(...)` picks the *most recent
  snapshot that differs from today's result* - consecutive identical runs are
  skipped, which is what makes `stef -p` idempotent (run it five times, diff only
  appears when reality actually changed).
- **Then** (always, unless `--no-history`) the current result is appended:
  `store.add(&history_cwd_string, &history_argv, &result.matches)?`.

Exit codes: 2 if any errors occurred, else 0/1 by match presence.

### 9.5 Recipient resolution helpers

`explicit_recipients` merges env-var + flag recipients, sorts, dedups, and
resolves them through GPG (erroring if *none* is a local secret key).
`history_recipients` picks: explicit list if given; else fingerprints discovered
in SOPS metadata during the search (so history is automatically wrapped to the
same GPG keys the user already trusts for SOPS); else fall back to the plain
local key file - with a warning to stderr if GPG inspection failed.

---

## 10. Two complete run-throughs

### Run A: `stef password config/`

1. `parse_compat` → no rewriting; `Cli` filled; `validate` passes.
2. Not `--history`/`--clear-history`/`--type-list`; not pass mode.
3. `invocation()`: positional list `["password", "config/"]` → pattern `password`,
   paths `["config/"]`. Not recursive → paths stay as given.
4. `run_search`:
   - matcher: case-sensitive regex `password`.
   - walker: root `config/`, max_depth 0 (no `-r` → files inside a directory arg
     are still searched? No - depth 0 means only `config/` itself; since it's a
     directory and not a file it's skipped, and a "is a directory (use -r)" error
     is recorded. Same as grep).
   - (With `-r`: every file under `config/` is probed by `SopsDetector`; encrypted
     ones are streamed through `sops --decrypt`, others searched directly.)
   - Each matching line → `CollectSink.matched()` → `MatchRecord` + `DisplayLine`.
5. `render_search` prints lines (filename prefixes if >1 file), green highlights.
6. History: `store.add(cwd, ["password", "config/"], matches)` - rows encrypted
   with ChaCha20Poly1305 under the local (or GPG-wrapped) key.
7. Exit code 0 (matches) / 1 (none) / 2 (errors).

### Run B: `stef -p 7d password config/` (a day later)

1. `rewrite_pass_duration` injects `--pass-window 7d`.
2. `history_argv_from_current()` records the identity argv `["password", "config/"]`
   (pass controls stripped) *before* anything else.
3. Search runs exactly as in Run A.
4. Pass mode: `parse_duration("7d") = 604800`; `since = now - 604800`;
   `for_command(cwd, ["password","config/"], None, Some(since))` fetches and
   decrypts every matching snapshot from the last 7 days.
5. `window_baseline` computes the max-multiplicity historical match set;
   `diff_matches` vs today's matches; `render_diff` prints red `-` lines for
   secrets that disappeared, green `+` for new ones.
6. Today's snapshot is stored. Exit 0/1/2.

---

## 11. Glossary

| Term          | Meaning                                                              |
|---------------|----------------------------------------------------------------------|
| crate         | a Rust package/library (pip package, composer package)               |
| `Cargo`       | Rust's build tool + package manager (pip + make)                     |
| struct        | data-only class (dataclass / DTO)                                    |
| trait         | interface + default methods (Protocol, interface)                    |
| `impl`        | implementation block: methods for a type                             |
| `enum`        | tagged union - variants can carry data                               |
| `match`       | exhaustive pattern-matching switch                                   |
| `Option<T>`   | `Some(T)` or `None` - the replacement for null                       |
| `Result<T,E>` | `Ok(T)` or `Err(E)` - explicit error returns                         |
| `?`           | propagate error / unwrap success (implicit try/except + rethrow)     |
| `bail!`       | return Err early with a message (raise)                              |
| ownership     | each value has one owner; freed when the owner leaves scope          |
| borrow        | `&T` read-only or `&mut T` exclusive temporary access                |
| `Clone`       | explicit deep copy (`.clone()`)                                      |
| `Vec<T>`      | growable list                                                        |
| `&[T]`        | borrowed read-only slice view                                        |
| `BTreeMap`    | sorted dict; `BTreeSet` sorted set                                   |
| `String`/`&str` | owned growable string / borrowed string view                       |
| `OsString`    | OS-native string (filesystem/env args, may be non-UTF-8)             |
| closure       | `|x| expr` - lambda                                                  |
| macro (`!`)   | compile-time code generation (`println!`, `json!`, `bail!`)          |
| `#[...]`      | attribute - compile-time metadata/decorator                          |
| derive        | auto-generate trait impls (`Clone`, `Serialize`, ...)                |
| lifetime      | compile-time proof a reference outlives its use (`<'a>`, `<'_>`)      |
| `pub`         | public visibility (default is private)                               |
| `mod`/`use`   | module declaration / import                                          |
| AEAD          | authenticated encryption (here: ChaCha20-Poly1305)                   |
| nonce         | single-use random value making encryption non-deterministic          |
| AAD           | extra authenticated-but-unencrypted data (here: `"stef-history-v1"`) |
| BLAKE3        | fast cryptographic hash; keyed use = MAC (here: search fingerprint)  |
| MSRV          | minimum supported Rust version                                       |

---

## Suggested reading order

1. `model.rs` - , pure data.
2. `render.rs` - plain output logic, few Rust exotica.
3. `diffing.rs` - small, real logic (maps, iterators, sorting).
4. `cli.rs` - derive-macros in action + hand-written argv wrangling.
5. `search.rs` - builder pattern, the Sink trait, subprocess streaming.
6. `history.rs` - the most Rust-flavored file: ownership, `Option` juggling, crypto, SQL.
7. `main.rs` - last, when all the pieces are familiar; it's just wiring.
