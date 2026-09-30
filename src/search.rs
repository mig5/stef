use crate::cli::{Cli, SearchInvocation, SortChoice};
use crate::model::{DisplayLine, FileResult, MatchRecord, SearchResult};
use crate::sops::{SopsDetector, spawn_decrypt};
use anyhow::{Context, Result, bail};
use grep_matcher::{LineTerminator, Matcher};
use grep_regex::{RegexMatcher, RegexMatcherBuilder};
use grep_searcher::{
    BinaryDetection, Encoding, Searcher, SearcherBuilder, Sink, SinkContext, SinkMatch,
};
use ignore::WalkBuilder;
use ignore::overrides::OverrideBuilder;
use ignore::types::TypesBuilder;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

pub fn list_types(cli: &Cli) -> Result<Vec<String>> {
    let mut builder = TypesBuilder::new();
    builder.add_defaults();
    for name in &cli.type_clear {
        builder.clear(name);
    }
    for def in &cli.type_add {
        builder
            .add_def(def)
            .with_context(|| format!("invalid --type-add {def:?}"))?;
    }
    let definitions = builder.definitions();
    Ok(definitions
        .iter()
        .map(|d| format!("{}: {}", d.name(), d.globs().join(", ")))
        .collect())
}

pub fn list_files(cli: &Cli, invocation: &SearchInvocation) -> Result<(Vec<String>, Vec<String>)> {
    let mut errors = Vec::new();
    let paths = normalized_paths(invocation);
    if !cli.recursive_requested() {
        for path in &paths {
            if path != Path::new("-") && path.is_dir() {
                errors.push(format!(
                    "{}: is a directory (use -r or -R to recurse)",
                    path.display()
                ));
            }
        }
    }
    let mut files = Vec::new();
    for entry in build_walker(cli, &paths)?.build() {
        match entry {
            Ok(entry) => {
                if entry.file_type().is_some_and(|ft| ft.is_file()) {
                    files.push(entry.path().display().to_string());
                }
            }
            Err(err) => errors.push(err.to_string()),
        }
    }
    Ok((files, errors))
}

pub fn run_search(cli: &Cli, invocation: &SearchInvocation) -> Result<SearchResult> {
    if invocation.patterns.is_empty() {
        bail!("no search pattern supplied");
    }
    let started = Instant::now();
    let matcher = build_matcher(cli, &invocation.patterns)?;
    let detector = SopsDetector::new(&cli.sops_glob)?;
    let paths = normalized_paths(invocation);
    let mut result = SearchResult::default();

    // stdin is deliberately searched as plaintext. For maximum compatibility
    // with old SOPS releases, transparent SOPS decryption requires a real file
    // name and therefore does not attempt to auto-decrypt stdin.
    if paths.iter().any(|p| p == Path::new("-")) {
        let mut searcher = build_searcher(cli)?;
        let mut sink = CollectSink::new("<stdin>".to_owned(), &matcher);
        let stdin = io::stdin();
        if let Err(err) = searcher.search_reader(&matcher, stdin.lock(), &mut sink) {
            result.errors.push(format!("stdin: {err}"));
        }
        result.files.push(sink.finish());
    }

    let fs_paths: Vec<PathBuf> = paths.into_iter().filter(|p| p != Path::new("-")).collect();
    if !cli.recursive_requested() {
        for path in &fs_paths {
            if path.is_dir() {
                result.errors.push(format!(
                    "{}: is a directory (use -r or -R to recurse)",
                    path.display()
                ));
            }
        }
    }
    if !fs_paths.is_empty() {
        let walker = build_walker(cli, &fs_paths)?;
        for entry in walker.build() {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    result.errors.push(err.to_string());
                    continue;
                }
            };
            if !entry.file_type().is_some_and(|ft| ft.is_file()) {
                continue;
            }
            let path = entry.path();
            result.searched_paths.push(path.display().to_string());
            if let Ok(meta) = entry.metadata() {
                result.bytes_searched = result.bytes_searched.saturating_add(meta.len());
            }

            let probe = if cli.no_sops {
                None
            } else {
                match detector.probe(path) {
                    Ok(probe) => Some(probe),
                    Err(err) => {
                        result.errors.push(format!("{}: {err:#}", path.display()));
                        continue;
                    }
                }
            };
            if let Some(probe) = &probe {
                result
                    .pgp_recipients
                    .extend(probe.pgp_fingerprints.iter().cloned());
            }

            let display_path = path.display().to_string();
            let mut sink = CollectSink::new(display_path.clone(), &matcher);
            let mut searcher = match build_searcher(cli) {
                Ok(s) => s,
                Err(err) => {
                    result.errors.push(format!("{}: {err:#}", path.display()));
                    continue;
                }
            };

            let search_result = if probe.as_ref().is_some_and(|p| p.encrypted) {
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
                        Err(err) => Err(err),
                    },
                    Err(err) => Err(err),
                }
            } else {
                searcher
                    .search_path(&matcher, path, &mut sink)
                    .map_err(|err| anyhow::anyhow!(err))
            };
            if let Err(err) = search_result {
                result.errors.push(format!("{}: {err:#}", path.display()));
            }
            result.files.push(sink.finish());
        }
    }

    if cli.sort == SortChoice::Path {
        result.files.sort_by(|a, b| a.path.cmp(&b.path));
    }
    for file in &result.files {
        result.matches.extend(file.matches.iter().cloned());
    }
    result.elapsed_millis = started.elapsed().as_millis();
    Ok(result)
}

fn normalized_paths(invocation: &SearchInvocation) -> Vec<PathBuf> {
    if invocation.paths.is_empty() {
        vec![PathBuf::from("-")]
    } else {
        invocation.paths.iter().map(PathBuf::from).collect()
    }
}

fn build_matcher(cli: &Cli, patterns: &[String]) -> Result<RegexMatcher> {
    let mut builder = RegexMatcherBuilder::new();
    builder
        .case_insensitive(cli.ignore_case)
        .case_smart(cli.smart_case)
        .fixed_strings(cli.fixed_strings)
        .word(cli.word_regexp)
        .whole_line(cli.line_regexp)
        .multi_line(cli.multiline)
        .dot_matches_new_line(cli.multiline_dotall)
        .ignore_whitespace(cli.ignore_whitespace)
        .swap_greed(cli.swap_greed)
        .unicode(!cli.no_unicode)
        .octal(cli.octal)
        .crlf(cli.crlf);
    if cli.multiline {
        builder.line_terminator(None);
    } else if !cli.crlf {
        builder.line_terminator(Some(b'\n'));
    }
    if let Some(limit) = cli.regex_size_limit {
        builder.size_limit(limit);
    }
    if let Some(limit) = cli.dfa_size_limit {
        builder.dfa_size_limit(limit);
    }
    if let Some(limit) = cli.regex_nest_limit {
        builder.nest_limit(limit);
    }
    builder
        .build_many(patterns)
        .context("building search pattern")
}

fn build_searcher(cli: &Cli) -> Result<Searcher> {
    let mut builder = SearcherBuilder::new();
    builder
        .invert_match(cli.invert_match)
        .line_number(true)
        .multi_line(cli.multiline)
        .before_context(cli.before_context_lines())
        .after_context(cli.after_context_lines())
        .passthru(cli.passthru)
        .max_matches(cli.max_count)
        .stop_on_nonmatch(cli.stop_on_nonmatch)
        .bom_sniffing(!cli.no_bom)
        .heap_limit(cli.heap_limit)
        .binary_detection(if cli.effective_text() {
            BinaryDetection::none()
        } else {
            BinaryDetection::quit(b'\x00')
        });
    if cli.crlf {
        builder.line_terminator(LineTerminator::crlf());
    }
    if let Some(label) = cli.encoding.as_deref() {
        let encoding =
            Encoding::new(label).with_context(|| format!("unknown encoding {label:?}"))?;
        builder.encoding(Some(encoding));
    }
    Ok(builder.build())
}

fn build_walker(cli: &Cli, paths: &[PathBuf]) -> Result<WalkBuilder> {
    let first = paths.first().cloned().unwrap_or_else(|| PathBuf::from("."));
    let mut walk = WalkBuilder::new(first);
    for path in paths.iter().skip(1) {
        walk.add(path);
    }
    walk.add_custom_ignore_filename(".rgignore");
    walk.hidden(!cli.effective_hidden());
    if cli.effective_no_ignore() {
        walk.ignore(false)
            .parents(false)
            .git_ignore(false)
            .git_global(false)
            .git_exclude(false);
    } else {
        walk.ignore(!cli.no_ignore_dot)
            .parents(!cli.no_ignore_parent)
            .git_ignore(!cli.no_ignore_vcs)
            .git_exclude(!cli.no_ignore_vcs)
            .git_global(!cli.no_ignore_global);
    }
    walk.ignore_case_insensitive(cli.ignore_file_case_insensitive)
        .follow_links(cli.follow || cli.recursive_follow_alias)
        .max_depth(if cli.recursive_requested() {
            cli.max_depth
        } else {
            Some(0)
        })
        .max_filesize(cli.max_filesize)
        .same_file_system(cli.one_file_system);
    if cli.sort == SortChoice::Path {
        walk.sort_by_file_path(|a, b| a.cmp(b));
    }
    for path in &cli.ignore_file {
        if let Some(err) = walk.add_ignore(path) {
            bail!("failed to add ignore file {}: {err}", path.display());
        }
    }

    if !cli.glob.is_empty() || !cli.iglob.is_empty() {
        let cwd = std::env::current_dir().context("reading current directory")?;
        let mut overrides = OverrideBuilder::new(cwd);
        for glob in &cli.glob {
            overrides
                .add(glob)
                .with_context(|| format!("invalid glob {glob:?}"))?;
        }
        if !cli.iglob.is_empty() {
            overrides
                .case_insensitive(true)
                .context("enabling case-insensitive globs")?;
            for glob in &cli.iglob {
                overrides
                    .add(glob)
                    .with_context(|| format!("invalid glob {glob:?}"))?;
            }
        }
        walk.overrides(overrides.build().context("building glob overrides")?);
    }

    if !cli.file_type.is_empty()
        || !cli.type_not.is_empty()
        || !cli.type_add.is_empty()
        || !cli.type_clear.is_empty()
    {
        let mut types = TypesBuilder::new();
        types.add_defaults();
        for name in &cli.type_clear {
            types.clear(name);
        }
        for def in &cli.type_add {
            types
                .add_def(def)
                .with_context(|| format!("invalid --type-add {def:?}"))?;
        }
        for name in &cli.file_type {
            types.select(name);
        }
        for name in &cli.type_not {
            types.negate(name);
        }
        walk.types(types.build().context("building file type matcher")?);
    }
    Ok(walk)
}

struct CollectSink<'m> {
    path: String,
    matcher: &'m RegexMatcher,
    result: FileResult,
}

impl<'m> CollectSink<'m> {
    fn new(path: String, matcher: &'m RegexMatcher) -> Self {
        Self {
            path: path.clone(),
            matcher,
            result: FileResult {
                path,
                ..FileResult::default()
            },
        }
    }

    fn finish(self) -> FileResult {
        self.result
    }

    fn clean_text(bytes: &[u8]) -> String {
        let mut end = bytes.len();
        while end > 0 && matches!(bytes[end - 1], b'\n' | b'\r') {
            end -= 1;
        }
        String::from_utf8_lossy(&bytes[..end]).into_owned()
    }

    fn spans(&self, bytes: &[u8]) -> Vec<(usize, usize)> {
        let mut spans = Vec::new();
        let _ = self.matcher.find_iter(bytes, |m| {
            spans.push((m.start(), m.end()));
            true
        });
        spans
    }
}

impl Sink for CollectSink<'_> {
    type Error = io::Error;

    fn matched(&mut self, _searcher: &Searcher, mat: &SinkMatch<'_>) -> Result<bool, Self::Error> {
        let bytes = mat.bytes();
        let text = Self::clean_text(bytes);
        let spans = self.spans(bytes);
        let line_number = mat.line_number().unwrap_or(1);
        let byte_offset = mat.absolute_byte_offset();
        self.result.match_lines += 1;
        self.result.submatches += spans.len() as u64;
        let record = MatchRecord {
            path: self.path.clone(),
            line_number,
            byte_offset,
            text: text.clone(),
            spans: spans.clone(),
        };
        self.result.matches.push(record);
        self.result.display_lines.push(DisplayLine {
            path: self.path.clone(),
            line_number,
            byte_offset,
            text,
            is_match: true,
            spans,
        });
        Ok(true)
    }

    fn context(
        &mut self,
        _searcher: &Searcher,
        context: &SinkContext<'_>,
    ) -> Result<bool, Self::Error> {
        self.result.display_lines.push(DisplayLine {
            path: self.path.clone(),
            line_number: context.line_number().unwrap_or(1),
            byte_offset: context.absolute_byte_offset(),
            text: Self::clean_text(context.bytes()),
            is_match: false,
            spans: Vec::new(),
        });
        Ok(true)
    }

    fn binary_data(
        &mut self,
        _searcher: &Searcher,
        _binary_byte_offset: u64,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use tempfile::tempdir;

    #[test]
    fn searches_plain_file() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("sample.txt");
        std::fs::write(&file, "alpha\nforgejo here\nomega\n").unwrap();
        let cli = Cli::parse_from(["stef", "forgejo", file.to_str().unwrap()]);
        let inv = cli.invocation().unwrap();
        let result = run_search(&cli, &inv).unwrap();
        assert_eq!(result.matches.len(), 1);
        assert!(result.matches[0].text.contains("forgejo"));
    }

    #[test]
    fn directory_is_not_searched_without_recursive_flag() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(nested.join("sample.txt"), "needle\n").unwrap();
        let cli = Cli::parse_from(["stef", "needle", dir.path().to_str().unwrap()]);
        let inv = cli.invocation().unwrap();
        let result = run_search(&cli, &inv).unwrap();
        assert!(result.matches.is_empty());
        assert!(result.errors.iter().any(|e| e.contains("use -r or -R")));
    }

    #[test]
    fn recursive_flag_searches_nested_files() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(nested.join("sample.txt"), "needle\n").unwrap();
        let cli = Cli::parse_from(["stef", "-r", "needle", dir.path().to_str().unwrap()]);
        let inv = cli.invocation().unwrap();
        let result = run_search(&cli, &inv).unwrap();
        assert_eq!(result.matches.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn uppercase_recursive_flag_follows_symlinked_directories() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let target = tempdir().unwrap();
        std::fs::write(target.path().join("sample.txt"), "needle\n").unwrap();
        symlink(target.path(), dir.path().join("linked")).unwrap();

        let cli = Cli::parse_from(["stef", "-R", "needle", dir.path().to_str().unwrap()]);
        let inv = cli.invocation().unwrap();
        let result = run_search(&cli, &inv).unwrap();
        assert_eq!(result.matches.len(), 1);
    }
}
