use anyhow::{Context, Result, bail};
use clap::{ArgAction, Parser, ValueEnum};
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ColorChoice {
    Auto,
    Always,
    Never,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum SortChoice {
    None,
    Path,
}

#[derive(Parser, Clone, Debug)]
#[command(
    name = "stef",
    version,
    about = "SOPS-aware grep with encrypted match history",
    long_about = None,
    disable_help_subcommand = true,
    after_help = "Pass mode examples:\n  stef -p\n  stef -p 7d\n  stef -p 12h password config/\n\nUse `stef -p -- 7d .` when the literal search pattern is duration-like."
)]
pub struct Cli {
    // stef history/SOPS options
    #[arg(
        short = 'p',
        long = "pass",
        help = "Compare with the most recent distinct previous result"
    )]
    pub pass: bool,

    #[arg(long = "pass-window", hide = true, value_name = "DURATION")]
    pub pass_window: Option<String>,

    #[arg(
        long,
        help = "List recent remembered searches (never prints stored match text)"
    )]
    pub history: bool,

    #[arg(long, default_value_t = 20, value_name = "N")]
    pub history_limit: usize,

    #[arg(
        long,
        help = "Delete remembered snapshots and VACUUM the history database"
    )]
    pub clear_history: bool,

    #[arg(long, help = "Search normally but do not save this run to history")]
    pub no_history: bool,

    #[arg(long, value_name = "DIR", env = "STEF_STATE_DIR")]
    pub state_dir: Option<PathBuf>,

    #[arg(long = "history-gpg-recipient", value_name = "KEY", action = ArgAction::Append)]
    pub history_gpg_recipient: Vec<String>,

    #[arg(long = "sops-glob", value_name = "GLOB", action = ArgAction::Append)]
    pub sops_glob: Vec<String>,

    #[arg(long, help = "Disable transparent SOPS detection/decryption")]
    pub no_sops: bool,

    // matcher options
    #[arg(short = 'e', long = "regexp", value_name = "PATTERN", action = ArgAction::Append)]
    pub regexp: Vec<String>,

    #[arg(short = 'f', long = "file", value_name = "PATTERNFILE", action = ArgAction::Append)]
    pub pattern_files: Vec<PathBuf>,

    #[arg(short = 'F', long = "fixed-strings")]
    pub fixed_strings: bool,

    #[arg(short = 'i', long = "ignore-case", conflicts_with_all = ["case_sensitive", "smart_case"])]
    pub ignore_case: bool,

    #[arg(short = 's', long = "case-sensitive", conflicts_with_all = ["ignore_case", "smart_case"])]
    pub case_sensitive: bool,

    #[arg(short = 'S', long = "smart-case", conflicts_with_all = ["ignore_case", "case_sensitive"])]
    pub smart_case: bool,

    #[arg(short = 'w', long = "word-regexp")]
    pub word_regexp: bool,

    #[arg(short = 'x', long = "line-regexp")]
    pub line_regexp: bool,

    #[arg(short = 'v', long = "invert-match")]
    pub invert_match: bool,

    #[arg(short = 'U', long = "multiline")]
    pub multiline: bool,

    #[arg(long = "multiline-dotall", requires = "multiline")]
    pub multiline_dotall: bool,

    #[arg(long = "ignore-whitespace")]
    pub ignore_whitespace: bool,

    #[arg(long = "swap-greed")]
    pub swap_greed: bool,

    #[arg(long = "no-unicode")]
    pub no_unicode: bool,

    #[arg(long = "octal")]
    pub octal: bool,

    #[arg(long = "crlf")]
    pub crlf: bool,

    #[arg(long = "regex-size-limit", value_name = "BYTES")]
    pub regex_size_limit: Option<usize>,

    #[arg(long = "dfa-size-limit", value_name = "BYTES")]
    pub dfa_size_limit: Option<usize>,

    #[arg(long = "regex-nest-limit", value_name = "N")]
    pub regex_nest_limit: Option<u32>,

    // searcher/context options
    #[arg(short = 'A', long = "after-context", value_name = "NUM")]
    pub after_context: Option<usize>,

    #[arg(short = 'B', long = "before-context", value_name = "NUM")]
    pub before_context: Option<usize>,

    #[arg(short = 'C', long = "context", value_name = "NUM")]
    pub context: Option<usize>,

    #[arg(long = "passthru")]
    pub passthru: bool,

    #[arg(short = 'm', long = "max-count", value_name = "NUM")]
    pub max_count: Option<u64>,

    #[arg(short = 'a', long = "text")]
    pub text: bool,

    #[arg(short = 'E', long = "encoding", value_name = "ENCODING")]
    pub encoding: Option<String>,

    #[arg(long = "no-bom")]
    pub no_bom: bool,

    #[arg(long = "stop-on-nonmatch")]
    pub stop_on_nonmatch: bool,

    #[arg(long = "heap-limit", value_name = "BYTES")]
    pub heap_limit: Option<usize>,

    // traversal/ignore options
    #[arg(
        short = 'r',
        long = "recursive",
        help = "Search directories recursively"
    )]
    pub recursive: bool,

    #[arg(
        short = 'R',
        help = "Search directories recursively and follow symbolic links"
    )]
    pub recursive_follow_alias: bool,

    #[arg(short = 'u', long = "unrestricted", action = ArgAction::Count)]
    pub unrestricted: u8,

    #[arg(long, help = "Search hidden files and directories")]
    pub hidden: bool,

    #[arg(long = "no-ignore")]
    pub no_ignore: bool,

    #[arg(long = "no-ignore-vcs")]
    pub no_ignore_vcs: bool,

    #[arg(long = "no-ignore-global")]
    pub no_ignore_global: bool,

    #[arg(long = "no-ignore-parent")]
    pub no_ignore_parent: bool,

    #[arg(long = "no-ignore-dot")]
    pub no_ignore_dot: bool,

    #[arg(long = "ignore-file", value_name = "PATH", action = ArgAction::Append)]
    pub ignore_file: Vec<PathBuf>,

    #[arg(long = "ignore-file-case-insensitive")]
    pub ignore_file_case_insensitive: bool,

    #[arg(short = 'g', long = "glob", value_name = "GLOB", action = ArgAction::Append)]
    pub glob: Vec<String>,

    #[arg(long = "iglob", value_name = "GLOB", action = ArgAction::Append)]
    pub iglob: Vec<String>,

    #[arg(short = 't', long = "type", value_name = "TYPE", action = ArgAction::Append)]
    pub file_type: Vec<String>,

    #[arg(short = 'T', long = "type-not", value_name = "TYPE", action = ArgAction::Append)]
    pub type_not: Vec<String>,

    #[arg(long = "type-add", value_name = "TYPE:GLOB", action = ArgAction::Append)]
    pub type_add: Vec<String>,

    #[arg(long = "type-clear", value_name = "TYPE", action = ArgAction::Append)]
    pub type_clear: Vec<String>,

    #[arg(long = "type-list")]
    pub type_list: bool,

    #[arg(long = "follow")]
    pub follow: bool,

    #[arg(long = "max-depth", value_name = "NUM")]
    pub max_depth: Option<usize>,

    #[arg(long = "max-filesize", value_name = "NUM")]
    pub max_filesize: Option<u64>,

    #[arg(long = "one-file-system")]
    pub one_file_system: bool,

    #[arg(long, value_enum, default_value_t = SortChoice::None)]
    pub sort: SortChoice,

    // output options
    #[arg(short = 'n', long = "line-number")]
    pub line_number: bool,

    #[arg(short = 'N', long = "no-line-number")]
    pub no_line_number: bool,

    #[arg(short = 'H', long = "with-filename")]
    pub with_filename: bool,

    #[arg(short = 'I', long = "no-filename")]
    pub no_filename: bool,

    #[arg(long = "heading")]
    pub heading: bool,

    #[arg(long = "no-heading")]
    pub no_heading: bool,

    #[arg(short = 'o', long = "only-matching")]
    pub only_matching: bool,

    #[arg(short = 'b', long = "byte-offset")]
    pub byte_offset: bool,

    #[arg(long = "column")]
    pub column: bool,

    #[arg(long = "vimgrep")]
    pub vimgrep: bool,

    #[arg(short = 'c', long = "count")]
    pub count: bool,

    #[arg(long = "count-matches")]
    pub count_matches: bool,

    #[arg(short = 'l', long = "files-with-matches")]
    pub files_with_matches: bool,

    #[arg(short = 'L', long = "files-without-match")]
    pub files_without_match: bool,

    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    #[arg(long = "files")]
    pub files: bool,

    #[arg(long = "json")]
    pub json: bool,

    #[arg(long = "stats")]
    pub stats: bool,

    #[arg(long = "no-messages")]
    pub no_messages: bool,

    #[arg(long, value_enum, default_value_t = ColorChoice::Auto)]
    pub color: ColorChoice,

    #[arg(value_name = "PATTERN_OR_PATH")]
    pub positional: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct SearchInvocation {
    pub patterns: Vec<String>,
    pub paths: Vec<String>,
}

impl Cli {
    pub fn parse_compat() -> Self {
        let raw: Vec<OsString> = std::env::args_os().collect();
        let cooked = rewrite_pass_duration(raw);
        Self::parse_from(cooked)
    }

    pub fn invocation(&self) -> Result<SearchInvocation> {
        let mut patterns = self.regexp.clone();
        for path in &self.pattern_files {
            let text = fs::read_to_string(path)
                .with_context(|| format!("reading pattern file {}", path.display()))?;
            patterns.extend(text.lines().map(ToOwned::to_owned));
        }

        let mut positional = self.positional.clone();
        if patterns.is_empty()
            && !self.files
            && !self.type_list
            && !self.history
            && !self.clear_history
        {
            if positional.is_empty() {
                bail!("a PATTERN is required (or use -e PATTERN)");
            }
            patterns.push(positional.remove(0));
        }
        let paths =
            if positional.is_empty() && !self.history && !self.clear_history && !self.type_list {
                if self.recursive || self.recursive_follow_alias || self.files {
                    vec![".".to_owned()]
                } else {
                    vec!["-".to_owned()]
                }
            } else {
                positional
            };
        Ok(SearchInvocation { patterns, paths })
    }

    pub fn before_context_lines(&self) -> usize {
        self.before_context.or(self.context).unwrap_or(0)
    }

    pub fn after_context_lines(&self) -> usize {
        self.after_context.or(self.context).unwrap_or(0)
    }

    pub fn effective_hidden(&self) -> bool {
        self.hidden || self.unrestricted >= 2
    }

    pub fn effective_no_ignore(&self) -> bool {
        self.no_ignore || self.unrestricted >= 1
    }

    pub fn effective_text(&self) -> bool {
        self.text || self.unrestricted >= 3
    }

    pub fn is_pass_mode(&self) -> bool {
        self.pass || self.pass_window.is_some()
    }

    pub fn recursive_requested(&self) -> bool {
        self.recursive || self.recursive_follow_alias
    }

    pub fn validate(&self) -> Result<()> {
        if self.no_filename && self.with_filename {
            bail!("--no-filename conflicts with --with-filename");
        }
        if self.heading && self.no_heading {
            bail!("--heading conflicts with --no-heading");
        }
        let summary = [
            self.count,
            self.count_matches,
            self.files_with_matches,
            self.files_without_match,
            self.quiet,
            self.files,
            self.json,
        ]
        .into_iter()
        .filter(|v| *v)
        .count();
        if summary > 1 {
            bail!(
                "choose only one of --count, --count-matches, --files-with-matches, --files-without-match, --quiet, --files or --json"
            );
        }
        if self.is_pass_mode() && summary > 0 {
            bail!("pass mode cannot be combined with summary/JSON output modes");
        }
        Ok(())
    }
}

pub fn parse_duration(value: &str) -> Result<i64> {
    if value.len() < 2 {
        bail!("invalid duration {value:?}; use e.g. 30m, 12h, 7d or 2w");
    }
    let (number, unit) = value.split_at(value.len() - 1);
    let n: i64 = number
        .parse()
        .with_context(|| format!("invalid duration {value:?}; use e.g. 30m, 12h, 7d or 2w"))?;
    if n < 0 {
        bail!("duration must be non-negative");
    }
    let seconds = match unit {
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        "w" => 7 * 24 * 60 * 60,
        _ => bail!("invalid duration unit {unit:?}; use m, h, d or w"),
    };
    n.checked_mul(seconds).context("duration is too large")
}

fn looks_like_duration(value: &str) -> bool {
    parse_duration(value).is_ok()
}

fn rewrite_pass_duration(raw: Vec<OsString>) -> Vec<OsString> {
    if raw.is_empty() {
        return raw;
    }
    let mut out = Vec::with_capacity(raw.len() + 2);
    out.push(raw[0].clone());
    let mut i = 1;
    let mut after_double_dash = false;
    while i < raw.len() {
        let text = raw[i].to_string_lossy();
        if after_double_dash {
            out.push(raw[i].clone());
            i += 1;
            continue;
        }
        if text == "--" {
            after_double_dash = true;
            out.push(raw[i].clone());
            i += 1;
            continue;
        }
        if text == "-p" || text == "--pass" {
            out.push(OsString::from("--pass"));
            if i + 1 < raw.len() {
                let next = raw[i + 1].to_string_lossy();
                if looks_like_duration(&next) {
                    out.push(OsString::from("--pass-window"));
                    out.push(raw[i + 1].clone());
                    i += 2;
                    continue;
                }
            }
            i += 1;
            continue;
        }
        if let Some(value) = text.strip_prefix("-p") {
            if !value.is_empty() && looks_like_duration(value) {
                out.push(OsString::from("--pass"));
                out.push(OsString::from("--pass-window"));
                out.push(OsString::from(value));
                i += 1;
                continue;
            }
        }
        if let Some(value) = text.strip_prefix("--pass=") {
            if looks_like_duration(value) {
                out.push(OsString::from("--pass"));
                out.push(OsString::from("--pass-window"));
                out.push(OsString::from(value));
                i += 1;
                continue;
            }
        }
        out.push(raw[i].clone());
        i += 1;
    }
    out
}

pub fn history_argv_from_current() -> Vec<String> {
    strip_history_controls(std::env::args().skip(1).collect())
}

pub fn strip_history_controls(args: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    let mut after_double_dash = false;
    while i < args.len() {
        let arg = &args[i];
        if after_double_dash {
            out.push(arg.clone());
            i += 1;
            continue;
        }
        if arg == "--" {
            after_double_dash = true;
            out.push(arg.clone());
            i += 1;
            continue;
        }
        if arg == "-p" || arg == "--pass" {
            if i + 1 < args.len() && looks_like_duration(&args[i + 1]) {
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if arg.starts_with("-p") && arg.len() > 2 && looks_like_duration(&arg[2..]) {
            i += 1;
            continue;
        }
        if arg.starts_with("--pass=") || arg == "--pass-window" {
            i += if arg == "--pass-window" { 2 } else { 1 };
            continue;
        }
        if matches!(
            arg.as_str(),
            "--no-history" | "--history" | "--clear-history"
        ) {
            i += 1;
            continue;
        }
        if matches!(
            arg.as_str(),
            "-n" | "--line-number"
                | "-N"
                | "--no-line-number"
                | "-H"
                | "--with-filename"
                | "-I"
                | "--no-filename"
                | "--heading"
                | "--no-heading"
                | "-o"
                | "--only-matching"
                | "-b"
                | "--byte-offset"
                | "--column"
                | "--vimgrep"
                | "-c"
                | "--count"
                | "--count-matches"
                | "-l"
                | "--files-with-matches"
                | "-L"
                | "--files-without-match"
                | "-q"
                | "--quiet"
                | "--json"
                | "--stats"
                | "--no-messages"
        ) {
            i += 1;
            continue;
        }
        if matches!(
            arg.as_str(),
            "--history-limit" | "--state-dir" | "--history-gpg-recipient" | "--color"
        ) {
            i += 2;
            continue;
        }
        if arg.starts_with("--history-limit=")
            || arg.starts_with("--state-dir=")
            || arg.starts_with("--history-gpg-recipient=")
            || arg.starts_with("--color=")
        {
            i += 1;
            continue;
        }
        out.push(arg.clone());
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_parser() {
        assert_eq!(parse_duration("7d").unwrap(), 604800);
        assert_eq!(parse_duration("12h").unwrap(), 43200);
        assert!(parse_duration("7").is_err());
    }

    #[test]
    fn strips_pass_controls() {
        let got =
            strip_history_controls(vec!["-p".into(), "7d".into(), "secret".into(), ".".into()]);
        assert_eq!(got, vec!["secret", "."]);
    }

    #[test]
    fn defaults_to_stdin_without_recursive_flag() {
        let cli = Cli::parse_from(["stef", "needle"]);
        let inv = cli.invocation().unwrap();
        assert_eq!(inv.paths, vec!["-"]);
    }

    #[test]
    fn recursive_search_defaults_to_current_directory() {
        let cli = Cli::parse_from(["stef", "-r", "needle"]);
        let inv = cli.invocation().unwrap();
        assert_eq!(inv.paths, vec!["."]);
    }

    #[test]
    fn strips_display_only_controls_from_history_identity() {
        let got = strip_history_controls(vec![
            "--json".into(),
            "--stats".into(),
            "--color".into(),
            "always".into(),
            "secret".into(),
            ".".into(),
        ]);
        assert_eq!(got, vec!["secret", "."]);
    }
}
