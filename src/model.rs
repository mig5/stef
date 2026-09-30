use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MatchRecord {
    pub path: String,
    pub line_number: u64,
    pub byte_offset: u64,
    pub text: String,
    pub spans: Vec<(usize, usize)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayLine {
    pub path: String,
    pub line_number: u64,
    pub byte_offset: u64,
    pub text: String,
    pub is_match: bool,
    pub spans: Vec<(usize, usize)>,
}

#[derive(Clone, Debug, Default)]
pub struct FileResult {
    pub path: String,
    pub matches: Vec<MatchRecord>,
    pub display_lines: Vec<DisplayLine>,
    pub match_lines: u64,
    pub submatches: u64,
}

#[derive(Clone, Debug, Default)]
pub struct SearchResult {
    pub files: Vec<FileResult>,
    pub matches: Vec<MatchRecord>,
    pub searched_paths: Vec<String>,
    pub pgp_recipients: BTreeSet<String>,
    pub errors: Vec<String>,
    pub bytes_searched: u64,
    pub elapsed_millis: u128,
}

impl SearchResult {
    pub fn any_match(&self) -> bool {
        !self.matches.is_empty()
    }
}
