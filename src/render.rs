use crate::cli::{Cli, ColorChoice};
use crate::diffing::MatchDiff;
use crate::history::Snapshot;
use crate::model::{DisplayLine, MatchRecord, SearchResult};
use anyhow::Result;
use serde_json::json;
use std::collections::BTreeMap;
use std::io::{self, IsTerminal, Write};

const RESET: &str = "\x1b[0m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const CYAN: &str = "\x1b[36m";
const YELLOW: &str = "\x1b[33m";
const DIM: &str = "\x1b[2m";

pub fn color_enabled(choice: ColorChoice) -> bool {
    match choice {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
    }
}

pub fn render_search(cli: &Cli, result: &SearchResult) -> Result<()> {
    if cli.quiet {
        return Ok(());
    }
    if cli.json {
        return render_json(result);
    }
    if cli.files_with_matches {
        for file in &result.files {
            if !file.matches.is_empty() {
                println!("{}", file.path);
            }
        }
        return Ok(());
    }
    if cli.files_without_match {
        for file in &result.files {
            if file.matches.is_empty() {
                println!("{}", file.path);
            }
        }
        return Ok(());
    }
    if cli.count || cli.count_matches {
        let include_path = cli.with_filename || (!cli.no_filename && result.files.len() > 1);
        for file in &result.files {
            let count = if cli.count_matches {
                file.submatches
            } else {
                file.match_lines
            };
            if include_path {
                println!("{}:{}", file.path, count);
            } else {
                println!("{count}");
            }
        }
        return Ok(());
    }

    let use_color = color_enabled(cli.color);
    if cli.vimgrep {
        for m in &result.matches {
            let column = m.spans.first().map(|(s, _)| s + 1).unwrap_or(1);
            println!("{}:{}:{}:{}", m.path, m.line_number, column, m.text);
        }
        return Ok(());
    }
    if cli.only_matching {
        for m in &result.matches {
            for (start, end) in &m.spans {
                if let Some(piece) = safe_slice(&m.text, *start, *end) {
                    if cli.with_filename || (!cli.no_filename && result.files.len() > 1) {
                        print!("{}:", m.path);
                    }
                    if !cli.no_line_number {
                        print!("{}:", m.line_number);
                    }
                    println!("{piece}");
                }
            }
        }
        return Ok(());
    }

    let heading = if cli.no_filename {
        false
    } else if cli.heading {
        true
    } else if cli.no_heading || cli.with_filename {
        false
    } else {
        result.files.len() > 1
    };
    let mut printed_file = false;
    for file in &result.files {
        if file.display_lines.is_empty() {
            continue;
        }
        if heading {
            if printed_file {
                println!();
            }
            if use_color {
                println!("{CYAN}{}{RESET}", file.path);
            } else {
                println!("{}", file.path);
            }
            for line in &file.display_lines {
                render_line(cli, line, false, use_color)?;
            }
        } else {
            let include_path = cli.with_filename || (!cli.no_filename && result.files.len() > 1);
            for line in &file.display_lines {
                render_line(cli, line, include_path, use_color)?;
            }
        }
        printed_file = true;
    }
    Ok(())
}

fn render_line(cli: &Cli, line: &DisplayLine, include_path: bool, color: bool) -> Result<()> {
    let sep = if line.is_match { ':' } else { '-' };
    if include_path {
        if color {
            print!("{CYAN}{}{RESET}{sep}", line.path);
        } else {
            print!("{}{sep}", line.path);
        }
    }
    if !cli.no_line_number {
        if color {
            print!("{YELLOW}{}{RESET}{sep}", line.line_number);
        } else {
            print!("{}{sep}", line.line_number);
        }
    }
    if cli.byte_offset {
        print!("{}{sep}", line.byte_offset);
    }
    if cli.column {
        let col = line.spans.first().map(|(start, _)| start + 1).unwrap_or(1);
        print!("{col}{sep}");
    }
    if line.is_match {
        println!("{}", highlight(&line.text, &line.spans, color));
    } else if color {
        println!("{DIM}{}{RESET}", line.text);
    } else {
        println!("{}", line.text);
    }
    io::stdout().flush()?;
    Ok(())
}

pub fn render_diff(diff: &MatchDiff, color_choice: ColorChoice) -> Result<()> {
    let color = color_enabled(color_choice);
    let mut by_path: BTreeMap<String, (Vec<&MatchRecord>, Vec<&MatchRecord>)> = BTreeMap::new();
    for m in &diff.removed {
        by_path.entry(m.path.clone()).or_default().0.push(m);
    }
    for m in &diff.added {
        by_path.entry(m.path.clone()).or_default().1.push(m);
    }
    if !diff.changed() {
        println!("No match changes.");
        return Ok(());
    }
    for (path, (removed, added)) in by_path {
        println!("@@ {path} @@");
        for m in removed {
            if color {
                println!("{RED}- {:>6} │ {}{RESET}", m.line_number, m.text);
            } else {
                println!("- {:>6} │ {}", m.line_number, m.text);
            }
        }
        for m in added {
            if color {
                println!("{GREEN}+ {:>6} │ {}{RESET}", m.line_number, m.text);
            } else {
                println!("+ {:>6} │ {}", m.line_number, m.text);
            }
        }
    }
    Ok(())
}

pub fn render_history(snapshots: &[Snapshot]) {
    println!("RUN\tUNIX_TIME\tMATCHES\tCWD\tCOMMAND");
    for snapshot in snapshots {
        println!(
            "{}\t{}\t{}\t{}\tstef {}",
            snapshot.run_id,
            snapshot.created_at,
            snapshot.matches.len(),
            snapshot.cwd,
            shellish_join(&snapshot.argv),
        );
    }
}

pub fn render_errors(cli: &Cli, result: &SearchResult) {
    if cli.no_messages {
        return;
    }
    for error in &result.errors {
        eprintln!("stef: {error}");
    }
}

pub fn render_stats(result: &SearchResult) {
    eprintln!("{} files searched", result.searched_paths.len());
    eprintln!("{} matching records", result.matches.len());
    eprintln!("{} bytes visited", result.bytes_searched);
    eprintln!("{} ms elapsed", result.elapsed_millis);
}

pub fn render_file_list(files: &[String], errors: &[String], no_messages: bool) {
    for file in files {
        println!("{file}");
    }
    if !no_messages {
        for error in errors {
            eprintln!("stef: {error}");
        }
    }
}

fn render_json(result: &SearchResult) -> Result<()> {
    for m in &result.matches {
        let submatches: Vec<_> = m
            .spans
            .iter()
            .map(|(start, end)| json!({"start": start, "end": end}))
            .collect();
        println!(
            "{}",
            serde_json::to_string(&json!({
                "type": "match",
                "data": {
                    "path": m.path.as_str(),
                    "line_number": m.line_number,
                    "absolute_offset": m.byte_offset,
                    "text": m.text.as_str(),
                    "submatches": submatches,
                }
            }))?
        );
    }
    println!(
        "{}",
        serde_json::to_string(&json!({
            "type": "summary",
            "data": {
                "matches": result.matches.len(),
                "files_searched": result.searched_paths.len(),
                "bytes_searched": result.bytes_searched,
                "elapsed_millis": result.elapsed_millis,
                "errors": result.errors.len(),
            }
        }))?
    );
    Ok(())
}

fn highlight(text: &str, spans: &[(usize, usize)], color: bool) -> String {
    if !color || spans.is_empty() {
        return text.to_owned();
    }
    let mut out = String::new();
    let mut at = 0usize;
    for &(start, end) in spans {
        if start < at
            || end < start
            || end > text.len()
            || !text.is_char_boundary(start)
            || !text.is_char_boundary(end)
        {
            continue;
        }
        out.push_str(&text[at..start]);
        out.push_str(GREEN);
        out.push_str(&text[start..end]);
        out.push_str(RESET);
        at = end;
    }
    out.push_str(&text[at..]);
    out
}

fn safe_slice(text: &str, start: usize, end: usize) -> Option<&str> {
    if start <= end
        && end <= text.len()
        && text.is_char_boundary(start)
        && text.is_char_boundary(end)
    {
        Some(&text[start..end])
    } else {
        None
    }
}

fn shellish_join(args: &[String]) -> String {
    args.iter()
        .map(|arg| {
            if arg
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_./:-".contains(&b))
            {
                arg.clone()
            } else {
                format!("'{0}'", arg.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
