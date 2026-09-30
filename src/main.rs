mod cli;
mod diffing;
mod history;
mod model;
mod render;
mod search;
mod sops;

use crate::cli::{Cli, history_argv_from_current, parse_duration, strip_history_controls};
use crate::diffing::{diff_matches, snapshots_equal, window_baseline};
use crate::history::{
    HistoryStore, default_state_dir, now_unix, recipients_from_env, resolve_secret_gpg_recipients,
};
use anyhow::{Context, Result, bail};
use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("stef: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<u8> {
    let mut cli = Cli::parse_compat();
    cli.validate()?;
    let state_dir = cli
        .state_dir
        .clone()
        .map(Ok)
        .unwrap_or_else(default_state_dir)?;
    let explicit_recipients = explicit_recipients(&cli)?;

    if cli.clear_history {
        if !HistoryStore::exists(&state_dir) {
            return Ok(0);
        }
        let store = HistoryStore::open(state_dir, &explicit_recipients)?;
        store.clear()?;
        return Ok(0);
    }
    if cli.history {
        if !HistoryStore::exists(&state_dir) {
            println!("No stef history yet.");
            return Ok(0);
        }
        let store = HistoryStore::open(state_dir, &explicit_recipients)?;
        render::render_history(&store.list_recent(cli.history_limit)?);
        return Ok(0);
    }
    if cli.type_list {
        for def in search::list_types(&cli)? {
            println!("{def}");
        }
        return Ok(0);
    }

    let has_explicit_search = !cli.regexp.is_empty()
        || !cli.pattern_files.is_empty()
        || !cli.positional.is_empty()
        || cli.files;

    let mut history_cwd = std::env::current_dir().context("reading current directory")?;
    let mut history_argv = history_argv_from_current();

    if cli.is_pass_mode() && !has_explicit_search {
        if !HistoryStore::exists(&state_dir) {
            bail!("no stef history exists yet; run a search first");
        }
        let store = HistoryStore::open(state_dir.clone(), &explicit_recipients)?;
        let latest = store
            .latest()?
            .context("no remembered stef search exists yet")?;
        history_cwd = PathBuf::from(&latest.cwd);
        history_argv = latest.argv.clone();
        std::env::set_current_dir(&history_cwd).with_context(|| {
            format!(
                "returning to remembered working directory {}",
                history_cwd.display()
            )
        })?;

        let mut args = vec!["stef".to_owned()];
        args.extend(latest.argv.clone());
        let mut remembered = Cli::parse_from(args);
        remembered.pass = true;
        remembered.pass_window = cli.pass_window.clone();
        remembered.no_history = cli.no_history;
        remembered.color = cli.color;
        remembered.state_dir = cli.state_dir.clone();
        remembered.history_gpg_recipient = cli.history_gpg_recipient.clone();
        remembered.history_limit = cli.history_limit;
        remembered.validate()?;
        cli = remembered;
    }

    let invocation = cli.invocation()?;
    if cli.files {
        let (files, errors) = search::list_files(&cli, &invocation)?;
        render::render_file_list(&files, &errors, cli.no_messages);
        return Ok(if errors.is_empty() { 0 } else { 2 });
    }

    // Re-canonicalize command identity after loading a remembered search. For
    // an explicit current search this removes pass/history-only controls; for
    // a remembered search it preserves the exact original search identity.
    if has_explicit_search {
        history_argv = strip_history_controls(history_argv);
    }
    let history_cwd_string = history_cwd.to_string_lossy().into_owned();

    let result = search::run_search(&cli, &invocation)?;
    render::render_errors(&cli, &result);
    if cli.stats {
        render::render_stats(&result);
    }

    if cli.is_pass_mode() {
        let recipients = history_recipients(
            &explicit_recipients,
            &result.pgp_recipients,
            cli.no_messages,
        )?;
        let store = HistoryStore::open(state_dir, &recipients)?;
        let prior = if let Some(window) = cli.pass_window.as_deref() {
            let seconds = parse_duration(window)?;
            let since = now_unix().saturating_sub(seconds);
            store.for_command(&history_cwd_string, &history_argv, None, Some(since))?
        } else {
            store.for_command(&history_cwd_string, &history_argv, None, None)?
        };

        if let Some(window) = cli.pass_window.as_deref() {
            let baseline = window_baseline(prior.iter().map(|s| s.matches.as_slice()));
            let diff = diff_matches(&baseline, &result.matches);
            render::render_diff(&diff, cli.color)?;
            if prior.is_empty() && !cli.no_messages {
                eprintln!(
                    "stef: no earlier snapshots were found inside the {window} history window"
                );
            }
        } else if let Some(previous) = prior
            .iter()
            .find(|s| !snapshots_equal(&s.matches, &result.matches))
        {
            render::render_diff(&diff_matches(&previous.matches, &result.matches), cli.color)?;
        } else if prior.is_empty() {
            println!("No previous snapshot for this search.");
        } else {
            println!("No distinct previous match state for this search.");
        }

        if !cli.no_history {
            store.add(&history_cwd_string, &history_argv, &result.matches)?;
        }
        if !result.errors.is_empty() {
            return Ok(2);
        }
        return Ok(if result.any_match() { 0 } else { 1 });
    }

    render::render_search(&cli, &result)?;
    if !cli.no_history {
        let recipients = history_recipients(
            &explicit_recipients,
            &result.pgp_recipients,
            cli.no_messages,
        )?;
        let store = HistoryStore::open(state_dir, &recipients)?;
        store.add(&history_cwd_string, &history_argv, &result.matches)?;
    }
    if !result.errors.is_empty() {
        Ok(2)
    } else if result.any_match() {
        Ok(0)
    } else {
        Ok(1)
    }
}

fn explicit_recipients(cli: &Cli) -> Result<Vec<String>> {
    let mut requested = recipients_from_env();
    requested.extend(cli.history_gpg_recipient.iter().cloned());
    requested.sort();
    requested.dedup();
    if requested.is_empty() {
        return Ok(Vec::new());
    }
    let resolved = resolve_secret_gpg_recipients(&requested)?;
    if resolved.is_empty() {
        bail!(
            "none of the requested --history-gpg-recipient values identifies a local GPG secret key"
        );
    }
    Ok(resolved)
}

fn history_recipients(
    explicit: &[String],
    discovered: &std::collections::BTreeSet<String>,
    no_messages: bool,
) -> Result<Vec<String>> {
    if !explicit.is_empty() {
        return Ok(explicit.to_vec());
    }
    if discovered.is_empty() {
        return Ok(Vec::new());
    }
    match resolve_secret_gpg_recipients(discovered.iter()) {
        Ok(values) => Ok(values),
        Err(err) => {
            if !no_messages {
                eprintln!(
                    "stef: warning: could not inspect the local GPG secret keyring ({err:#}); using the private local history key backend"
                );
            }
            Ok(Vec::new())
        }
    }
}
