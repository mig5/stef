use crate::model::MatchRecord;
use anyhow::{Context, Result, bail};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const AAD: &[u8] = b"stef-history-v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SnapshotPayload {
    cwd: String,
    argv: Vec<String>,
    matches: Vec<MatchRecord>,
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub run_id: i64,
    pub created_at: i64,
    pub cwd: String,
    pub argv: Vec<String>,
    pub matches: Vec<MatchRecord>,
}

pub fn default_state_dir() -> Result<PathBuf> {
    if let Some(value) = std::env::var_os("STEF_STATE_DIR") {
        return Ok(PathBuf::from(value));
    }
    if let Some(value) = std::env::var_os("XDG_STATE_HOME") {
        return Ok(PathBuf::from(value).join("stef"));
    }
    let home =
        std::env::var_os("HOME").context("HOME is unset and XDG_STATE_HOME is not configured")?;
    Ok(PathBuf::from(home).join(".local/state/stef"))
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub fn resolve_secret_gpg_recipients<I, S>(candidates: I) -> Result<Vec<String>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut found = Vec::new();
    for candidate in candidates {
        let candidate = candidate.as_ref().trim();
        if candidate.is_empty() {
            continue;
        }
        if let Some(fp) = secret_key_fingerprint(candidate)? {
            if !found.contains(&fp) {
                found.push(fp);
            }
        }
    }
    Ok(found)
}

fn gpg_binary() -> std::ffi::OsString {
    std::env::var_os("STEF_GPG").unwrap_or_else(|| "gpg".into())
}

fn secret_key_fingerprint(selector: &str) -> Result<Option<String>> {
    let output = Command::new(gpg_binary())
        .args([
            "--batch",
            "--with-colons",
            "--fingerprint",
            "--list-secret-keys",
            selector,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .with_context(|| "running gpg to resolve a secret-key recipient")?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut saw_sec = false;
    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.first() == Some(&"sec") {
            saw_sec = true;
            continue;
        }
        if saw_sec && fields.first() == Some(&"fpr") {
            if let Some(fp) = fields.get(9).filter(|v| !v.is_empty()) {
                return Ok(Some(normalize_fp(fp)));
            }
        }
    }
    Ok(None)
}

fn normalize_fp(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase()
}

pub struct HistoryStore {
    db_path: PathBuf,
    key: [u8; 32],
}

impl HistoryStore {
    pub fn exists(state_dir: &Path) -> bool {
        ["history.key", "history.key.gpg", "history.sqlite3"]
            .iter()
            .any(|name| state_dir.join(name).exists())
    }

    pub fn open(state_dir: PathBuf, gpg_recipients: &[String]) -> Result<Self> {
        prepare_dir(&state_dir)?;
        let key_path = state_dir.join("history.key");
        let gpg_key_path = state_dir.join("history.key.gpg");
        let db_path = state_dir.join("history.sqlite3");
        let key = load_or_create_key(&key_path, &gpg_key_path, &db_path, gpg_recipients)?;
        let store = Self { db_path, key };
        store.init_db()?;
        Ok(store)
    }

    fn connect(&self) -> Result<Connection> {
        if !self.db_path.exists() {
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            opts.mode(0o600);
            match opts.open(&self.db_path) {
                Ok(file) => drop(file),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(err) => {
                    return Err(err)
                        .with_context(|| format!("creating {}", self.db_path.display()));
                }
            }
        }
        let conn = Connection::open(&self.db_path)
            .with_context(|| format!("opening history database {}", self.db_path.display()))?;
        set_private_permissions(&self.db_path, false)?;
        Ok(conn)
    }

    fn init_db(&self) -> Result<()> {
        let conn = self.connect()?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at INTEGER NOT NULL,
                signature BLOB NOT NULL,
                nonce BLOB NOT NULL,
                payload BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_runs_signature_id
                ON runs(signature, id DESC);
            CREATE INDEX IF NOT EXISTS idx_runs_signature_created
                ON runs(signature, created_at DESC);",
        )?;
        Ok(())
    }

    fn signature(&self, cwd: &str, argv: &[String]) -> Result<[u8; 32]> {
        let raw = serde_json::to_vec(&(cwd, argv))?;
        Ok(*blake3::keyed_hash(&self.key, &raw).as_bytes())
    }

    fn encrypt(&self, payload: &SnapshotPayload) -> Result<([u8; 12], Vec<u8>)> {
        let raw = serde_json::to_vec(payload)?;
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).context("generating history nonce")?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &raw,
                    aad: AAD,
                },
            )
            .map_err(|_| anyhow::anyhow!("failed to encrypt stef history payload"))?;
        Ok((nonce, encrypted))
    }

    fn decrypt(&self, nonce: &[u8], payload: &[u8]) -> Result<SnapshotPayload> {
        if nonce.len() != 12 {
            bail!("invalid nonce in stef history database");
        }
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let raw = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: payload,
                    aad: AAD,
                },
            )
            .map_err(|_| anyhow::anyhow!("failed to decrypt stef history payload"))?;
        serde_json::from_slice(&raw).context("decoding stef history payload")
    }

    pub fn add(&self, cwd: &str, argv: &[String], matches: &[MatchRecord]) -> Result<i64> {
        let created_at = now_unix();
        let signature = self.signature(cwd, argv)?;
        let payload = SnapshotPayload {
            cwd: cwd.to_owned(),
            argv: argv.to_vec(),
            matches: matches.to_vec(),
        };
        let (nonce, encrypted) = self.encrypt(&payload)?;
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO runs(created_at, signature, nonce, payload) VALUES (?1, ?2, ?3, ?4)",
            params![
                created_at,
                signature.as_slice(),
                nonce.as_slice(),
                encrypted
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    fn row_to_snapshot(&self, row: (i64, i64, Vec<u8>, Vec<u8>)) -> Result<Snapshot> {
        let (run_id, created_at, nonce, encrypted) = row;
        let payload = self.decrypt(&nonce, &encrypted)?;
        Ok(Snapshot {
            run_id,
            created_at,
            cwd: payload.cwd,
            argv: payload.argv,
            matches: payload.matches,
        })
    }

    pub fn latest(&self) -> Result<Option<Snapshot>> {
        let conn = self.connect()?;
        let row = conn
            .query_row(
                "SELECT id, created_at, nonce, payload FROM runs ORDER BY id DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        row.map(|r| self.row_to_snapshot(r)).transpose()
    }

    pub fn for_command(
        &self,
        cwd: &str,
        argv: &[String],
        limit: Option<usize>,
        since: Option<i64>,
    ) -> Result<Vec<Snapshot>> {
        let signature = self.signature(cwd, argv)?;
        let conn = self.connect()?;
        let mut out = Vec::new();
        match (since, limit) {
            (Some(since), Some(limit)) => {
                let mut stmt = conn.prepare(
                    "SELECT id, created_at, nonce, payload FROM runs
                     WHERE signature = ?1 AND created_at >= ?2
                     ORDER BY id DESC LIMIT ?3",
                )?;
                let rows = stmt
                    .query_map(params![signature.as_slice(), since, limit as i64], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                    })?;
                for row in rows {
                    out.push(self.row_to_snapshot(row?)?);
                }
            }
            (Some(since), None) => {
                let mut stmt = conn.prepare(
                    "SELECT id, created_at, nonce, payload FROM runs
                     WHERE signature = ?1 AND created_at >= ?2
                     ORDER BY id DESC",
                )?;
                let rows = stmt.query_map(params![signature.as_slice(), since], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                })?;
                for row in rows {
                    out.push(self.row_to_snapshot(row?)?);
                }
            }
            (None, Some(limit)) => {
                let mut stmt = conn.prepare(
                    "SELECT id, created_at, nonce, payload FROM runs
                     WHERE signature = ?1 ORDER BY id DESC LIMIT ?2",
                )?;
                let rows = stmt.query_map(params![signature.as_slice(), limit as i64], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                })?;
                for row in rows {
                    out.push(self.row_to_snapshot(row?)?);
                }
            }
            (None, None) => {
                let mut stmt = conn.prepare(
                    "SELECT id, created_at, nonce, payload FROM runs
                     WHERE signature = ?1 ORDER BY id DESC",
                )?;
                let rows = stmt.query_map(params![signature.as_slice()], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                })?;
                for row in rows {
                    out.push(self.row_to_snapshot(row?)?);
                }
            }
        }
        Ok(out)
    }

    pub fn list_recent(&self, limit: usize) -> Result<Vec<Snapshot>> {
        let conn = self.connect()?;
        let mut stmt = conn
            .prepare("SELECT id, created_at, nonce, payload FROM runs ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt.query_map(params![limit as i64], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(self.row_to_snapshot(row?)?);
        }
        Ok(out)
    }

    pub fn clear(&self) -> Result<()> {
        let conn = self.connect()?;
        conn.execute("DELETE FROM runs", [])?;
        conn.execute_batch("VACUUM")?;
        Ok(())
    }
}

fn prepare_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    set_private_permissions(path, true)
}

fn set_private_permissions(path: &Path, directory: bool) -> Result<()> {
    #[cfg(unix)]
    {
        let mode = if directory { 0o700 } else { 0o600 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("setting private permissions on {}", path.display()))?;
    }
    Ok(())
}

fn check_private_key_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let mode = fs::metadata(path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "refusing to use history key with permissions {:o}; run: chmod 600 {}",
                mode,
                path.display()
            );
        }
    }
    Ok(())
}

fn load_or_create_key(
    key_path: &Path,
    gpg_key_path: &Path,
    db_path: &Path,
    recipients: &[String],
) -> Result<[u8; 32]> {
    if gpg_key_path.exists() {
        check_private_key_permissions(gpg_key_path)?;
        let key = decrypt_gpg_key(gpg_key_path)?;
        if !recipients.is_empty() {
            write_gpg_key(gpg_key_path, &key, recipients)?;
        }
        return Ok(key);
    }
    if key_path.exists() {
        check_private_key_permissions(key_path)?;
        let bytes = fs::read(key_path)?;
        if bytes.len() != 32 {
            bail!("invalid stef history key: {}", key_path.display());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        if !recipients.is_empty() {
            write_gpg_key(gpg_key_path, &key, recipients)?;
            fs::remove_file(key_path)?;
        }
        return Ok(key);
    }
    if db_path.exists() && fs::metadata(db_path)?.len() > 0 {
        bail!(
            "stef history database exists but its key is missing: {}",
            db_path.display()
        );
    }
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).context("generating stef history key")?;
    if recipients.is_empty() {
        write_local_key(key_path, &key)?;
    } else {
        write_gpg_key(gpg_key_path, &key, recipients)?;
    }
    Ok(key)
}

fn write_local_key(path: &Path, key: &[u8; 32]) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(key)?;
    file.sync_all()?;
    set_private_permissions(path, false)?;
    Ok(())
}

fn write_gpg_key(path: &Path, key: &[u8; 32], recipients: &[String]) -> Result<()> {
    if recipients.is_empty() {
        bail!("cannot GPG-encrypt history without a recipient");
    }
    let mut cmd = Command::new(gpg_binary());
    cmd.args(["--batch", "--yes", "--trust-model", "always", "--encrypt"]);
    for recipient in recipients {
        cmd.arg("--recipient").arg(recipient);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("starting gpg to encrypt stef history key")?;
    child
        .stdin
        .as_mut()
        .context("capturing gpg stdin")?
        .write_all(key)?;
    drop(child.stdin.take());
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "failed to GPG-encrypt stef history key: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let tmp = path.with_extension("gpg.tmp");
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts.open(&tmp)?;
    file.write_all(&output.stdout)?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    set_private_permissions(path, false)?;
    Ok(())
}

fn decrypt_gpg_key(path: &Path) -> Result<[u8; 32]> {
    let output = Command::new(gpg_binary())
        .args(["--quiet", "--decrypt"])
        .arg(path)
        .output()
        .context("starting gpg to decrypt stef history key")?;
    if !output.status.success() {
        bail!(
            "failed to decrypt stef history key with GPG: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    if output.stdout.len() != 32 {
        bail!("invalid GPG-wrapped stef history key: {}", path.display());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&output.stdout);
    Ok(key)
}

pub fn recipients_from_env() -> Vec<String> {
    std::env::var("STEF_HISTORY_GPG_RECIPIENT")
        .ok()
        .into_iter()
        .flat_map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn local_history_round_trip() {
        let dir = tempdir().unwrap();
        let store = HistoryStore::open(dir.path().to_path_buf(), &[]).unwrap();
        let m = MatchRecord {
            path: "secret.yml".into(),
            line_number: 3,
            byte_offset: 10,
            text: "password: secret".into(),
            spans: vec![(10, 16)],
        };
        store
            .add("/tmp", &["password".into(), ".".into()], &[m.clone()])
            .unwrap();
        let latest = store.latest().unwrap().unwrap();
        assert_eq!(latest.matches, vec![m]);
    }

    #[test]
    fn database_does_not_contain_plain_match() {
        let dir = tempdir().unwrap();
        let store = HistoryStore::open(dir.path().to_path_buf(), &[]).unwrap();
        let m = MatchRecord {
            path: "x".into(),
            line_number: 1,
            byte_offset: 0,
            text: "VERY_SECRET_VALUE_12345".into(),
            spans: vec![],
        };
        store.add("/tmp", &["secret".into()], &[m]).unwrap();
        let bytes = fs::read(dir.path().join("history.sqlite3")).unwrap();
        assert!(
            !bytes
                .windows(b"VERY_SECRET_VALUE_12345".len())
                .any(|w| w == b"VERY_SECRET_VALUE_12345")
        );
    }
}
