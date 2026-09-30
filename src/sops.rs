use anyhow::{Context, Result, bail};
use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::bytes::Regex;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{ChildStdout, Command, Stdio};
use std::sync::OnceLock;

const PROBE_CHUNK: usize = 256 * 1024;
const DEFAULT_GLOBS: &[&str] = &[
    "*.yaml", "*.yml", "*.json", "*.env", ".env", "*.env.*", "*.ini", "*.sops", "*.sops.*",
];

#[derive(Debug, Clone)]
pub struct SopsProbe {
    pub encrypted: bool,
    pub pgp_fingerprints: BTreeSet<String>,
}

#[derive(Debug)]
pub struct DecryptReader {
    child: std::process::Child,
    stdout: Option<ChildStdout>,
    path: PathBuf,
}

impl DecryptReader {
    pub fn stdout(&mut self) -> Result<ChildStdout> {
        self.stdout
            .take()
            .context("internal error: SOPS stdout already consumed")
    }

    pub fn wait(mut self) -> Result<()> {
        let status = self
            .child
            .wait()
            .with_context(|| format!("waiting for SOPS decrypt of {}", self.path.display()))?;
        if !status.success() {
            bail!(
                "sops --decrypt failed for {} with {}",
                self.path.display(),
                status
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct SopsDetector {
    globs: GlobSet,
}

impl SopsDetector {
    pub fn new(extra_globs: &[String]) -> Result<Self> {
        let mut builder = GlobSetBuilder::new();
        for pattern in DEFAULT_GLOBS
            .iter()
            .copied()
            .chain(extra_globs.iter().map(String::as_str))
        {
            builder
                .add(Glob::new(pattern).with_context(|| format!("invalid SOPS glob {pattern:?}"))?);
        }
        Ok(Self {
            globs: builder.build()?,
        })
    }

    pub fn is_candidate(&self, path: &Path) -> bool {
        let file_name = path.file_name().map(Path::new);
        self.globs.is_match(path)
            || file_name.is_some_and(|name| self.globs.is_match(name))
            || path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|name| name.contains(".sops."))
    }

    pub fn probe(&self, path: &Path) -> Result<SopsProbe> {
        if !self.is_candidate(path) {
            return Ok(SopsProbe {
                encrypted: false,
                pgp_fingerprints: BTreeSet::new(),
            });
        }
        let bytes = read_probe_bytes(path)?;
        let has_enc = bytes
            .windows(b"ENC[AES256_GCM".len())
            .any(|w| w == b"ENC[AES256_GCM");
        let has_sops_metadata = bytes.windows(b"\nsops:".len()).any(|w| w == b"\nsops:")
            || bytes.windows(b"\"sops\"".len()).any(|w| w == b"\"sops\"")
            || bytes.windows(b"sops_".len()).any(|w| w == b"sops_")
            || bytes.windows(b"[sops]".len()).any(|w| w == b"[sops]")
            || path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|name| name.contains(".sops."));
        let encrypted = has_enc && has_sops_metadata;
        let pgp_fingerprints = if encrypted {
            pgp_fingerprints(&bytes)
        } else {
            BTreeSet::new()
        };
        Ok(SopsProbe {
            encrypted,
            pgp_fingerprints,
        })
    }
}

fn read_probe_bytes(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let len = file.metadata()?.len();
    let mut out = Vec::new();
    let first_len = len.min(PROBE_CHUNK as u64) as usize;
    out.resize(first_len, 0);
    file.read_exact(&mut out)?;
    if len > PROBE_CHUNK as u64 {
        let tail_len = len.min(PROBE_CHUNK as u64) as usize;
        file.seek(SeekFrom::End(-(tail_len as i64)))?;
        let start = out.len();
        out.resize(start + tail_len, 0);
        file.read_exact(&mut out[start..])?;
    }
    Ok(out)
}

fn fp_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:[\"']?fp[\"']?\s*[:=]|sops_pgp[^\r\n=]*_fp\s*=)\s*[\"']?([0-9a-f]{40,64})"#,
        )
        .expect("hard-coded SOPS fingerprint regex is valid")
    })
}

pub fn pgp_fingerprints(bytes: &[u8]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for caps in fp_regex().captures_iter(bytes) {
        if let Some(value) = caps.get(1) {
            out.insert(String::from_utf8_lossy(value.as_bytes()).to_ascii_uppercase());
        }
    }
    out
}

pub fn spawn_decrypt(path: &Path) -> Result<DecryptReader> {
    let sops = std::env::var_os("STEF_SOPS").unwrap_or_else(|| "sops".into());
    let mut child = Command::new(&sops)
        .arg("--decrypt")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| {
            format!(
                "starting {:?} --decrypt {} (install sops or set STEF_SOPS)",
                sops,
                path.display()
            )
        })?;
    let stdout = child
        .stdout
        .take()
        .context("failed to capture SOPS stdout")?;
    Ok(DecryptReader {
        child,
        stdout: Some(stdout),
        path: path.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_pgp_fingerprints() {
        let data = br#"sops:\n  pgp:\n    - fp: ABCDEF0123456789ABCDEF0123456789ABCDEF01\n"#;
        let values = pgp_fingerprints(data);
        assert!(values.contains("ABCDEF0123456789ABCDEF0123456789ABCDEF01"));
    }

    #[test]
    fn detects_sops_yaml_but_not_plain_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let encrypted = dir.path().join("secrets.yaml");
        let plain = dir.path().join("plain.yaml");
        std::fs::write(
            &encrypted,
            "password: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\nsops:\n  mac: ENC[AES256_GCM,data:m,iv:n,tag:o,type:str]\n",
        )
        .unwrap();
        std::fs::write(&plain, "password: plaintext\n").unwrap();
        let detector = SopsDetector::new(&[]).unwrap();
        assert!(detector.probe(&encrypted).unwrap().encrypted);
        assert!(!detector.probe(&plain).unwrap().encrypted);
    }
}
