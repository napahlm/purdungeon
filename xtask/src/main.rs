//! Repository chores that need more than a shell one-liner. Run through the
//! Justfile (`just fetch-corpus`) or directly:
//!
//! ```text
//! cargo run -p xtask -- fetch-corpus [--force]   download missing corpus captures, verify sha256
//! cargo run -p xtask -- verify-corpus            check what is already on disk
//! ```
//!
//! The corpus is listed in `crates/core/tests/corpus/manifest.toml`; the
//! files themselves are gitignored. Downloads go through the system `curl`
//! (present on Windows 10+, macOS and Linux) so this tool pulls no TLS
//! crates into the tree.

use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct Manifest {
    capture: Vec<Capture>,
}

#[derive(Deserialize)]
struct Capture {
    name: String,
    file: String,
    url: String,
    sha256: String,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("fetch-corpus") => fetch_corpus(args.iter().any(|a| a == "--force")),
        Some("verify-corpus") => verify_corpus(),
        _ => Err("usage: cargo run -p xtask -- <fetch-corpus [--force] | verify-corpus>".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/core/tests/corpus")
}

fn load_manifest(dir: &Path) -> Result<Manifest, String> {
    let path = dir.join("manifest.toml");
    let text = fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hasher.finalize().iter().fold(String::new(), |mut hex, b| {
        let _ = write!(hex, "{b:02x}");
        hex
    }))
}

fn fetch_corpus(force: bool) -> Result<(), String> {
    let dir = corpus_dir();
    let manifest = load_manifest(&dir)?;
    for capture in &manifest.capture {
        let target = dir.join(&capture.file);
        if target.exists() && !force {
            if sha256_file(&target)? == capture.sha256 {
                println!("ok       {} (already present)", capture.name);
                continue;
            }
            println!("redo     {} (present but sha256 differs)", capture.name);
        }
        println!("fetching {} from {}", capture.name, capture.url);
        let partial = dir.join(format!("{}.part", capture.file));
        let status = Command::new("curl")
            .args(["-L", "--fail", "--retry", "3", "--progress-bar", "-o"])
            .arg(&partial)
            .arg(&capture.url)
            .status()
            .map_err(|e| format!("run curl: {e} (is curl installed and on PATH?)"))?;
        if !status.success() {
            let _ = fs::remove_file(&partial);
            return Err(format!("curl failed for {} ({status})", capture.name));
        }
        let actual = sha256_file(&partial)?;
        if actual != capture.sha256 {
            let _ = fs::remove_file(&partial);
            return Err(format!(
                "{}: sha256 mismatch after download\n  expected {}\n  actual   {actual}",
                capture.name, capture.sha256
            ));
        }
        fs::rename(&partial, &target).map_err(|e| format!("rename {}: {e}", partial.display()))?;
        println!("ok       {} (sha256 verified)", capture.name);
    }
    Ok(())
}

fn verify_corpus() -> Result<(), String> {
    let dir = corpus_dir();
    let manifest = load_manifest(&dir)?;
    let mut failures = 0;
    for capture in &manifest.capture {
        let target = dir.join(&capture.file);
        if !target.exists() {
            println!("missing  {}", capture.name);
            continue;
        }
        if sha256_file(&target)? == capture.sha256 {
            println!("ok       {}", capture.name);
        } else {
            println!(
                "BAD      {} (sha256 differs from the manifest)",
                capture.name
            );
            failures += 1;
        }
    }
    if failures > 0 {
        return Err(format!("{failures} corpus file(s) failed verification"));
    }
    Ok(())
}
