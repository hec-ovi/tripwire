use anyhow::{Context, Result, bail};
use clap::Parser;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use tripwire::log;

/// Policy gate and tamper-evident recorder for MCP stdio servers.
#[derive(Parser)]
#[command(version)]
enum Cli {
    /// Check a session log's hash chain.
    Verify {
        log: PathBuf,
        /// Also require the last record's hash to equal this (detects a truncated tail).
        #[arg(long)]
        head: Option<String>,
    },
}

fn main() -> ExitCode {
    let result = match Cli::parse() {
        Cli::Verify { log, head } => verify(&log, head.as_deref()),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("tripwire: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn read_verified(path: &Path) -> Result<Vec<serde_json::Value>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    log::verify(&text).with_context(|| format!("{} failed verification", path.display()))
}

fn verify(path: &Path, expected_head: Option<&str>) -> Result<ExitCode> {
    let records = read_verified(path)?;
    let head = log::head(&records);
    if let Some(expected) = expected_head
        && expected != head
    {
        bail!("head is {head}, expected {expected}: the log was truncated or extended");
    }
    println!("ok: {} records, head {head}", records.len());
    Ok(ExitCode::SUCCESS)
}
