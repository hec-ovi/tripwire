use anyhow::{Context, Result, bail};
use clap::Parser;
use std::fs::OpenOptions;
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use tripwire::replay::{self, Replay};
use tripwire::{log, policy::Policy, proxy};

/// Policy gate and tamper-evident recorder for MCP stdio servers.
#[derive(Parser)]
#[command(version)]
enum Cli {
    /// Run an MCP server behind the policy gate, logging every message.
    Run {
        #[arg(long)]
        policy: PathBuf,
        /// Session log to create; must not exist yet.
        #[arg(long)]
        log: PathBuf,
        /// Server command and arguments, after `--`.
        #[arg(last = true, required = true)]
        server: Vec<String>,
    },
    /// Check a session log's hash chain.
    Verify {
        log: PathBuf,
        /// Also require the last record's hash to equal this (detects a truncated tail).
        #[arg(long)]
        head: Option<String>,
    },
    /// Serve a verified session log as an MCP server on stdin/stdout.
    Replay { log: PathBuf },
}

fn main() -> ExitCode {
    let result = match Cli::parse() {
        Cli::Run {
            policy,
            log,
            server,
        } => run(&policy, &log, &server),
        Cli::Verify { log, head } => verify(&log, head.as_deref()),
        Cli::Replay { log } => replay(&log),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("tripwire: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(policy: &Path, log: &Path, server: &[String]) -> Result<ExitCode> {
    let policy = Policy::load(policy)?;
    // create_new: a session log is never overwritten or appended to.
    let log_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(log)
        .with_context(|| format!("cannot create log {}", log.display()))?;
    let mut child = Command::new(&server[0])
        .args(&server[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("cannot start {}", server[0]))?;
    let server_in = child.stdin.take().expect("piped stdin");
    let server_out = BufReader::new(child.stdout.take().expect("piped stdout"));
    let stdin = BufReader::new(io::stdin());
    let result = proxy::run(policy, log_file, stdin, io::stdout(), server_in, server_out);
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    result?;
    Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
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

fn replay(path: &Path) -> Result<ExitCode> {
    let records = read_verified(path)?;
    replay::serve(Replay::new(&records), io::stdin().lock(), io::stdout())?;
    Ok(ExitCode::SUCCESS)
}
