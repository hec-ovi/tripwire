//! Hash-chained JSONL session log.
//!
//! Each record's `hash` is the SHA-256 of the record without `hash`, serialized
//! as compact JSON with sorted keys (serde_json's default map is a BTreeMap).
//! `prev` links each record to the one before it.

use anyhow::{Result, bail};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub const CLIENT_TO_SERVER: &str = "client_to_server";
pub const SERVER_TO_CLIENT: &str = "server_to_client";
pub const TRIPWIRE_TO_CLIENT: &str = "tripwire_to_client";

pub struct Log<W> {
    out: W,
    seq: u64,
    prev: String,
}

impl<W: Write> Log<W> {
    pub fn new(out: W) -> Self {
        Log {
            out,
            seq: 0,
            prev: GENESIS.into(),
        }
    }

    /// Append one record. `kind` is "message", "deny" or "rejected"; the last two carry a reason.
    pub fn append(
        &mut self,
        dir: &str,
        kind: &str,
        message: &Value,
        reason: Option<&str>,
    ) -> io::Result<()> {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        let mut record = json!({
            "seq": self.seq,
            "ts_ms": ts_ms,
            "dir": dir,
            "kind": kind,
            "message": message,
            "prev": self.prev,
        });
        if let Some(reason) = reason {
            record["reason"] = reason.into();
        }
        let hash = sha256_hex(&record.to_string());
        record["hash"] = hash.clone().into();
        writeln!(self.out, "{record}")?;
        self.out.flush()?;
        self.seq += 1;
        self.prev = hash;
        Ok(())
    }
}

fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Check the whole chain and return its records. Errors name the first bad line.
pub fn verify(text: &str) -> Result<Vec<Value>> {
    let mut records = Vec::new();
    let mut prev = GENESIS.to_string();
    for (i, line) in text.lines().enumerate() {
        let lineno = i + 1;
        let Ok(mut record) = serde_json::from_str::<Value>(line) else {
            bail!("line {lineno}: not valid JSON");
        };
        let Some(Value::String(hash)) = record.as_object_mut().and_then(|r| r.remove("hash"))
        else {
            bail!("line {lineno}: missing hash");
        };
        if record["seq"] != i {
            bail!("line {lineno}: expected seq {i}, found {}", record["seq"]);
        }
        if record["prev"] != prev.as_str() {
            bail!("line {lineno}: prev does not match the previous record's hash");
        }
        if sha256_hex(&record.to_string()) != hash {
            bail!("line {lineno}: hash mismatch, record was modified");
        }
        record["hash"] = hash.clone().into();
        records.push(record);
        prev = hash;
    }
    Ok(records)
}

/// Hash of the last record, or GENESIS for an empty log.
pub fn head(records: &[Value]) -> &str {
    records
        .last()
        .and_then(|r| r["hash"].as_str())
        .unwrap_or(GENESIS)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Three records; 0.1 + 0.002 needs 17 digits and only round-trips with float_roundtrip.
    fn sample() -> String {
        let mut log = Log::new(Vec::new());
        let call = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call"});
        log.append(CLIENT_TO_SERVER, "message", &call, None)
            .unwrap();
        let reply = json!({"jsonrpc": "2.0", "id": 1, "result": {"n": 0.1 + 0.002}});
        log.append(SERVER_TO_CLIENT, "message", &reply, None)
            .unwrap();
        log.append(CLIENT_TO_SERVER, "deny", &call, Some("no"))
            .unwrap();
        String::from_utf8(log.out).unwrap()
    }

    fn verify_err(text: &str) -> String {
        verify(text).unwrap_err().to_string()
    }

    #[test]
    fn written_log_verifies() {
        let text = sample();
        let records = verify(&text).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0]["prev"], GENESIS);
        assert_eq!(records[1]["prev"], records[0]["hash"]);
        assert_eq!(records[2]["reason"], "no");
        assert_eq!(head(&records), records[2]["hash"]);
        assert_eq!(head(&verify("").unwrap()), GENESIS);
    }

    #[test]
    fn edited_field_is_detected() {
        let text = sample().replacen("tools/call", "tools/list", 1);
        assert_eq!(
            verify_err(&text),
            "line 1: hash mismatch, record was modified"
        );
    }

    #[test]
    fn deleted_line_is_detected() {
        let text = sample();
        let lines: Vec<&str> = text.lines().collect();
        let text = [lines[0], lines[2]].join("\n");
        assert_eq!(verify_err(&text), "line 2: expected seq 1, found 2");
    }

    #[test]
    fn reordered_lines_are_detected() {
        let text = sample();
        let lines: Vec<&str> = text.lines().collect();
        let text = [lines[1], lines[0], lines[2]].join("\n");
        assert_eq!(verify_err(&text), "line 1: expected seq 0, found 1");
    }

    #[test]
    fn garbage_line_is_detected() {
        let text = format!("{}not json\n", sample());
        assert_eq!(verify_err(&text), "line 4: not valid JSON");
    }

    #[test]
    fn truncated_tail_needs_the_head_hash() {
        let text = sample();
        let full_head = head(&verify(&text).unwrap()).to_string();
        let lines: Vec<&str> = text.lines().collect();
        let truncated = verify(&lines[..2].join("\n")).unwrap();
        assert_ne!(head(&truncated), full_head);
    }
}
