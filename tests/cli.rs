//! End to end with the real binary: re-run an agent against a recorded session
//! (`run -- tripwire replay`), then verify and tamper with the new log.

use serde_json::{Value, json};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use tripwire::log::{CLIENT_TO_SERVER, Log, SERVER_TO_CLIENT};

const BIN: &str = env!("CARGO_BIN_EXE_tripwire");

fn tripwire(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(BIN)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn call(id: u64, tool: &str) -> Value {
    let params = json!({"name": tool, "arguments": {"path": "README.md"}});
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params})
}

#[test]
fn record_replay_verify_and_tamper() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("cli");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let path = |name: &str| dir.join(name).to_str().unwrap().to_string();
    let (old, new, policy) = (path("old.jsonl"), path("new.jsonl"), path("policy.toml"));

    let mut log = Log::new(File::create(&old).unwrap());
    log.append(CLIENT_TO_SERVER, "message", &call(1, "read_file"), None)
        .unwrap();
    let text = json!({"content": [{"type": "text", "text": "hello"}]});
    let reply = json!({"jsonrpc": "2.0", "id": 1, "result": text});
    log.append(SERVER_TO_CLIENT, "message", &reply, None)
        .unwrap();
    let rules = "default = \"deny\"\n[[rule]]\ntool = \"read_file\"\naction = \"allow\"\n";
    fs::write(&policy, rules).unwrap();

    let input = format!("{}\n{}\n", call(7, "read_file"), call(8, "shell"));
    let run = [
        "run", "--policy", &policy, "--log", &new, "--", BIN, "replay", &old,
    ];
    let out = tripwire(&run, &input);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let replies: Vec<Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let by_id = |id: u64| replies.iter().find(|r| r["id"] == id).unwrap();
    assert_eq!(by_id(7)["result"], text);
    assert_eq!(by_id(8)["result"]["isError"], true);

    let out = tripwire(&["verify", &new], "");
    let report = String::from_utf8(out.stdout).unwrap();
    assert!(report.starts_with("ok: 4 records, head "), "{report}");
    let head = report.trim().rsplit(' ').next().unwrap();
    assert!(
        tripwire(&["verify", &new, "--head", head], "")
            .status
            .success()
    );
    assert!(
        !tripwire(&run, &input).status.success(),
        "must not overwrite a log"
    );

    let recorded = fs::read_to_string(&new).unwrap();
    let line = recorded.lines().position(|l| l.contains("hello")).unwrap() + 1;
    fs::write(&new, recorded.replace("hello", "hellp")).unwrap();
    for args in [["verify", &new], ["replay", &new]] {
        let out = tripwire(&args, "");
        assert_eq!(out.status.code(), Some(1));
        let err = String::from_utf8(out.stderr).unwrap();
        assert!(
            err.contains(&format!("line {line}: hash mismatch")),
            "{err}"
        );
    }
}
