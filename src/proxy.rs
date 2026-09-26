//! The stdio proxy: gate `tools/call`, filter `tools/list`, log every message.
//!
//! Each line is parsed and the re-serialized value is what gets logged and
//! forwarded, so the server only ever sees what the gate evaluated.

use crate::log::{CLIENT_TO_SERVER, Log, SERVER_TO_CLIENT, TRIPWIRE_TO_CLIENT};
use crate::policy::Policy;
use anyhow::Result;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::sync::{Arc, Mutex};
use std::thread;

struct Shared<L, C> {
    policy: Mutex<Policy>,
    log: Mutex<Log<L>>,
    /// Lock order: `client` before `log`, so log order matches what the client receives.
    client: Mutex<C>,
    /// Client request id (canonical JSON) -> method, to recognize `tools/list` responses.
    pending: Mutex<HashMap<String, String>>,
}

impl<L: Write, C: Write> Shared<L, C> {
    fn log(&self, dir: &str, kind: &str, msg: &Value, reason: Option<&str>) -> io::Result<()> {
        self.log.lock().unwrap().append(dir, kind, msg, reason)
    }

    /// Log a message the client sent but that is not forwarded, then answer it ourselves.
    fn refuse(&self, msg: &Value, kind: &str, reason: &str, reply: Value) -> io::Result<()> {
        let mut client = self.client.lock().unwrap();
        let mut log = self.log.lock().unwrap();
        log.append(CLIENT_TO_SERVER, kind, msg, Some(reason))?;
        log.append(TRIPWIRE_TO_CLIENT, "message", &reply, None)?;
        writeln!(client, "{reply}")?;
        client.flush()
    }
}

/// Run the proxy until the server closes its output. The client pump is not
/// joined: if the server exits we return even if the client never closes stdin.
pub fn run<L, CI, CO, SI, SO>(
    policy: Policy,
    log: L,
    client_in: CI,
    client_out: CO,
    server_in: SI,
    server_out: SO,
) -> Result<()>
where
    L: Write + Send + 'static,
    CI: BufRead + Send + 'static,
    CO: Write + Send + 'static,
    SI: Write + Send + 'static,
    SO: BufRead,
{
    let shared = Arc::new(Shared {
        policy: Mutex::new(policy),
        log: Mutex::new(Log::new(log)),
        client: Mutex::new(client_out),
        pending: Mutex::new(HashMap::new()),
    });
    let client_side = Arc::clone(&shared);
    thread::spawn(move || {
        // Returning drops server_in, which closes the server's stdin.
        if let Err(e) = client_pump(&client_side, client_in, server_in) {
            eprintln!("tripwire: client side: {e:#}");
        }
    });
    server_pump(&shared, server_out)
}

fn client_pump<L: Write, C: Write>(
    sh: &Shared<L, C>,
    input: impl BufRead,
    mut server: impl Write,
) -> Result<()> {
    for line in input.split(b'\n') {
        let line = line?;
        if line.trim_ascii().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_slice::<Value>(&line) else {
            let raw = Value::String(String::from_utf8_lossy(&line).into_owned());
            sh.refuse(
                &raw,
                "rejected",
                "unparseable JSON",
                error(-32700, "parse error"),
            )?;
            continue;
        };
        if !msg.is_object() {
            let reason = "not a single JSON-RPC object (batches are not supported)";
            sh.refuse(&msg, "rejected", reason, error(-32600, reason))?;
            continue;
        }
        if msg["method"] == "tools/call" {
            let params = &msg["params"];
            let (allowed, reason) = match params["name"].as_str() {
                Some(name) => {
                    let d = sh
                        .policy
                        .lock()
                        .unwrap()
                        .evaluate(name, &params["arguments"]);
                    (d.allowed, d.reason)
                }
                None => (false, "tools/call without a string params.name".to_string()),
            };
            if !allowed {
                let text = format!("tripwire: blocked by policy: {reason}");
                let reply = json!({
                    "jsonrpc": "2.0",
                    "id": msg["id"],
                    "result": {"content": [{"type": "text", "text": text}], "isError": true},
                });
                sh.refuse(&msg, "deny", &reason, reply)?;
                continue;
            }
        }
        if let (Some(id), Some(method)) = (msg.get("id"), msg["method"].as_str()) {
            let mut pending = sh.pending.lock().unwrap();
            pending.insert(id.to_string(), method.to_string());
        }
        sh.log(CLIENT_TO_SERVER, "message", &msg, None)?;
        writeln!(server, "{msg}")?;
        server.flush()?;
    }
    Ok(())
}

fn server_pump<L: Write, C: Write>(sh: &Shared<L, C>, input: impl BufRead) -> Result<()> {
    for line in input.split(b'\n') {
        let line = line?;
        if line.trim_ascii().is_empty() {
            continue;
        }
        let Ok(mut msg) = serde_json::from_slice::<Value>(&line) else {
            let raw = Value::String(String::from_utf8_lossy(&line).into_owned());
            sh.log(SERVER_TO_CLIENT, "rejected", &raw, Some("unparseable JSON"))?;
            continue;
        };
        if let (Some(id), None) = (msg.get("id"), msg.get("method")) {
            let method = sh.pending.lock().unwrap().remove(&id.to_string());
            let tools = msg
                .pointer_mut("/result/tools")
                .and_then(Value::as_array_mut);
            if let (Some("tools/list"), Some(tools)) = (method.as_deref(), tools) {
                let policy = sh.policy.lock().unwrap();
                tools.retain(|t| t["name"].as_str().is_some_and(|n| !policy.hides(n)));
            }
        }
        let mut client = sh.client.lock().unwrap();
        sh.log(SERVER_TO_CLIENT, "message", &msg, None)?;
        writeln!(client, "{msg}")?;
        client.flush()?;
    }
    Ok(())
}

fn error(code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": null, "error": {"code": code, "message": message}})
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Cursor, PipeReader, PipeWriter};

    const POLICY: &str = r#"
        default = "deny"
        [[rule]]
        tool = "shell"
        action = "deny"
        [[rule]]
        tool = "read_file"
        action = "allow"
        deny_args = ['\.ssh']
    "#;

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl Write for Buf {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Buf {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
        fn values(&self) -> Vec<Value> {
            let text = self.text();
            text.lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        }
    }

    /// Records the raw lines it receives; lists three tools and echoes every other request.
    fn mock_server(input: PipeReader, mut output: PipeWriter, mut seen: Buf) {
        for line in BufReader::new(input).lines() {
            let line = line.unwrap();
            writeln!(seen, "{line}").unwrap();
            let msg: Value = serde_json::from_str(&line).unwrap();
            let (Some(id), Some(method)) = (msg.get("id"), msg["method"].as_str()) else {
                continue;
            };
            let result = match method {
                "tools/list" => json!({"tools": [{"name": "read_file"}, {"name": "shell"}]}),
                _ => json!({"echo": msg}),
            };
            let reply = json!({"jsonrpc": "2.0", "id": id, "result": result});
            writeln!(output, "{reply}").unwrap();
        }
    }

    struct Session {
        client: Vec<Value>,
        server: Buf,
        log: String,
    }

    fn session(client_lines: &[&str]) -> Session {
        let (to_server, server_in) = io::pipe().unwrap();
        let (server_out, from_server) = io::pipe().unwrap();
        let (client, server, log) = (Buf::default(), Buf::default(), Buf::default());
        let seen = server.clone();
        let mock = thread::spawn(move || mock_server(to_server, from_server, seen));
        let input = Cursor::new(client_lines.join("\n").into_bytes());
        let policy = Policy::from_toml(POLICY).unwrap();
        let server_out = BufReader::new(server_out);
        run(
            policy,
            log.clone(),
            input,
            client.clone(),
            server_in,
            server_out,
        )
        .unwrap();
        mock.join().unwrap();
        let log = log.text();
        crate::log::verify(&log).unwrap();
        Session {
            client: client.values(),
            server,
            log,
        }
    }

    fn call(id: u64, tool: &str, args: Value) -> String {
        let params = json!({"name": tool, "arguments": args});
        json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params}).to_string()
    }

    #[test]
    fn allowed_call_is_forwarded_and_answered() {
        let s = session(&[&call(1, "read_file", json!({"path": "src/main.rs"}))]);
        assert_eq!(s.server.values().len(), 1);
        assert_eq!(s.client.len(), 1);
        assert_eq!(s.client[0]["id"], 1);
        assert_eq!(s.client[0]["result"]["echo"]["params"]["name"], "read_file");
    }

    #[test]
    fn denied_calls_never_reach_the_server() {
        let no_name = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":7}}"#;
        let s = session(&[
            &call(1, "shell", json!({"cmd": "id"})),
            &call(2, "read_file", json!({"path": "/home/u/.ssh/id_rsa"})),
            no_name,
        ]);
        assert_eq!(s.server.text(), "");
        assert_eq!(s.client.len(), 3);
        for (reply, id) in s.client.iter().zip([1, 2, 3]) {
            assert_eq!(reply["id"], id);
            assert_eq!(reply["result"]["isError"], true);
            let text = reply["result"]["content"][0]["text"].as_str().unwrap();
            assert!(text.starts_with("tripwire: blocked by policy: "), "{text}");
        }
        let records = crate::log::verify(&s.log).unwrap();
        let kinds: Vec<_> = records.iter().map(|r| (&r["dir"], &r["kind"])).collect();
        assert_eq!(kinds[0], (&json!("client_to_server"), &json!("deny")));
        assert_eq!(kinds[1], (&json!("tripwire_to_client"), &json!("message")));
        assert_eq!(records[0]["reason"], r#"rule 1 ("shell") denies this tool"#);
    }

    #[test]
    fn tools_list_hides_tools_denied_by_name() {
        let s = session(&[r#"{"jsonrpc":"2.0","id":"a","method":"tools/list"}"#]);
        assert_eq!(
            s.client[0]["result"]["tools"],
            json!([{"name": "read_file"}])
        );
    }

    #[test]
    fn duplicate_keys_cannot_smuggle_a_call_past_the_gate() {
        // serde_json keeps the last duplicate key; a first-wins server would see tools/call.
        let smuggle = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell"},"method":"ping"}"#;
        let caught = r#"{"jsonrpc":"2.0","id":2,"method":"ping","method":"tools/call","params":{"name":"shell"}}"#;
        let s = session(&[smuggle, caught]);
        let seen = s.server.text();
        assert_eq!(seen.lines().count(), 1);
        assert_eq!(seen.matches("\"method\"").count(), 1);
        assert!(seen.contains(r#""method":"ping""#) && !seen.contains("tools/call"));
        let denied = s.client.iter().find(|m| m["id"] == 2).unwrap();
        assert_eq!(denied["result"]["isError"], true);
    }

    #[test]
    fn batches_and_garbage_are_rejected() {
        let batch = format!("[{}]", call(1, "shell", json!({})));
        let s = session(&["{not json", &batch, "42"]);
        assert_eq!(s.server.text(), "");
        let codes: Vec<_> = s
            .client
            .iter()
            .map(|m| m["error"]["code"].clone())
            .collect();
        assert_eq!(codes, [-32700, -32600, -32600]);
        assert!(s.client.iter().all(|m| m["id"].is_null()));
    }

    #[test]
    fn other_messages_pass_through() {
        let lines = [
            r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///x"}}"#,
            r#"{"jsonrpc":"2.0","id":"srv-1","result":{"model":"m"}}"#,
        ];
        let s = session(&lines);
        let seen: Vec<Value> = s.server.values();
        let sent: Vec<Value> = lines
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(seen, sent);
        assert_eq!(s.client.len(), 2);
    }
}
