//! Act as an MCP server that answers from a recorded session.
//!
//! Requests are matched on method + canonical params (`initialize` on method
//! alone, since client info differs between clients). Repeated requests get
//! the recorded responses in order, then the last one again.

use crate::log::{CLIENT_TO_SERVER, SERVER_TO_CLIENT};
use anyhow::Result;
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, Write};

pub struct Replay {
    answers: HashMap<String, VecDeque<Value>>,
}

impl Replay {
    /// Pair each forwarded client request with the server response that answered it.
    pub fn new(records: &[Value]) -> Replay {
        let mut requests = HashMap::new();
        let mut answers: HashMap<String, VecDeque<Value>> = HashMap::new();
        for record in records.iter().filter(|r| r["kind"] == "message") {
            let msg = &record["message"];
            let Some(id) = msg.get("id") else { continue };
            match (record["dir"].as_str(), msg["method"].as_str()) {
                (Some(CLIENT_TO_SERVER), Some(method)) => {
                    requests.insert(id.to_string(), key(method, &msg["params"]));
                }
                (Some(SERVER_TO_CLIENT), None) => {
                    if let Some(key) = requests.remove(&id.to_string()) {
                        answers.entry(key).or_default().push_back(msg.clone());
                    }
                }
                _ => {}
            }
        }
        Replay { answers }
    }

    /// The reply to one incoming message; None for notifications and responses.
    pub fn answer(&mut self, msg: &Value) -> Option<Value> {
        let (id, method) = (msg.get("id")?, msg["method"].as_str()?);
        let queue = self.answers.get_mut(&key(method, &msg["params"]));
        let recorded = queue.and_then(|q| match q.len() {
            1 => q.front().cloned(),
            _ => q.pop_front(),
        });
        if let Some(mut reply) = recorded {
            reply["id"] = id.clone();
            return Some(reply);
        }
        let mut what = method.to_string();
        if let ("tools/call", Some(tool)) = (method, msg["params"]["name"].as_str()) {
            what = format!("{method} {tool}");
        }
        let message = format!("tripwire replay: no recorded response for {what}");
        eprintln!("{message}");
        Some(json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32001, "message": message}}))
    }
}

fn key(method: &str, params: &Value) -> String {
    match method {
        "initialize" => method.to_string(),
        _ => format!("{method} {params}"),
    }
}

pub fn serve(mut replay: Replay, input: impl BufRead, mut output: impl Write) -> Result<()> {
    for line in input.split(b'\n') {
        let line = line?;
        if line.trim_ascii().is_empty() {
            continue;
        }
        let reply = match serde_json::from_slice::<Value>(&line) {
            Ok(msg) => replay.answer(&msg),
            Err(_) => Some(json!({
                "jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "parse error"}
            })),
        };
        if let Some(reply) = reply {
            writeln!(output, "{reply}")?;
            output.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::{Log, verify};

    fn replay(exchanges: &[(&str, &str, Value)]) -> Replay {
        let mut text = Vec::new();
        let mut log = Log::new(&mut text);
        for (dir, kind, msg) in exchanges {
            log.append(dir, kind, msg, None).unwrap();
        }
        let text = String::from_utf8(text).unwrap();
        Replay::new(&verify(&text).unwrap())
    }

    fn request(id: u64, method: &str, params: Value) -> Value {
        json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
    }

    fn response(id: u64, result: Value) -> Value {
        json!({"jsonrpc": "2.0", "id": id, "result": result})
    }

    #[test]
    fn repeated_requests_are_served_in_order_then_repeat_the_last() {
        let params = json!({"name": "clock", "arguments": {}});
        let mut r = replay(&[
            (
                CLIENT_TO_SERVER,
                "message",
                request(1, "tools/call", params.clone()),
            ),
            (
                CLIENT_TO_SERVER,
                "message",
                request(2, "tools/call", params.clone()),
            ),
            (SERVER_TO_CLIENT, "message", response(2, json!("second"))),
            (SERVER_TO_CLIENT, "message", response(1, json!("first"))),
        ]);
        let results: Vec<Value> = (10..14)
            .map(|id| {
                r.answer(&request(id, "tools/call", params.clone()))
                    .unwrap()
            })
            .collect();
        assert_eq!(results[0], response(10, json!("second")));
        assert_eq!(results[1], response(11, json!("first")));
        assert_eq!(results[3], response(13, json!("first")));
    }

    #[test]
    fn initialize_is_matched_on_method_alone() {
        let mut r = replay(&[
            (
                CLIENT_TO_SERVER,
                "message",
                request(0, "initialize", json!({"clientInfo": "a"})),
            ),
            (
                SERVER_TO_CLIENT,
                "message",
                response(0, json!({"serverInfo": "s"})),
            ),
        ]);
        let reply = r.answer(&request(5, "initialize", json!({"clientInfo": "b"})));
        assert_eq!(reply, Some(response(5, json!({"serverInfo": "s"}))));
    }

    #[test]
    fn unmatched_requests_get_an_error_and_notifications_nothing() {
        let call = request(1, "tools/call", json!({"name": "rm"}));
        let mut r = replay(&[
            (CLIENT_TO_SERVER, "deny", call.clone()),
            (
                SERVER_TO_CLIENT,
                "message",
                response(1, json!("never forwarded")),
            ),
        ]);
        let reply = r.answer(&call).unwrap();
        assert_eq!(reply["id"], 1);
        assert_eq!(reply["error"]["code"], -32001);
        let text = "tripwire replay: no recorded response for tools/call rm";
        assert_eq!(reply["error"]["message"], text);
        let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        assert_eq!(r.answer(&note), None);
    }
}
