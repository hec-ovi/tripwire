# Design

## Threat model

- **The agent may be prompt-injected.** Anything it reads (a web page, a
  file, a tool result) can steer it into calling tools with hostile
  arguments. Every line from the client is untrusted input.
- **The server is trusted to do what it is told.** tripwire limits what the
  server is told; it does not contain what the server does with an allowed
  call.
- **The log reader wants to know nothing was changed** after the session:
  no record edited, dropped, inserted or reordered.

## Proxy invariants

- **I1 Forward what you evaluated.** Every line is parsed into a
  `serde_json::Value`, and the re-serialized value is what gets logged and
  forwarded, never the original bytes. JSON parsers disagree on duplicate
  keys (`{"method":"ping","method":"tools/call"}`); after re-serialization
  there is one `method`, the one the gate saw.
- **I2 Fail closed on what you cannot understand.** A client line that is
  not JSON gets a -32700 parse error; a batch array or any other non-object
  gets -32600. Neither is forwarded. Batches were removed from MCP in
  2025-06-18 and would let a `tools/call` ride past the gate.
- **I3 Denied calls never reach the server.** tripwire answers a denied
  `tools/call` itself, with the request's id and an MCP tool error, so the
  agent can continue. A call without a string `params.name` is denied.
- **I4 Least privilege in discovery.** `tools/list` responses lose the tools
  the policy denies by name alone. Tools that are denied only for some
  arguments stay listed.

## Log invariants

- **Write-ahead.** A message is logged before it is forwarded or delivered.
  If a log write fails, the message is not sent and that direction stops
  (the server's stdin is closed, or tripwire exits), so nothing crosses
  unrecorded.
- **Chained.** Each record stores the SHA-256 of its own canonical JSON
  (sorted keys, no whitespace, `hash` left out) and the previous record's
  hash. `verify` recomputes both and checks `seq` runs 0, 1, 2, ... so an
  edit, deletion, insertion or reorder is reported at its line.
  `serde_json`'s `float_roundtrip` feature is on so that numbers re-serialize
  identically when the log is read back.
- **One session, one file.** `run` refuses to open an existing log, so a
  session is never appended to another.
- **Ordered.** Sequence numbers are assigned under the log lock, and
  messages to the client are written while holding the client lock, so the
  log order is the order in which messages were processed and delivered.
- **Tamper-evident, not tamper-proof.** Whoever can write the file can
  recompute the whole chain, and removing lines from the end leaves a valid
  chain. Both change the head hash, so keep the head (`verify` prints it)
  somewhere the writer cannot reach and check it with `--head`.

## Non-goals

- **Gating anything but `tools/call`.** Tools are where an agent acts.
  `initialize`, notifications, `resources/*`, `prompts/*` and requests from
  the server (such as sampling) pass through and are logged. Gating them
  would need rules over URIs and prompt names, a second policy language for a
  smaller risk; limit what the server exposes in its own configuration.
- **Sandboxing.** An allowed call runs with the server's full authority. Run
  the server as a restricted user or in a container if that matters.
- **Path normalization.** Regexes see the argument strings as sent. Resolving
  paths correctly needs each tool's argument semantics, the server's working
  directory and the file system's symlinks; a wrong guess would silently
  allow. Refusing `..` and dotfiles outright is simpler and fails closed.
- **Replay beyond exact matches.** Replay matches method and exact params, so
  a request that differs in any field, `_meta` included, gets -32001 rather
  than a guess.
- **An async runtime.** One client and one server need two blocking threads.
