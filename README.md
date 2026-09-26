# tripwire

tripwire is a proxy between an MCP client (the agent) and one MCP server over
stdio. It checks every `tools/call` against a TOML policy before the server
sees it, records every message in both directions in a hash-chained JSONL log
that `tripwire verify` can check, and can replay a recorded session as a
server, so a new model or prompt can be tested against recorded tool results
without touching real systems. It is built for agents that may be
prompt-injected: a denied call never reaches the server.

## Quick start

```sh
docker build --target export --output dist .    # static binary at dist/tripwire
mkdir -p ~/.tripwire && cp examples/policy.toml ~/.tripwire/
```

Then start the server through tripwire in the agent's MCP config, for example:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "sh",
      "args": ["-c", "exec /path/to/dist/tripwire run --policy ~/.tripwire/policy.toml --log ~/.tripwire/$(date +%s)-$$.jsonl -- npx -y @modelcontextprotocol/server-filesystem ~/project"]
    }
  }
}
```

`sh -c` gives each session a new log file; tripwire refuses to write to an
existing one. Afterwards, `dist/tripwire verify ~/.tripwire/<session>.jsonl`.
Rust is only needed inside Docker; `scripts/dev.sh cargo test` runs the tests.

## Policy

```toml
default = "deny"            # "allow" | "deny", required

[[rule]]
tool = "read_*"             # exact name, or a glob where * matches anything
action = "allow"            # "allow" | "deny"
deny_args = ['(^|/)\.ssh(/|$)', '\.env$']   # optional regexes
max_calls = 50              # optional; allowed calls per session for this rule
```

The first rule whose `tool` matches decides; if none matches, `default`
does. A `deny` rule denies. An `allow` rule denies when any `deny_args`
regex matches any string in the arguments (nested values and object keys
included), or once it has allowed `max_calls` calls. A denied call is
answered by tripwire as a tool error (`isError: true`, text
`tripwire: blocked by policy: <reason>`), so the agent can carry on. Tools
denied by name alone are also removed from `tools/list` responses. Unknown
keys and invalid regexes stop tripwire at startup; there is no implicit
allow. [examples/policy.toml](examples/policy.toml) is a commented policy
for filesystem, fetch and shell servers.

## Commands

```
tripwire run --policy <policy.toml> --log <session.jsonl> -- <server-cmd> [args...]
tripwire verify <session.jsonl> [--head <hex>]
tripwire replay <session.jsonl>
```

- `run` starts the server and proxies the agent's stdin/stdout to it. It
  exits with the server's exit code when the server exits or after the agent
  closes stdin.
- `verify` checks the hash chain and prints `ok: <n> records, head <hash>`,
  or the first bad line and exits 1. `--head` also requires the last hash to
  match, which is the only way to detect lines cut from the end. If
  tripwire was killed while writing a record, `verify` reports an
  incomplete last record; the records before it are intact.
- `replay` verifies the log, then answers requests from it: matched on
  method and exact params (`initialize` on method alone), with the id of the
  new request. Repeated requests get the recorded responses in order, then
  the last one again. An unrecorded request gets error -32001;
  notifications are ignored.

Re-run an agent against a recorded session, with the gate on:

```sh
tripwire run --policy policy.toml --log new.jsonl -- tripwire replay old.jsonl
```

## Log format

One JSON object per line, keys sorted:

```
{"dir":"client_to_server","hash":"…","kind":"message","message":{…},"prev":"…","seq":0,"ts_ms":…}
```

`dir` is `client_to_server`, `server_to_client` or `tripwire_to_client`.
`kind` is `message` (forwarded or sent), `deny` (a `tools/call` the policy
refused) or `rejected` (a line that was not forwarded, such as invalid JSON
or a batch); those two carry a `reason`. `hash` is the SHA-256 of the record
without `hash`, as compact JSON with sorted keys; `prev` is the previous
record's hash, 64 zeros for the first. `verify` requires every line to be
exactly this serialization, so it also rejects bytes that parse to the same
record, such as extra whitespace or a duplicate key.

## What it does not do

- It is not a sandbox. An allowed call can do anything the server can do.
- Regexes match the raw argument strings, not normalized paths: `^/etc/`
  does not match `/srv/../etc/passwd`. Deny `..` outright.
- Only `tools/call` is gated. Everything else (initialize, notifications,
  resources, prompts, requests from the server) passes through and is logged.
- The log is tamper-evident, not tamper-proof. Anyone who can write the
  file can rewrite the whole chain; lines cut from the end, or a rewritten
  chain, are only detected with `--head` and a head hash kept elsewhere.

See [docs/DESIGN.md](docs/DESIGN.md) for the threat model and invariants.

## License

MIT
