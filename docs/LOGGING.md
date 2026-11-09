# Decision log

`/var/log/egress/decisions.log` in the guest (owned by the `egress` user; read it with `sudo`).
One JSON object per line. Every line starts with the same keys, so simple greps and consumers
keep working whatever the event:

| Key | Meaning |
|---|---|
| `ts` | Local time, ISO 8601 with offset |
| `method` | HTTP method; `CONNECT`, `TCP`, `UDP`, `TLS` or `RULE` for non-request events |
| `host`, `path` | Target host and normalized path (lower-cased, `..` collapsed, query dropped) |
| `decision` | See below |
| `by` | Who decided: `rule`, `once` (operator, this request only), `default-deny`, `host-mismatch`, `client`, `upstream`, `tui`, `reload` |
| `event` | `decision`, `response`, `error`, `rule` or `tls` |
| `rule` | The rule that decided it: `{action, host, path, methods}`, or `null` |

## Events

**`decision`** (one per request, plus one per CONNECT or raw stream the proxy rules on)

| `decision` | Meaning |
|---|---|
| `allow` / `deny` | A rule (or the operator, `by: once`) decided. A release from hold carries `waited_s` and a `reason` saying who released it |
| `held` | No rule matched; the request waits for an operator. `reason` says whether nothing matched the host and path or only the method excluded it, and `near_rules` lists the rules that cover the path but not this method |
| `abandoned` | The client gave up while the request was held; nothing was enforced |
| `passthrough` | CONNECT to a passthrough host: not inspected, so no method or path is known |
| `handshake-failed` | (`event: tls`) the client rejected the proxy's certificate; `reason` has the error |

Request detail on `decision` lines: `id` (flow id; the matching `response` line has the same one),
`scheme`, `port`, `http_version`, `user_agent`, `req_bytes`, `query_keys`, `service`, and the
guest user (`uid`, `user`).

**`response`** (`decision: response`, `by: upstream`) is what an allowed request got back:
`status`, `resp_bytes`, `content_type`, `duration_ms`, `upstream_ip`, plus `id` and the user.
Responses the proxy generated itself (its 403s) are not logged as responses.

**`error`** is a request that failed upstream (`reason` has the message; `was_held` says whether
it was still waiting for an operator).

**`rule`** is an audit entry for a rule change: `decision` is `add` or `remove`, `rule` is the
rule, `by` is `tui` for a key press in the approval UI or `reload` for an edit made outside the
proxy (`egress-rule`, a rebuild).

## What is never logged

Request and response bodies, header values other than `User-Agent` (truncated to 200 characters),
and query-string values. Query parameter **names** are logged, and so is the value of `service`
because git smart-HTTP uses it to separate a fetch (`git-upload-pack`) from a push
(`git-receive-pack`). Passthrough hosts and raw streams are logged at connection level only.

## Which user

The proxy finds the client's loopback socket in `/proc/net/tcp` and records its owner. That is how
a request from `agent` is told apart from one from `lima`. It is `null` when the socket was not
found, for example when the client had already closed by the time the line was written.

## Recipes

```sh
# everything the agent user was refused or left waiting
limactl shell agent -- sudo jq -c 'select(.user=="agent" and (.decision=="deny" or .decision=="held"))' /var/log/egress/decisions.log

# writes that were allowed
limactl shell agent -- sudo jq -c 'select(.event=="decision" and .decision=="allow" and (.method|IN("POST","PUT","PATCH","DELETE")))' /var/log/egress/decisions.log

# every rule change, newest last
limactl shell agent -- sudo jq -c 'select(.event=="rule")' /var/log/egress/decisions.log
```
