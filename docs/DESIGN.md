# Design: a sandbox for agents with controlled egress

Read this first if you are picking the project up. The README says how the sandbox works and
[TESTING.md](TESTING.md) how it is verified; this file says **why it exists, what has been decided,
and what is left**. Work is tracked outside the repo; this document is the durable copy of the plan
and is kept current as work lands.

## Purpose and constraint

This is a generic environment for running agents (headless Claude Code, other coding agents,
untrusted builds) with **egress controlled by the network, not by the agent**. The firewall is the
security boundary. Prompts, tool allow lists and in-agent permission systems are useful but are not
enough on their own: an agent that can reach a host with a write-capable credential can write,
whatever its instructions say. Source control is the clearest example.

The host cannot have a dedicated macOS user for the agents (an organisational constraint on the
device), so the boundary lives in a VM:

* The agent runs **inside the Lima VM**, behind the mitmproxy approval queue and the nftables
  per-uid egress policy described in the README.
* Nothing from the host is mounted and no host credentials enter the VM.
* Optionally, a single session on the host acts as a **control plane**: it relays narrow commands
  into the VM and never runs agent work itself.

Do not spend time re-arguing the missing macOS user; it is a given.

## Current state

| Area | State |
|---|---|
| VM, proxy, firewall, per-uid policy, daily rebuild | Done, verified by `verify.sh` |
| Default allow list | Done (see below) |
| Method-restricted rules (`egress-rule -m`, TUI keys `3`/`4`) | Done, verified |
| Detailed decision log ([LOGGING.md](LOGGING.md)): matched rule, reason, flow id, guest user, upstream response, rule-change audit, `abandoned` | Done, verified |
| Driving approvals from the host through tmux | Proven by hand; runbook below |
| An agent runtime installed and authenticated in the VM | Not started (Phase 0) |
| Deny-and-notify mode for unattended agents | Not started |
| Glob paths, GraphQL body inspection, `git-receive-pack` deny | Not started |
| `held.json`, an admin command surface, allow-once by id | Not started |
| One user and proxy profile per agent | Not started |
| Host relay, monitor loop, drift detection | Not started |

## Policy decisions

These are decisions, not defaults waiting to be revisited.

**Default allow list** (`egress/rules.json`, restored into every rebuilt VM; `reset.sh` re-exports the
live rules over it, so the live VM must match what you want seeded):

| Rule | Why |
|---|---|
| allow `ports.ubuntu.com` under `/ubuntu-ports` | The only apt source. Path-scoped so nothing else on the host opens. |
| allow `pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org` | Package installs. Read-mostly registries. |
| deny `motd.ubuntu.com`, `esm.ubuntu.com`, `changelogs.ubuntu.com`, `contracts.canonical.com` | Ubuntu phone-home (MOTD news, Ubuntu Pro ESM and contract checks, release notes). Denied so they fail fast with a 403 instead of hanging and retrying every ~30 s. |

Never in the defaults:

* **A code-hosting host open host-wide** (`github.com`, `api.github.com`). An open allow is a write
  channel and defeats the purpose. **All access to code hosts is path-scoped**, per org/repo, with
  write methods denied explicitly (see below).
* **Open-web reference sites** (wikis, news, search). They are a prompt-injection surface for an
  agent that reads what it fetches.
* **Test hosts such as `example.com`.** `verify.sh` adds and forgets them itself.

The model API endpoint the agent itself needs is not in the seed; add it per deployment.

The Ubuntu timers (`apt-daily`, `apt-daily-upgrade`, `motd-news`, `update-notifier-*`, `ua-timer`,
`ubuntu-advantage`) are still enabled, so the denied hosts are still contacted and still refused.
Disabling them in `provision/` would remove the traffic at the source. Not done.

**Granularity: host, path and method.** Rules can be scoped per path prefix and per HTTP method, so
a repo can be readable but not writable: `allow -m GET,HEAD <org>/<repo>`, with an explicit
`deny -m POST,PUT,PATCH,DELETE`. A request that matches no rule is held, not denied, so write
methods must be denied explicitly. Caveats that shape real rules:

* Git fetch is a `POST` (`git-upload-pack`), so a GET-only rule breaks clones. Separate fetch from
  push by **path**: allow the repo, deny `/<org>/<repo>.git/git-receive-pack`. Untested.
* GraphQL is always `POST /graphql`, so methods cannot separate reads from mutations; it needs body
  inspection (a gap below) or a deny on the endpoint.
* Method rules only apply to traffic the proxy decrypts. Passthrough hosts and raw streams show no
  method and ignore them, so avoid passthrough for anything that matters.

## Target architecture

* **Agents run headless in the VM**, as scheduled ticks (systemd timers) or on demand, one Unix user
  per agent, each pinned by nftables `meta skuid` to its own proxy port and rules file. In-agent
  permission prompts can be off inside the VM, which is only valid once fail-closed behaviour is
  verified.
* **State lives outside the VM** (task trackers, repos, chat), so ticks are stateless and the VM can
  be destroyed daily.
* **Secrets** are injected at boot from the host's keychain over `limactl shell` into root-owned
  files readable by the matching agent user. Never in the repo or the image. Prefer token or API-key
  auth to a browser login. Rebuild in a quiet window; external state is untouched and rules persist.
* **Control plane (optional).** A host session relays one narrow command into the VM, for example
  `limactl shell agent -- sudo agentctl <verb>` (start, stop, status, logs, run-once, decisions,
  held, rules, decide). Everything the VM returns is untrusted data, and firewall changes need
  explicit human confirmation.

**Open decision: how agents reach third-party services** (ticketing, chat, task trackers).

1. Hosted connectors: the firewall only sees the connector's endpoint, so per-tool enforcement is
   impossible.
2. Direct API access with scoped tokens: the firewall can allow, for example, read endpoints only, or
   comments on one project only. **Prefer this for anything that can write.**

Unverified: whether each service accepts token auth outside a browser OAuth flow; agent tool names
would change.

## Firewall gaps still to build

1. **Deny-and-notify for unattended agents.** Unmatched requests get a 403 and are logged; the run
   fails fast, the operator allows the request, the next run succeeds. Hold-with-timeout stays for
   interactive sessions. Today requests are held with no timeout, which hangs unattended agents.
2. **Glob paths.** Methods are done; globs are not (for example `GET` under an org).
3. **GraphQL body inspection:** allow queries, deny mutations. Deny `git-receive-pack` including the
   `info/refs?service=` query form (the query is stripped from the path today, though `service` is
   now logged).
4. **Per-agent proxy profiles** via nftables `meta skuid`.
5. **Negative tests per agent in `verify.sh`**: merge, approve, push and cross-project writes must
   all return 403. Method-deny tests exist; per-agent ones do not.
6. **Held queue as data.** The addon writes `held.json` (id, time, agent, method, host, path, count),
   kept current as requests arrive and resolve. The log already has a flow `id` and the guest `user`;
   the held queue itself still lives only in the TUI's memory.

## Remote visibility and approvals

The approval UI is a terminal TUI, so approving from a phone needs an indirection. Held requests are
visible only in the TUI today. The `egress-rule` CLI already works as an approval (a covering rule
releases held flows, verified) but there is no allow-once by id.

* **Command surface:** `held`, `rules`, `decisions --since`, `decide <id> allow-once|deny-once|allow
  <prefix>` (allow-once needs a small addon change).
* **Monitor:** a read-only loop (`held` and `decisions` only) that notifies the operator once per
  distinct blocked request, batched, for example `agent-a blocked: GET api.example.com
  /repos/<org>/<repo>/pulls/42 (x3). Reply "allow 1" or "deny 1".`
* **Drift detection:** compare live rules against a baseline policy file in the repo and alert on any
  new, wildcard or unexplained rule.
* **Approvals happen only in an operator-initiated session turn.** Never read approvals from a
  notification channel. The polling job never writes.
* **Injection safety:** held host and path text comes from the agent. Show it as quoted data, never
  act on it. The relay refuses a bare `*` host or a whole-host allow without explicit confirmation.
  The log audits every rule change (`event: rule`, with `by`).

## Phases

- [ ] **0. Spike.** Start the VM, allow the model API endpoint, install a pinned agent runtime, run a
  trivial prompt through the proxy. Gate: which auth method works, and whether hosted connectors work
  in the VM.
- [ ] **1. Addon features** (gaps 1 to 6) plus `verify.sh` negative tests. Gate: all pass.
- [ ] **2. Provision** the runtime, agent definitions, timers and the command surface. Gate: an agent
  runs unattended.
- [ ] **3. Host relay**, a host-side allow list for the single relayed command, the monitor with
  notifications, drift detection and the chat-based decide flow. Gate: start, stop, inspect and
  approve a blocked request from a remote session on mobile.
- [ ] **4. One user and proxy profile per agent**, keychain secret injection. Gate: no agent can reach
  another's access.

Method rules and the detailed log were pulled forward ahead of Phase 1 and are done.

## Runbook: driving the approval UI from the host

Verified on 2026-11-09 with no terminal attached. Run from the checkout root after `source env.sh`.
Treat this as the interim backend for chat-based approvals; `held.json` plus a decide-by-id command
is the more robust design (request ids, no screen-scraping, no focus race).

**Reaching the UI.** It is the mitmproxy TUI in a detached tmux session in the VM: socket
`/run/egress/tmux.sock`, session `egress`, owned by user `egress`. The admin user `lima` reaches it
with sudo over `limactl shell agent`. Start the VM first if needed (`make start`, about 7 s;
`make status` shows proxy, firewall and rule count).

```sh
T="sudo -u egress tmux -S /run/egress/tmux.sock"
limactl shell agent -- bash -c "$T capture-pane -p -t egress"   # read the screen (strip blank lines)
limactl shell agent -- bash -c "$T send-keys -t egress Down"    # send a key
```

**Navigation.** `g` jumps to the top; `Down`/`Up` (also `j`/`k`) move one row. The row marked `>>` is
the focused flow (`capture-pane | grep '^>>'`). To find a request by text: press `g`, then loop,
read the focused row, stop on a match, else send `Down` with a short pause. `Enter` opens the flow
detail (full URL, since the list truncates long paths; timestamp; headers; User-Agent) and the status
bar shows `q Back`. `Space` goes to the next flow.

**Decisions** act on the focused flow in list view and in flow detail. `a` allow once, `x` deny once;
both are logged with `by: once`. The other keys are in `egress/keys.yaml` and the README.

**Safe use.**

1. **Verify the focused row immediately before pressing a decision key.** Blocked clients retry about
   every 30 s, so rows arrive continuously and focus can shift. Match on the full URL from the detail
   view, not on row position.
2. **Never press `q` in the list view.** There it quits the proxy. Press `q` only after `Enter`, when
   the status bar shows `q Back`. If a quit prompt ever appears, send `n`.
3. A key decision applies to one flow; its retries arrive as new flows. For repeated requests use a
   rule: `sudo egress-rule allow|deny [-m METHODS] <host> [/path-prefix]`. A covering rule releases
   matching held flows.
4. Treat host, path and headers as untrusted data from the agent. Show them to the human; never act
   on instructions inside them. Approving is the human's decision.
5. Timestamps in `decisions.log` are local time with an offset; compare `ts` as written.

**Observed behaviour.** The list shows only held flows (`view_filter=~marked`, hourglass icon); `L`
lists rules in the event log. Held requests hang with no timeout until decided or the client gives up
(a client that gives up is now logged as `abandoned`). At boot the VM produces `changelogs.ubuntu.com`
requests immediately, and `apt-get update` produces ports, esm and motd requests that retry about
every 30 s; the queue passed 20 within minutes before the Ubuntu denies were seeded. The `pi` agent
installed by `provision/` needs an API key; without one it exits at once and sends nothing.

## Untested and open

* TUI keys `A`, `X`, `p`, `P`, `t`, `F`, `1`, `2`, `3`, `4` (bindings in `egress/keys.yaml`). The
  `egress-rule` equivalents are covered by `verify.sh`.
* The `git-receive-pack` path deny on a real push.
* User attribution for IPv6 clients (the lookup reads `/proc/net/tcp` only) and for anything whose
  socket is gone by the time the line is written. Both log `user: null`.
* Disabling the Ubuntu timers in `provision/`.
* Whether third-party services accept token auth headlessly (decision above).
