# Disposable agent sandbox (Lima + mitmproxy + nftables)

An Ubuntu 24.04 VM (Apple Virtualization.framework) in which untrusted agent work runs.
Nothing from the host is mounted, no host credentials enter the VM, and **all** outbound
traffic goes through a mitmproxy approval queue where you allow or deny by host or URL path.
Destroy and rebuild it every day.

All state lives under `~/lima` (`LIMA_HOME=~/lima/.lima`, set by `env.sh`). The only thing
Lima keeps elsewhere is its download cache (`~/Library/Caches/lima`). `source ~/lima/env.sh`
in any shell where you want to run `limactl` against this VM.

## Layout

| Path | Purpose |
|---|---|
| `agent.yaml` | Lima instance config (CPU/RAM/disk at the top) |
| `provision/10..90-*.sh` | Run by Lima at first boot: packages, users, mitmproxy venv + CA, pi agent, proxy client config |
| `provision/push-config.sh` | Installs `egress/*` into the VM and locks it down (called by `reset.sh`) |
| `egress/addon.py` | The mitmproxy addon (hold / allow / deny / passthrough) |
| `egress/rules.json` | Persisted decisions (restored into each rebuilt VM) |
| `egress/nftables.conf` | Fail-closed firewall |
| `egress/keys.yaml` | Keybindings for the approval UI |
| `egress/egress-*` , `tmux.conf`, `egress-proxy.service` | Proxy launcher, admin CLI, systemd unit |
| `reset.sh` / `verify.sh` | Daily rebuild / automated checks |

## First-time setup

Lima 2.2.1 is already installed (`/opt/homebrew/bin/limactl`). Then:

```sh
~/lima/reset.sh        # no VM yet, so this just builds one (~10 min the first time)
~/lima/verify.sh       # expect ALL CHECKS PASSED
```

## Daily workflow

```sh
source ~/lima/env.sh
~/lima/reset.sh                                   # 1. saves rules, deletes, rebuilds, restores rules
~/lima/verify.sh                                  #    (optional) prove the guarantees still hold

# terminal A: the approval UI (leave it open; detach with ctrl-b d)
limactl shell agent -- egress-ui

# terminal B: work as the unprivileged user
limactl shell agent -- sudo -iu agent
agent$ git clone https://x-access-token:<SCOPED_TOKEN>@github.com/<org>/<repo>.git   # first use is held until you approve github.com/<org>/<repo>
agent$ pi                                         # supply your own short-lived model credentials here
```

`limactl shell agent` alone logs in as the admin user `lima` (sudo). Use it only for
administration; run agents and builds as `agent`.

### Approving requests (terminal A)

The list shows **only held requests** (`view_filter=~marked`, ⌛ icon). Move with `j`/`k`,
then press a key on the focused flow:

| Key | Action | Command |
|---|---|---|
| `a` | allow this request once | `egress.allow_once` |
| `x` | deny this request once (403) | `egress.deny_once` |
| `A` / `X` | allow / deny the **host**, any path | `egress.allow_host` / `egress.deny_host` |
| `p` / `P` | allow / deny the **first two path segments**, e.g. `github.com/<org>/<repo>/*` | `egress.allow_path` / `egress.deny_path` |
| `1` / `2` | allow / deny a **custom prefix** (prompt opens; type `/org/repo/subdir`, Enter) | `egress.allow_prefix` / `egress.deny_prefix` |
| `t` | **passthrough**: no TLS interception for this host (hostname-only decision) | `egress.passthrough_host` |
| `F` | forget every rule for this host | `egress.forget` |
| `L` | list rules in the event log (`E` opens it) | `egress.list` |

Other held flows that a new rule now covers are released or denied automatically.
Clear the held-only filter with `:set view_filter=` to see all traffic; `?` shows help.

Precedence: path-prefix rule > host rule; longer prefix > shorter; exact host > `*.wildcard`;
deny wins a tie. Path matching is case-insensitive, strips the query, collapses `..`, and
treats `/org/repo.git/...` as `/org/repo`.

### Adding or revoking rules without the UI

```sh
limactl shell agent -- sudo egress-rule list
limactl shell agent -- sudo egress-rule allow registry.npmjs.org
limactl shell agent -- sudo egress-rule allow github.com /my-org/my-repo
limactl shell agent -- sudo egress-rule deny  github.com /my-org/my-repo/blob
limactl shell agent -- sudo egress-rule forget registry.npmjs.org
```

The proxy reloads `/var/lib/egress/rules.json` within a second. Decisions are logged
(timestamp, method, host, path, decision only) to `/var/log/egress/decisions.log`.
`rules.json` on the host is refreshed by `reset.sh`; it contains hostnames you have visited,
so think before committing it to a public repo.

### Tools that break under TLS interception

Certificate-pinned clients fail the handshake. The proxy logs
`TLS handshake failed for <host>`. Press `t` on that host's flow (or
`sudo egress-rule passthrough <host>`) and retry. Passthrough carries the connection
uninspected: you are trusting the hostname only. Raw TCP/UDP through CONNECT is refused
unless the host has a host-level allow or passthrough rule. SSH (git over `ssh://`) is not
supported: use HTTPS with a scoped token.

### Corporate TLS-inspecting proxy

Not needed on this machine (no proxy configured on the host). If that changes, put
`EGRESS_UPSTREAM=http://proxy.corp:3128` and optionally `EGRESS_UPSTREAM_CA=/etc/egress/upstream-ca.pem`
in `egress/upstream.env`, drop the corporate root CA at `egress/corp-ca.pem`, adjust the
`tcp dport` in the `egress` rule of `nftables.conf` if the proxy isn't on 80/443, and
re-run `provision/push-config.sh` (or `reset.sh`). This path is wired but untested.

## Design notes and trade-offs

* **`plain: true`.** Disables mounts, dynamic port forwarding, the guest agent, containerd,
  Rosetta, ssh-agent forwarding and host clock sync; `limactl shell/copy` and provisioning
  still work. The cost is no host clock sync after the Mac sleeps; `systemd-timesyncd`
  (NTP allowed by the firewall) corrects it.
* **`mounts: []` in a standalone template.** The stock `default.yaml` pulls in
  `_default/mounts` (which mounts `~`) through `base:`; `agent.yaml` has no `base:`.
* **Loopback.** For the agent only `127.0.0.1:8080` is reachable on loopback, as specified,
  so tools inside the VM cannot talk to their own localhost servers. To allow it, uncomment
  the `dev-loopback` rule in `egress/nftables.conf` (it still excludes the DNS stub).
* **Why not mount-free host file transfer?** Use `limactl copy` explicitly for anything
  you want to move (it goes over the Lima SSH channel and is always your decision).
* **Roles.** `lima` = admin (sudo, still firewalled: its apt/curl also use the proxy).
  `agent` = no sudo, no extra groups. `egress` = owns `/var/lib/egress` (rules, CA key,
  logs) and the proxy; `/etc/egress`, `/etc/nftables.conf` and the addon are root-owned.

## Threat model

Protects against: a compromised or malicious build/agent touching the host (no mounts, no
forwarded agent or ports, no host credentials in the image); credential theft *from the host*;
uncontrolled egress (default-deny, per-URL approval, direct DNS/UDP/IPv6/other ports blocked,
proxy-ignoring tools fail closed); the agent tampering with the proxy or firewall.

Does **not** protect against:
* Anything already inside the VM can be exfiltrated through hosts you approve (an allowed
  `github.com/<org>/<repo>/*` is a write channel if the token you give it can write).
  Approve narrowly, use read-only scoped tokens.
* A malicious package running as `agent` can read everything `agent` can, including the
  credentials you supply at runtime.
* Domain fronting: the proxy decides on the CONNECT/Host name and checks the Host header
  against it, but does not pin the TLS SNI the client presents upstream.
* Kernel or hypervisor escapes; side channels; whatever the Apple Virtualization stack allows.
* Content-level abuse of approved hosts (e.g. data in URLs or request bodies you never see; bodies are not logged by design).
