# Testing

Two ways to check the sandbox: the automated `verify.sh`, and manual poking with the approval UI.
Run commands from the checkout root, or use the `make` targets.

## Automated: `verify.sh`

```sh
./verify.sh                # or: make verify
./verify.sh --post-reset   # after a rebuild; see "Persistence across rebuilds"
```

It needs a running VM and outbound access through the proxy (it reaches GitHub, npm, PyPI and the
Ubuntu mirrors). Approvals are simulated with `egress-rule`, which the proxy hot-reloads, so the TUI
is not exercised. Expect `ALL CHECKS PASSED`; any failure prints the evidence it saw.

| Section | What it proves |
|---|---|
| isolation | No host mounts in the guest, no forwarded SSH agent or `~/.ssh` for `agent`, `agent` has no sudo or privileged groups |
| firewall | Direct DNS, IPv6 and UDP/443 are blocked; drop counters are shown as evidence |
| agent cannot tamper | `agent` cannot stop the proxy, edit the firewall, addon or rules, or read the rules file or CA key (9 attempts, all denied); proxy and firewall still up afterwards |
| default deny / hold / approve / deny | An unmatched request is held, released and succeeds after an allow, and returns 403 after a deny |
| tools through the proxy | `apt`, `git clone`, `npm install` and `pip download` work once their hosts are allowed, and fail when denied |
| path-level rule | A path allow for one repo does not open the rest of the host; a longer deny prefix beats a shorter allow |
| dev server isolation | A server listening in the guest is not reachable from the host and opens no new host listeners |

Rules the script adds for the test hosts (`example.com`, `github.com`, the package registries and
Ubuntu mirrors) are forgotten when their section finishes.

### Persistence across rebuilds

Proving that approvals survive `reset.sh` needs state to exist before the rebuild, so this check
runs in two phases:

1. `./verify.sh` ends by adding a throwaway marker rule (`verify-persist.invalid`) and writing a
   marker file in the agent's home. The `.invalid` TLD never resolves, so the rule matches no real traffic.
2. Run `./reset.sh`, then `./verify.sh --post-reset`. It asserts the marker rule was restored into the
   new VM and the marker file is gone (the agent's home is fresh), then removes the marker rule.

`reset.sh` strips the marker from the saved host `egress/rules.json`, so it never lands in version control.

## Manual: exercising the proxy

Use three terminals, each with `source env.sh` (the `make` targets set it for you).

1. Approval UI: `make ui`
2. Decision log: `make log` (JSON lines: time, method, host, path, decision, who decided)
3. Test shell as the unprivileged user: `make agent`

Then, in the agent shell:

```sh
# Default deny: held until you decide in the UI (-m stops it hanging forever)
curl -sS -m 60 -o /dev/null -w '%{http_code}\n' https://example.com/

# Confirm interception: the certificate issuer should be mitmproxy
curl -svI -m 60 https://example.com/ 2>&1 | grep -E 'issuer|HTTP/'

# Bypass attempts: should fail immediately, never reaching the UI
curl -sS --noproxy '*' -m 5 https://example.com/
ping -c1 1.1.1.1
```

What to expect:

| Action | Result |
|---|---|
| `a` / `A` in the UI | The request completes (once / for the whole host) |
| `x` / `X` in the UI | The client gets `403 Blocked by egress policy` |
| Bypass attempts | Immediate failure; drop counters rise |
| No decision | The client hangs until its own timeout. The proxy has no hold timeout |

Inspect the rules and firewall with `make rules`, `make status`, and from an admin shell
(`make shell`): `sudo nft list table inet egress_fw`, `sudo journalctl -u egress-proxy -f`.

For a stress run, fire many parallel requests at different hosts with a generous `-m` and work
through them in the UI; paths are lowercased in the log, matching how rules are compared.
