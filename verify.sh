#!/usr/bin/env bash
# Automated checks. Run after first boot and after each reset.
#   ./verify.sh              full run (approvals are simulated by editing rules.json via egress-rule,
#                            which the proxy hot-reloads; the TUI itself is documented in README)
#   ./verify.sh --post-reset check that rules persisted and /home/agent is fresh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$ROOT/env.sh"
VM=agent
TEST_ORG_REPO=octocat/Hello-World

fails=0
admin() { limactl shell "$VM" -- "$@" 2>&1 | grep -v 'unable to resolve host'; return "${PIPESTATUS[0]}"; }
as_agent() { limactl shell "$VM" -- sudo -n -u agent -H bash -lc "$1" 2>&1 | grep -v 'unable to resolve host'; return "${PIPESTATUS[0]}"; }
rule() { limactl shell "$VM" -- sudo egress-rule "$@" >/dev/null 2>&1; sleep 2.5; }  # proxy polls every 1s
pass() { printf 'PASS  %s\n' "$1"; [ -n "${2:-}" ] && printf '      %s\n' "${2//$'\n'/$'\n      '}"; return 0; }
fail() { printf 'FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '      %s\n' "${2//$'\n'/$'\n      '}"; fails=$((fails+1)); }
check() { # name, expected-rc-is-zero(0/1 means want fail), output
  local name=$1 want=$2 rc=$3 out=$4
  if { [ "$want" = ok ] && [ "$rc" = 0 ]; } || { [ "$want" = bad ] && [ "$rc" != 0 ]; }; then pass "$name" "rc=$rc ${out:0:300}"; else fail "$name" "rc=$rc ${out:0:300}"; fi
}

if [ "${1:-}" = "--post-reset" ]; then
  out=$(admin sudo egress-rule list); echo "$out"
  grep -q 'verify-persist.invalid' <<<"$out" && pass "rules persisted across reset" || fail "rules persisted across reset" "$out"
  out=$(as_agent 'ls -A /home/agent | grep -v -E "^(\.bash|\.profile|\.cache|\.npm|\.config|\.local|\.sudo_as_admin_successful)" ; ls /home/agent/session-marker 2>&1'); rc=$?
  grep -q 'session-marker' <<<"$out" && ! grep -q 'No such file' <<<"$out" && fail "agent home is fresh" "$out" || pass "agent home is fresh (no session-marker)" "$out"
  rule forget verify-persist.invalid
  [ "$fails" = 0 ]; exit $?
fi

echo "== isolation =="
out=$(admin bash -c 'ls /Users 2>&1; echo ---; mount | grep -E "virtiofs|sshfs|9p|/Users|/Volumes" || echo "(no host-style mounts)"; findmnt -rn -t virtiofs,fuse.sshfs,9p || echo "(no virtiofs/sshfs/9p)"'); rc=$?
if grep -q 'No such file' <<<"$out" && grep -q 'no host-style mounts' <<<"$out" && grep -q 'no virtiofs' <<<"$out"; then pass "no host mounts in guest" "$out"; else fail "no host mounts in guest" "$out"; fi

out=$(as_agent 'echo "SSH_AUTH_SOCK=[${SSH_AUTH_SOCK:-}]"; ls -la ~/.ssh 2>&1 | head -2; ls /home/lima/.ssh 2>&1 | head -2; wc -l < /home/lima/.ssh/authorized_keys' 2>&1)
if grep -q 'SSH_AUTH_SOCK=\[\]' <<<"$out" && grep -q 'agent/.ssh' <<<"$out"; then pass "SSH_AUTH_SOCK empty; no ~/.ssh for agent" "$out"; else fail "SSH_AUTH_SOCK empty; no ~/.ssh for agent" "$out"; fi

out=$(as_agent 'sudo -n true; id'); rc=$?
grep -q 'uid=.*(agent) gid=.*(agent) groups=.*(agent)$' <<<"$out" && ! grep -q -E 'sudo|adm|lxd' <<<"$(grep groups= <<<"$out")" && [ "$rc" = 0 ] \
  && pass "agent has no sudo and no privileged groups" "$out" || fail "agent has no sudo and no privileged groups" "$out"
out=$(as_agent 'sudo -n true'); check "sudo -n true fails as agent" bad $? "$out"

echo "== firewall =="
out=$(as_agent 'curl -sS --noproxy "*" --max-time 8 https://example.com -o /dev/null'); check "direct curl (--noproxy) blocked" bad $? "$out"
out=$(as_agent 'dig +time=3 +tries=1 @1.1.1.1 example.com +short'); rc=$?
if [ -z "$(grep -E '^[0-9.]+$' <<<"$out")" ]; then pass "direct DNS (dig @1.1.1.1) fails" "rc=$rc $out"; else fail "direct DNS (dig @1.1.1.1) fails" "$out"; fi
out=$(as_agent 'curl -6 -sS --noproxy "*" --max-time 6 https://ipv6.google.com -o /dev/null; bash -c "exec 3<>/dev/tcp/2606:4700:4700::1111/443" 2>&1'); rc=$?
[ "$rc" != 0 ] && pass "IPv6 egress blocked" "$out" || fail "IPv6 egress blocked" "$out"
out=$(as_agent 'python3 - <<PY
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3); s.connect(("1.1.1.1",443))
try: s.send(b"quic"); print("GOT", s.recv(10))
except Exception as e: print("blocked:", type(e).__name__)
PY'); grep -q '^blocked' <<<"$out" && pass "UDP 443 egress blocked" "$out" || fail "UDP 443 egress blocked" "$out"
out=$(admin sudo nft list chain inet egress_fw output | grep -E 'counter packets' | head -3); pass "firewall drop counters (evidence)" "$out"

echo "== agent cannot tamper =="
tamper=""; tn=0
for c in 'systemctl stop egress-proxy' 'pkill -9 -f mitmproxy' 'nft flush ruleset' 'echo x >> /etc/nftables.conf' 'echo x >> /etc/egress/addon.py' 'echo x >> /var/lib/egress/rules.json' 'cat /var/lib/egress/rules.json' 'cat /var/lib/egress/mitm/mitmproxy-ca.pem' 'ls /run/egress'; do
  o=$(as_agent "$c"); r=$?; tamper+="rc=$r  $c  -> ${o%%$'\n'*}"$'\n'; [ "$r" != 0 ] && tn=$((tn+1))
done
if [ "$tn" = 9 ]; then pass "agent cannot stop proxy, edit firewall/addon/rules, or read rules/CA key (9/9 denied)" "$tamper"; else fail "agent tamper attempts ($tn/9 denied)" "$tamper"; fi
out=$(admin bash -c 'systemctl is-active egress-proxy; sudo nft list table inet egress_fw >/dev/null && echo firewall-loaded'); pass "proxy + firewall still up afterwards" "$out"

echo "== default deny / hold / approve / deny (via proxy) =="
rule forget example.com
as_agent 'rm -f /tmp/held.out; (curl -sS --max-time 45 -o /dev/null -w "%{http_code}" https://example.com > /tmp/held.out 2>&1; echo " rc=$?" >> /tmp/held.out) >/dev/null 2>&1 </dev/null &' >/dev/null
sleep 6
out=$(as_agent 'cat /tmp/held.out'); log=$(admin sudo grep -c '"host": "example.com".*"held"' /var/log/egress/decisions.log)
if [ -z "$out" ] && [ "${log:-0}" -ge 1 ]; then pass "request held until decided (curl still waiting, 'held' logged)" "held entries: $log"; else fail "request held until decided" "out=[$out] log=$log"; fi
rule allow example.com; sleep 3
out=$(as_agent 'cat /tmp/held.out'); grep -q '^200 rc=0' <<<"$out" && pass "held request released and succeeded after approval" "$out" || fail "held request released and succeeded after approval" "$out"
rule deny example.com
out=$(as_agent 'curl -sS --max-time 15 -o /dev/null -w "%{http_code}" https://example.com');  grep -q 403 <<<"$out" && pass "blocked after deny (CONNECT refused with 403)" "$out" || fail "blocked after deny" "$out"
rule forget example.com

echo "== tools through the proxy =="
tool() { # name, command-as-agent
  local name=$1 cmd=$2 out rc
  out=$(as_agent "$cmd"); rc=$?; echo "$rc|$out"
}
for h in ports.ubuntu.com archive.ubuntu.com security.ubuntu.com github.com registry.npmjs.org pypi.org files.pythonhosted.org; do rule allow "$h"; done
out=$(admin sudo apt-get update 2>&1 | tail -3); rc=$?; out=$(admin bash -c 'sudo apt-get update 2>&1 | tail -2; sudo apt-get install -y hello 2>&1 | tail -2; hello'); grep -q 'Hello, world' <<<"$out" && pass "apt update+install works after approval" "$out" || fail "apt works after approval" "$out"
out=$(as_agent 'rm -rf /tmp/t && git clone -q --depth 1 https://github.com/'$TEST_ORG_REPO'.git /tmp/t && echo cloned'); grep -q cloned <<<"$out" && pass "git clone over HTTPS works after approval" "$out" || fail "git clone works after approval" "$out"
out=$(as_agent 'rm -rf /tmp/n && mkdir /tmp/n && cd /tmp/n && npm init -y >/dev/null && npm install --no-audit --no-fund is-odd 2>&1 | tail -2'); grep -q 'added' <<<"$out" && pass "npm install works after approval" "$out" || fail "npm install works after approval" "$out"
out=$(as_agent 'rm -rf /tmp/p && mkdir /tmp/p && cd /tmp/p && pip download --no-deps -q six 2>&1 | tail -2; ls /tmp/p'); grep -q 'six' <<<"$out" && pass "pip download works after approval" "$out" || fail "pip works after approval" "$out"
for h in ports.ubuntu.com archive.ubuntu.com security.ubuntu.com github.com registry.npmjs.org pypi.org files.pythonhosted.org; do rule deny "$h"; done
out=$(admin bash -c 'sudo apt-get update 2>&1 | tail -3'); grep -q -E 'Err|Failed|403|Could not' <<<"$out" && pass "apt fails when denied" "$out" || fail "apt fails when denied" "$out"
out=$(as_agent 'rm -rf /tmp/t2; git clone -q --depth 1 https://github.com/'$TEST_ORG_REPO'.git /tmp/t2 2>&1 | tail -2'); grep -q -i -E 'fatal|403|error' <<<"$out" && pass "git fails when denied" "$out" || fail "git fails when denied" "$out"
out=$(as_agent 'rm -rf /tmp/n2 && mkdir /tmp/n2 && cd /tmp/n2 && npm init -y >/dev/null && npm install --no-audit --no-fund --fetch-retries=0 left-pad 2>&1 | tail -2'); grep -q -i -E 'ERR|403' <<<"$out" && pass "npm fails when denied" "$out" || fail "npm fails when denied" "$out"
out=$(as_agent 'cd /tmp/p && pip download --no-deps --retries 0 -q requests 2>&1 | tail -2'); grep -q -i -E 'error|403|proxy' <<<"$out" && pass "pip fails when denied" "$out" || fail "pip fails when denied" "$out"
for h in ports.ubuntu.com archive.ubuntu.com security.ubuntu.com github.com registry.npmjs.org pypi.org files.pythonhosted.org; do rule forget "$h"; done

echo "== path-level rule =="
rule allow github.com "/$TEST_ORG_REPO"
out=$(as_agent 'rm -rf /tmp/t3; git clone -q --depth 1 https://github.com/'$TEST_ORG_REPO'.git /tmp/t3 && echo cloned-allowed-path'); grep -q cloned-allowed-path <<<"$out" && pass "allowed path prefix works (github.com/$TEST_ORG_REPO)" "$out" || fail "allowed path prefix works" "$out"
out=$(as_agent 'curl -sS --max-time 8 -o /dev/null -w "%{http_code}" https://github.com/torvalds/linux; echo " rc=$?"'); grep -q -E 'rc=28|rc=2[0-9]|000' <<<"$out" && pass "other GitHub path is still held (curl timed out)" "$out" || fail "other GitHub path is still held" "$out"
rule deny github.com "/$TEST_ORG_REPO/blob"
out=$(as_agent 'curl -sS --max-time 15 -o /dev/null -w "%{http_code}" https://github.com/'$TEST_ORG_REPO'/blob/master/README'); [ "$out" = 403 ] && pass "longer deny prefix beats shorter allow prefix" "HTTP $out" || fail "longer deny prefix beats allow" "$out"
rule forget github.com

echo "== dev server not reachable from host =="
before=$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $1,$9}' | sort -u)
as_agent 'nohup python3 -m http.server 8000 >/tmp/http.log 2>&1 &' >/dev/null; sleep 3
up=$(admin bash -c 'ss -ltn | grep :8000 || echo not-listening')
after=$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $1,$9}' | sort -u)
new=$(comm -13 <(echo "$before") <(echo "$after")); hostcurl=$(curl -s --max-time 3 http://127.0.0.1:8000 >/dev/null 2>&1; echo "curl rc=$?")
as_agent 'pkill -f "http.server 8000"' >/dev/null
if grep -q LISTEN <<<"$up" && [ -z "$new" ] && [ "$hostcurl" != "curl rc=0" ]; then pass "guest dev server (guest: listening) not reachable from host; no new host listeners" "guest: $up
new host listeners: (none)
host $hostcurl"; else fail "dev server isolation" "guest: $up
new host listeners: $new
$hostcurl"; fi

# leave evidence for --post-reset
rule allow verify-persist.invalid
as_agent 'echo marker > /home/agent/session-marker' >/dev/null

echo
if [ "$fails" = 0 ]; then echo "ALL CHECKS PASSED. After ./reset.sh run: ./verify.sh --post-reset"; else echo "$fails CHECK(S) FAILED"; fi
[ "$fails" = 0 ]
