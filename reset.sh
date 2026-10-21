#!/usr/bin/env bash
# Daily teardown + rebuild. Approvals survive via egress/rules.json.
#   ./reset.sh          rebuild (asks before deleting if the rules copy-out failed)
#   ./reset.sh --force  delete even if the rules could not be saved
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$ROOT/env.sh"
VM=agent
force=0; [ "${1:-}" = "--force" ] && force=1

confirm() { [ "$force" = 1 ] && return 0; read -r -p "$1 [y/N] " a; [ "$a" = y ] || [ "$a" = Y ]; }

if limactl list -q 2>/dev/null | grep -qx "$VM"; then
  saved=0
  if [ "$(limactl list --format '{{.Status}}' "$VM")" = Running ]; then
    if limactl shell "$VM" -- sudo bash -c 'install -m 0600 -o lima -g lima /var/lib/egress/rules.json /tmp/rules.export.json' \
       && limactl copy "$VM:/tmp/rules.export.json" "$ROOT/egress/rules.json.new" \
       && jq -e '.rules|type=="array"' "$ROOT/egress/rules.json.new" >/dev/null; then
      mv "$ROOT/egress/rules.json.new" "$ROOT/egress/rules.json"; saved=1
      echo "rules saved: $(jq '.rules|length' "$ROOT/egress/rules.json") rule(s)"
    else
      rm -f "$ROOT/egress/rules.json.new"
      echo "WARNING: could not copy rules.json out of the VM." >&2
    fi
  else
    echo "WARNING: VM is not running; rules cannot be saved." >&2
  fi
  if [ "$saved" = 0 ]; then confirm "Delete the VM anyway (approvals since last save are lost)?" || { echo "aborted"; exit 1; }; fi
  limactl delete -f "$VM"
fi

limactl start --name="$VM" --tty=false "$ROOT/agent.yaml"
PUSH_RULES=1 "$ROOT/provision/push-config.sh"

echo "--- status ---"
limactl list "$VM"
limactl shell "$VM" -- bash -c '
  printf "proxy:    "; systemctl is-active egress-proxy
  printf "firewall: "; sudo nft list table inet egress_fw >/dev/null 2>&1 && echo loaded || echo NOT LOADED
  printf "agent cli: "; sudo -u agent -H bash -lc "pi --version" 2>&1 | tail -1
  printf "rules:    "; sudo jq ".rules|length" /var/lib/egress/rules.json'
