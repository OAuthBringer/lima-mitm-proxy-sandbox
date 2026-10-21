#!/usr/bin/env bash
# Install addon, firewall, unit, rules and helpers into the running VM, then lock it down.
# Idempotent; run by reset.sh after every (re)build, and safe to re-run after editing egress/*.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../env.sh
. "$ROOT/env.sh"
VM=agent
E="$ROOT/egress"
STAGE=/tmp/egress-stage

limactl shell "$VM" -- bash -c "rm -rf $STAGE && mkdir -m 0700 $STAGE"
files=(addon.py rules.json nftables.conf keys.yaml egress-run egress-session tmux.conf egress-proxy.service egress-rule egress-ui)
for f in "${files[@]}"; do limactl copy "$E/$f" "$VM:$STAGE/$f"; done
for opt in upstream.env corp-ca.pem; do
  [ -f "$E/$opt" ] && limactl copy "$E/$opt" "$VM:$STAGE/$opt"
done

limactl shell "$VM" -- sudo PUSH_RULES="${PUSH_RULES:-0}" bash -s <<REMOTE
set -euo pipefail
S=$STAGE
install -d -o root -g root -m 0755 /etc/egress
install -m 0644 -o root -g root \$S/addon.py /etc/egress/addon.py
install -m 0644 -o root -g root \$S/keys.yaml /etc/egress/keys.yaml
install -m 0644 -o root -g root \$S/tmux.conf /etc/egress/tmux.conf
ln -sf /etc/egress/keys.yaml /var/lib/egress/mitm/keys.yaml
install -m 0755 -o root -g root \$S/egress-run /usr/local/bin/egress-run
install -m 0755 -o root -g root \$S/egress-session /usr/local/bin/egress-session
install -m 0755 -o root -g root \$S/egress-rule /usr/local/bin/egress-rule
install -m 0755 -o root -g root \$S/egress-ui /usr/local/bin/egress-ui
install -m 0644 -o root -g root \$S/egress-proxy.service /etc/systemd/system/egress-proxy.service
install -m 0644 -o root -g root \$S/nftables.conf /etc/nftables.conf
# rules: restore from the host copy only on a fresh VM or when PUSH_RULES=1 (reset.sh); otherwise
# keep the live file so re-running this script never discards approvals made in the TUI.
if [ ! -f /var/lib/egress/rules.json ] || [ "${PUSH_RULES:-0}" = 1 ]; then
  jq -e '.rules|type=="array"' \$S/rules.json >/dev/null
  install -m 0600 -o egress -g egress \$S/rules.json /var/lib/egress/rules.json
fi
if [ -f \$S/upstream.env ]; then install -m 0644 \$S/upstream.env /etc/egress/upstream.env; else rm -f /etc/egress/upstream.env; fi
if [ -f \$S/corp-ca.pem ]; then install -m 0644 \$S/corp-ca.pem /usr/local/share/ca-certificates/corp-ca.crt; update-ca-certificates >/dev/null; fi
rm -rf \$S

nft -c -f /etc/nftables.conf
systemctl daemon-reload
systemctl enable nftables egress-proxy >/dev/null 2>&1
systemctl restart egress-proxy
systemctl restart nftables
touch /etc/egress/.locked
REMOTE
echo "config pushed; firewall loaded"
