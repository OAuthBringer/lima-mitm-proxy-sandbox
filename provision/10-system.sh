#!/bin/bash
# Base packages, toolchains, and the three roles (lima admin / agent / egress).
# Idempotent. Skipped once the firewall lockdown marker exists (re-runs on reboot).
set -eu -o pipefail
[ -e /etc/egress/.locked ] && exit 0
export DEBIAN_FRONTEND=noninteractive

NODE_VERSION=24.22.1
NODE_SHA256=dbabf7a1cbf947e6059ffad2c27b80041db97dea1e553b62afdee7f13fca336e

# sudo/hostname lookups must not need DNS once the firewall is up
grep -q "[[:space:]]$(hostname)\$" /etc/hosts || echo "127.0.1.1 $(hostname)" >> /etc/hosts

apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates git curl jq unzip build-essential nftables tmux \
  python3 python3-pip python3-venv dnsutils netcat-openbsd xz-utils

# Node LTS from the official tarball, checksum pinned.
if [ "$(node -v 2>/dev/null || true)" != "v${NODE_VERSION}" ]; then
  tmp=$(mktemp -d)
  curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-arm64.tar.xz" -o "$tmp/node.tar.xz"
  echo "${NODE_SHA256}  $tmp/node.tar.xz" | sha256sum -c -
  tar -xJf "$tmp/node.tar.xz" -C /usr/local --strip-components=1 --no-same-owner
  rm -rf "$tmp"
fi

# agent: unprivileged, own primary group only, no sudo, locked password.
id -u agent >/dev/null 2>&1 || useradd -m -s /bin/bash -U agent
passwd -l agent >/dev/null
chmod 0750 /home/agent
# egress: system user that owns the proxy, rules and CA key.
id -u egress >/dev/null 2>&1 || useradd --system -U -d /var/lib/egress -s /usr/sbin/nologin egress
install -d -o egress -g egress -m 0700 /var/lib/egress
install -d -o egress -g egress -m 0750 /var/log/egress
install -d -o root -g root -m 0755 /etc/egress
