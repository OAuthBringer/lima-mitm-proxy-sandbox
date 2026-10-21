#!/bin/bash
# mitmproxy in an isolated venv (pinned) + CA generation + guest trust store.
# The addon, firewall, unit and rules are pushed later by provision/push-config.sh.
set -eu -o pipefail
[ -e /etc/egress/.locked ] && exit 0

MITMPROXY_VERSION=12.2.3
CONFDIR=/var/lib/egress/mitm

if ! /opt/mitmproxy/bin/pip show mitmproxy 2>/dev/null | grep -qx "Version: ${MITMPROXY_VERSION}"; then
  python3 -m venv /opt/mitmproxy
  /opt/mitmproxy/bin/pip install --no-cache-dir "mitmproxy==${MITMPROXY_VERSION}"
fi
chown -R root:root /opt/mitmproxy

install -d -o egress -g egress -m 0700 "$CONFDIR"
# Creates the CA only if absent. The key stays 0600 egress:egress.
runuser -u egress -- /opt/mitmproxy/bin/python -I - <<'PY'
from mitmproxy import certs
certs.CertStore.from_store("/var/lib/egress/mitm", "mitmproxy", 2048)
PY
chmod 0600 "$CONFDIR"/mitmproxy-ca.pem

# Trusted inside the VM only.
install -m 0644 "$CONFDIR/mitmproxy-ca-cert.pem" /usr/local/share/ca-certificates/egress-mitmproxy.crt
update-ca-certificates
