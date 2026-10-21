#!/bin/bash
# Point every tool at the egress proxy and trust its CA. Runs last so earlier
# provisioning steps (which need direct network) are unaffected.
set -eu -o pipefail

PROXY=http://127.0.0.1:8080
BUNDLE=/etc/ssl/certs/ca-certificates.crt
CA=/usr/local/share/ca-certificates/egress-mitmproxy.crt

vars="HTTP_PROXY=$PROXY
HTTPS_PROXY=$PROXY
http_proxy=$PROXY
https_proxy=$PROXY
NO_PROXY=localhost,127.0.0.1,::1
no_proxy=localhost,127.0.0.1,::1
NODE_USE_ENV_PROXY=1
NODE_EXTRA_CA_CERTS=$CA
SSL_CERT_FILE=$BUNDLE
REQUESTS_CA_BUNDLE=$BUNDLE
CURL_CA_BUNDLE=$BUNDLE
PIP_CERT=$BUNDLE
GIT_SSL_CAINFO=$BUNDLE"

# /etc/environment (PAM: ssh, sudo) and profile.d (login shells).
sed -i '/# egress-proxy begin/,/# egress-proxy end/d' /etc/environment
{ echo "# egress-proxy begin"; echo "$vars"; echo "# egress-proxy end"; } >> /etc/environment
{ echo "# managed by provision/90-client-config.sh"; echo "$vars" | sed 's/^/export /'; } > /etc/profile.d/egress-proxy.sh

cat > /etc/apt/apt.conf.d/95egress-proxy <<EOF
Acquire::http::Proxy "$PROXY/";
Acquire::https::Proxy "$PROXY/";
EOF

cat > /etc/gitconfig <<EOF
[http]
	proxy = $PROXY
	sslCAInfo = $BUNDLE
EOF

cat > /etc/npmrc <<EOF
proxy=$PROXY
https-proxy=$PROXY
cafile=$BUNDLE
EOF

cat > /etc/pip.conf <<EOF
[global]
proxy = $PROXY
cert = $BUNDLE
EOF
