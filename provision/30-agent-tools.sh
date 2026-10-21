#!/bin/bash
# Coding agent (pi) installed as the unprivileged `agent` user. No keys/tokens here.
set -eu -o pipefail
[ -e /etc/egress/.locked ] && exit 0

PI_VERSION=1.3.0

cat > /etc/profile.d/agent-path.sh <<'EOF'
export PATH="$HOME/.npm-global/bin:$PATH"
EOF

runuser -u agent -- bash -c "
  set -eu
  mkdir -p ~/.npm-global
  npm config set prefix ~/.npm-global
  for i in 1 2 3; do npm install -g @earendil-works/pi-coding-agent@${PI_VERSION} && break; sleep 3; done
  command -v pi >/dev/null || [ -x ~/.npm-global/bin/pi ]
"
