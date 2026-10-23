# Source this (or let the scripts do it) so all Lima state lives next to this file (<repo>/.lima).
export LIMA_HOME="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)/.lima"
