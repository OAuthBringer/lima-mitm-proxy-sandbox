# Helper targets for the disposable agent sandbox. Run `make` for the list.
ROOT := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
export LIMA_HOME := $(ROOT)/.lima
VM ?= agent
SHELL := /bin/bash

.DEFAULT_GOAL := help
.PHONY: help up reset verify start stop status shell agent ui rules log destroy push put get

help: ## Show this help
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  make %-8s %s\n", $$1, $$2}'

up: ## Build the VM (or daily-rebuild if it exists); saves and restores egress rules
	$(ROOT)/reset.sh

reset: up ## Alias for up

verify: ## Run the automated guarantee checks
	$(ROOT)/verify.sh

start: ## Start a stopped VM
	limactl start $(VM)

stop: ## Stop the VM without deleting it
	limactl stop $(VM)

status: ## VM status plus proxy, firewall and rule count
	@limactl list $(VM)
	@limactl shell $(VM) -- bash -c 'printf "proxy:    "; systemctl is-active egress-proxy; \
	  printf "firewall: "; sudo nft list table inet egress_fw >/dev/null 2>&1 && echo loaded || echo NOT LOADED; \
	  printf "rules:    "; sudo jq ".rules|length" /var/lib/egress/rules.json'

shell: ## Shell as the admin user (lima, sudo)
	limactl shell $(VM)

agent: ## Shell as the unprivileged agent user
	limactl shell $(VM) -- sudo -iu agent

ui: ## Open the egress approval UI (detach with ctrl-b d)
	limactl shell $(VM) -- egress-ui

rules: ## List egress rules
	limactl shell $(VM) -- sudo egress-rule list

log: ## Follow the egress decision log
	limactl shell $(VM) -- sudo tail -f /var/log/egress/decisions.log

push: ## Re-install egress config into the running VM
	$(ROOT)/provision/push-config.sh

put: ## Copy host file into VM: make put SRC=./file [DST=/tmp/]
	@test -n "$(SRC)" || { echo "usage: make put SRC=<host path> [DST=<vm path>]"; exit 1; }
	limactl copy -r "$(SRC)" "$(VM):$(or $(DST),/tmp/)"

get: ## Copy VM file to host: make get SRC=/path/in/vm [DST=.]
	@test -n "$(SRC)" || { echo "usage: make get SRC=<vm path> [DST=<host path>]"; exit 1; }
	limactl copy -r "$(VM):$(SRC)" "$(or $(DST),.)"

destroy: ## Delete the VM (prompts; unsaved approvals are lost, use `make reset` to keep them)
	@read -r -p "Delete VM '$(VM)' without saving rules? [y/N] " a; [ "$$a" = y ] || [ "$$a" = Y ] || { echo aborted; exit 1; }
	limactl delete -f $(VM)
