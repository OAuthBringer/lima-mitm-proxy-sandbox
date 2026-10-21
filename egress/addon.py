"""Egress approval addon for mitmproxy.

Default deny: a request that matches no rule is held (flow.intercept()) until the
operator decides in the TUI (keys in keys.yaml) or edits rules.json.

Rule precedence: path-prefix rules beat host rules; longer prefix beats shorter;
exact host beats wildcard host; deny beats allow on a tie.
Only timestamp, method, host, path (no query) and decision are ever logged.
"""
import asyncio
import json
import os
import posixpath
import time
import urllib.parse
from collections.abc import Sequence
from pathlib import Path
from typing import Optional

from mitmproxy import command, ctx, http, tls
from mitmproxy import flow as mflow

RULES_PATH = Path(os.environ.get("EGRESS_RULES", "/var/lib/egress/rules.json"))
LOG_PATH = Path(os.environ.get("EGRESS_LOG", "/var/log/egress/decisions.log"))
HELD_MARK = ":hourglass:"
WARN_MARK = ":warning:"


def norm_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def norm_path(path: str) -> str:
    """Decode, collapse ../ and //, lowercase, drop query, trailing '/' and '*'."""
    path = urllib.parse.urlsplit(path).path
    path = urllib.parse.unquote(path).lower().rstrip("*")
    path = posixpath.normpath("/" + path.lstrip("/")) if path else "/"
    if path.startswith("//"):
        path = "/" + path.lstrip("/")
    return path.rstrip("/") or "/"


def host_matches(pattern: str, host: str) -> bool:
    if pattern == host:
        return True
    return pattern.startswith("*.") and host.endswith(pattern[1:]) and host != pattern[2:]


def path_matches(prefix: str, path: str) -> bool:
    if path == prefix or path.startswith(prefix + "/"):
        return True
    # git smart-HTTP uses /org/repo.git/...; treat it as the same repo.
    if path.startswith(prefix + ".git"):
        rest = path[len(prefix) + 4:]
        return rest == "" or rest.startswith("/")
    return False


class Rules:
    def __init__(self, path: Path):
        self.path = path
        self.rules: list = []
        self.mtime = 0.0
        self.load()

    def load(self) -> bool:
        try:
            st = self.path.stat()
            data = json.loads(self.path.read_text())
            rules = []
            for r in data.get("rules", []):
                if r.get("action") not in ("allow", "deny", "passthrough"):
                    continue
                p = r.get("path")
                p = norm_path(p) if p else None
                rules.append({"action": r["action"], "host": norm_host(r["host"]),
                              "path": None if p == "/" else p})
            self.rules, self.mtime = rules, st.st_mtime
            return True
        except FileNotFoundError:
            self.rules, self.mtime = [], 0.0
        except Exception as e:  # corrupt file: keep previous rules (fail closed to what we had)
            ctx.log.error(f"egress: cannot load {self.path}: {e}")
        return False

    def changed_on_disk(self) -> bool:
        try:
            return self.path.stat().st_mtime != self.mtime
        except FileNotFoundError:
            return bool(self.rules)

    def save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"version": 1, "rules": self.rules}, indent=2) + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)
        self.mtime = self.path.stat().st_mtime

    def add(self, action: str, host: str, path: Optional[str]) -> None:
        host = norm_host(host)
        path = None if path in (None, "", "/") else norm_path(path)
        self.rules = [r for r in self.rules if not (r["host"] == host and r["path"] == path)]
        self.rules.append({"action": action, "host": host, "path": path})
        self.save()

    def forget(self, host: str, path: Optional[str] = None) -> int:
        host = norm_host(host)
        before = len(self.rules)
        self.rules = [r for r in self.rules
                      if not (r["host"] == host and (path is None or r["path"] == norm_path(path)))]
        self.save()
        return before - len(self.rules)

    def decide(self, host: str, path: Optional[str]) -> Optional[dict]:
        """Best matching rule for host (+ normalized path), or None."""
        best, best_key = None, None
        for r in self.rules:
            if not host_matches(r["host"], host):
                continue
            if r["path"] is not None:
                if path is None or not path_matches(r["path"], path):
                    continue
            key = (r["path"] is not None, len(r["path"] or ""), r["host"] == host, r["action"] == "deny")
            if best_key is None or key > best_key:
                best, best_key = r, key
        return best

    def has_path_allow(self, host: str) -> bool:
        return any(host_matches(r["host"], host) and r["path"] and r["action"] == "allow"
                   for r in self.rules)


class Egress:
    def __init__(self):
        self.rules = Rules(RULES_PATH)
        self.held: dict = {}
        self.connects: dict = {}

    # ---- logging -----------------------------------------------------------
    def _log(self, method: str, host: str, path: str, decision: str, by: str) -> None:
        line = json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "method": method,
                           "host": host, "path": path, "decision": decision, "by": by})
        try:
            with open(LOG_PATH, "a") as f:
                f.write(line + "\n")
        except OSError as e:
            ctx.log.warn(f"egress: log write failed: {e}")

    # ---- lifecycle ---------------------------------------------------------
    def running(self):
        asyncio.get_running_loop().create_task(self._watch())

    async def _watch(self):
        while True:
            await asyncio.sleep(1)
            if self.rules.changed_on_disk() and self.rules.load():
                ctx.log.info("egress: rules reloaded from disk")
                self._sweep()

    def _sweep(self) -> None:
        """Re-evaluate held flows after a rule change."""
        for fid, f in list(self.held.items()):
            if not f.intercepted:
                self.held.pop(fid, None)
                continue
            r = self.rules.decide(f.request.host.lower(), norm_path(f.request.path))
            if r and r["action"] != "deny":
                self._release(f, "allow", "rule")
            elif r:
                self._release(f, "deny", "rule")

    def _release(self, f: http.HTTPFlow, decision: str, by: str) -> None:
        self.held.pop(f.id, None)
        f.marked = ""
        if decision == "deny":
            f.response = http.Response.make(
                403, b"Blocked by egress policy\n", {"Content-Type": "text/plain"})
        if f.intercepted:
            f.resume()
        self._log(f.request.method, f.request.host, norm_path(f.request.path), decision, by)

    # ---- hooks -------------------------------------------------------------
    def http_connect(self, flow: http.HTTPFlow):
        host = flow.request.host.lower()
        self.connects[flow.client_conn.id] = flow
        r = self.rules.decide(host, None)
        if r and r["action"] == "deny" and not self.rules.has_path_allow(host):
            flow.response = http.Response.make(403, b"Blocked by egress policy\n")
            self._log("CONNECT", host, "", "deny", "rule")
        elif r and r["action"] == "passthrough":
            self._log("CONNECT", host, "", "passthrough", "rule")
        # unknown host: proceed; the request itself is held once its path is visible

    def tls_clienthello(self, data: tls.ClientHelloData):
        host = (data.context.client.sni or data.context.server.address[0] or "").lower()
        r = self.rules.decide(host, None)
        if r and r["action"] == "passthrough":
            data.ignore_connection = True

    def tls_failed_client(self, data: tls.TlsData):
        host = (data.context.client.sni or data.context.server.address[0] or "?").lower()
        f = self.connects.get(data.context.client.id)
        if f:
            f.marked = WARN_MARK
        self._log("TLS", host, "", "handshake-failed", "client")
        ctx.log.warn(f"egress: TLS handshake failed for {host}. If the client pins certificates, "
                     f"press t on that flow (clear the view filter with :set view_filter=) to passthrough.")

    def client_disconnected(self, client):
        self.connects.pop(client.id, None)

    def request(self, flow: http.HTTPFlow):
        host = flow.request.host.lower()
        path = norm_path(flow.request.path)
        method = flow.request.method
        hdr = flow.request.host_header
        if hdr and norm_host(hdr.rsplit(":", 1)[0] if not hdr.startswith("[") else hdr) != host:
            flow.response = http.Response.make(403, b"Host header mismatch\n")
            self._log(method, host, path, "deny", "host-mismatch")
            return
        r = self.rules.decide(host, path)
        if r and r["action"] != "deny":
            self._log(method, host, path, "allow", "rule")
        elif r:
            flow.response = http.Response.make(
                403, b"Blocked by egress policy\n", {"Content-Type": "text/plain"})
            self._log(method, host, path, "deny", "rule")
        else:
            flow.intercept()
            flow.marked = HELD_MARK
            self.held[flow.id] = flow
            self._log(method, host, path, "held", "default-deny")

    def error(self, flow: http.HTTPFlow):
        self.held.pop(flow.id, None)
        flow.marked = ""

    def _tcp_gate(self, flow, kind: str):
        """Non-HTTP streams are never inspected: only host-level allow/passthrough may carry them."""
        host = (flow.server_conn.sni or flow.server_conn.address[0] or "").lower()
        r = self.rules.decide(host, None)
        ok = bool(r) and r["action"] in ("allow", "passthrough")
        self._log(kind, host, "", "allow" if ok else "deny", "rule" if r else "default-deny")
        if not ok:
            flow.kill()

    def tcp_start(self, flow):
        self._tcp_gate(flow, "TCP")

    def udp_start(self, flow):
        self._tcp_gate(flow, "UDP")

    # ---- operator commands (bound in keys.yaml) ----------------------------
    @staticmethod
    def _http(flows: Sequence[mflow.Flow]):
        return [f for f in flows if isinstance(f, http.HTTPFlow)]

    @staticmethod
    def _prefix(f: http.HTTPFlow) -> str:
        segs = [s for s in norm_path(f.request.path).split("/") if s][:2]
        if len(segs) == 2 and segs[1].endswith(".git"):
            segs[1] = segs[1][:-4]
        return "/" + "/".join(segs)

    @command.command("egress.allow_once")
    def allow_once(self, flows: Sequence[mflow.Flow]) -> None:
        for f in self._http(flows):
            if f.intercepted:
                self._release(f, "allow", "once")

    @command.command("egress.deny_once")
    def deny_once(self, flows: Sequence[mflow.Flow]) -> None:
        for f in self._http(flows):
            if f.intercepted:
                self._release(f, "deny", "once")

    def _rule(self, flows, action: str, path_level: bool, prefix: Optional[str] = None) -> None:
        for f in self._http(flows):
            host = f.request.host.lower()
            path = None
            if path_level:
                path = prefix or self._prefix(f)
                if path in ("", "/"):
                    ctx.log.warn("egress: no path to build a prefix from; use a host rule")
                    continue
            self.rules.add(action, host, path)
            ctx.log.info(f"egress: {action} {host}{path or ''}")
        self._sweep()

    @command.command("egress.allow_host")
    def allow_host(self, flows: Sequence[mflow.Flow]) -> None:
        self._rule(flows, "allow", False)

    @command.command("egress.deny_host")
    def deny_host(self, flows: Sequence[mflow.Flow]) -> None:
        self._rule(flows, "deny", False)

    @command.command("egress.allow_path")
    def allow_path(self, flows: Sequence[mflow.Flow]) -> None:
        self._rule(flows, "allow", True)

    @command.command("egress.deny_path")
    def deny_path(self, flows: Sequence[mflow.Flow]) -> None:
        self._rule(flows, "deny", True)

    @command.command("egress.allow_prefix")
    def allow_prefix(self, flows: Sequence[mflow.Flow], prefix: str) -> None:
        self._rule(flows, "allow", True, prefix)

    @command.command("egress.deny_prefix")
    def deny_prefix(self, flows: Sequence[mflow.Flow], prefix: str) -> None:
        self._rule(flows, "deny", True, prefix)

    @command.command("egress.passthrough_host")
    def passthrough_host(self, flows: Sequence[mflow.Flow]) -> None:
        self._rule(flows, "passthrough", False)

    @command.command("egress.passthrough_name")
    def passthrough_name(self, host: str) -> None:
        self.rules.add("passthrough", host, None)
        self._sweep()

    @command.command("egress.forget")
    def forget(self, flows: Sequence[mflow.Flow]) -> None:
        for f in self._http(flows):
            n = self.rules.forget(f.request.host.lower())
            ctx.log.info(f"egress: removed {n} rule(s) for {f.request.host}")

    @command.command("egress.list")
    def list_rules(self) -> None:
        for r in self.rules.rules:
            ctx.log.info(f"egress rule: {r['action']:<11} {r['host']}{r['path'] or ''}")
        ctx.log.info(f"egress: {len(self.rules.rules)} rule(s), {len(self.held)} held")


addons = [Egress()]
