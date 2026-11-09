"""Egress approval addon for mitmproxy.

Default deny: a request that matches no rule is held (flow.intercept()) until the
operator decides in the TUI (keys in keys.yaml) or edits rules.json.

A rule may carry a `methods` list (e.g. ["GET", "HEAD"]); without it the rule matches any
method. Method-restricted rules can only match requests we decrypt: CONNECT, raw TCP/UDP and
passthrough hosts carry no visible method, so they ignore such rules.

Rule precedence: path-prefix rules beat host rules; longer prefix beats shorter;
exact host beats wildcard host; a method-restricted rule beats an any-method rule;
deny beats allow on a tie.

Every line of the decision log is one JSON object with the same leading keys (ts, method, host,
path, decision, by) followed by the detail for that event: the matching rule, the reason, which
guest user made the request, the response status, and so on. Request and response bodies,
header values (other than User-Agent) and query values are never logged. Query parameter names
are, and so is the value of `service` (git smart-HTTP uses it to tell a fetch from a push).
"""
import asyncio
import json
import os
import posixpath
import pwd
import re
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


METHOD_RE = re.compile(r"^[A-Z][A-Z0-9_-]*$")


def norm_methods(methods) -> Optional[list]:
    """Sorted, upper-cased, de-duplicated list; None means any method (empty or '*').

    Raises ValueError on a malformed name rather than dropping it: dropping would
    silently widen a rule to every method.
    """
    if isinstance(methods, str):
        methods = methods.split(",")
    ms = sorted({m.strip().upper() for m in (methods or []) if m and m.strip()})
    if not ms or "*" in ms:
        return None
    bad = [m for m in ms if not METHOD_RE.match(m)]
    if bad:
        raise ValueError(f"invalid HTTP method(s): {', '.join(bad)}")
    return ms


def rule_view(r: Optional[dict]) -> Optional[dict]:
    return None if r is None else {"action": r["action"], "host": r["host"],
                                   "path": r["path"], "methods": r["methods"]}


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
                try:
                    methods = norm_methods(r.get("methods"))
                except ValueError as e:
                    ctx.log.error(f"egress: skipping rule for {r.get('host')}: {e}")
                    continue
                if r["action"] == "passthrough" and methods:
                    ctx.log.error(f"egress: skipping passthrough rule for {r.get('host')}: "
                                  f"passthrough cannot be restricted by method")
                    continue
                rules.append({"action": r["action"], "host": norm_host(r["host"]),
                              "path": None if p == "/" else p, "methods": methods})
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
        out = [{k: v for k, v in r.items() if k != "methods" or v is not None} for r in self.rules]
        tmp.write_text(json.dumps({"version": 1, "rules": out}, indent=2) + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)
        self.mtime = self.path.stat().st_mtime

    def add(self, action: str, host: str, path: Optional[str], methods=None) -> dict:
        host = norm_host(host)
        path = None if path in (None, "", "/") else norm_path(path)
        methods = None if action == "passthrough" else norm_methods(methods)
        self.rules = [r for r in self.rules
                      if not (r["host"] == host and r["path"] == path and r["methods"] == methods)]
        rule = {"action": action, "host": host, "path": path, "methods": methods}
        self.rules.append(rule)
        self.save()
        return rule

    def forget(self, host: str, path: Optional[str] = None, methods=None) -> list:
        """Remove rules for host; narrowed to a path, and to one method set, when given."""
        host = norm_host(host)
        path = None if path is None else (None if norm_path(path) == "/" else norm_path(path))
        methods = norm_methods(methods)
        gone = [r for r in self.rules if r["host"] == host
                and (path is None or r["path"] == path)
                and (methods is None or r["methods"] == methods)]
        self.rules = [r for r in self.rules if r not in gone]
        self.save()
        return gone

    def decide(self, host: str, path: Optional[str], method: Optional[str] = None) -> Optional[dict]:
        """Best matching rule for host (+ normalized path, + request method), or None.

        path/method are None where the traffic has none (CONNECT, TLS, raw streams); rules
        scoped to a path or a method cannot match those.
        """
        method = method.upper() if method else None
        best, best_key = None, None
        for r in self.rules:
            if not host_matches(r["host"], host):
                continue
            if r["path"] is not None:
                if path is None or not path_matches(r["path"], path):
                    continue
            if r["methods"] is not None and (method is None or method not in r["methods"]):
                continue
            key = (r["path"] is not None, len(r["path"] or ""), r["host"] == host,
                   r["methods"] is not None, r["action"] == "deny")
            if best_key is None or key > best_key:
                best, best_key = r, key
        return best

    def near(self, host: str, path: str, method: str) -> list:
        """Rules that cover host and path but are limited to other methods; explains a hold."""
        return [r for r in self.rules
                if host_matches(r["host"], host) and r["methods"] is not None
                and method.upper() not in r["methods"]
                and (r["path"] is None or path_matches(r["path"], path))]

    def has_scoped_allow(self, host: str) -> bool:
        """An allow limited to a path or methods exists for host (so a host-level deny must
        not refuse the CONNECT outright; the request decides)."""
        return any(host_matches(r["host"], host) and (r["path"] or r["methods"])
                   and r["action"] == "allow" for r in self.rules)


class Egress:
    def __init__(self):
        self.rules = Rules(RULES_PATH)
        self.held: dict = {}
        self.connects: dict = {}
        self.peers: dict = {}

    # ---- logging -----------------------------------------------------------
    def _log(self, method: str, host: str, path: str, decision: str, by: str,
             rule: Optional[dict] = None, event: str = "decision", **extra) -> None:
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "method": method, "host": host,
                 "path": path, "decision": decision, "by": by, "event": event,
                 "rule": rule_view(rule)}
        entry.update(extra)
        line = json.dumps(entry)
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
            if self.rules.changed_on_disk():
                before = self.rules.rules
                if self.rules.load():
                    ctx.log.info("egress: rules reloaded from disk")
                    self._audit_diff(before, self.rules.rules)
                    self._sweep()

    def _audit_rule(self, change: str, rule: dict, by: str) -> None:
        self._log("RULE", rule["host"], rule["path"] or "", change, by, rule=rule, event="rule")

    def _audit_diff(self, before: list, after: list) -> None:
        """Rules edited outside the proxy (egress-rule, a rebuild) show up as add/remove events."""
        for r in before:
            if r not in after:
                self._audit_rule("remove", r, "reload")
        for r in after:
            if r not in before:
                self._audit_rule("add", r, "reload")

    def _peer(self, conn) -> dict:
        """Which guest user opened this connection: the client's socket on loopback is in
        /proc/net/tcp with its owner's uid."""
        if conn.id in self.peers:
            return self.peers[conn.id]
        uid = None
        peer = conn.peername
        if peer and peer[0] in ("127.0.0.1", "::ffff:127.0.0.1"):
            want = f"0100007F:{peer[1]:04X}"
            try:
                with open("/proc/net/tcp") as fh:
                    next(fh)
                    for line in fh:
                        cols = line.split()
                        if cols[1] == want:
                            uid = int(cols[7])
                            break
            except (OSError, ValueError, IndexError):
                pass
        if uid is None:
            return {"uid": None, "user": None}
        try:
            user = pwd.getpwuid(uid).pw_name
        except KeyError:
            user = str(uid)
        self.peers[conn.id] = {"uid": uid, "user": user}
        return self.peers[conn.id]

    def _req_info(self, flow: http.HTTPFlow) -> dict:
        req = flow.request
        qs = urllib.parse.parse_qsl(urllib.parse.urlsplit(req.path).query, keep_blank_values=True)
        info = {"id": flow.id, "scheme": req.scheme, "port": req.port,
                "http_version": req.http_version,
                "query_keys": sorted({k for k, _ in qs}),
                "req_bytes": len(req.raw_content) if req.raw_content is not None else None,
                "user_agent": (req.headers.get("user-agent") or "")[:200] or None}
        service = next((v for k, v in qs if k == "service"), None)
        if service:
            info["service"] = service[:64]
        # remembered on the flow so a later release still names the user after the client is gone
        who = flow.metadata.setdefault("egress_peer", self._peer(flow.client_conn))
        info.update(who)
        return info

    def _sweep(self) -> None:
        """Re-evaluate held flows after a rule change."""
        for fid, f in list(self.held.items()):
            if not f.intercepted:
                self.held.pop(fid, None)
                continue
            r = self.rules.decide(f.request.host.lower(), norm_path(f.request.path), f.request.method)
            if r and r["action"] != "deny":
                self._release(f, "allow", "rule", r)
            elif r:
                self._release(f, "deny", "rule", r)

    def _release(self, f: http.HTTPFlow, decision: str, by: str, rule: Optional[dict] = None) -> None:
        self.held.pop(f.id, None)
        f.marked = ""
        if decision == "deny":
            f.metadata["egress_synthetic"] = True
            f.response = http.Response.make(
                403, b"Blocked by egress policy\n", {"Content-Type": "text/plain"})
        if f.intercepted:
            f.resume()
        held_at = f.metadata.get("egress_held_at")
        self._log(f.request.method, f.request.host, norm_path(f.request.path), decision, by, rule,
                  reason="released from hold by " + ("operator, this request only" if by == "once"
                                                     else "a new or changed rule"),
                  waited_s=round(time.time() - held_at, 1) if held_at else None, **self._req_info(f))

    # ---- hooks -------------------------------------------------------------
    def http_connect(self, flow: http.HTTPFlow):
        host = flow.request.host.lower()
        self.connects[flow.client_conn.id] = flow
        r = self.rules.decide(host, None)
        who = self._peer(flow.client_conn)
        if r and r["action"] == "deny" and not self.rules.has_scoped_allow(host):
            flow.metadata["egress_synthetic"] = True
            flow.response = http.Response.make(403, b"Blocked by egress policy\n")
            self._log("CONNECT", host, "", "deny", "rule", r, reason="matched deny rule",
                      port=flow.request.port, **who)
        elif r and r["action"] == "passthrough":
            self._log("CONNECT", host, "", "passthrough", "rule", r,
                      reason="matched passthrough rule (not inspected: method and path unknown)",
                      port=flow.request.port, **who)
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
        self._log("TLS", host, "", "handshake-failed", "client", event="tls",
                  reason=str(data.conn.error) if getattr(data.conn, "error", None) else None,
                  **self._peer(data.context.client))
        ctx.log.warn(f"egress: TLS handshake failed for {host}. If the client pins certificates, "
                     f"press t on that flow (clear the view filter with :set view_filter=) to passthrough.")

    def client_disconnected(self, client):
        self.connects.pop(client.id, None)
        self.peers.pop(client.id, None)
        # A held request whose client gave up (curl timeout, killed process) can no longer be
        # answered: drop it from the queue so no later rule logs a decision that enforced nothing.
        for fid, f in list(self.held.items()):
            if f.client_conn.id != client.id:
                continue
            self.held.pop(fid, None)
            f.marked = ""
            held_at = f.metadata.get("egress_held_at")
            self._log(f.request.method, f.request.host.lower(), norm_path(f.request.path),
                      "abandoned", "client", reason="client disconnected while the request was held",
                      waited_s=round(time.time() - held_at, 1) if held_at else None,
                      **self._req_info(f))
            if f.killable:
                f.kill()

    def request(self, flow: http.HTTPFlow):
        host = flow.request.host.lower()
        path = norm_path(flow.request.path)
        method = flow.request.method
        info = self._req_info(flow)
        hdr = flow.request.host_header
        if hdr and norm_host(hdr.rsplit(":", 1)[0] if not hdr.startswith("[") else hdr) != host:
            flow.metadata["egress_synthetic"] = True
            flow.response = http.Response.make(403, b"Host header mismatch\n")
            self._log(method, host, path, "deny", "host-mismatch",
                      reason=f"Host header {hdr!r} does not match the connection target", **info)
            return
        r = self.rules.decide(host, path, method)
        if r and r["action"] != "deny":
            self._log(method, host, path, "allow", "rule", r, reason="matched allow rule", **info)
        elif r:
            flow.metadata["egress_synthetic"] = True
            flow.response = http.Response.make(
                403, b"Blocked by egress policy\n", {"Content-Type": "text/plain"})
            self._log(method, host, path, "deny", "rule", r, reason="matched deny rule", **info)
        else:
            flow.intercept()
            flow.marked = HELD_MARK
            flow.metadata["egress_held_at"] = time.time()
            self.held[flow.id] = flow
            near = self.rules.near(host, path, method)
            self._log(method, host, path, "held", "default-deny",
                      reason=("no rule matches this method on this path" if near
                              else "no rule matches this host and path"),
                      near_rules=[rule_view(n) for n in near], **info)

    def response(self, flow: http.HTTPFlow):
        """Outcome of an allowed request: what the upstream answered. Our own 403s are skipped."""
        if flow.metadata.get("egress_synthetic") or flow.request.method == "CONNECT" or not flow.response:
            return
        resp = flow.response
        started, ended = flow.request.timestamp_start, resp.timestamp_end
        peer = flow.server_conn.peername
        self._log(flow.request.method, flow.request.host.lower(), norm_path(flow.request.path),
                  "response", "upstream", event="response", id=flow.id, status=resp.status_code,
                  resp_bytes=len(resp.raw_content) if resp.raw_content is not None else None,
                  content_type=(resp.headers.get("content-type") or "")[:100] or None,
                  duration_ms=round((ended - started) * 1000) if started and ended else None,
                  upstream_ip=peer[0] if peer else None,
                  **self._peer(flow.client_conn))

    def error(self, flow: http.HTTPFlow):
        was_held = self.held.pop(flow.id, None) is not None
        flow.marked = ""
        if flow.error and flow.request.method != "CONNECT":
            self._log(flow.request.method, flow.request.host.lower(), norm_path(flow.request.path),
                      "error", "upstream", event="error", id=flow.id, reason=flow.error.msg,
                      was_held=was_held)

    def _tcp_gate(self, flow, kind: str):
        """Non-HTTP streams are never inspected: only host-level allow/passthrough may carry them."""
        host = (flow.server_conn.sni or flow.server_conn.address[0] or "").lower()
        r = self.rules.decide(host, None)
        ok = bool(r) and r["action"] in ("allow", "passthrough")
        self._log(kind, host, "", "allow" if ok else "deny", "rule" if r else "default-deny", r,
                  reason=("matched host-level rule" if ok else
                          "raw streams are only carried for a host-level allow or passthrough rule"),
                  port=flow.server_conn.address[1], **self._peer(flow.client_conn))
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

    def _rule(self, flows, action: str, path_level: bool, prefix: Optional[str] = None,
              this_method: bool = False) -> None:
        for f in self._http(flows):
            host = f.request.host.lower()
            path = None
            if path_level:
                path = prefix or self._prefix(f)
                if path in ("", "/"):
                    ctx.log.warn("egress: no path to build a prefix from; use a host rule")
                    continue
            methods = [f.request.method] if this_method else None
            rule = self.rules.add(action, host, path, methods)
            self._audit_rule("add", rule, "tui")
            ctx.log.info(f"egress: {action} {host}{path or ''} {','.join(methods or [])}".rstrip())
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

    @command.command("egress.allow_path_method")
    def allow_path_method(self, flows: Sequence[mflow.Flow]) -> None:
        self._rule(flows, "allow", True, this_method=True)

    @command.command("egress.deny_path_method")
    def deny_path_method(self, flows: Sequence[mflow.Flow]) -> None:
        self._rule(flows, "deny", True, this_method=True)

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
        self._audit_rule("add", self.rules.add("passthrough", host, None), "tui")
        self._sweep()

    @command.command("egress.forget")
    def forget(self, flows: Sequence[mflow.Flow]) -> None:
        for f in self._http(flows):
            gone = self.rules.forget(f.request.host.lower())
            for r in gone:
                self._audit_rule("remove", r, "tui")
            ctx.log.info(f"egress: removed {len(gone)} rule(s) for {f.request.host}")

    @command.command("egress.list")
    def list_rules(self) -> None:
        for r in self.rules.rules:
            ms = f" [{','.join(r['methods'])}]" if r["methods"] else ""
            ctx.log.info(f"egress rule: {r['action']:<11} {r['host']}{r['path'] or ''}{ms}")
        ctx.log.info(f"egress: {len(self.rules.rules)} rule(s), {len(self.held)} held")


addons = [Egress()]
