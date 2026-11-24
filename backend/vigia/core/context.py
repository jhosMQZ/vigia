"""Per-scan execution context shared by all modules and adapters."""
from __future__ import annotations

import asyncio
import json
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import update

from vigia.core.findings import SEV_RANK, FindingDraft
from vigia.config import get_settings
from vigia.core.profiles import EffectiveConfig
from vigia.core.toolrunner import ToolResult, ToolRunner
from vigia.db import Finding, Scan, ScanEvent, SessionLocal, ToolRun, utcnow
from vigia.security.http import ScopedHttpClient, StopScan
from vigia.security.redact import redact, redact_obj
from vigia.security.scope import ScopeGuard


@dataclass
class Form:
    page: str
    action: str
    method: str
    fields: dict[str, str]  # name -> default value
    field_types: dict[str, str] = field(default_factory=dict)
    enctype: str = "application/x-www-form-urlencoded"


@dataclass
class ApiEndpoint:
    method: str
    url: str
    params: list[dict[str, Any]] = field(default_factory=list)  # {name, in: query|path|header|body, type, required}
    body_schema: dict[str, Any] | None = None
    auth_required: bool | None = None
    source: str = "crawl"  # crawl | openapi | postman | js | code
    operation_id: str | None = None


@dataclass
class KnowledgeBase:
    """What the scan has learnt so far; written by discovery modules, read by analysis modules."""
    base_urls: list[str] = field(default_factory=list)
    urls: set[str] = field(default_factory=set)
    pages: dict[str, dict[str, Any]] = field(default_factory=dict)  # url -> {status, ctype, title, size}
    forms: list[Form] = field(default_factory=list)
    params: dict[str, set[str]] = field(default_factory=dict)  # url-template -> param names
    scripts: set[str] = field(default_factory=set)
    api: list[ApiEndpoint] = field(default_factory=list)
    graphql: set[str] = field(default_factory=set)
    technologies: dict[str, dict[str, Any]] = field(default_factory=dict)  # name -> {version, evidence, host}
    open_ports: dict[str, list[dict[str, Any]]] = field(default_factory=dict)  # host -> [{port, service, banner}]
    tls: dict[str, dict[str, Any]] = field(default_factory=dict)
    code_routes: list[dict[str, Any]] = field(default_factory=list)  # {method, path, file, line, auth, framework}
    dependencies: list[dict[str, Any]] = field(default_factory=list)  # {ecosystem, name, version, file}
    languages: dict[str, int] = field(default_factory=dict)
    login_urls: set[str] = field(default_factory=set)
    canaries: dict[str, dict[str, Any]] = field(default_factory=dict)  # canary -> {url, param} (stored XSS)
    responses: Any = None  # modules.common.ResponseStore
    soft404: dict[str, Any] = field(default_factory=dict)  # origin -> baseline fingerprint
    authenticated: list[str] = field(default_factory=list)  # identity names with a working session
    error_signatures: set[str] = field(default_factory=set)  # host|signature already reported


class ScanContext:
    def __init__(self, scan_id: int, project_id: int, cfg: EffectiveConfig, workspace: Path, *,
                 guard: ScopeGuard | None, source_dir: Path | None, lab_mode: bool = False,
                 identities: dict[str, dict[str, Any]] | None = None):
        self.scan_id = scan_id
        self.project_id = project_id
        self.cfg = cfg
        self.workspace = workspace
        self.evidence_dir = workspace / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.guard = guard
        self.source_dir = source_dir
        self.lab_mode = lab_mode
        self.identities = identities or {}
        self.kb = KnowledgeBase()
        from vigia.modules.common import ResponseStore  # local import: modules depend on core, not vice versa
        self.kb.responses = ResponseStore()
        self.findings: list[FindingDraft] = []
        self.cancel_event = asyncio.Event()
        self.thread_cancel = threading.Event()
        self.started = time.monotonic()
        self.deadline = self.started + cfg.max_duration_min * 60
        self.http: ScopedHttpClient | None = None
        self.gateway = None  # vigia.security.gateway.EgressGateway (scope lane), started in open_http()
        self.public_gateway = None  # public lane (third-party sources), started on demand with an egress
        self.upstream = None  # vigia.security.egress.Upstream when VIGIA_HTTP_PROXY is set
        self.resolver = None
        self.isolation: dict | None = None  # result of vigia.security.isolation.check() for this scan
        self._loop: asyncio.AbstractEventLoop | None = None
        self.runner = ToolRunner(workspace / "tools", cancel_event=self.thread_cancel)
        self.tool_versions: dict[str, str] = {}
        self.stop_reason: str | None = None
        self._events: list[ScanEvent] = []
        self._progress: dict[str, Any] = {}
        self._last_flush = 0.0
        self._last_cancel_check = 0.0
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ lifecycle
    @property
    def egress_active(self) -> bool:
        """True when a dedicated egress is configured: nothing may leave except through it."""
        return self.upstream is not None

    def open_egress(self, upstream=None, resolver=None) -> None:  # noqa: ANN001 - injected by tests/audit
        """Start the scope gateway (every engine and, with an egress, every native socket goes through it)."""
        if self.guard is None or self.gateway is not None:
            return
        from vigia.security.egress import configured_upstream
        from vigia.security.gateway import EgressGateway, ScopePolicy
        from vigia.security.resolver import build_resolver
        s = get_settings()
        self._loop = asyncio.get_running_loop()
        self.upstream = upstream if upstream is not None else configured_upstream()
        trace = self.workspace / "egress-trace.jsonl"
        self.gateway = EgressGateway(ScopePolicy(self.guard), self.upstream, dns_stub=True, trace_path=trace,
                                     on_egress_down=self._egress_down,
                                     # same non-destructive policy as the native client (enforceable on plain HTTP)
                                     allowed_methods={"GET", "HEAD", "OPTIONS", "POST"} | (
                                         {"PUT", "PATCH"} if self.lab_mode else set()))
        if resolver is None:
            resolver = build_resolver(s.dns_resolver, self.upstream, trace=lambda rec: self.gateway._record(**rec))
        self.resolver = resolver
        self.guard.resolver = resolver
        self.gateway.start()
        self.guard.blocked_local_ports |= {self.gateway.port, self.gateway.dns_port}

    def _egress_down(self, reason: str) -> None:
        """Called from the gateway thread: the egress failed. Stop everything; never fall back to direct."""
        msg = f"la salida configurada dejó de responder ({reason}); el análisis se detiene sin conexión directa de reserva"
        self.stop_reason = self.stop_reason or msg
        if self.http is not None:
            self.http.stopped_reason = self.http.stopped_reason or msg
        self.thread_cancel.set()
        if self._loop is not None:
            try:
                self._loop.call_soon_threadsafe(self.cancel_event.set)
            except RuntimeError:
                pass

    def open_http(self) -> ScopedHttpClient | None:
        if self.guard is None:
            return None
        self.open_egress()
        assert self.gateway is not None
        self.http = ScopedHttpClient(
            self.guard, rps=self.cfg.rps, concurrency=self.cfg.concurrency, max_requests=self.cfg.max_requests,
            stop_failure_ratio=self.cfg.stop.get("max_error_ratio", 0.3) if self.cfg.stop else 0.3,
            trace_path=self.workspace / "http-trace.jsonl", cancel_event=self.cancel_event,
            # dedicated egress: through the gateway (scope + remote DNS + upstream only, no direct fallback)
            proxy=self.gateway.http_url if self.egress_active else None, gateway_token=self.gateway.token,
            # non-destructive policy enforced at the transport: PUT/PATCH only in lab scopes, DELETE/TRACE never
            allowed_methods={"GET", "HEAD", "OPTIONS", "POST"} | ({"PUT", "PATCH"} if self.lab_mode else set()))
        return self.http

    async def net_open(self, ip: str, port: int, timeout: float = 5.0) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Raw TCP stream to an already-validated (pinned) IP: via the gateway/egress when configured, else direct.
        Raises OSError subclasses for closed/filtered ports and StopScan (EgressDown) if the egress fails."""
        if self.egress_active:
            from vigia.security.gateway import open_via_gateway
            assert self.gateway is not None
            return await open_via_gateway(self.gateway.port, ip, port, timeout, username=self.gateway.username,
                                          password=self.gateway.password)
        return await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)

    def engine_env(self, lane: str = "scope") -> dict[str, str]:
        """Proxy variables for an engine (backstop to its explicit proxy flags). Scope lane for engines that talk to
        targets; public lane (third-party sources/telemetry) for the rest. Empty when no egress is configured and the
        engine does not touch targets."""
        url = None
        if lane == "scope" and self.gateway is not None:
            url = self.gateway.http_url
        elif self.egress_active:
            url = self.public_proxy_url()
        if not url:
            return {}
        env = {}
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            env[k] = env[k.lower()] = url
        env["NO_PROXY"] = env["no_proxy"] = ""
        return env

    def public_proxy_url(self) -> str | None:
        """Loopback proxy for this scan's third-party traffic (crt.sh, engines' passive sources): through the egress,
        public addresses only. None without an egress (direct, as before)."""
        if not self.egress_active:
            return None
        if self.public_gateway is None:
            from vigia.security.gateway import EgressGateway, PublicPolicy
            self.public_gateway = EgressGateway(PublicPolicy(self.resolver), self.upstream, lane="public",
                                                trace_path=self.workspace / "egress-trace.jsonl",
                                                on_egress_down=self._egress_down).start()
        return self.public_gateway.http_url

    @property
    def isolated(self) -> bool:
        """Engines run inside the network-less AppContainer (preventive, verified for this scan)."""
        return bool(self.egress_active and self.isolation and self.isolation.get("ok")
                    and self.isolation.get("mode") == "appcontainer")

    @property
    def netwatch(self) -> bool:
        return self.egress_active and get_settings().egress_kill_switch

    async def fetch(self, url: str, *, method: str = "GET", identity: str = "default", module: str = "",
                    store: bool = True, **kw: Any):
        """Scoped request through the shared client; GET responses are stored for other modules."""
        self.check()
        assert self.http is not None
        r = await self.http.request(method, url, identity=identity, module=module, **kw)
        if store and method == "GET" and r.status < 500:
            self.kb.responses.add(r, identity)
        if r.status >= 400:
            self._error_page(r, module)
        return r

    def _error_page(self, r, module: str) -> None:  # noqa: ANN001
        """Any module may provoke a verbose error: report internal details once per origin and signature."""
        from urllib.parse import urlsplit

        from vigia.modules.common import ERROR_SIGNATURES, find_signature
        sig = find_signature(r.content[:60000].decode("utf-8", errors="replace"), ERROR_SIGNATURES)
        if not sig:
            return
        host = urlsplit(r.url).hostname or ""
        key = f"{host}|{sig[0]}"
        if key in self.kb.error_signatures:
            return
        self.kb.error_signatures.add(key)
        self.add(FindingDraft(
            title=f"Error con detalle interno ({sig[0]}) en {host}", category="error_disclosure", module="headers",
            confidence="confirmed", native_evidence=True, asset=host, endpoint=r.url, method=r.method,
            description=f"Una petición de prueba ({module or 'escaneo'}) provocó una respuesta {r.status} que expone "
                        f"{sig[0]}: rutas, código o consultas internas visibles para cualquier visitante.",
            evidence={"request": f"{r.method} {r.url}", "status": r.status, "response_excerpt": sig[1][:800]},
            fingerprint_extra=sig[0]))

    async def close(self) -> None:
        if self.http is not None:
            await self.http.aclose()
        if self.gateway is not None:
            summary = self.gateway.summary()
            self.emit("info", "egress", f"Pasarela de salida: {summary['connections']} conexiones permitidas, "
                      f"{summary['refused']} bloqueadas, {summary['dns_answered']} respuestas DNS del stub", summary)
            await asyncio.to_thread(self.gateway.stop)
        if self.public_gateway is not None:
            self.emit("info", "egress", "Carril público de la salida", self.public_gateway.summary())
            await asyncio.to_thread(self.public_gateway.stop)
        self.flush(force=True)

    # ------------------------------------------------------------------ control
    def check(self) -> None:
        """Raise StopScan if cancelled, past the deadline, outside the window or the target degrades."""
        now = time.monotonic()
        if now - self._last_cancel_check > 2.0:
            self._last_cancel_check = now
            with SessionLocal() as db:
                if db.get(Scan, self.scan_id).cancel_requested:  # type: ignore[union-attr]
                    self.stop_reason = "cancelado por el usuario"
        if not self.stop_reason and now > self.deadline:
            self.stop_reason = f"duración máxima alcanzada ({self.cfg.max_duration_min} min)"
        if not self.stop_reason and self.cfg.window and not in_window(self.cfg.window):
            self.stop_reason = "fin de la ventana de ejecución autorizada"
        if not self.stop_reason and self.http is not None and self.http.stopped_reason:
            self.stop_reason = self.http.stopped_reason
        if self.stop_reason:
            self.cancel_event.set()
            self.thread_cancel.set()
            raise StopScan(self.stop_reason)

    @property
    def stopping(self) -> bool:
        return self.stop_reason is not None

    # ------------------------------------------------------------------ events / progress
    def emit(self, level: str, module: str, message: str, data: dict[str, Any] | None = None) -> None:
        ev = ScanEvent(scan_id=self.scan_id, ts=utcnow(), level=level, module=module[:48],
                       message=redact(message, 2000), data=redact_obj(data) if data else None)
        with self._lock:
            self._events.append(ev)
        self.flush()

    def progress(self, module: str, status: str, pct: int | None = None, detail: str | None = None) -> None:
        with self._lock:
            entry = self._progress.setdefault(module, {})
            entry.update({"status": status, "updated": utcnow().isoformat(timespec="seconds")})
            if pct is not None:
                entry["pct"] = max(0, min(100, pct))
            if detail is not None:
                entry["detail"] = detail[:200]
        self.flush(force=status in ("done", "failed", "skipped"))

    def flush(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_flush < 0.5:
            return
        with self._lock:
            events, self._events = self._events, []
            progress = json.loads(json.dumps(self._progress))
            self._last_flush = now
        with SessionLocal() as db:
            if events:
                db.add_all(events)
            stats = {"requests": self.http.requests_made if self.http else 0, "findings": len(self.findings),
                     "urls": len(self.kb.urls), "elapsed_s": int(now - self.started)}
            db.execute(update(Scan).where(Scan.id == self.scan_id).values(progress=progress, stats=stats))
            db.commit()

    # ------------------------------------------------------------------ results
    def add(self, f: FindingDraft) -> FindingDraft:
        """Register a raw finding; persisted immediately so the console shows partial results."""
        f.evidence = redact_obj(f.evidence)
        if f.snippet:
            f.snippet = redact(f.snippet, 1500)
        with self._lock:
            self.findings.append(f)
        from vigia.correlation.catalog import enrich  # local import to avoid a cycle
        enrich(f)
        with SessionLocal() as db:
            db.add(Finding(scan_id=self.scan_id, project_id=self.project_id, fingerprint=f.fingerprint, title=f.title[:255],
                           category=f.category, module=f.module, severity=f.severity, confidence=f.confidence,
                           cvss_vector=f.cvss_vector, cwe=f.cwe, cve=f.cve, owasp=f.owasp, asset=f.asset[:512],
                           endpoint=(f.endpoint or None) and f.endpoint[:2048], method=f.method, parameter=f.parameter,
                           file=f.file, line=f.line, function=f.function, snippet=f.snippet, description=f.description,
                           evidence=f.evidence, impact=f.impact, likelihood=f.likelihood or "medium",
                           recommendation=f.recommendation, references=f.references, sources=f.sources,
                           validation_status="raw"))
            db.commit()
        self.emit("finding", f.module, f"[{f.severity.upper()}] {f.title}",
                  {"endpoint": f.endpoint, "file": f.file, "line": f.line, "confidence": f.confidence})
        if self.cfg.stop.get("stop_on_first_critical") and SEV_RANK[f.severity] == 4 and f.confidence == "confirmed":
            self.stop_reason = "condición de parada: primer hallazgo crítico confirmado"
        return f

    def record_tool(self, tool: str, res: ToolResult, findings_count: int = 0) -> None:
        version = self.tool_versions.get(tool)
        with SessionLocal() as db:
            db.add(ToolRun(scan_id=self.scan_id, tool=tool, version=version, command=_safe_cmd(res.command),
                           status=res.status, exit_code=res.exit_code, duration=res.duration,
                           max_rss_mb=res.max_rss_mb, findings_count=findings_count,
                           stderr_tail=redact(res.stderr_tail, 4000) if res.stderr else None, error=res.error))
            db.commit()

    def record_tool_skip(self, tool: str, reason: str) -> None:
        with SessionLocal() as db:
            db.add(ToolRun(scan_id=self.scan_id, tool=tool, status="skipped", error=reason[:1000]))
            db.commit()
        self.emit("info", f"tool:{tool}", f"{tool} omitido: {reason}")


def _safe_cmd(argv: list[str]) -> list[str]:
    out, hide = [], False
    for a in argv:
        if hide:
            out.append("****")
            hide = False
            continue
        if a.lower() in ("-h", "--header", "-H", "--auth", "-auth", "--api-key", "-apikey", "--token", "-config"):
            hide = True
        out.append(redact(a, 300))
    return out


def in_window(window: dict[str, Any], now: datetime | None = None) -> bool:
    now = now or datetime.now()
    if now.weekday() not in window.get("weekdays", list(range(7))):
        return False
    start, end, h = window["start_hour"], window["end_hour"], now.hour
    return start <= h < end if start < end else (h >= start or h < end) if start != end else True
