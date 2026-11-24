"""Scope-enforcing, rate-limited HTTP client used by every native module."""
from __future__ import annotations

import asyncio
import json
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from vigia import USER_AGENT
from vigia.security.errors import StopScan
from vigia.security.scope import ScopeGuard, ScopeViolation

FORBIDDEN_METHODS = {"DELETE", "TRACE", "CONNECT"}


class HttpError(Exception):
    pass


class BudgetExceeded(Exception):
    pass


__all__ = ["BudgetExceeded", "HttpError", "HttpResponse", "Identity", "ScopedHttpClient", "StopScan"]


@dataclass
class HttpResponse:
    method: str
    url: str
    status: int
    headers: httpx.Headers
    content: bytes
    truncated: bool
    elapsed: float
    redirects: list[str]
    request_headers: dict[str, str]
    request_body: bytes | None = None

    @property
    def text(self) -> str:
        ctype = self.headers.get("content-type", "")
        enc = "utf-8"
        if "charset=" in ctype:
            enc = ctype.split("charset=")[-1].split(";")[0].strip().strip('"') or "utf-8"
        try:
            return self.content.decode(enc, errors="replace")
        except LookupError:
            return self.content.decode("utf-8", errors="replace")

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name, default)

    @property
    def set_cookies(self) -> list[str]:
        return self.headers.get_list("set-cookie")

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()

    def json(self) -> Any:
        return json.loads(self.content)


@dataclass
class _Cookie:
    domain: str
    host_only: bool
    path: str
    name: str
    value: str


@dataclass
class Identity:
    name: str
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[_Cookie] = field(default_factory=list)

    def cookie_header(self, host: str, path: str) -> str:
        pairs = []
        for c in self.cookies:
            ok = host == c.domain if c.host_only else (host == c.domain or host.endswith("." + c.domain))
            if ok and path.startswith(c.path or "/"):
                pairs.append(f"{c.name}={c.value}")
        return "; ".join(pairs)

    def store(self, host: str, raw: str) -> None:
        parts = [p.strip() for p in raw.split(";")]
        if not parts or "=" not in parts[0]:
            return
        name, _, value = parts[0].partition("=")
        domain, host_only, path, expired = host, True, "/", False
        for attr in parts[1:]:
            k, _, v = attr.partition("=")
            k = k.strip().lower()
            if k == "domain" and v:
                d = v.strip().lstrip(".").lower()
                if host == d or host.endswith("." + d):  # ignore cookies for foreign domains
                    domain, host_only = d, False
            elif k == "path" and v:
                path = v.strip()
            elif k == "max-age" and v.strip().lstrip("-").isdigit() and int(v) <= 0:
                expired = True
        self.cookies = [c for c in self.cookies if not (c.name == name and c.domain == domain and c.path == path)]
        if not expired:
            self.cookies.append(_Cookie(domain, host_only, path, name.strip(), value.strip()))


class _RateLimiter:
    def __init__(self, rps: float):
        self.interval = 1.0 / rps if rps > 0 else 0.0
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        if not self.interval:
            return
        async with self._lock:
            now = time.monotonic()
            delay = self._next - now
            self._next = max(now, self._next) + self.interval
        if delay > 0:
            await asyncio.sleep(delay)


class ScopedHttpClient:
    def __init__(self, guard: ScopeGuard, *, rps: float = 10, concurrency: int = 5, max_requests: int = 5000,
                 timeout: float = 15.0, verify: bool = False, max_body: int = 2_000_000,
                 allowed_methods: set[str] | None = None, stop_failure_ratio: float = 0.8,
                 trace_path: Path | None = None, cancel_event: asyncio.Event | None = None,
                 proxy: str | None = None, gateway_token: str | None = None):
        self.guard = guard
        self.proxy = proxy
        self.gateway_token = gateway_token  # replies forged by Vigía's own egress gateway carry this token
        self.max_requests = max_requests
        self.max_body = max_body
        self.allowed_methods = (allowed_methods or {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"}) - FORBIDDEN_METHODS
        self.stop_failure_ratio = stop_failure_ratio
        self.trace_path = trace_path
        self.cancel_event = cancel_event
        self.requests_made = 0
        self._hard_timeout = timeout * 2 + 5  # absolute ceiling per phase (send / body), independent of httpx
        self.stopped_reason: str | None = None
        self.identities: dict[str, Identity] = {"default": Identity("default")}
        self._window: deque[bool] = deque(maxlen=50)
        self._consecutive_conn_errors = 0
        self._sem = asyncio.Semaphore(max(1, concurrency))
        self._rl = _RateLimiter(rps)
        self._trace_lock = threading.Lock()
        self._client = httpx.AsyncClient(
            verify=verify, timeout=httpx.Timeout(timeout, connect=min(timeout, 10.0)), follow_redirects=False,
            trust_env=False,  # never pick up HTTP(S)_PROXY / netrc from the worker environment
            # Egress policy: the proxy is passed explicitly (never from the environment). When set, httpx routes
            # every request through it and raises on failure — there is no silent fallback to a direct connection.
            proxy=proxy,
            limits=httpx.Limits(max_connections=max(2, concurrency * 2), max_keepalive_connections=concurrency),
            headers={"User-Agent": USER_AGENT, "Accept-Encoding": "gzip, deflate"},
        )

    async def __aenter__(self) -> "ScopedHttpClient":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    def identity(self, name: str) -> Identity:
        return self.identities.setdefault(name, Identity(name))

    def _trace(self, rec: dict[str, Any]) -> None:
        if not self.trace_path:
            return
        with self._trace_lock, open(self.trace_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def _check_stop(self) -> None:
        if self.cancel_event is not None and self.cancel_event.is_set():
            self.stopped_reason = self.stopped_reason or "cancelado"
        if self.stopped_reason:
            raise StopScan(self.stopped_reason)

    def _record_outcome(self, failure: bool, conn_error: bool) -> None:
        self._window.append(failure)
        self._consecutive_conn_errors = self._consecutive_conn_errors + 1 if conn_error else 0
        if self._consecutive_conn_errors >= 15:
            self.stopped_reason = "el objetivo dejó de responder (15 errores de conexión consecutivos)"
        elif len(self._window) >= 40 and sum(self._window) / len(self._window) >= self.stop_failure_ratio:
            self.stopped_reason = (f"degradación del servicio: {sum(self._window)}/{len(self._window)} "
                                   "respuestas recientes son 5xx/timeout; se detiene para no afectar al objetivo")

    async def request(self, method: str, url: str, *, headers: dict[str, str] | None = None,
                      params: dict[str, Any] | None = None, data: Any = None, json_body: Any = None,
                      content: bytes | str | None = None, identity: str = "default", follow_redirects: bool = True,
                      max_redirects: int = 5, module: str = "") -> HttpResponse:
        method = method.upper()
        if method not in self.allowed_methods:
            raise ScopeViolation(f"Método {method} no permitido por la política de pruebas")
        ident = self.identity(identity)
        redirects: list[str] = []
        current = url
        cur_method = method
        start = time.monotonic()
        while True:
            self._check_stop()
            if self.requests_made >= self.max_requests:
                raise BudgetExceeded(f"Presupuesto de {self.max_requests} peticiones agotado")
            checked = await self.guard.check_url(current)  # raises ScopeViolation
            parts = urlsplit(current)
            ip = checked.pinned_ip
            ip_host = f"[{ip}]" if ip.version == 6 else str(ip)
            target = urlunsplit((parts.scheme, f"{ip_host}:{checked.port}", parts.path or "/", parts.query, ""))
            default_port = 443 if parts.scheme == "https" else 80
            host_disp = f"[{checked.host}]" if ":" in checked.host else checked.host
            host_header = host_disp if checked.port == default_port else f"{host_disp}:{checked.port}"
            hdrs: dict[str, str] = {"Host": host_header}
            hdrs.update(ident.headers)
            cookie = ident.cookie_header(checked.host, parts.path or "/")
            if cookie:
                hdrs["Cookie"] = cookie
            if headers:
                hdrs.update(headers)
            ext = {"sni_hostname": checked.host} if parts.scheme == "https" and str(ip) != checked.host else {}
            if self.proxy:
                # Through Vigía's gateway: hand it the *name*. The gateway resolves it with this same guard (same pinned
                # IP, anti-rebinding intact) and TLS carries the right SNI — httpx drops sni_hostname inside a tunnel.
                target = urlunsplit((parts.scheme, f"{host_disp}:{checked.port}", parts.path or "/", parts.query, ""))
                ext = {}
            req = self._client.build_request(cur_method, target, headers=hdrs, params=params if not redirects else None,
                                             data=data if not redirects else None,
                                             json=json_body if not redirects else None,
                                             content=content if not redirects else None, extensions=ext)
            await self._rl.wait()
            self.requests_made += 1
            t0 = time.monotonic()
            async with self._sem:
                self._check_stop()
                try:
                    resp = await asyncio.wait_for(self._client.send(req, stream=True), self._hard_timeout)
                except (httpx.TimeoutException, httpx.NetworkError, httpx.ProtocolError, httpx.ProxyError,
                        asyncio.TimeoutError) as e:
                    conn = isinstance(e, (httpx.ConnectError, httpx.ConnectTimeout, httpx.ProxyError))
                    if self.proxy and (isinstance(e, httpx.ConnectError) or "Egress Down" in str(e)):
                        # With an egress every TCP connection goes to the proxy/gateway: failing to reach it means the
                        # egress is down. Stop the scan — never retry directly.
                        self.stopped_reason = self.stopped_reason or (
                            "la salida configurada (proxy/túnel) dejó de responder; el análisis se detiene sin "
                            "conexión directa de reserva")
                        self._trace({"ts": time.time(), "module": module, "id": identity, "method": cur_method,
                                     "url": current, "error": "egress-down"})
                        raise StopScan(self.stopped_reason) from e
                    if isinstance(e, httpx.ProxyError) and "Forbidden" in str(e):
                        raise ScopeViolation(f"la pasarela de salida bloqueó {current}") from e
                    self._record_outcome(True, conn)
                    self._trace({"ts": time.time(), "module": module, "id": identity, "method": cur_method,
                                 "url": current, "error": type(e).__name__})
                    raise HttpError(f"{type(e).__name__} en {cur_method} {current}") from e
                buf = bytearray()
                truncated = False

                async def _read() -> None:
                    nonlocal truncated
                    async for chunk in resp.aiter_bytes():
                        buf.extend(chunk)
                        if len(buf) > self.max_body:
                            truncated = True
                            del buf[self.max_body:]
                            break
                try:
                    await asyncio.wait_for(_read(), self._hard_timeout)
                except (httpx.HTTPError, ValueError, asyncio.TimeoutError):
                    truncated = True
                finally:
                    await resp.aclose()
            elapsed = time.monotonic() - t0
            gw = resp.headers.get("x-vigia-gateway", "")
            if self.gateway_token and gw.startswith(self.gateway_token + " "):  # reply from the gateway, not the target
                why = gw.split(" ", 1)[1]
                if why == "Egress Down":
                    self.stopped_reason = self.stopped_reason or (
                        "la salida configurada (proxy/túnel) dejó de responder; el análisis se detiene sin conexión "
                        "directa de reserva")
                    raise StopScan(self.stopped_reason)
                if why == "Forbidden":
                    raise ScopeViolation(f"la pasarela de salida bloqueó {current}")
                self._record_outcome(True, True)
                self._trace({"ts": time.time(), "module": module, "id": identity, "method": cur_method,
                             "url": current, "error": f"gateway:{why}"})
                raise HttpError(f"{why} en {cur_method} {current} (a través de la salida)")
            self._record_outcome(resp.status_code >= 500, False)
            for sc in resp.headers.get_list("set-cookie"):
                ident.store(checked.host, sc)
            self._trace({"ts": time.time(), "module": module, "id": identity, "method": cur_method, "url": current,
                         "status": resp.status_code, "ms": int(elapsed * 1000), "size": len(buf),
                         "egress": "egress" if self.proxy else "direct"})
            if follow_redirects and resp.status_code in (301, 302, 303, 307, 308) and "location" in resp.headers:
                if len(redirects) >= max_redirects:
                    raise HttpError(f"Demasiadas redirecciones desde {url}")
                nxt = urljoin(current, resp.headers["location"])
                downgrade = current.startswith("https://") and nxt.startswith("http://")
                try:
                    await self.guard.check_url(nxt)
                    if downgrade and (ident.headers or ident.cookies):
                        raise ScopeViolation("redirección HTTPS→HTTP con credenciales de prueba: no se sigue")
                except ScopeViolation:
                    # Off-scope redirect: return the 3xx itself, never follow.
                    return HttpResponse(cur_method, current, resp.status_code, resp.headers, bytes(buf), truncated,
                                        time.monotonic() - start, redirects, hdrs, _body_bytes(req))
                redirects.append(current)
                current = nxt
                if resp.status_code in (301, 302, 303) and cur_method not in ("GET", "HEAD"):
                    cur_method = "GET"
                continue
            return HttpResponse(cur_method, current, resp.status_code, resp.headers, bytes(buf), truncated,
                                elapsed, redirects, hdrs, _body_bytes(req))

    async def get(self, url: str, **kw: Any) -> HttpResponse:
        return await self.request("GET", url, **kw)


def _body_bytes(req: httpx.Request) -> bytes | None:
    try:
        return req.content[:4096] if req.content else None
    except httpx.RequestNotRead:
        return None
