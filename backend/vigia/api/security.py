"""Cross-cutting HTTP protections: security headers, body-size limits, rate limiting, request IDs, safe errors."""
from __future__ import annotations

import threading
import time
import uuid
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from vigia.config import get_settings
from vigia.security import audit

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
       "connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'")


class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:  # noqa: ANN001
        rid = uuid.uuid4().hex[:12]
        request.state.request_id = rid
        response = await call_next(request)
        h = response.headers
        h.setdefault("X-Request-ID", rid)
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "no-referrer"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        h["Cross-Origin-Resource-Policy"] = "same-origin"
        if "content-security-policy" not in h:
            h["Content-Security-Policy"] = CSP
        if request.url.path.startswith("/api"):
            h["Cache-Control"] = "no-store"
        if request.url.scheme == "https":
            h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if "server" in h:
            del h["server"]
        return response


class BodyLimit:
    """Rejects bodies above the limit while streaming (does not trust Content-Length alone)."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        s = get_settings()
        path = scope.get("path", "")
        limit = s.max_upload_mb * 1024 * 1024 if path.endswith(("/upload", "/spec")) else s.max_json_body_kb * 1024
        cl = dict(scope.get("headers") or []).get(b"content-length")
        if cl and cl.isdigit() and int(cl) > limit:
            await JSONResponse({"detail": "Cuerpo de la petición demasiado grande"}, 413)(scope, receive, send)
            return
        received = 0

        async def limited() -> Message:
            nonlocal received
            msg = await receive()
            if msg["type"] == "http.request":
                received += len(msg.get("body", b""))
                if received > limit:
                    raise _TooLarge()
            return msg

        try:
            await self.app(scope, limited, send)
        except _TooLarge:
            await JSONResponse({"detail": "Cuerpo de la petición demasiado grande"}, 413)(scope, receive, send)


class _TooLarge(Exception):
    pass


class RateLimiter:
    """Sliding-window limiter per key (in-process; put a shared limiter in front for multi-node deployments)."""

    def __init__(self) -> None:
        self.hits: dict[str, deque[float]] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str, limit: int, window: float = 60.0) -> bool:
        now = time.monotonic()
        with self.lock:
            q = self.hits[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            if len(self.hits) > 50000:  # bound memory
                for k in list(self.hits)[:10000]:
                    if not self.hits[k]:
                        del self.hits[k]
            return True


limiter = RateLimiter()


class RateLimit(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:  # noqa: ANN001
        s = get_settings()
        ip = request.client.host if request.client else "?"
        path = request.url.path
        if path.startswith("/api/auth/login") or path.startswith("/api/auth/token"):
            if not limiter.allow(f"login:{ip}", s.login_rate_limit_per_minute):
                if limiter.allow(f"audit-rl:{ip}", 1):
                    audit.record("security.rate_limited", ip=ip, target=path, severity="warn",
                                 details={"nota": "se registra una vez por minuto e IP"})
                return JSONResponse({"detail": "Demasiados intentos; espera un minuto"}, 429, headers={"Retry-After": "60"})
        elif path.startswith("/api") and not limiter.allow(f"api:{ip}", s.api_rate_limit_per_minute):
            return JSONResponse({"detail": "Límite de peticiones excedido"}, 429, headers={"Retry-After": "60"})
        response = await call_next(request)
        if path.startswith("/api"):  # advertise the policy (IETF RateLimit header fields)
            limit = s.login_rate_limit_per_minute if path.startswith("/api/auth/") else s.api_rate_limit_per_minute
            response.headers["RateLimit-Policy"] = f"{limit};w=60"
        return response
