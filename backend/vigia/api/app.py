"""FastAPI application factory."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from vigia import __version__
from vigia.api import routes_auth, routes_projects, routes_scans
from vigia.api.security import BodyLimit, RateLimit, SecurityHeaders
from vigia.config import get_settings
from vigia.db import init_db

log = logging.getLogger("vigia.api")


def create_app(start_worker: bool | None = None) -> FastAPI:
    s = get_settings()
    worker_holder: dict = {}

    @asynccontextmanager
    async def lifespan(app: FastAPI):  # noqa: ANN202
        init_db()
        if start_worker if start_worker is not None else s.embedded_worker:
            from vigia.core.worker import Worker
            w = Worker()
            w.start_background()
            worker_holder["w"] = w
        yield
        if "w" in worker_holder:
            worker_holder["w"].stop()

    app = FastAPI(title="Vigía API", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None,
                  openapi_url=None)
    app.add_middleware(RateLimit)
    app.add_middleware(SecurityHeaders)
    if s.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=s.cors_origins, allow_credentials=True,
                           allow_methods=["GET", "POST", "PATCH", "DELETE"],
                           allow_headers=["Content-Type", "X-CSRF-Token", "Authorization"], max_age=600)
    app.add_middleware(BodyLimit)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [{"field": ".".join(str(x) for x in e.get("loc", [])[1:]), "msg": e.get("msg", "")[:200]}
                  for e in exc.errors()][:20]
        return JSONResponse({"detail": "Datos de entrada inválidos", "errors": errors}, 422)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse({"detail": exc.detail}, exc.status_code, headers=getattr(exc, "headers", None))

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        rid = getattr(request.state, "request_id", "?")
        log.exception("Error no controlado (request_id=%s)", rid)
        return JSONResponse({"detail": "Error interno", "request_id": rid}, 500)

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok"}

    app.include_router(routes_auth.router)
    app.include_router(routes_projects.router)
    app.include_router(routes_scans.router)

    dist = s.home / "frontend" / "dist"
    if s.serve_frontend and (dist / "index.html").exists():
        index = dist / "index.html"

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str) -> FileResponse:
            if path.startswith("api/"):
                raise HTTPException(404, "No encontrado")
            target = (dist / path).resolve()
            if path and target.is_file() and dist.resolve() in target.parents:
                return FileResponse(target, headers={"Cache-Control": "public, max-age=31536000, immutable"}
                                    if "/assets/" in target.as_posix() else {"Cache-Control": "no-store"})
            return FileResponse(index, headers={"Cache-Control": "no-store"})
    return app

