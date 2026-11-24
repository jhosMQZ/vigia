"""API dependencies: authentication (cookie or bearer), CSRF, RBAC and per-project access control."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from fastapi import Depends, HTTPException, Request, WebSocket, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from vigia.config import get_settings
from vigia.db import Project, ProjectMember, SessionLocal, User
from vigia.security import audit
from vigia.security.auth import AuthError, authenticate_token, csrf_matches

SESSION_COOKIE = "vigia_session"
CSRF_COOKIE = "vigia_csrf"
CSRF_HEADER = "x-csrf-token"
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}
WRITE_ROLES = {"owner", "analyst"}


def db_session() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def client_ip(request: Request | WebSocket) -> str:
    return request.client.host if request.client else ""


@dataclass
class Principal:
    user: User
    claims: dict
    via: str  # cookie | bearer

    @property
    def is_admin(self) -> bool:
        return self.user.role == "admin"


def _token_from(request: Request | WebSocket) -> tuple[str | None, str]:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip(), "bearer"
    return request.cookies.get(SESSION_COOKIE), "cookie"


def current_principal(request: Request, db: Session = Depends(db_session)) -> Principal:
    token, via = _token_from(request)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "No autenticado")
    try:
        user, claims = authenticate_token(db, token)
    except AuthError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(e)) from e
    if via == "cookie" and request.method in UNSAFE:
        if not csrf_matches(request.headers.get(CSRF_HEADER), request.cookies.get(CSRF_COOKIE)):
            audit.record("security.csrf_rejected", user_id=user.id, username=user.username, ip=client_ip(request),
                         target=request.url.path, severity="warn")
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Token CSRF ausente o inválido")
    request.state.user = user
    return Principal(user, claims, via)


def require_role(*roles: str):  # noqa: ANN201
    def dep(p: Principal = Depends(current_principal)) -> Principal:
        if p.user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Permisos insuficientes")
        return p
    return dep


require_admin = require_role("admin")
require_writer = require_role("admin", "analyst")


def project_role(db: Session, p: Principal, project_id: int) -> str | None:
    if p.is_admin:
        return "owner"
    m = db.scalar(select(ProjectMember).where(ProjectMember.project_id == project_id, ProjectMember.user_id == p.user.id))
    return m.role if m else None


def get_project(db: Session, p: Principal, project_id: int, *, write: bool = False, owner: bool = False) -> Project:
    """Fetch a project the principal may access; 404 when it does not exist *or* is not accessible."""
    proj = db.get(Project, project_id)
    role = project_role(db, p, project_id) if proj else None
    if proj is None or role is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Proyecto no encontrado")
    if owner and role != "owner":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Solo el propietario del proyecto puede hacer esto")
    if write and (role not in WRITE_ROLES or p.user.role == "viewer"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Acceso de solo lectura a este proyecto")
    return proj


def accessible_project_ids(db: Session, p: Principal) -> list[int] | None:
    """None means 'all' (admin)."""
    if p.is_admin:
        return None
    return list(db.scalars(select(ProjectMember.project_id).where(ProjectMember.user_id == p.user.id)))


def ws_principal(ws: WebSocket, db: Session) -> Principal | None:
    s = get_settings()
    origin = ws.headers.get("origin")
    host = ws.headers.get("host", "")
    allowed = set(s.cors_origins) | {f"http://{host}", f"https://{host}"}
    if origin is None or origin not in allowed:  # cross-site WebSocket hijacking protection
        return None
    token, via = _token_from(ws)
    if not token:
        return None
    try:
        user, claims = authenticate_token(db, token)
    except AuthError:
        return None
    return Principal(user, claims, via)
