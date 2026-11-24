"""Authentication, users, audit log, engines, profiles and dashboard."""
from __future__ import annotations

from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vigia.api.deps import (CSRF_COOKIE, SESSION_COOKIE, Principal, accessible_project_ids, client_ip, current_principal,
                            db_session, require_admin)
from vigia.api.schemas import LoginIn, PasswordChangeIn, UserCreateIn, UserUpdateIn
from vigia.core.profiles import PROFILES
from vigia.db import AuditLog, Finding, Project, Scan, User, utcnow
from vigia.security import audit
from vigia.security.auth import AuthError, hash_password, issue_token, login, new_csrf_token, password_problems, revoke

router = APIRouter(prefix="/api")


def _user_out(u: User) -> dict:
    return {"id": u.id, "username": u.username, "role": u.role, "is_active": u.is_active,
            "created_at": u.created_at.isoformat() if u.created_at else None}


def _secure(request: Request) -> bool:
    return request.url.scheme == "https"


@router.post("/auth/login")
def do_login(body: LoginIn, request: Request, response: Response, db: Session = Depends(db_session)) -> dict:
    ip = client_ip(request)
    try:
        user = login(db, body.username, body.password)
    except AuthError as e:
        audit.record("auth.login_failed", username=body.username[:64], ip=ip, severity="warn", details={"reason": str(e)})
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(e)) from e
    tok = issue_token(user)
    csrf = new_csrf_token()
    max_age = int((tok.expires_at - utcnow()).total_seconds())
    response.set_cookie(SESSION_COOKIE, tok.token, httponly=True, secure=_secure(request), samesite="strict", path="/",
                        max_age=max_age)
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=_secure(request), samesite="strict", path="/",
                        max_age=max_age)
    audit.record("auth.login", user_id=user.id, username=user.username, ip=ip)
    return {"user": _user_out(user), "csrf_token": csrf, "expires_at": tok.expires_at.isoformat() + "Z"}


@router.post("/auth/token")
def api_token(body: LoginIn, request: Request, db: Session = Depends(db_session)) -> dict:
    """Bearer token for CLI/CI (no cookies, no CSRF)."""
    try:
        user = login(db, body.username, body.password)
    except AuthError as e:
        audit.record("auth.token_failed", username=body.username[:64], ip=client_ip(request), severity="warn")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(e)) from e
    tok = issue_token(user)
    audit.record("auth.token", user_id=user.id, username=user.username, ip=client_ip(request))
    return {"access_token": tok.token, "token_type": "bearer", "expires_at": tok.expires_at.isoformat() + "Z"}


@router.post("/auth/logout")
def do_logout(request: Request, response: Response, p: Principal = Depends(current_principal),
              db: Session = Depends(db_session)) -> dict:
    revoke(db, p.claims)
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    audit.record("auth.logout", user_id=p.user.id, username=p.user.username, ip=client_ip(request))
    return {"ok": True}


@router.get("/auth/me")
def me(p: Principal = Depends(current_principal)) -> dict:
    return {"user": _user_out(p.user), "expires_at": p.claims.get("exp")}


@router.post("/auth/password")
def change_password(body: PasswordChangeIn, request: Request, response: Response,
                    p: Principal = Depends(current_principal), db: Session = Depends(db_session)) -> dict:
    from vigia.security.auth import verify_password
    user = db.get(User, p.user.id)
    if not verify_password(user.password_hash, body.current_password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "La contraseña actual no es correcta")
    probs = password_problems(body.new_password, user.username)
    if probs:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Contraseña débil: " + "; ".join(probs))
    user.password_hash = hash_password(body.new_password)
    user.token_version += 1  # invalidates every existing session
    db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")
    audit.record("auth.password_changed", user_id=user.id, username=user.username, ip=client_ip(request))
    return {"ok": True, "relogin": True}


# ------------------------------------------------------------------ users (admin)
@router.get("/users")
def list_users(p: Principal = Depends(require_admin), db: Session = Depends(db_session)) -> list[dict]:
    return [_user_out(u) for u in db.scalars(select(User).order_by(User.username))]


@router.post("/users", status_code=201)
def create_user(body: UserCreateIn, request: Request, p: Principal = Depends(require_admin),
                db: Session = Depends(db_session)) -> dict:
    if db.scalar(select(User).where(User.username == body.username)):
        raise HTTPException(status.HTTP_409_CONFLICT, "El usuario ya existe")
    probs = password_problems(body.password, body.username)
    if probs:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Contraseña débil: " + "; ".join(probs))
    u = User(username=body.username, password_hash=hash_password(body.password), role=body.role)
    db.add(u)
    db.commit()
    audit.record("user.created", user_id=p.user.id, username=p.user.username, target=f"user:{u.id}",
                 details={"username": u.username, "role": u.role}, ip=client_ip(request), severity="warn")
    return _user_out(u)


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: UserUpdateIn, request: Request, p: Principal = Depends(require_admin),
                db: Session = Depends(db_session)) -> dict:
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(404, "Usuario no encontrado")
    changes = body.model_dump(exclude_none=True)
    if u.id == p.user.id and (changes.get("role", "admin") != "admin" or changes.get("is_active") is False):
        raise HTTPException(400, "No puedes retirarte el rol de administrador ni desactivarte a ti mismo")
    if "password" in changes:
        probs = password_problems(changes["password"], u.username)
        if probs:
            raise HTTPException(400, "Contraseña débil: " + "; ".join(probs))
        u.password_hash = hash_password(changes.pop("password"))
        u.token_version += 1
    for k, v in changes.items():
        setattr(u, k, v)
    if "role" in changes or changes.get("is_active") is False:
        u.token_version += 1  # privilege change: force re-authentication
    db.commit()
    audit.record("user.updated", user_id=p.user.id, username=p.user.username, target=f"user:{u.id}",
                 details={k: v for k, v in body.model_dump(exclude_none=True).items() if k != "password"} |
                 ({"password_reset": True} if body.password else {}), ip=client_ip(request), severity="warn")
    return _user_out(u)


# ------------------------------------------------------------------ audit / engines / profiles
@router.get("/audit")
def audit_log(limit: int = 200, before: int | None = None, p: Principal = Depends(require_admin),
              db: Session = Depends(db_session)) -> list[dict]:
    q = select(AuditLog).order_by(AuditLog.id.desc()).limit(max(1, min(limit, 1000)))
    if before:
        q = q.where(AuditLog.id < before)
    return [{"id": a.id, "ts": a.ts.isoformat(), "username": a.username, "action": a.action, "target": a.target,
             "details": a.details, "ip": a.ip, "severity": a.severity} for a in db.scalars(q)]


@router.get("/audit/verify")
def audit_verify(p: Principal = Depends(require_admin), db: Session = Depends(db_session)) -> dict:
    return audit.verify_chain(db)


@router.get("/engines")
def engines(refresh: bool = False, p: Principal = Depends(current_principal)) -> list[dict]:
    from vigia.tools.registry import get_registry
    out = []
    for st in get_registry().all(refresh=refresh and p.is_admin):
        d = st.to_dict()
        d.pop("argv_prefix", None)
        if not p.is_admin:
            d.pop("path", None)
        out.append(d)
    return out


@router.get("/profiles")
def profiles(p: Principal = Depends(current_principal)) -> list[dict]:
    return [pr.to_dict() for pr in PROFILES.values()]


@router.get("/privacy")
def privacy(check_egress_ip: bool = False, p: Principal = Depends(current_principal)) -> dict:
    """Real isolation/privacy status. The egress-IP probe (admin only) contacts a configured echo endpoint."""
    from vigia.security.privacy import privacy_status
    st = privacy_status(check_egress_ip=check_egress_ip and p.is_admin)
    if not p.is_admin and isinstance(st.get("tunnel"), dict):
        # local file paths (they include the Windows account name) are only for whoever administers the egress
        st["tunnel"] = {k: v for k, v in st["tunnel"].items() if k not in ("known_hosts",)}
    return st


@router.post("/privacy/check")
def privacy_check(request: Request, p: Principal = Depends(current_principal)) -> dict:
    """Admin: verify isolation, the egress (opening the SSH tunnel if configured) and remote DNS now."""
    if not p.is_admin:
        raise HTTPException(403, "Solo un administrador puede lanzar la verificación")
    from vigia.security.privacy import run_check
    res = run_check()
    audit.record("privacy.check", user_id=p.user.id, username=p.user.username, details={"ok": res.get("ok")},
                 ip=client_ip(request))
    return res


@router.get("/privacy/checks")
def privacy_checks(p: Principal = Depends(current_principal)) -> list[dict]:
    from vigia.security.privacy import check_history
    return check_history()


@router.get("/settings/privacy")
def privacy_settings(p: Principal = Depends(current_principal)) -> dict:
    if not p.is_admin:
        raise HTTPException(403, "Solo un administrador puede ver esta configuración")
    from vigia.security.runtime_settings import describe
    from vigia.security.sshtunnel import ssh_binary
    return {"settings": describe(), "ssh_client": str(ssh_binary() or "")}


@router.patch("/settings/privacy")
def update_privacy_settings(body: dict, request: Request, p: Principal = Depends(current_principal)) -> dict:
    if not p.is_admin:
        raise HTTPException(403, "Solo un administrador puede cambiar esta configuración")
    from vigia.security.runtime_settings import SettingsError, describe, save
    if not isinstance(body, dict) or len(body) > 20:
        raise HTTPException(422, "Cuerpo no válido")
    try:
        save(body)
    except SettingsError as e:
        raise HTTPException(422, str(e)) from e
    audit.record("settings.privacy_changed", user_id=p.user.id, username=p.user.username,
                 details={"keys": sorted(body)}, ip=client_ip(request))
    return {"settings": describe()}


@router.get("/dashboard")
def dashboard(p: Principal = Depends(current_principal), db: Session = Depends(db_session)) -> dict:
    ids = accessible_project_ids(db, p)
    pq = select(Project)
    sq = select(Scan)
    if ids is not None:
        pq = pq.where(Project.id.in_(ids or [-1]))
        sq = sq.where(Scan.project_id.in_(ids or [-1]))
    projects = db.scalars(pq).all()
    scans = db.scalars(sq.order_by(Scan.id.desc()).limit(500)).all()
    latest: dict[int, Scan] = {}
    for s in scans:
        if s.status in ("completed", "stopped") and s.project_id not in latest:
            latest[s.project_id] = s
    sev = defaultdict(int)
    open_by_project = {}
    for pid, s in latest.items():
        rows = db.execute(select(Finding.severity, func.count()).where(
            Finding.scan_id == s.id, Finding.remediation_status.notin_(("fixed", "false_positive", "accepted_risk")))
            .group_by(Finding.severity)).all()
        open_by_project[pid] = {k: v for k, v in rows}
        for k, v in rows:
            sev[k] += v
    # the concrete open problems to act on first (latest completed scan of each project), in plain language
    from vigia.correlation.plain import plain_for
    sev_rank = {"critical": 0, "high": 1, "medium": 2}
    top_rows = db.scalars(select(Finding).where(
        Finding.scan_id.in_([s.id for s in latest.values()] or [-1]), Finding.severity.in_(tuple(sev_rank)),
        Finding.remediation_status.in_(("open", "in_progress"))).limit(400)).all()
    top_rows = sorted(top_rows, key=lambda f: (sev_rank[f.severity], -f.priority))[:8]
    fixed = db.scalar(select(func.count()).select_from(Finding).where(
        Finding.scan_id.in_([s.id for s in latest.values()] or [-1]), Finding.remediation_status == "fixed")) or 0
    trend = [{"scan_id": s.id, "project_id": s.project_id, "date": (s.finished_at or s.created_at).isoformat(),
              "risk": (s.summary or {}).get("risk_score"), "findings": (s.summary or {}).get("findings")}
             for s in sorted(scans, key=lambda s: s.id) if s.status in ("completed", "stopped")][-60:]
    names = {pr.id: pr.name for pr in projects}
    return {"projects": len(projects), "scans": len(scans), "running": sum(1 for s in scans if s.status == "running"),
            "open_by_severity": {k: sev.get(k, 0) for k in ("critical", "high", "medium", "low", "info")},
            "per_project": [{"project_id": pid, "name": names.get(pid, "?"), "last_scan": latest[pid].id,
                             "risk": (latest[pid].summary or {}).get("risk_score"), "open": open_by_project.get(pid, {})}
                            for pid in latest],
            "recent": [{"id": s.id, "project_id": s.project_id, "project": names.get(s.project_id, "?"), "profile": s.profile,
                        "status": s.status, "created_at": s.created_at.isoformat(),
                        "findings": (s.summary or {}).get("findings"), "risk": (s.summary or {}).get("risk_score")}
                       for s in scans[:12]],
            "trend": trend, "fixed": fixed,
            "top_open": [{"id": f.id, "scan_id": f.scan_id, "project_id": f.project_id,
                          "project": names.get(f.project_id, "?"), "severity": f.severity,
                          "title": plain_for(f.category)["title"], "where": f.endpoint or f.file or f.asset,
                          "status": f.remediation_status} for f in top_rows]}
