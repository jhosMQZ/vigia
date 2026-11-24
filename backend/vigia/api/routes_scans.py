"""Scans, live console (WebSocket), findings, attack chains, history comparison and reports."""
from __future__ import annotations

import asyncio
import re

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from vigia.api.deps import Principal, client_ip, current_principal, db_session, get_project, ws_principal
from vigia.api.schemas import FindingUpdateIn, ScanIn
from vigia.config import get_settings
from vigia.core.orchestrator import _authorization_problem
from vigia.core.profiles import PROFILES, effective_config
from vigia.correlation.plain import plain_for
from vigia.db import AttackChain, Credential, Finding, Scan, ScanEvent, Scope, SessionLocal, SourceArtifact, ToolRun
from vigia.reports.generate import REPORT_FILES, generate_all, report_dir
from vigia.security import audit

router = APIRouter(prefix="/api")
_WS_OPEN: dict[int, int] = {}
_WS_LOCK = __import__("threading").Lock()
SORTS = {"priority": Finding.priority.desc(), "cvss": Finding.cvss_score.desc().nullslast(), "id": Finding.id.asc(),
         "severity": Finding.priority.desc()}


def _scan_out(s: Scan) -> dict:
    return {"id": s.id, "project_id": s.project_id, "scope_id": s.scope_id, "source_id": s.source_id, "profile": s.profile,
            "profile_name": PROFILES[s.profile].name if s.profile in PROFILES else s.profile, "status": s.status,
            "config": s.config, "progress": s.progress, "summary": s.summary, "stats": s.stats, "error": s.error,
            "cancel_requested": s.cancel_requested, "created_at": s.created_at.isoformat(),
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "finished_at": s.finished_at.isoformat() if s.finished_at else None}


def _scan(db: Session, p: Principal, scan_id: int, write: bool = False) -> Scan:
    s = db.get(Scan, scan_id)
    if s is None:
        raise HTTPException(404, "Escaneo no encontrado")
    get_project(db, p, s.project_id, write=write)
    return s


@router.post("/projects/{project_id}/scans", status_code=201)
def create_scan(project_id: int, body: ScanIn, request: Request, p: Principal = Depends(current_principal),
                db: Session = Depends(db_session)) -> dict:
    get_project(db, p, project_id, write=True)
    prof = PROFILES[body.profile]
    scope = None
    if body.scope_id is not None:
        scope = db.get(Scope, body.scope_id)
        if scope is None or scope.project_id != project_id:
            raise HTTPException(404, "Alcance no encontrado en este proyecto")
        problem = _authorization_problem(scope)
        if problem:
            raise HTTPException(409, f"{problem}. Registra la autorización antes de lanzar análisis activos.")
    if body.source_id is not None:
        src = db.get(SourceArtifact, body.source_id)
        if src is None or src.project_id != project_id or src.kind not in ("zip", "git", "path"):
            raise HTTPException(404, "Código fuente no encontrado en este proyecto")
    if prof.needs_target and not prof.needs_source and scope is None:
        raise HTTPException(400, f"El perfil {prof.name} requiere un alcance autorizado")
    if prof.needs_source and not prof.needs_target and body.source_id is None:
        raise HTTPException(400, f"El perfil {prof.name} requiere código fuente importado")
    if prof.key == "full" and (scope is None and body.source_id is None):
        raise HTTPException(400, "Full Security Assessment necesita un alcance y/o código fuente")
    for cid in body.config.credential_ids:
        c = db.get(Credential, cid)
        if c is None or c.project_id != project_id:
            raise HTTPException(404, f"Credencial {cid} no encontrada en este proyecto")
    for sid in body.config.spec_source_ids:
        sp = db.get(SourceArtifact, sid)
        if sp is None or sp.project_id != project_id or sp.kind not in ("openapi", "postman"):
            raise HTTPException(404, f"Especificación {sid} no encontrada en este proyecto")
    if body.config.openapi_url and scope is not None:
        from urllib.parse import urlsplit

        from vigia.security.scope import ScopeGuard
        g = ScopeGuard.build(scope.targets, scope.exclusions)
        if not g.host_matches(urlsplit(body.config.openapi_url).hostname or ""):
            raise HTTPException(400, "openapi_url debe pertenecer al alcance")
    running = db.scalar(select(func.count()).select_from(Scan).where(Scan.project_id == project_id,
                                                                     Scan.status.in_(("queued", "running"))))
    if running and running >= 3:
        raise HTTPException(429, "Este proyecto ya tiene 3 escaneos en cola o en ejecución")
    effective_config(body.profile, body.config)  # validates the combination
    scan = Scan(project_id=project_id, scope_id=body.scope_id, source_id=body.source_id, profile=body.profile,
                config=body.config.model_dump(), created_by=p.user.id)
    db.add(scan)
    db.commit()
    audit.record("scan.created", user_id=p.user.id, username=p.user.username, target=f"scan:{scan.id}",
                 details={"project": project_id, "profile": body.profile, "scope": body.scope_id, "source": body.source_id,
                          "targets": scope.targets if scope else None, "intensity": body.config.intensity},
                 ip=client_ip(request))
    return _scan_out(scan)


@router.get("/projects/{project_id}/scans")
def list_scans(project_id: int, p: Principal = Depends(current_principal), db: Session = Depends(db_session)) -> list:
    get_project(db, p, project_id)
    return [_scan_out(s) for s in db.scalars(select(Scan).where(Scan.project_id == project_id).order_by(Scan.id.desc())
                                             .limit(200))]


@router.get("/scans/{scan_id}")
def get_scan(scan_id: int, p: Principal = Depends(current_principal), db: Session = Depends(db_session)) -> dict:
    return _scan_out(_scan(db, p, scan_id))


@router.post("/scans/{scan_id}/cancel")
def cancel_scan(scan_id: int, request: Request, p: Principal = Depends(current_principal),
                db: Session = Depends(db_session)) -> dict:
    s = _scan(db, p, scan_id, write=True)
    if s.status == "queued":
        s.status, s.error = "cancelled", "Cancelado antes de empezar"
    elif s.status == "running":
        s.cancel_requested = True
    else:
        raise HTTPException(409, f"El escaneo está en estado {s.status}")
    db.commit()
    audit.record("scan.cancel", user_id=p.user.id, username=p.user.username, target=f"scan:{scan_id}",
                 ip=client_ip(request))
    return _scan_out(s)


@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: int, request: Request, p: Principal = Depends(current_principal),
                db: Session = Depends(db_session)) -> dict:
    from vigia.security.extract import force_rmtree
    s = _scan(db, p, scan_id, write=True)
    if s.status in ("queued", "running"):
        raise HTTPException(409, "Cancela el escaneo antes de eliminarlo")
    cfg = get_settings()
    force_rmtree(report_dir(scan_id))
    force_rmtree(cfg.data_dir / "workspaces" / f"scan-{scan_id}")
    db.delete(s)
    db.commit()
    audit.record("scan.deleted", user_id=p.user.id, username=p.user.username, target=f"scan:{scan_id}",
                 ip=client_ip(request), severity="warn")
    return {"ok": True}


@router.get("/scans/{scan_id}/events")
def scan_events(scan_id: int, after: int = 0, limit: int = 500, p: Principal = Depends(current_principal),
                db: Session = Depends(db_session)) -> list:
    _scan(db, p, scan_id)
    q = select(ScanEvent).where(ScanEvent.scan_id == scan_id, ScanEvent.id > after).order_by(ScanEvent.id).limit(
        max(1, min(limit, 2000)))
    return [_ev(e) for e in db.scalars(q)]


def _ev(e: ScanEvent) -> dict:
    return {"id": e.id, "ts": e.ts.isoformat(), "level": e.level, "module": e.module, "message": e.message,
            "data": e.data if e.level != "error" or not e.data else {k: v for k, v in e.data.items() if k != "trace"}}


@router.get("/scans/{scan_id}/tools")
def scan_tools(scan_id: int, p: Principal = Depends(current_principal), db: Session = Depends(db_session)) -> list:
    _scan(db, p, scan_id)
    return [{"id": t.id, "tool": t.tool, "version": t.version, "status": t.status, "exit_code": t.exit_code,
             "duration": t.duration, "max_rss_mb": t.max_rss_mb, "findings": t.findings_count, "error": t.error,
             "command": t.command if p.is_admin else None, "stderr_tail": t.stderr_tail if p.is_admin else None}
            for t in db.scalars(select(ToolRun).where(ToolRun.scan_id == scan_id).order_by(ToolRun.id))]


def _finding_out(f: Finding, full: bool = False) -> dict:
    d = {"id": f.id, "scan_id": f.scan_id, "project_id": f.project_id, "fingerprint": f.fingerprint, "title": f.title,
         "category": f.category, "module": f.module, "severity": f.severity, "confidence": f.confidence,
         "cvss_score": f.cvss_score, "cvss_vector": f.cvss_vector, "cwe": f.cwe, "cve": f.cve, "owasp": f.owasp,
         "asset": f.asset, "endpoint": f.endpoint, "method": f.method, "parameter": f.parameter, "file": f.file,
         "line": f.line, "priority": f.priority, "validation_status": f.validation_status,
         "remediation_status": f.remediation_status, "sources": f.sources, "chain_ids": f.chain_ids,
         "plain": plain_for(f.category)}
    if full:
        d.update({"function": f.function, "snippet": f.snippet, "description": f.description, "evidence": f.evidence,
                  "impact": f.impact, "likelihood": f.likelihood, "recommendation": f.recommendation,
                  "references": f.references, "analyst_notes": f.analyst_notes})
    return d


@router.get("/scans/{scan_id}/findings")
def scan_findings(scan_id: int, severity: str | None = None, confidence: str | None = None, status: str | None = None,
                  category: str | None = None, q: str | None = None, sort: str = "priority", offset: int = 0,
                  limit: int = 200, p: Principal = Depends(current_principal), db: Session = Depends(db_session)) -> dict:
    _scan(db, p, scan_id)
    query = select(Finding).where(Finding.scan_id == scan_id)
    for col, val in ((Finding.severity, severity), (Finding.confidence, confidence), (Finding.remediation_status, status),
                     (Finding.category, category)):
        if val:
            vals = [v for v in val.split(",") if re.fullmatch(r"[\w\-]{1,40}", v)][:10]
            if vals:
                query = query.where(col.in_(vals))
    if q:
        like = f"%{q[:100].replace('%', '').replace('_', '')}%"
        query = query.where(or_(Finding.title.ilike(like), Finding.endpoint.ilike(like), Finding.file.ilike(like),
                                Finding.cwe.ilike(like)))
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    rows = db.scalars(query.order_by(SORTS.get(sort, SORTS["priority"]), Finding.id).offset(max(0, offset))
                      .limit(max(1, min(limit, 1000))))
    return {"total": total, "items": [_finding_out(f) for f in rows]}


def _finding(db: Session, p: Principal, finding_id: int, write: bool = False) -> Finding:
    f = db.get(Finding, finding_id)
    if f is None:
        raise HTTPException(404, "Hallazgo no encontrado")
    get_project(db, p, f.project_id, write=write)
    return f


@router.get("/findings/{finding_id}")
def get_finding(finding_id: int, p: Principal = Depends(current_principal), db: Session = Depends(db_session)) -> dict:
    return _finding_out(_finding(db, p, finding_id), full=True)


@router.patch("/findings/{finding_id}")
def update_finding(finding_id: int, body: FindingUpdateIn, request: Request, p: Principal = Depends(current_principal),
                   db: Session = Depends(db_session)) -> dict:
    f = _finding(db, p, finding_id, write=True)
    changes = body.model_dump(exclude_none=True)
    for k, v in changes.items():
        setattr(f, k, v)
    if changes.get("remediation_status") == "false_positive":
        f.validation_status = "false_positive"
    db.commit()
    audit.record("finding.updated", user_id=p.user.id, username=p.user.username, target=f"finding:{finding_id}",
                 details={k: (v if k != "analyst_notes" else f"{len(v)} caracteres") for k, v in changes.items()},
                 ip=client_ip(request))
    return _finding_out(f, full=True)


@router.get("/scans/{scan_id}/chains")
def scan_chains(scan_id: int, p: Principal = Depends(current_principal), db: Session = Depends(db_session)) -> list:
    _scan(db, p, scan_id)
    return [{"id": c.id, "rule": c.rule, "title": c.title, "severity": c.severity, "narrative": c.narrative,
             "steps": c.steps, "recommendation": c.recommendation}
            for c in db.scalars(select(AttackChain).where(AttackChain.scan_id == scan_id))]


@router.get("/scans/{scan_id}/compare/{other_id}")
def compare(scan_id: int, other_id: int, p: Principal = Depends(current_principal), db: Session = Depends(db_session)) -> dict:
    """Diff by fingerprint: new (in scan, not in other), fixed (in other, not in scan), persistent."""
    a = _scan(db, p, scan_id)
    b = _scan(db, p, other_id)
    if a.project_id != b.project_id:
        raise HTTPException(400, "Solo se comparan escaneos del mismo proyecto")
    fa = {f.fingerprint: f for f in db.scalars(select(Finding).where(Finding.scan_id == a.id))}
    fb = {f.fingerprint: f for f in db.scalars(select(Finding).where(Finding.scan_id == b.id))}
    new = [fa[k] for k in fa.keys() - fb.keys()]
    fixed = [fb[k] for k in fb.keys() - fa.keys()]
    persistent = [fa[k] for k in fa.keys() & fb.keys()]
    key = lambda f: -f.priority  # noqa: E731
    return {"scan": a.id, "baseline": b.id, "risk": {"scan": (a.summary or {}).get("risk_score"),
                                                     "baseline": (b.summary or {}).get("risk_score")},
            "new": [_finding_out(f) for f in sorted(new, key=key)],
            "fixed": [_finding_out(f) for f in sorted(fixed, key=key)],
            "persistent": [_finding_out(f) for f in sorted(persistent, key=key)]}


@router.get("/scans/{scan_id}/reports/{fmt}")
def download_report(scan_id: int, fmt: str, request: Request, p: Principal = Depends(current_principal),
                    db: Session = Depends(db_session)) -> FileResponse:
    s = _scan(db, p, scan_id)
    if fmt not in REPORT_FILES:
        raise HTTPException(404, "Formato desconocido")
    path = report_dir(scan_id) / REPORT_FILES[fmt]
    if not path.exists():
        if s.status in ("queued", "running"):
            raise HTTPException(409, "El informe estará disponible al terminar el escaneo")
        generate_all(scan_id)
        if not path.exists():
            raise HTTPException(404, "Informe no disponible para este escaneo")
    media = {"json": "application/json", "csv": "text/csv; charset=utf-8", "html": "text/html; charset=utf-8",
             "executive": "text/html; charset=utf-8", "executive_pdf": "application/pdf",
             "pdf": "application/pdf", "sbom": "application/vnd.cyclonedx+json"}[fmt]
    audit.record("report.downloaded", user_id=p.user.id, username=p.user.username, target=f"scan:{scan_id}",
                 details={"format": fmt}, ip=client_ip(request))
    resp = FileResponse(path, media_type=media, filename=f"vigia-scan-{scan_id}-{REPORT_FILES[fmt]}")
    if fmt in ("html", "executive"):  # report opened in the browser: lock it down (no scripts at all)
        resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox"
    return resp


@router.websocket("/ws/scans/{scan_id}")
async def ws_scan(ws: WebSocket, scan_id: int) -> None:
    with SessionLocal() as db:
        p = ws_principal(ws, db)
        scan = db.get(Scan, scan_id) if p else None
        allowed = False
        if p and scan:
            try:
                get_project(db, p, scan.project_id)
                allowed = True
            except HTTPException:
                allowed = False
    if not allowed:
        await ws.close(code=4403)
        return
    uid = p.user.id  # type: ignore[union-attr]
    with _WS_LOCK:
        if _WS_OPEN.get(uid, 0) >= 5:
            allowed = False
        else:
            _WS_OPEN[uid] = _WS_OPEN.get(uid, 0) + 1
    if not allowed:
        await ws.close(code=4429)
        return
    try:
        await _stream(ws, scan_id)
    finally:
        with _WS_LOCK:
            _WS_OPEN[uid] = max(0, _WS_OPEN.get(uid, 1) - 1)


async def _stream(ws: WebSocket, scan_id: int) -> None:
    await ws.accept()
    last = int(ws.query_params.get("after", "0") or 0)
    try:
        while True:
            with SessionLocal() as db:
                evs = db.scalars(select(ScanEvent).where(ScanEvent.scan_id == scan_id, ScanEvent.id > last)
                                 .order_by(ScanEvent.id).limit(500)).all()
                sc = db.get(Scan, scan_id)
                if sc is None:
                    break
                if evs:
                    last = evs[-1].id
                await ws.send_json({"type": "state", "scan": _scan_out(sc), "events": [_ev(e) for e in evs]})
                if sc.status not in ("queued", "running") and not evs:
                    break
            await asyncio.sleep(0.5)
    except (WebSocketDisconnect, RuntimeError):
        return
    await ws.close()
