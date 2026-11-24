"""Projects, members, scopes + authorization records, source imports and test credentials."""
from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from vigia.api.deps import Principal, accessible_project_ids, client_ip, current_principal, db_session, get_project, \
    require_writer
from vigia.api.schemas import (AUTH_STATEMENT, AuthorizeIn, CredentialIn, GitSourceIn, MemberIn, PathSourceIn, ProjectIn,
                               ProjectUpdateIn, ScopeIn, ScopeUpdateIn, TargetsValidateIn)
from vigia.config import get_settings
from vigia.db import Credential, Project, ProjectMember, Scan, Scope, SourceArtifact, User, utcnow
from vigia.security import audit
from vigia.security.crypto import encrypt_json
from vigia.security.extract import UnsafeArchive, force_rmtree, safe_copy_tree, safe_extract_zip, safe_git_clone
from vigia.security.scope import ScopeViolation, validate_target_definition

router = APIRouter(prefix="/api")


def _proj_out(pr: Project, role: str | None = None) -> dict:
    return {"id": pr.id, "name": pr.name, "description": pr.description, "created_at": pr.created_at.isoformat(),
            "role": role}


@router.get("/projects")
def list_projects(p: Principal = Depends(current_principal), db: Session = Depends(db_session)) -> list[dict]:
    ids = accessible_project_ids(db, p)
    q = select(Project).order_by(Project.id.desc())
    if ids is not None:
        q = q.where(Project.id.in_(ids or [-1]))
    roles = {m.project_id: m.role for m in db.scalars(select(ProjectMember).where(ProjectMember.user_id == p.user.id))}
    return [_proj_out(pr, "owner" if p.is_admin else roles.get(pr.id)) for pr in db.scalars(q)]


@router.post("/projects", status_code=201)
def create_project(body: ProjectIn, request: Request, p: Principal = Depends(require_writer),
                   db: Session = Depends(db_session)) -> dict:
    pr = Project(name=body.name, description=body.description, owner_id=p.user.id)
    db.add(pr)
    db.flush()
    db.add(ProjectMember(project_id=pr.id, user_id=p.user.id, role="owner"))
    db.commit()
    audit.record("project.created", user_id=p.user.id, username=p.user.username, target=f"project:{pr.id}",
                 details={"name": pr.name}, ip=client_ip(request))
    return _proj_out(pr, "owner")


@router.get("/projects/{project_id}")
def get_project_ep(project_id: int, p: Principal = Depends(current_principal), db: Session = Depends(db_session)) -> dict:
    from vigia.api.deps import project_role
    pr = get_project(db, p, project_id)
    return _proj_out(pr, project_role(db, p, project_id))


@router.patch("/projects/{project_id}")
def update_project(project_id: int, body: ProjectUpdateIn, request: Request, p: Principal = Depends(current_principal),
                   db: Session = Depends(db_session)) -> dict:
    pr = get_project(db, p, project_id, owner=True)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(pr, k, v)
    db.commit()
    audit.record("project.updated", user_id=p.user.id, username=p.user.username, target=f"project:{pr.id}",
                 ip=client_ip(request))
    return _proj_out(pr, "owner")


@router.delete("/projects/{project_id}")
def delete_project(project_id: int, request: Request, p: Principal = Depends(current_principal),
                   db: Session = Depends(db_session)) -> dict:
    pr = get_project(db, p, project_id, owner=True)
    if db.scalar(select(Scan.id).where(Scan.project_id == project_id, Scan.status.in_(("queued", "running")))):
        raise HTTPException(409, "Cancela los escaneos en curso antes de eliminar el proyecto")
    s = get_settings()
    scan_ids = list(db.scalars(select(Scan.id).where(Scan.project_id == project_id)))
    store = (s.data_dir / "sources").resolve()
    for src in db.scalars(select(SourceArtifact).where(SourceArtifact.project_id == project_id)):
        root = Path(src.path).parent.resolve()
        if store in root.parents:  # never follow a tampered path outside the source store
            force_rmtree(root)
    for sid in scan_ids:
        force_rmtree(s.data_dir / "reports" / f"scan-{sid}")
        force_rmtree(s.data_dir / "workspaces" / f"scan-{sid}")
    db.delete(pr)
    db.commit()
    audit.record("project.deleted", user_id=p.user.id, username=p.user.username, target=f"project:{project_id}",
                 details={"name": pr.name, "scans": len(scan_ids)}, ip=client_ip(request), severity="warn")
    return {"ok": True}


# ------------------------------------------------------------------ members
@router.get("/projects/{project_id}/members")
def list_members(project_id: int, p: Principal = Depends(current_principal), db: Session = Depends(db_session)) -> list:
    get_project(db, p, project_id)
    rows = db.execute(select(ProjectMember, User).join(User, User.id == ProjectMember.user_id)
                      .where(ProjectMember.project_id == project_id)).all()
    return [{"user_id": u.id, "username": u.username, "role": m.role} for m, u in rows]


@router.post("/projects/{project_id}/members", status_code=201)
def add_member(project_id: int, body: MemberIn, request: Request, p: Principal = Depends(current_principal),
               db: Session = Depends(db_session)) -> dict:
    get_project(db, p, project_id, owner=True)
    u = db.scalar(select(User).where(User.username == body.username.lower(), User.is_active.is_(True)))
    if u is None:
        raise HTTPException(404, "Usuario no encontrado")
    role = "viewer" if u.role == "viewer" else body.role  # global viewers can never write
    m = db.scalar(select(ProjectMember).where(ProjectMember.project_id == project_id, ProjectMember.user_id == u.id))
    if m:
        m.role = role
    else:
        db.add(ProjectMember(project_id=project_id, user_id=u.id, role=role))
    db.commit()
    audit.record("project.member_set", user_id=p.user.id, username=p.user.username, target=f"project:{project_id}",
                 details={"member": u.username, "role": role}, ip=client_ip(request))
    return {"user_id": u.id, "username": u.username, "role": role}


@router.delete("/projects/{project_id}/members/{user_id}")
def remove_member(project_id: int, user_id: int, request: Request, p: Principal = Depends(current_principal),
                  db: Session = Depends(db_session)) -> dict:
    get_project(db, p, project_id, owner=True)
    owners = db.scalars(select(ProjectMember).where(ProjectMember.project_id == project_id, ProjectMember.role == "owner")).all()
    if len(owners) == 1 and owners[0].user_id == user_id:
        raise HTTPException(400, "El proyecto debe conservar al menos un propietario")
    db.execute(delete(ProjectMember).where(ProjectMember.project_id == project_id, ProjectMember.user_id == user_id))
    db.commit()
    audit.record("project.member_removed", user_id=p.user.id, username=p.user.username, target=f"project:{project_id}",
                 details={"user_id": user_id}, ip=client_ip(request))
    return {"ok": True}


# ------------------------------------------------------------------ scopes
def _scope_out(sc: Scope) -> dict:
    valid = bool(sc.auth_attested_at) and (sc.auth_valid_until is None or sc.auth_valid_until > utcnow())
    return {"id": sc.id, "project_id": sc.project_id, "name": sc.name, "targets": sc.targets, "exclusions": sc.exclusions,
            "allow_private": sc.allow_private, "lab_mode": sc.lab_mode, "allowed_ports": sc.allowed_ports,
            "max_rps": sc.max_rps, "created_at": sc.created_at.isoformat(),
            "authorization": {"valid": valid, "attested_at": sc.auth_attested_at.isoformat() if sc.auth_attested_at else None,
                              "attested_by": sc.auth_attested_by, "reference": sc.auth_reference,
                              "valid_until": sc.auth_valid_until.isoformat() if sc.auth_valid_until else None,
                              "statement": sc.auth_statement}}


def _validate_targets(targets: list[str], allow_private: bool) -> list[str]:
    from vigia.security.scope import _PRIVATE_NETS, _parse_ip  # noqa: PLC2701
    s = get_settings()
    errors, out = [], []
    for t in targets:
        try:
            spec = validate_target_definition(t)
        except ScopeViolation as e:
            errors.append(f"{t}: {e}")
            continue
        ip = _parse_ip(spec.host or "") if spec.kind == "ip" else None
        private = (ip is not None and any(ip.version == n.version and ip in n for n in _PRIVATE_NETS)) or (
            spec.kind == "cidr" and spec.network is not None and spec.network.is_private) or spec.host in ("localhost",)
        if private and not (allow_private and s.allow_private_targets):
            errors.append(f"{t}: objetivo interno; requiere allow_private en el alcance y VIGIA_ALLOW_PRIVATE_TARGETS")
            continue
        out.append(spec.raw)
    if errors:
        raise HTTPException(422, {"errors": errors})
    return out


@router.post("/scopes/validate")
def validate_targets(body: TargetsValidateIn, p: Principal = Depends(current_principal)) -> dict:
    results = []
    for t in body.targets:
        try:
            spec = validate_target_definition(t)
            results.append({"target": t, "ok": True, "kind": spec.kind})
        except ScopeViolation as e:
            results.append({"target": t, "ok": False, "error": str(e)})
    return {"results": results}


@router.get("/projects/{project_id}/scopes")
def list_scopes(project_id: int, p: Principal = Depends(current_principal), db: Session = Depends(db_session)) -> list:
    get_project(db, p, project_id)
    return [_scope_out(s) for s in db.scalars(select(Scope).where(Scope.project_id == project_id).order_by(Scope.id))]


@router.post("/projects/{project_id}/scopes", status_code=201)
def create_scope(project_id: int, body: ScopeIn, request: Request, p: Principal = Depends(current_principal),
                 db: Session = Depends(db_session)) -> dict:
    get_project(db, p, project_id, write=True)
    if body.lab_mode and not p.is_admin:
        raise HTTPException(403, "Solo un administrador puede marcar un alcance como laboratorio")
    targets = _validate_targets(body.targets, body.allow_private)
    sc = Scope(project_id=project_id, name=body.name, targets=targets, exclusions=body.exclusions,
               allow_private=body.allow_private, lab_mode=body.lab_mode, allowed_ports=body.allowed_ports,
               max_rps=body.max_rps, created_by=p.user.id)
    db.add(sc)
    db.commit()
    audit.record("scope.created", user_id=p.user.id, username=p.user.username, target=f"scope:{sc.id}",
                 details={"project": project_id, "targets": targets, "allow_private": sc.allow_private,
                          "lab_mode": sc.lab_mode}, ip=client_ip(request))
    return _scope_out(sc)


def _scope(db: Session, p: Principal, scope_id: int, write: bool = False) -> Scope:
    sc = db.get(Scope, scope_id)
    if sc is None:
        raise HTTPException(404, "Alcance no encontrado")
    get_project(db, p, sc.project_id, write=write)
    return sc


@router.get("/scopes/{scope_id}")
def get_scope(scope_id: int, p: Principal = Depends(current_principal), db: Session = Depends(db_session)) -> dict:
    return _scope_out(_scope(db, p, scope_id))


@router.patch("/scopes/{scope_id}")
def update_scope(scope_id: int, body: ScopeUpdateIn, request: Request, p: Principal = Depends(current_principal),
                 db: Session = Depends(db_session)) -> dict:
    sc = _scope(db, p, scope_id, write=True)
    changes = body.model_dump(exclude_none=True)
    if changes.get("lab_mode") and not p.is_admin:
        raise HTTPException(403, "Solo un administrador puede marcar un alcance como laboratorio")
    if "targets" in changes:
        changes["targets"] = _validate_targets(changes["targets"], changes.get("allow_private", sc.allow_private))
    material = {"targets", "exclusions", "allow_private", "lab_mode", "allowed_ports"} & set(changes)
    for k, v in changes.items():
        setattr(sc, k, v)
    if material:  # what was authorised changed: the attestation no longer applies
        sc.auth_attested_at = sc.auth_attested_by = sc.auth_statement = sc.auth_reference = sc.auth_valid_until = None
    db.commit()
    audit.record("scope.updated", user_id=p.user.id, username=p.user.username, target=f"scope:{sc.id}",
                 details={"changes": sorted(changes), "authorization_reset": bool(material)}, ip=client_ip(request))
    return _scope_out(sc)


@router.delete("/scopes/{scope_id}")
def delete_scope(scope_id: int, request: Request, p: Principal = Depends(current_principal),
                 db: Session = Depends(db_session)) -> dict:
    sc = _scope(db, p, scope_id, write=True)
    if db.scalar(select(Scan.id).where(Scan.scope_id == scope_id)):
        raise HTTPException(409, "El alcance tiene escaneos asociados (se conserva para trazabilidad)")
    db.delete(sc)
    db.commit()
    audit.record("scope.deleted", user_id=p.user.id, username=p.user.username, target=f"scope:{scope_id}",
                 ip=client_ip(request))
    return {"ok": True}


@router.get("/authorization-statement")
def authorization_statement(p: Principal = Depends(current_principal)) -> dict:
    return {"statement": AUTH_STATEMENT}


@router.post("/scopes/{scope_id}/authorize")
def authorize_scope(scope_id: int, body: AuthorizeIn, request: Request, p: Principal = Depends(current_principal),
                    db: Session = Depends(db_session)) -> dict:
    sc = _scope(db, p, scope_id, write=True)
    if body.statement.strip() != AUTH_STATEMENT:
        raise HTTPException(400, "El texto de la declaración no coincide con el vigente")
    if body.valid_until and body.valid_until.replace(tzinfo=None) <= utcnow():
        raise HTTPException(400, "La fecha de validez ya ha pasado")
    sc.auth_attested_by = p.user.id
    sc.auth_attested_at = utcnow()
    sc.auth_statement = AUTH_STATEMENT + (f" Contacto del titular: {body.owner_contact}" if body.owner_contact else "")
    sc.auth_reference = body.reference
    sc.auth_valid_until = body.valid_until.replace(tzinfo=None) if body.valid_until else None
    sc.auth_ip = client_ip(request)
    db.commit()
    audit.record("scope.authorized", user_id=p.user.id, username=p.user.username, target=f"scope:{sc.id}",
                 details={"targets": sc.targets, "reference": body.reference, "valid_until": str(sc.auth_valid_until),
                          "user_agent": request.headers.get("user-agent", "")[:200]}, ip=client_ip(request), severity="warn")
    return _scope_out(sc)


# ------------------------------------------------------------------ sources
def _src_out(s: SourceArtifact) -> dict:
    return {"id": s.id, "kind": s.kind, "origin": s.origin, "files": s.files_count, "size_bytes": s.size_bytes,
            "sha256": s.sha256, "created_at": s.created_at.isoformat()}


def _new_source_dir() -> Path:
    base = get_settings().data_dir / "sources"
    base.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix="src-", dir=base))


def _register(db: Session, p: Principal, project_id: int, kind: str, origin: str, path: Path, stats, request: Request) -> dict:  # noqa: ANN001
    src = SourceArtifact(project_id=project_id, kind=kind, origin=origin[:1024], path=str(path), files_count=stats.files,
                         size_bytes=stats.bytes, sha256=stats.sha256, created_by=p.user.id)
    db.add(src)
    db.commit()
    audit.record("source.imported", user_id=p.user.id, username=p.user.username, target=f"source:{src.id}",
                 details={"project": project_id, "kind": kind, "origin": origin[:200], "files": stats.files,
                          "skipped": len(stats.skipped)}, ip=client_ip(request))
    out = _src_out(src)
    out["skipped"] = stats.skipped[:50]
    return out


@router.get("/projects/{project_id}/sources")
def list_sources(project_id: int, p: Principal = Depends(current_principal), db: Session = Depends(db_session)) -> list:
    get_project(db, p, project_id)
    return [_src_out(s) for s in db.scalars(select(SourceArtifact).where(SourceArtifact.project_id == project_id)
                                            .order_by(SourceArtifact.id.desc()))]


async def _save_upload(file: UploadFile, dest: Path, limit: int) -> None:
    size = 0
    with open(dest, "wb") as fh:
        while chunk := await file.read(1 << 20):
            size += len(chunk)
            if size > limit:
                raise HTTPException(413, "Fichero demasiado grande")
            fh.write(chunk)


@router.post("/projects/{project_id}/sources/upload", status_code=201)
async def upload_source(project_id: int, request: Request, file: UploadFile = File(...),
                        p: Principal = Depends(current_principal), db: Session = Depends(db_session)) -> dict:
    get_project(db, p, project_id, write=True)
    s = get_settings()
    if not (file.filename or "").lower().endswith(".zip"):
        raise HTTPException(400, "Solo se admiten archivos .zip")
    root = _new_source_dir()
    blob = root / "upload.zip"
    try:
        await _save_upload(file, blob, s.max_upload_mb * 1024 * 1024)
        stats = safe_extract_zip(blob, root / "tree")
    except UnsafeArchive as e:
        force_rmtree(root)
        audit.record("source.rejected", user_id=p.user.id, username=p.user.username, details={"reason": str(e)},
                     ip=client_ip(request), severity="warn")
        raise HTTPException(400, f"Archivo rechazado: {e}") from e
    except HTTPException:
        force_rmtree(root)
        raise
    finally:
        blob.unlink(missing_ok=True)
    return _register(db, p, project_id, "zip", file.filename or "upload.zip", root / "tree", stats, request)


@router.post("/projects/{project_id}/sources/git", status_code=201)
def git_source(project_id: int, body: GitSourceIn, request: Request, p: Principal = Depends(current_principal),
               db: Session = Depends(db_session)) -> dict:
    get_project(db, p, project_id, write=True)
    root = _new_source_dir()
    try:
        stats = safe_git_clone(body.url, root / "tree", get_settings().git_allowed_hosts, ref=body.ref)
    except UnsafeArchive as e:
        force_rmtree(root)
        raise HTTPException(400, str(e)) from e
    return _register(db, p, project_id, "git", body.url + (f"@{body.ref}" if body.ref else ""), root / "tree", stats, request)


@router.post("/projects/{project_id}/sources/path", status_code=201)
def path_source(project_id: int, body: PathSourceIn, request: Request, p: Principal = Depends(current_principal),
                db: Session = Depends(db_session)) -> dict:
    get_project(db, p, project_id, write=True)
    s = get_settings()
    if not p.is_admin:
        raise HTTPException(403, "Solo un administrador puede importar carpetas del servidor")
    target = Path(body.path).resolve()
    roots = [r.resolve() for r in s.allowed_import_roots]
    if not roots or not any(target == r or r in target.parents for r in roots):
        raise HTTPException(400, "Ruta fuera de VIGIA_ALLOWED_IMPORT_ROOTS")
    root = _new_source_dir()
    try:
        stats = safe_copy_tree(target, root / "tree")
    except UnsafeArchive as e:
        force_rmtree(root)
        raise HTTPException(400, str(e)) from e
    return _register(db, p, project_id, "path", str(target), root / "tree", stats, request)


@router.post("/projects/{project_id}/sources/spec", status_code=201)
async def upload_spec(project_id: int, request: Request, file: UploadFile = File(...),
                      p: Principal = Depends(current_principal), db: Session = Depends(db_session)) -> dict:
    """OpenAPI (JSON/YAML) or Postman collection used as discovery input for API audits."""
    from vigia.modules.api import load_spec_text, parse_openapi, parse_postman
    get_project(db, p, project_id, write=True)
    root = _new_source_dir()
    dest = root / "spec.txt"
    try:
        await _save_upload(file, dest, 15 * 1024 * 1024)
        data = load_spec_text(dest.read_text(encoding="utf-8", errors="replace"))
        kind = "postman" if "item" in data and "info" in data else "openapi"
        n = len(parse_postman(data) if kind == "postman" else parse_openapi(data, "https://placeholder.invalid/"))
    except (ValueError, UnicodeError) as e:
        force_rmtree(root)
        raise HTTPException(400, f"Especificación no válida: {e}") from e
    except Exception as e:  # noqa: BLE001 - YAML parser errors
        force_rmtree(root)
        raise HTTPException(400, f"Especificación no válida: {type(e).__name__}") from e

    class _S:  # minimal stats object for _register
        files, bytes, sha256, skipped = 1, dest.stat().st_size, "", []
    out = _register(db, p, project_id, kind, file.filename or "spec", dest, _S(), request)
    out["operations"] = n
    return out


@router.delete("/sources/{source_id}")
def delete_source(source_id: int, request: Request, p: Principal = Depends(current_principal),
                  db: Session = Depends(db_session)) -> dict:
    src = db.get(SourceArtifact, source_id)
    if src is None:
        raise HTTPException(404, "Fuente no encontrada")
    get_project(db, p, src.project_id, write=True)
    if db.scalar(select(Scan.id).where(Scan.source_id == source_id, Scan.status.in_(("queued", "running")))):
        raise HTTPException(409, "La fuente está en uso por un escaneo en curso")
    root = Path(src.path).parent.resolve()
    if (get_settings().data_dir / "sources").resolve() not in root.parents:
        raise HTTPException(500, "Ruta de la fuente fuera del almacén; no se elimina")
    force_rmtree(root)
    db.delete(src)
    db.commit()
    audit.record("source.deleted", user_id=p.user.id, username=p.user.username, target=f"source:{source_id}",
                 ip=client_ip(request))
    return {"ok": True}


# ------------------------------------------------------------------ credentials (test accounts)
REQUIRED = {"form": {"login_url", "username", "password"}, "json": {"login_url", "body"}, "bearer": {"token"},
            "header": {"name", "value"}, "basic": {"username", "password"}, "cookie": {"cookie"}}


@router.get("/projects/{project_id}/credentials")
def list_credentials(project_id: int, p: Principal = Depends(current_principal), db: Session = Depends(db_session)) -> list:
    get_project(db, p, project_id)
    return [{"id": c.id, "name": c.name, "kind": c.kind, "created_at": c.created_at.isoformat()}
            for c in db.scalars(select(Credential).where(Credential.project_id == project_id))]


@router.post("/projects/{project_id}/credentials", status_code=201)
def create_credential(project_id: int, body: CredentialIn, request: Request, p: Principal = Depends(current_principal),
                      db: Session = Depends(db_session)) -> dict:
    get_project(db, p, project_id, write=True)
    missing = REQUIRED[body.kind] - set(body.data)
    if missing:
        raise HTTPException(400, f"Faltan campos para '{body.kind}': {', '.join(sorted(missing))}")
    for k in ("login_url", "verify_url"):
        if k in body.data and not str(body.data[k]).startswith(("http://", "https://")):
            raise HTTPException(400, f"{k} debe ser una URL http(s)")
    c = Credential(project_id=project_id, name=body.name, kind=body.kind,
                   data_enc=encrypt_json({**body.data, "role": body.role}), created_by=p.user.id)
    db.add(c)
    db.commit()
    audit.record("credential.created", user_id=p.user.id, username=p.user.username, target=f"credential:{c.id}",
                 details={"project": project_id, "name": c.name, "kind": c.kind}, ip=client_ip(request))
    return {"id": c.id, "name": c.name, "kind": c.kind}


@router.delete("/credentials/{cred_id}")
def delete_credential(cred_id: int, request: Request, p: Principal = Depends(current_principal),
                      db: Session = Depends(db_session)) -> dict:
    c = db.get(Credential, cred_id)
    if c is None:
        raise HTTPException(404, "Credencial no encontrada")
    get_project(db, p, c.project_id, write=True)
    db.delete(c)
    db.commit()
    audit.record("credential.deleted", user_id=p.user.id, username=p.user.username, target=f"credential:{cred_id}",
                 ip=client_ip(request))
    return {"ok": True}

