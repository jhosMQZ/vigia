"""Command line interface: serve · worker · init-admin · tools · scan (CI) · audit · keys · retention."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from datetime import timedelta
from pathlib import Path


def _db():  # noqa: ANN202
    from vigia.db import SessionLocal, init_db
    init_db()
    return SessionLocal()


def cmd_serve(a: argparse.Namespace) -> int:
    import uvicorn

    from vigia.api.app import create_app
    from vigia.config import get_settings
    s = get_settings()
    host, port = a.host or s.bind_host, a.port or s.bind_port
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"AVISO: escuchando en {host}. Expón Vigía solo detrás de un proxy TLS y con acceso restringido.")
    uvicorn.run(create_app(start_worker=not a.no_worker), host=host, port=port, server_header=False,
                proxy_headers=a.behind_proxy, forwarded_allow_ips="127.0.0.1" if a.behind_proxy else None,
                log_level="info")
    return 0


def cmd_worker(a: argparse.Namespace) -> int:
    import logging

    from vigia.core.worker import Worker
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    w = Worker(parallel=a.parallel)
    try:
        w.loop()
    except KeyboardInterrupt:
        w.stop()
    return 0


def cmd_init_admin(a: argparse.Namespace) -> int:
    from sqlalchemy import select

    from vigia.db import User
    from vigia.security import audit
    from vigia.security.auth import hash_password, password_problems
    username = a.username.strip().lower()
    password = os.environ.get("VIGIA_ADMIN_PASSWORD") or getpass.getpass(f"Contraseña para {username}: ")
    probs = password_problems(password, username)
    if probs:
        print("Contraseña débil: " + "; ".join(probs), file=sys.stderr)
        return 2
    with _db() as db:
        u = db.scalar(select(User).where(User.username == username))
        if u and not a.reset:
            print(f"El usuario {username} ya existe (usa --reset para cambiar su contraseña)", file=sys.stderr)
            return 1
        if u:
            u.password_hash, u.role, u.is_active = hash_password(password), "admin", True
            u.token_version += 1
            u.failed_logins, u.locked_until = 0, None
        else:
            db.add(User(username=username, password_hash=hash_password(password), role="admin"))
        db.commit()
    audit.record("user.admin_initialised", username="cli", target=username, severity="warn")
    print(f"Administrador «{username}» listo.")
    return 0


def cmd_tools(a: argparse.Namespace) -> int:
    from vigia.tools.registry import get_registry
    if a.action == "install":
        from vigia.tools.installer import install
        res = install(a.names or None, force=a.force)
        return 1 if any(str(v).startswith("ERROR") for v in res.values()) else 0
    for st in get_registry().all(refresh=True):
        print(f"{st.name:12} {st.status:13} {st.version or '':12} {st.license[:30]:30} {st.reason or ''}")
    from vigia.tools.browser import availability
    ok, reason = availability()
    print(f"{'browser':12} {'available' if ok else 'missing':13} {'':12} {'Apache-2.0 (Chromium)':30} {reason}")
    return 0


def cmd_scan(a: argparse.Namespace) -> int:
    """Local/CI mode: import code and/or use an existing authorised scope, run in-process, emit reports."""
    from sqlalchemy import select

    from vigia.core.orchestrator import run_scan
    from vigia.core.queue import worker_identity
    from vigia.db import Finding, Project, ProjectMember, Scan, Scope, SourceArtifact, User, utcnow
    from vigia.reports.generate import REPORT_FILES, report_dir
    from vigia.security import audit
    from vigia.security.extract import safe_copy_tree, safe_extract_zip
    from vigia.config import get_settings
    import tempfile
    s = get_settings()
    with _db() as db:
        user = db.scalar(select(User).where(User.username == a.user.lower(), User.is_active.is_(True)))
        if user is None:
            print(f"Usuario {a.user} no encontrado (crea uno con init-admin)", file=sys.stderr)
            return 2
        proj = db.scalar(select(Project).where(Project.name == a.project))
        if proj is None:
            proj = Project(name=a.project, owner_id=user.id)
            db.add(proj)
            db.flush()
            db.add(ProjectMember(project_id=proj.id, user_id=user.id, role="owner"))
            db.commit()
        source_id = None
        if a.source:
            src_path = Path(a.source).resolve()
            root = Path(tempfile.mkdtemp(prefix="src-", dir=s.data_dir / "sources"))
            stats = safe_extract_zip(src_path, root / "tree") if src_path.suffix.lower() == ".zip" else \
                safe_copy_tree(src_path, root / "tree")
            src = SourceArtifact(project_id=proj.id, kind="zip" if src_path.suffix == ".zip" else "path",
                                 origin=str(src_path), path=str(root / "tree"), files_count=stats.files,
                                 size_bytes=stats.bytes, sha256=stats.sha256, created_by=user.id)
            db.add(src)
            db.commit()
            source_id = src.id
        scope_id = None
        if a.scope_id:
            sc = db.get(Scope, a.scope_id)
            if sc is None or sc.project_id != proj.id:
                print("El alcance no pertenece al proyecto", file=sys.stderr)
                return 2
            scope_id = sc.id
        cfg = json.loads(a.config) if a.config else {}
        scan = Scan(project_id=proj.id, scope_id=scope_id, source_id=source_id, profile=a.profile, config=cfg,
                    created_by=user.id, status="running", worker_id="cli", started_at=utcnow(),
                    lease_until=utcnow() + timedelta(hours=12))
        db.add(scan)
        db.commit()
        sid = scan.id
    audit.record("scan.created", user_id=user.id, username=user.username, target=f"scan:{sid}",
                 details={"via": "cli", "profile": a.profile, "project": a.project})
    t0 = time.monotonic()
    run_scan(sid, "cli")
    with _db() as db:
        scan = db.get(Scan, sid)
        findings = db.scalars(select(Finding).where(Finding.scan_id == sid)).all()
        print(f"Escaneo #{sid}: {scan.status} en {time.monotonic() - t0:.0f}s — {len(findings)} hallazgos "
              f"{json.dumps((scan.summary or {}).get('by_severity', {}))}")
        if scan.error:
            print(f"Detalle: {scan.error}")
        for fmt, name in REPORT_FILES.items():
            p = report_dir(sid) / name
            if p.exists():
                print(f"  {fmt:5} {p}")
        order = ["info", "low", "medium", "high", "critical"]
        if a.fail_on:
            threshold = order.index(a.fail_on)
            bad = [f for f in findings if order.index(f.severity) >= threshold and f.confidence in ("confirmed", "likely")
                   and f.remediation_status not in ("accepted_risk", "false_positive")]
            if bad:
                print(f"FALLO: {len(bad)} hallazgos ≥ {a.fail_on} (confirmados o probables)")
                return 3
        return 0 if scan.status in ("completed", "stopped") else 1


def cmd_audit(a: argparse.Namespace) -> int:
    from vigia.security.audit import verify_chain
    with _db() as db:
        r = verify_chain(db)
    print(json.dumps(r, ensure_ascii=False))
    return 0 if r["ok"] else 4


def cmd_keys(a: argparse.Namespace) -> int:
    from sqlalchemy import select

    from vigia.db import Credential
    from vigia.security.crypto import add_master_key, rotate_token
    add_master_key()
    with _db() as db:
        n = 0
        for c in db.scalars(select(Credential)):
            c.data_enc = rotate_token(c.data_enc)
            n += 1
        db.commit()
    print(f"Clave maestra rotada; {n} credenciales re-cifradas. Puedes retirar las claves antiguas de master.key.")
    return 0


def cmd_retention(a: argparse.Namespace) -> int:
    """Delete workspaces older than the retention window and evidence/reports past evidence_retention_days."""
    from vigia.config import get_settings
    from vigia.security.extract import force_rmtree
    s = get_settings()
    now = time.time()
    removed = 0
    for d in (s.data_dir / "workspaces").glob("scan-*"):
        if now - d.stat().st_mtime > s.workspace_retention_hours * 3600:
            force_rmtree(d)
            removed += 1
    for d in (s.data_dir / "reports").glob("scan-*"):
        if now - d.stat().st_mtime > s.evidence_retention_days * 86400:
            force_rmtree(d)
            removed += 1
    print(f"{removed} directorios eliminados por política de retención")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="vigia", description="Vigía — plataforma de pretesting de seguridad")
    sub = p.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("serve", help="API + interfaz web (+ worker embebido)")
    sp.add_argument("--host")
    sp.add_argument("--port", type=int)
    sp.add_argument("--no-worker", action="store_true")
    sp.add_argument("--behind-proxy", action="store_true", help="confiar en X-Forwarded-* del proxy local")
    sp.set_defaults(fn=cmd_serve)
    sw = sub.add_parser("worker", help="worker independiente")
    sw.add_argument("--parallel", type=int)
    sw.set_defaults(fn=cmd_worker)
    si = sub.add_parser("init-admin", help="crear o restablecer un administrador")
    si.add_argument("--username", default="admin")
    si.add_argument("--reset", action="store_true")
    si.set_defaults(fn=cmd_init_admin)
    st = sub.add_parser("tools", help="estado o instalación de motores externos")
    st.add_argument("action", choices=["status", "install"])
    st.add_argument("names", nargs="*", help="motores; 'browser' instala Chromium para el navegador aislado")
    st.add_argument("--force", action="store_true")
    st.set_defaults(fn=cmd_tools)
    sc = sub.add_parser("scan", help="escaneo local (CI)")
    sc.add_argument("--project", required=True)
    sc.add_argument("--profile", default="code")
    sc.add_argument("--source", help="carpeta o .zip con el código")
    sc.add_argument("--scope-id", type=int, help="alcance ya autorizado (vía web)")
    sc.add_argument("--user", default="admin")
    sc.add_argument("--config", help="JSON con ScanConfig")
    sc.add_argument("--fail-on", choices=["low", "medium", "high", "critical"])
    sc.set_defaults(fn=cmd_scan)
    sa = sub.add_parser("audit", help="verificar la cadena de auditoría")
    sa.add_argument("action", choices=["verify"])
    sa.set_defaults(fn=cmd_audit)
    sk = sub.add_parser("keys", help="rotar la clave maestra de cifrado")
    sk.add_argument("action", choices=["rotate"])
    sk.set_defaults(fn=cmd_keys)
    sr = sub.add_parser("retention", help="aplicar la política de retención")
    sr.set_defaults(fn=cmd_retention)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
