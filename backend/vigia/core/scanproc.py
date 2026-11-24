"""Confined scan execution: each scan in its own AppContainer, with its own private data root and database.

Used when the dedicated egress is the local end of a tunnel (``VIGIA_HTTP_PROXY`` on loopback, e.g. ``ssh -D``) and
preventive isolation is ``appcontainer``. The kernel then forbids any traffic but loopback for the worker, its
gateway, the native modules, every engine and Chromium.

Data isolation (the container never touches Vigía's main data directory):
  * the parent decrypts only the credentials selected for this scan and sends them, together with a minimal *seed*
    (the scan, its project, its scope and the sources it references), over an inherited pipe;
  * the child creates a private data root ``workspaces/scan-<id>/iso`` with its own SQLite database, workspace,
    cache and temporary directory — the only path it may write — and read-only access to the code and to this scan's
    source tree;
  * the parent mirrors events, raw findings, engine runs and progress into the main database while the scan runs,
    propagates cancellation, renews the lease, and at the end correlates the findings against the project history,
    generates the reports, keeps the traces/evidence and deletes the private root;
  * master keys, other projects, other scans and the main database are never reachable from the container.
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

CHILD_FLAG = "VIGIA_CONFINED_SCAN"


def should_confine(scan_id: int) -> tuple[bool, str]:
    from vigia.config import get_settings
    from vigia.db import Scan, SessionLocal
    from vigia.security import appcontainer as ac
    from vigia.security.egress import ProxyError, Upstream
    from vigia.security.isolation import resolve_mode
    from vigia.security.egress import effective_proxy_url
    s = get_settings()
    if sys.platform != "win32" or not s.confine_worker or ac.in_container():
        return False, "no aplica"
    url = effective_proxy_url()
    if not url:
        return False, "sin salida dedicada"
    try:
        if Upstream.parse(url).transport != "loopback":
            return False, "la salida no es un túnel local (proxy remoto): el worker necesita alcanzarlo"
    except ProxyError:
        return False, "proxy inválido"
    if resolve_mode(s.egress_isolation) != "appcontainer":
        return False, "aislamiento distinto de appcontainer"
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None or not scan.scope_id:
            return False, "escaneo sin objetivos"
    return True, "salida por túnel local + AppContainer"


# ---------------------------------------------------------------------------------------------- row (de)serialisation
def _row(obj: Any) -> dict[str, Any]:
    out = {}
    for c in obj.__table__.columns:
        v = getattr(obj, c.name)
        out[c.name] = v.isoformat() if isinstance(v, datetime) else v
    return out


def _restore(model: Any, data: dict[str, Any]) -> Any:
    from sqlalchemy import DateTime
    vals = {}
    for c in model.__table__.columns:
        if c.name not in data:
            continue
        v = data[c.name]
        if v is not None and isinstance(c.type, DateTime) and isinstance(v, str):
            v = datetime.fromisoformat(v)
        vals[c.name] = v
    return model(**vals)


def _seed(scan_id: int) -> tuple[dict[str, Any], list[Path]]:
    """Only what this scan needs: its scan row, project, scope, referenced sources and the users they point at."""
    from vigia.core.profiles import effective_config
    from vigia.db import Project, Scan, Scope, SessionLocal, SourceArtifact, User
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        project = db.get(Project, scan.project_id)
        scope = db.get(Scope, scan.scope_id) if scan.scope_id else None
        cfg = effective_config(scan.profile, scan.config)
        src_ids = [x for x in [scan.source_id, *cfg.spec_source_ids] if x]
        sources = [s for s in (db.get(SourceArtifact, i) for i in src_ids)
                   if s is not None and s.project_id == scan.project_id]
        user_ids = {project.owner_id, scan.created_by}
        if scope is not None:
            user_ids |= {scope.created_by, scope.auth_attested_by}
        user_ids |= {s.created_by for s in sources}
        users = [{"id": u.id, "username": f"user-{u.id}", "password_hash": "!", "role": u.role, "is_active": True}
                 for u in (db.get(User, i) for i in user_ids if i) if u is not None]
        seed = {"users": users, "project": _row(project), "scope": _row(scope) if scope else None,
                "sources": [_row(s) for s in sources], "scan": _row(scan)}
        return seed, [Path(s.path) for s in sources]


def _apply_seed(seed: dict[str, Any]) -> None:
    from vigia.db import Project, Scan, Scope, SessionLocal, SourceArtifact, User, init_db
    init_db()
    with SessionLocal() as db:
        for u in seed["users"]:
            db.add(_restore(User, u))
        db.flush()
        db.add(_restore(Project, seed["project"]))
        db.flush()
        if seed.get("scope"):
            db.add(_restore(Scope, seed["scope"]))
        for s in seed.get("sources", []):
            db.add(_restore(SourceArtifact, s))
        db.flush()
        db.add(_restore(Scan, seed["scan"]))
        db.commit()


# ---------------------------------------------------------------------------------------------- live mirror
class _Mirror:
    """Copies the child's progress, events, raw findings and engine runs into the main database."""

    def __init__(self, scan_id: int, iso_db: Path, project_id: int):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        self.scan_id = scan_id
        self.project_id = project_id
        self.engine = create_engine(f"sqlite:///{iso_db.as_posix()}", connect_args={"timeout": 30})
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.last = {"events": 0, "findings": 0, "tools": 0}

    def sync(self) -> dict[str, Any] | None:
        from sqlalchemy import select, update

        from vigia.db import Finding, Scan, ScanEvent, SessionLocal, ToolRun
        try:
            with self.Session() as iso:
                child = iso.get(Scan, self.scan_id)
                if child is None:
                    return None
                evs = iso.scalars(select(ScanEvent).where(ScanEvent.id > self.last["events"])
                                  .order_by(ScanEvent.id)).all()
                fds = iso.scalars(select(Finding).where(Finding.id > self.last["findings"]).order_by(Finding.id)).all()
                tls = iso.scalars(select(ToolRun).where(ToolRun.id > self.last["tools"]).order_by(ToolRun.id)).all()
                state = {"status": child.status, "error": child.error, "progress": child.progress, "stats": child.stats}
                with SessionLocal() as db:
                    main = db.get(Scan, self.scan_id)
                    if main is not None and main.cancel_requested and not child.cancel_requested:
                        iso.execute(update(Scan).where(Scan.id == self.scan_id).values(cancel_requested=True))
                        iso.commit()
                    for model, rows, key in ((ScanEvent, evs, "events"), (Finding, fds, "findings"),
                                             (ToolRun, tls, "tools")):
                        for r in rows:
                            data = _row(r)
                            data.pop("id", None)
                            # the container is untrusted: whatever it wrote, rows land on THIS scan and project only
                            data["scan_id"] = self.scan_id
                            if model is Finding:
                                data["project_id"] = self.project_id
                            db.add(_restore(model, data))
                            self.last[key] = r.id
                    db.execute(update(Scan).where(Scan.id == self.scan_id)
                               .values(progress=state["progress"], stats=state["stats"]))
                    db.commit()
                return state
        except Exception:  # noqa: BLE001 - the child may be mid-write; try again on the next tick
            return None

    def close(self) -> None:
        self.engine.dispose()


# ---------------------------------------------------------------------------------------------- parent
def run_confined(scan_id: int, worker_id: str) -> None:
    from vigia.config import get_settings
    from vigia.core import queue
    from vigia.core.findings import FindingDraft
    from vigia.core.toolrunner import _Job
    from vigia.correlation.engine import correlate_and_store
    from vigia.db import ScanEvent, SessionLocal, utcnow
    from vigia.reports.generate import generate_all
    from vigia.security import appcontainer as ac
    from vigia.security import audit
    from vigia.security.crypto import CryptoError
    s = get_settings()
    try:
        identities = _decrypt_identities(scan_id)
        seed, source_paths = _seed(scan_id)
    except CryptoError as e:
        queue.finish(scan_id, worker_id, "failed", error=f"No se pudieron descifrar las credenciales: {e}")
        return
    backend = Path(__file__).resolve().parents[2]
    venv_py = Path(sys.executable)
    ws = s.data_dir.resolve() / "workspaces" / f"scan-{scan_id}"
    iso = ws / "iso"
    if iso.exists():
        shutil.rmtree(iso, ignore_errors=True)
    home = iso / "home"
    home.mkdir(parents=True, exist_ok=True)
    for code in (s.tools_dir, venv_py.parent.parent, Path(sys._base_executable).resolve().parent, backend):  # type: ignore[attr-defined]
        ac.grant_code_readable(code)  # non-secret code readable by any AppContainer (once)
    name = f"vigia.scan.{scan_id}.{secrets.token_hex(3)}"
    status, error, result = "failed", None, None
    with ac.ScanContainer(name) as sc:
        sc.allow(iso, write=True, inherit=True)  # the only writable path: private DB, workspace, cache, temp
        sc.allow(home, write=True, inherit=True)
        for p in source_paths:
            if p.is_dir():
                sc.allow_tree(p)
            elif p.exists():
                sc.allow(p.parent, write=False)
                sc.allow(p, write=False)
        with SessionLocal() as db:
            db.add(ScanEvent(scan_id=scan_id, ts=utcnow(), level="info", module="egress",
                             message="Escaneo ejecutado en un AppContainer propio con datos privados (base de datos, "
                                     "sandbox, caché y temporales exclusivos): el sistema solo permite loopback hacia el "
                                     "túnel local y el contenedor no accede a otros proyectos ni a las claves",
                             data={"container": name, "sid": sc.sid}))
            db.commit()
        secret_env = ("VIGIA_MASTER_KEY", "VIGIA_JWT_SECRET", "VIGIA_AUDIT_KEY", "VIGIA_DATABASE_URL", "VIGIA_DATA_DIR",
                      "VIGIA_NVD_API_KEY", "VIGIA_ZAP_API_KEY", "VIGIA_SSH_TUNNEL", "VIGIA_SSH_KNOWN_HOSTS",
                      "VIGIA_SSH_IDENTITY")
        env = {k: v for k, v in os.environ.items() if k.startswith("VIGIA_") and k not in secret_env}
        from vigia.security.egress import effective_proxy_url
        env["VIGIA_HTTP_PROXY"] = effective_proxy_url() or ""  # the scan's tunnel endpoint (loopback)
        sysroot = os.environ.get("SYSTEMROOT", r"C:\Windows")
        env.update({"VIGIA_DATA_DIR": str(iso), "VIGIA_TOOLS_DIR": str(s.tools_dir), "VIGIA_EMBEDDED_WORKER": "false",
                    "SYSTEMROOT": sysroot, "LOCALAPPDATA": str(home), "TEMP": str(home), "TMP": str(home),
                    "USERPROFILE": str(home), "HOME": str(home), "APPDATA": str(home), "PYTHONUTF8": "1",
                    "PYTHONDONTWRITEBYTECODE": "1", CHILD_FLAG: "1",
                    "NODE_OPTIONS": "--preserve-symlinks --preserve-symlinks-main",
                    "VIGIA_SYSTEM_DNS_SERVER": ac.system_dns_server(),
                    "PATH": os.pathsep.join([str(venv_py.parent), rf"{sysroot}\System32"])})
        if os.environ.get("SSL_CERT_FILE"):  # test CA of the network lab (audit only)
            env["SSL_CERT_FILE"] = os.environ["SSL_CERT_FILE"]
            sc.allow(Path(os.environ["SSL_CERT_FILE"]).parent, write=False)
            sc.allow(Path(os.environ["SSL_CERT_FILE"]), write=False)
        r_fd, w_fd = os.pipe()
        log = open(ws / "confined-worker.log", "ab")  # noqa: SIM115 - closed below
        job = _Job(max(4096, s.tool_max_memory_mb * 3))
        try:
            proc = ac.spawn([str(venv_py), "-I", "-m", "vigia.core.scanproc", str(scan_id), worker_id], env=env,
                            cwd=str(backend), stdin_fd=r_fd, stdout_fd=log.fileno(), stderr_fd=log.fileno(),
                            suspended=True, container_override=sc.container)
            job.assign_and_resume(proc)
        finally:
            os.close(r_fd)
            log.close()
        payload = json.dumps({"identities": identities, "seed": seed}, default=str).encode()
        identities.clear()
        view = memoryview(payload)
        while view:
            view = view[os.write(w_fd, view):]
        os.close(w_fd)
        mirror = _Mirror(scan_id, iso / "vigia.db", seed["project"]["id"])
        limit = int((seed["scan"].get("config") or {}).get("max_duration_min") or 120) * 60 + 900
        deadline, last_lease = time.monotonic() + limit, 0.0
        while proc.poll() is None and time.monotonic() < deadline:
            if (iso / "vigia.db").exists():
                mirror.sync()
            if time.monotonic() - last_lease > max(5, s.worker_lease_seconds // 3):
                queue.renew_lease(scan_id, worker_id)
                last_lease = time.monotonic()
            time.sleep(1)
        if proc.poll() is None:
            job.terminate()
        code = proc.poll()
        job.close()
        proc.close()
        state = mirror.sync() or {}
        mirror.close()
        try:
            result = json.loads((iso / "result.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            result = None
        status = (result or {}).get("status") or state.get("status") or "failed"
        error = (result or {}).get("error") or state.get("error")
        if result is None:
            tail = (ws / "confined-worker.log").read_bytes()[-400:].decode("utf-8", "replace") \
                if (ws / "confined-worker.log").exists() else ""
            status = "failed"
            error = (error or "") + f" El proceso confinado terminó sin entregar resultados (código {code}): {tail[-300:]}"
        # keep traces/evidence like any other scan, then destroy the private root (database, cache, temporary files)
        child_ws = iso / "workspaces" / f"scan-{scan_id}"
        for item in ("http-trace.jsonl", "egress-trace.jsonl", "evidence"):
            src = child_ws / item
            if not _plain_path(src, iso):  # never follow a link/junction planted by the container
                continue
            if src.is_dir():
                from vigia.security.extract import safe_copy_tree
                safe_copy_tree(src, ws / item, skip_dirs=set())
            elif src.is_file():
                shutil.copy2(src, ws / item)
    shutil.rmtree(iso, ignore_errors=True)
    summary: dict[str, Any] = {}
    if result is not None:
        try:
            drafts = [_draft(FindingDraft, d) for d in result.get("findings", [])]
            summary = correlate_and_store(scan_id, seed["project"]["id"], drafts, result.get("code_routes") or [],
                                          s.offline)
            summary.update({k: result.get(k) for k in ("requests", "urls", "technologies", "stop_reason")})
            generate_all(scan_id, result.get("dependencies") or [], status)
        except Exception as e:  # noqa: BLE001
            status = "failed" if status == "completed" else status
            error = (error + " | " if error else "") + f"Correlación/informes: {type(e).__name__}: {e}"
    queue.finish(scan_id, worker_id, status, summary=summary, error=error)
    audit.record("scan.finished", target=f"scan:{scan_id}",
                 details={"status": status, "findings": summary.get("findings"), "confined": True, "container": name})


def _plain_path(p: Path, root: Path) -> bool:
    """True if ``p`` exists and neither it nor any folder between it and ``root`` is a symlink or junction."""
    from vigia.security.extract import _is_junction
    if not p.exists() and not p.is_symlink():
        return False
    cur = p
    while True:
        if cur.is_symlink() or _is_junction(cur):
            return False
        if cur == root or cur.parent == cur:
            return True
        cur = cur.parent


def _draft(cls: Any, d: dict[str, Any]) -> Any:
    import dataclasses
    names = {f.name for f in dataclasses.fields(cls)}
    return cls(**{k: v for k, v in d.items() if k in names})


def _decrypt_identities(scan_id: int) -> dict:
    from vigia.core.profiles import effective_config
    from vigia.db import Credential, Scan, SessionLocal
    from vigia.security.crypto import decrypt_json
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        cfg = effective_config(scan.profile, scan.config)
        out = {}
        for cid in cfg.credential_ids:
            cred = db.get(Credential, cid)
            if cred is not None and cred.project_id == scan.project_id:  # strictly this project's credentials
                out[cred.name] = {"kind": cred.kind, **decrypt_json(cred.data_enc)}
        return out


# ---------------------------------------------------------------------------------------------- child
def main() -> None:
    """Child side (inside the scan's AppContainer, VIGIA_DATA_DIR = its private root)."""
    scan_id, worker_id = int(sys.argv[1]), sys.argv[2]
    os.environ[CHILD_FLAG] = "1"
    from vigia.security.appcontainer import use_container_pipes
    use_container_pipes()  # asyncio/Playwright pipes in the container's private namespace
    payload = json.loads(sys.stdin.read() or "{}")
    _apply_seed(payload["seed"])
    from vigia.core.orchestrator import run_scan_inprocess
    run_scan_inprocess(scan_id, worker_id, identities=payload.get("identities") or {})


if __name__ == "__main__":
    main()
