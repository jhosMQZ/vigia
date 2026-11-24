"""Scan orchestrator: preparation → recon/code → discovery → analysis (+ engines) → correlation → reports."""
from __future__ import annotations

import asyncio
import os
import traceback
from pathlib import Path
from typing import Any

from vigia.config import get_settings
from vigia.core import queue
from vigia.core.context import ScanContext, in_window
from vigia.core.profiles import effective_config
from vigia.db import Credential, Project, Scan, Scope, SessionLocal, SourceArtifact, utcnow
from vigia.security import audit
from vigia.security.crypto import CryptoError, decrypt_json
from vigia.security.extract import force_rmtree
from vigia.security.http import BudgetExceeded, StopScan
from vigia.security.scope import ScopeGuard, ScopeViolation

PHASES = ("recon", "discovery", "analysis", "correlation")


class ScanRefused(Exception):
    pass


def _authorization_problem(scope: Scope) -> str | None:
    if not scope.auth_attested_at or not scope.auth_attested_by or not scope.auth_statement:
        return "El alcance no tiene una declaración de autorización registrada"
    if scope.auth_valid_until and scope.auth_valid_until < utcnow():
        return "La autorización del alcance ha caducado"
    return None


def build_context(scan_id: int, worker_id: str, identities_override: dict | None = None) -> ScanContext:
    s = get_settings()
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            raise ScanRefused("El escaneo no existe")
        project = db.get(Project, scan.project_id)
        cfg = effective_config(scan.profile, scan.config)
        guard = None
        lab = False
        if cfg.profile.needs_target or scan.scope_id:
            scope = db.get(Scope, scan.scope_id) if scan.scope_id else None
            if scope is None or scope.project_id != scan.project_id:
                if cfg.profile.needs_target and not cfg.profile.needs_source:
                    raise ScanRefused("Este perfil requiere un alcance autorizado")
            else:
                problem = _authorization_problem(scope)
                if problem:
                    raise ScanRefused(problem)
                try:
                    guard = ScopeGuard.build(scope.targets, list(scope.exclusions or []) + cfg.exclusions,
                                             scope_allow_private=scope.allow_private,
                                             global_allow_private=s.allow_private_targets,
                                             allowed_ports=scope.allowed_ports,
                                             blocked_local_ports=[s.bind_port, 5173])
                except ScopeViolation as e:
                    raise ScanRefused(f"Alcance inválido: {e}") from e
                cfg.rps = min(cfg.rps, scope.max_rps or cfg.rps)
                lab = scope.lab_mode
        source_dir = None
        if scan.source_id:
            src = db.get(SourceArtifact, scan.source_id)
            if src is None or src.project_id != scan.project_id:
                raise ScanRefused("El código fuente no pertenece al proyecto")
            source_dir = Path(src.path)
            if not source_dir.is_dir():
                raise ScanRefused("El código fuente importado ya no está disponible (retención)")
        if cfg.profile.needs_source and not cfg.profile.needs_target and source_dir is None:
            raise ScanRefused("Code Audit requiere importar código fuente")
        if cfg.profile.needs_target and guard is None and source_dir is None:
            raise ScanRefused("No hay objetivo ni código que analizar")
        if cfg.window and not in_window(cfg.window):
            raise ScanRefused("Fuera de la ventana de ejecución configurada")
        identities: dict[str, dict[str, Any]] = dict(identities_override or {})
        for cid in ([] if identities_override is not None else cfg.credential_ids):
            cred = db.get(Credential, cid)
            if cred is None or cred.project_id != scan.project_id:
                raise ScanRefused(f"Credencial {cid} no pertenece al proyecto")
            try:
                identities[cred.name] = {"kind": cred.kind, **decrypt_json(cred.data_enc)}
            except CryptoError as e:
                raise ScanRefused(f"No se pudo descifrar la credencial {cred.name}") from e
        spec_files: list[str] = []
        for sid in cfg.spec_source_ids:
            spec = db.get(SourceArtifact, sid)
            if spec is None or spec.project_id != scan.project_id or spec.kind not in ("openapi", "postman"):
                raise ScanRefused(f"Especificación {sid} no pertenece al proyecto")
            spec_files.append(spec.path)
        if guard is not None:  # egress policy: fail closed, never fall back to a direct connection
            from vigia.security.egress import require_proxy_decision
            has_public = any(t.kind in ("host", "wildcard") for t in guard.targets) or any(
                t.kind in ("ip", "cidr") for t in guard.targets)
            refusal = require_proxy_decision(has_public)
            if refusal:
                raise ScanRefused(refusal)
        ws = s.data_dir / "workspaces" / f"scan-{scan_id}"
        ws.mkdir(parents=True, exist_ok=True)
        ctx = ScanContext(scan_id, scan.project_id, cfg, ws, guard=guard, source_dir=source_dir, lab_mode=lab,
                          identities=identities)
        ctx.spec_files = spec_files  # type: ignore[attr-defined]
        if guard is not None:
            ctx.kb.base_urls = list(dict.fromkeys(guard.seed_urls()))
        ctx.emit("info", "orchestrator", f"Proyecto «{project.name if project else '?'}», perfil {cfg.profile.name}, "
                 f"intensidad {cfg.intensity}", {"modules": cfg.modules, "tools": cfg.tools,
                                                 "targets": [t.raw for t in guard.targets] if guard else [],
                                                 "source": bool(source_dir), "lab_mode": lab})
        return ctx


async def _run_unit(ctx: ScanContext, name: str, coro_factory) -> None:  # noqa: ANN001
    ctx.progress(name, "running", 0)
    try:
        await coro_factory()
        ctx.progress(name, "done", 100)
    except StopScan as e:
        ctx.progress(name, "stopped", detail=str(e))
        raise
    except BudgetExceeded as e:
        ctx.emit("warn", name, f"Presupuesto de peticiones agotado: {e}")
        ctx.progress(name, "stopped", detail="presupuesto agotado")
    except ScopeViolation as e:
        ctx.emit("warn", name, f"Bloqueado por el control de alcance: {e}")
        ctx.progress(name, "done", 100, detail="bloqueos de alcance registrados")
    except Exception as e:  # noqa: BLE001 - a failing module must never take down the scan; error is surfaced
        ctx.emit("error", name, f"{type(e).__name__}: {e}", {"trace": traceback.format_exc()[-3000:]})
        ctx.progress(name, "failed", detail=f"{type(e).__name__}: {str(e)[:150]}")


def _audit(*a, **kw) -> None:  # noqa: ANN002, ANN003
    """The confined child has no access to data/keys (audit HMAC key): the parent records the audit entry."""
    if os.environ.get("VIGIA_CONFINED_SCAN") != "1":
        audit.record(*a, **kw)


async def run_scan_async(scan_id: int, worker_id: str, identities: dict | None = None) -> None:
    from vigia.modules import MODULES
    from vigia.tools.adapters import ADAPTERS
    from vigia.correlation.engine import correlate_and_store
    from vigia.reports.generate import generate_all

    s = get_settings()
    loop = asyncio.get_running_loop()
    default_handler = loop.get_exception_handler()

    def _quiet(lp, context):  # noqa: ANN001 - Windows proactor noise when a peer resets a closed socket
        if isinstance(context.get("exception"), (ConnectionResetError, ConnectionAbortedError)):
            return
        if default_handler is not None:
            default_handler(lp, context)
        else:
            lp.default_exception_handler(context)
    loop.set_exception_handler(_quiet)
    try:
        ctx = build_context(scan_id, worker_id, identities_override=identities)
    except ScanRefused as e:
        queue.finish(scan_id, worker_id, "failed", error=str(e))
        _audit("scan.refused", target=f"scan:{scan_id}", details={"reason": str(e)}, severity="warn")
        return

    async def lease_keeper() -> None:
        while True:
            await asyncio.sleep(max(5, s.worker_lease_seconds // 3))
            await asyncio.to_thread(queue.renew_lease, scan_id, worker_id)

    keeper = asyncio.create_task(lease_keeper())
    from vigia.core.watchdog import Watchdog
    dog = Watchdog(ctx, asyncio.get_running_loop())
    dog.start()
    beat = asyncio.create_task(dog.heartbeat())
    status, error = "completed", None
    try:
        ctx.open_http()
        if ctx.guard is not None:
            _announce_egress(ctx)
        if ctx.egress_active:  # prove the tunnel forwards and remote DNS answers before touching any target
            from vigia.security.egress import preflight_tunnel
            refusal = await preflight_tunnel(ctx.upstream, ctx.resolver)
            if refusal:
                raise ScanRefused(refusal)
            from vigia.security.isolation import check as isolation_check
            ctx.isolation = await asyncio.to_thread(isolation_check, None, ctx.workspace / "isolation")
            if ctx.isolation.get("confined_worker"):
                probe = await asyncio.to_thread(_worker_direct_probe)
                ctx.isolation["worker_direct_probe"] = probe
                if not probe.startswith("blocked:10013"):
                    raise ScanRefused("El proceso del escaneo debería estar confinado pero una conexión directa de prueba "
                                      f"no fue bloqueada por el sistema ({probe}); no se continúa")
                ctx.emit("info", "egress", "Proceso de Vigía confinado: su propia conexión directa de prueba fue "
                         "bloqueada por el kernel (10013) antes de salir", {"probe": probe})
            iso = ctx.isolation
            if iso["mode"] == "detect":
                ctx.emit("warn", "egress", "Sin aislamiento preventivo de red (VIGIA_EGRESS_ISOLATION=detect): las "
                         "conexiones directas de un motor solo se detectan después de producirse (kill switch)", iso)
            elif not iso["ok"]:
                raise ScanRefused(f"Aislamiento de red preventivo NO verificado (modo {iso['mode']}): {iso['detail']}. "
                                  "No se ejecuta ningún motor sin él. Corrige el aislamiento o, asumiendo el riesgo, "
                                  "usa VIGIA_EGRESS_ISOLATION=detect")
            else:
                ctx.emit("info", "egress", f"Aislamiento preventivo verificado ({iso['mode']}): los motores y Chromium "
                         "no pueden abrir conexiones directas, UDP ni DNS del sistema", iso)
        selected = [MODULES[m]() for m in ctx.cfg.modules if m in MODULES]
        adapters = [ADAPTERS[t]() for t in ctx.cfg.tools if t in ADAPTERS]
        if adapters:  # probe engine versions off the event loop (subprocesses must never block the loop)
            from vigia.tools.registry import get_registry
            reg = get_registry()
            await asyncio.gather(*(asyncio.to_thread(reg.status, a.tool) for a in adapters))
        if ctx.http is not None:
            from vigia.modules.auth_setup import setup_identities
            await _run_unit(ctx, "auth", lambda: setup_identities(ctx))
        for phase in PHASES:
            ctx.check()
            units = []
            for mod in selected:
                if phase not in mod.active_phases():
                    continue
                why = mod.applicable(ctx)
                label = mod.name if len(mod.active_phases()) == 1 else f"{mod.name}:{phase}"
                if why:
                    ctx.progress(label, "skipped", detail=why)
                    continue
                units.append(_run_unit(ctx, label, lambda m=mod, ph=phase: m.run_phase(ctx, ph)))
            for ad in adapters:
                if ad.phase != phase:
                    continue
                why = ad.applicable(ctx)
                if why:
                    ctx.record_tool_skip(ad.tool, why)
                    ctx.progress(f"tool:{ad.tool}", "skipped", detail=why)
                    continue
                units.append(_run_unit(ctx, f"tool:{ad.tool}", lambda a=ad: a.run(ctx)))
            if units:
                ctx.emit("info", "orchestrator", f"Fase «{phase}»: {len(units)} unidades")
                await asyncio.gather(*units)
    except ScanRefused as e:
        status, error = "failed", str(e)
        ctx.emit("error", "egress", f"Escaneo rechazado antes de contactar con ningún objetivo: {e}")
    except StopScan as e:
        status = "cancelled" if "cancelado" in str(e) else "stopped"
        error = str(e)
        ctx.emit("warn", "orchestrator", f"Escaneo detenido: {e}")
    except Exception as e:  # noqa: BLE001
        status, error = "failed", f"{type(e).__name__}: {e}"
        ctx.emit("error", "orchestrator", error, {"trace": traceback.format_exc()[-3000:]})
    finally:
        ctx.thread_cancel.set() if status in ("cancelled", "stopped", "failed") else None
        await ctx.close()
    summary: dict[str, Any] = {}
    if os.environ.get("VIGIA_CONFINED_SCAN") == "1":
        # Confined child: hand the raw results to the parent, which correlates them against the project history and
        # writes the reports in the main database (the container never sees other scans or projects).
        try:
            _write_confined_result(ctx, status, error)
        finally:
            keeper.cancel()
            beat.cancel()
            dog.close()
            ctx.flush(force=True)
        queue.finish(scan_id, worker_id, status, error=error)
        return
    try:
        ctx.progress("correlation", "running", 10)
        summary = await asyncio.to_thread(correlate_and_store, scan_id, ctx.project_id, ctx.findings,
                                          ctx.kb.code_routes, s.offline)
        summary["requests"] = ctx.http.requests_made if ctx.http else 0
        summary["urls"] = len(ctx.kb.urls)
        summary["technologies"] = {k: v.get("version") for k, v in list(ctx.kb.technologies.items())[:40]}
        summary["stop_reason"] = ctx.stop_reason
        ctx.progress("correlation", "done", 100)
        ctx.progress("reports", "running", 10)
        await asyncio.to_thread(generate_all, scan_id, ctx.kb.dependencies, status)
        ctx.progress("reports", "done", 100)
    except Exception as e:  # noqa: BLE001
        status = "failed" if status == "completed" else status
        error = (error + " | " if error else "") + f"Correlación/informes: {type(e).__name__}: {e}"
        ctx.emit("error", "correlation", error, {"trace": traceback.format_exc()[-3000:]})
    finally:
        keeper.cancel()
        beat.cancel()
        dog.close()
        ctx.flush(force=True)
    queue.finish(scan_id, worker_id, status, summary=summary, error=error)
    _audit("scan.finished", target=f"scan:{scan_id}", details={"status": status, "findings": summary.get("findings"),
                                                                      "error": error})
    _cleanup_workspace(ctx)


def _announce_egress(ctx: ScanContext) -> None:
    """Scan event with the real egress/DNS configuration and who can observe what (never claims anonymity)."""
    from vigia.security.egress import visibility
    resolver = ctx.resolver
    remote = bool(getattr(resolver, "remote", False))
    vis = visibility(ctx.upstream, remote, getattr(resolver, "description", "?"))
    data = {"salida": getattr(ctx.upstream, "display", "directa"), "transporte": getattr(ctx.upstream, "transport", "direct"),
            "dns": getattr(resolver, "description", "?"), "dns_remoto": remote, "kill_switch": ctx.netwatch,
            "pasarela": ctx.gateway.http_url if ctx.gateway else None, "visibilidad": vis}
    if ctx.egress_active:
        msg = (f"Salida dedicada {data['salida']} (transporte: {data['transporte']}); DNS: {data['dns']}; todos los motores "
               "pasan por la pasarela de alcance; sin conexión directa de reserva")
        level = "warn" if data["transporte"] == "plaintext" else "info"
        if data["transporte"] == "plaintext":
            msg += ". AVISO: el protocolo del proxy viaja en claro: tu proveedor de Internet ve destinos y peticiones"
        loc = [t.raw for t in (ctx.guard.targets if ctx.guard else []) if t.kind == "ip" and (t.host or "").startswith("127.")]
        if loc:
            msg += "; hay objetivos en loopback: solo serán alcanzables si la salida puede llegar a ellos"
        ctx.emit(level, "egress", msg, data)
    else:
        ctx.emit("info", "egress", "Sin salida dedicada: las conexiones salen de la red del equipo (el objetivo ve tu IP); "
                 f"DNS: {data['dns']}. Los motores pasan igualmente por la pasarela de alcance.", data)


def _cleanup_workspace(ctx: ScanContext) -> None:
    """Remove tool sandboxes (they may hold copies of target content); keep evidence + http trace."""
    tools_dir = ctx.workspace / "tools"
    if tools_dir.exists():
        force_rmtree(tools_dir)


def _write_confined_result(ctx: ScanContext, status: str, error: str | None) -> None:
    import json
    out = {"status": status, "error": error, "findings": [f.to_dict() for f in ctx.findings],
           "code_routes": ctx.kb.code_routes, "dependencies": ctx.kb.dependencies,
           "requests": ctx.http.requests_made if ctx.http else 0, "urls": len(ctx.kb.urls),
           "technologies": {k: v.get("version") for k, v in list(ctx.kb.technologies.items())[:40]},
           "stop_reason": ctx.stop_reason}
    path = get_settings().data_dir / "result.json"
    path.write_text(json.dumps(out, ensure_ascii=False, default=str), encoding="utf-8")


def _worker_direct_probe() -> str:
    """From the scan process itself: a direct TCP connection to TEST-NET must be refused by the OS (WSAEACCES)."""
    import socket
    s = socket.socket()
    s.settimeout(3)
    try:
        s.connect(("192.0.2.1", 80))
        return "connected"
    except socket.timeout:
        return "timeout: el SYN salió"
    except OSError as e:
        return f"blocked:{getattr(e, 'winerror', None) or e.errno}"
    finally:
        s.close()


def run_scan_inprocess(scan_id: int, worker_id: str, identities: dict | None = None) -> None:
    asyncio.run(run_scan_async(scan_id, worker_id, identities))


def run_scan(scan_id: int, worker_id: str) -> None:
    """Entry point used by the worker, the CLI and the tests.

    With ``VIGIA_SSH_TUNNEL`` a dedicated SSH tunnel (strict host-key check) is opened for this scan and closed at the
    end; with a local tunnel egress and AppContainer isolation the whole scan runs confined in its own container
    (vigia.core.scanproc); otherwise in this process."""
    from vigia.core.scanproc import run_confined, should_confine
    from vigia.security.egress import egress_override
    from vigia.security.sshtunnel import Tunnel, TunnelConfig, TunnelError
    s = get_settings()
    tunnel = None
    try:
        cfg = TunnelConfig.from_settings()
        if cfg is not None:
            if s.http_proxy:
                raise TunnelError("Configura VIGIA_SSH_TUNNEL o VIGIA_HTTP_PROXY, no ambos")
            tunnel = Tunnel(cfg).start(s.data_dir / "workspaces" / f"scan-{scan_id}")
            _event(scan_id, "info", f"Túnel SSH establecido con {cfg.display} (identidad del servidor verificada contra "
                                    f"{cfg.known_hosts.name}); se cerrará al terminar el análisis")
    except TunnelError as e:
        _event(scan_id, "error", f"Escaneo rechazado antes de contactar con ningún objetivo: {e}")
        queue.finish(scan_id, worker_id, "failed", error=str(e))
        _audit("scan.refused", target=f"scan:{scan_id}", details={"reason": str(e)}, severity="warn")
        return
    try:
        with egress_override(tunnel.socks_url if tunnel else None):
            ok, _why = should_confine(scan_id)
            if ok:
                run_confined(scan_id, worker_id)
            else:
                run_scan_inprocess(scan_id, worker_id)
    finally:
        if tunnel is not None:
            alive = tunnel.alive
            tunnel.stop()
            _event(scan_id, "info", "Túnel SSH cerrado" + ("" if alive else " (se había caído durante el análisis: "
                                                           "el escaneo se detuvo sin conexión directa)"))


def _event(scan_id: int, level: str, message: str) -> None:
    from vigia.db import ScanEvent, SessionLocal, utcnow
    with SessionLocal() as db:
        db.add(ScanEvent(scan_id=scan_id, ts=utcnow(), level=level, module="egress", message=message))
        db.commit()
