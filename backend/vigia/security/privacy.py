"""Aggregated, real privacy/isolation status for the privacy panel. Reports facts, never claims anonymity."""
from __future__ import annotations

import sys

from vigia.config import get_settings
from vigia.security.egress import egress_status

IS_WINDOWS = sys.platform == "win32"


def privacy_status(check_egress_ip: bool = False) -> dict:
    s = get_settings()
    egress = egress_status(check_ip=check_egress_ip)
    browser_ok, browser_reason = _browser()
    st = {
        "egress": egress.to_dict(),
        "dns": _dns(s),
        "visibility": _visibility(s),
        "engines_egress": _engines_egress(),
        "isolation": _isolation(s),
        "tunnel": tunnel_info(),
        "last_check": (check_history(1) or [None])[0],
        "kill_switch": {"enabled": s.egress_kill_switch,
                        "detail": "Detectivo: sondea los sockets de cada motor cada 0,2 s y mata el árbol de procesos si "
                                  "ve TCP/UDP fuera de loopback. Complementa al aislamiento preventivo; no lo sustituye."},
        "leaks": _recent_leaks(),
        "last_audit": _last_audit(s),
        "protection": None,  # filled below
        "worker_isolation": {
            "platform": sys.platform,
            "process": "Job Object con KILL_ON_JOB_CLOSE y límite de memoria; el árbol de procesos muere al terminar"
                       if IS_WINDOWS else "setrlimit (memoria/CPU/descriptores) + sesión nueva + PR_SET_PDEATHSIG",
            "filesystem": "HOME, TEMP y la configuración del motor se redirigen a un sandbox por ejecución. "
                          + ("En este host no hay aislamiento del sistema de ficheros por ruta absoluta: para un "
                             "aislamiento fuerte, ejecuta los workers en el contenedor sin root del despliegue."
                             if IS_WINDOWS else "Ejecuta en contenedor sin root para aislamiento completo."),
            "environment": "Entorno mínimo: el proceso del motor no hereda secretos (claves, tokens) ni proxies.",
            "cleanup": "Los sandboxes de los motores se borran al terminar cada escaneo; los workspaces caducan a las "
                       f"{s.workspace_retention_hours} h y las evidencias a los {s.evidence_retention_days} días.",
        },
        "network_scope": {
            "always_blocked": ["metadatos cloud (169.254.169.254 y equivalentes)", "rangos reservados y link-local",
                               "servicios de terceros", "los puertos de la propia plataforma"],
            "private_targets": "permitidos" if s.allow_private_targets else "bloqueados (VIGIA_ALLOW_PRIVATE_TARGETS)",
            "every_request_checked": True,
            "egress_gateway": "Todos los motores (y, con salida dedicada, todos los sockets nativos) pasan por la pasarela "
                              "loopback, que vuelve a aplicar el alcance y solo conecta a través de la salida.",
            "kill_switch": s.egress_kill_switch,
            "connection_trace": "Cada petición, redirección e IP resuelta queda en http-trace.jsonl del escaneo.",
        },
        "data_protection": {
            "redaction": True,
            "redacted": ["contraseñas", "API keys", "tokens", "cookies", "JWT", "claves privadas",
                         "cadenas de conexión", "datos en cabeceras sensibles"],
            "credentials_at_rest": "Las cuentas de prueba se cifran con Fernet (clave en data/keys o "
                                   "VIGIA_MASTER_KEY).",
            "identity_to_model": "Vigía no envía tu actividad ni los secretos a ningún modelo; las evidencias se "
                                 "almacenan ya redactadas.",
        },
        "browser": {
            "available": browser_ok,
            "detail": "Navegador efímero: sin cookies, extensiones, sesiones ni perfil personal; cada petición del "
                      "navegador pasa por el control de alcance." if browser_ok else browser_reason,
            "enabled": s.browser_enabled,
        },
        "identity_note": "Vigía se identifica ante el objetivo con su User-Agent y no falsifica el origen. No existe "
                         "anonimato absoluto: el objetivo ve la IP de salida (la del proxy, si está configurado) y que "
                         "la herramienta es Vigía. Esto es lo correcto en una auditoría autorizada.",
    }
    st["protection"] = protection_summary(st)
    return st


def _dns(s) -> dict:  # noqa: ANN001
    try:
        from vigia.security.resolver import build_resolver
        r = build_resolver(s.dns_resolver, s.http_proxy)
    except Exception as e:  # noqa: BLE001
        return {"resolution": "error", "remote": False, "detail": f"VIGIA_DNS_RESOLVER inválido: {e}"}
    if r.remote:
        return {"resolution": "remote", "remote": True, "resolver": r.description,
                "detail": "Los nombres de los objetivos se resuelven con DoH/DNS-TCP a través de la salida, con ECS 0/0. "
                          "Si el resolutor remoto falla no se recurre al DNS local. Los motores usan el stub DNS de la "
                          "pasarela (solo nombres en alcance)."}
    warn = " Con salida dedicada esto es una fuga: tu proveedor de DNS ve cada objetivo." if s.http_proxy else ""
    return {"resolution": "local", "remote": False, "resolver": r.description,
            "detail": "Resolución con el resolutor del sistema (normalmente el de tu proveedor de Internet)." + warn}


def _visibility(s) -> dict:  # noqa: ANN001
    from vigia.security.egress import ProxyError, Upstream, visibility
    try:
        up = Upstream.parse(s.http_proxy) if s.http_proxy else None
    except ProxyError:
        up = None
    d = _dns(s)
    return visibility(up, bool(d.get("remote")), d.get("resolver", "?"))


STATES = {1: "Compatible con proxy y verificado", 2: "Compatible parcialmente",
          3: "Bloqueado cuando se exige proxy", 4: "Disponible solo en modo directo"}

# Evidence = automated tests that observe the result from the target's side (tests/privacy).
ENGINE_MATRIX = [
    ("Cliente HTTP nativo", [1], "Pasarela (nombre → IP fijada), SNI conservado, redirecciones controladas.",
     "AppContainer del escaneo con túnel local; por código con proxy remoto",
     "test_native_http_tcp_tls_dns_all_leave_through_egress, test_whole_scan_runs_confined_and_only_the_egress_reaches_the_target"),
    ("Puertos, banners, TLS nativo, AXFR", [1], "SOCKS5 a la pasarela con credenciales.",
     "AppContainer del escaneo con túnel local; por código con proxy remoto",
     "test_native_http_tcp_tls_dns_all_leave_through_egress"),
    ("Chromium / Playwright", [1], "Chromium dentro del AppContainer (CDP por tuberías), pasarela, sin DNS local, sin "
     "QUIC, API WebRTC eliminada.", "AppContainer (preventivo)", "test_isolated_chromium_hostile_page"),
    ("ffuf", [1], "-x a la pasarela.", "AppContainer (preventivo)", "test_isolated_ffuf_reaches_target_only_through_gateway"),
    ("sslyze", [1], "--https_tunnel a la pasarela.", "AppContainer (preventivo)", "test_isolated_sslyze_through_gateway"),
    ("subfinder", [2], "Carril público de la salida + stub DNS; no contacta objetivos. Su funcionamiento contra fuentes "
     "reales no se ha probado (no se usan servicios de terceros en las pruebas).", "AppContainer (preventivo)",
     "arranque verificado dentro del contenedor"),
    ("ZAP", [2, 3], "Salida por la pasarela verificada, pero la JVM no puede ejecutarse en el AppContainer sin "
     "administrador: bloqueado con aislamiento obligatorio; disponible con VIGIA_EGRESS_ISOLATION=detect o sin salida.",
     "no aislable sin administrador", "test_zap_daemon_through_gateway_with_kill_switch"),
    ("Nuclei", [3, 4], "Sus plantillas tcp y peticiones raw conectan directamente aunque se use -proxy.", "—",
     "auditoría de red (tap del objetivo vio la IP doméstica)"),
    ("Nmap", [3, 4], "El escáner de puertos ignora --proxies.", "—", "documentación de Nmap"),
    ("testssl.sh", [3, 4], "Sockets propios y DNS con herramientas locales.", "—", "análisis del motor"),
    ("opengrep", [2], "Sin red; no puede ejecutarse en el AppContainer: bloqueado si el escaneo tiene objetivos y "
     "salida con aislamiento obligatorio. Sin salida funciona igual que antes.", "no aislable", "prueba manual en el "
     "contenedor ('{HOME}')"),
    ("trivy, gitleaks, betterleaks, bandit, checkov", [1], "Sin red esperada; variables de proxy al carril público.",
     "AppContainer (preventivo)", "test_isolated_code_engine_still_works y pruebas manuales en el contenedor"),
    ("Servicios externos (OSV/NVD/KEV, crt.sh, instalador)", [2], "Carril público de un solo uso (credenciales + "
     "atribución), cerrado al terminar; extremo a extremo no probado contra los servicios reales.",
     "proceso de Vigía: confinado por código", "test_single_use_public_lane_closes_with_its_client"),
]


def _engines_egress() -> list[dict]:
    return [{"engine": n, "states": st, "state_labels": [STATES[x] for x in st], "detail": d, "isolation": iso,
             "evidence": ev} for n, st, d, iso, ev in ENGINE_MATRIX]


def _isolation(s) -> dict:  # noqa: ANN001
    from vigia.security.isolation import last_status, resolve_mode
    mode = resolve_mode(s.egress_isolation)
    last = last_status()
    return {"mode": mode, "preventive": mode != "detect", "last_check": last,
            "verified": bool(last and last.get("ok") and last.get("mode") == mode),
            "worker_confined": _worker_confinable(s),
            "scope": (("Todo el escaneo (proceso de Vigía, pasarela, módulos nativos, motores y Chromium) se ejecuta en "
                       "un AppContainer propio por escaneo: el sistema solo permite loopback hacia el túnel local."
                       if _worker_confinable(s) else
                       "Motores externos y Chromium confinados en un AppContainer sin red (solo loopback hacia la "
                       "pasarela). El proceso de Vigía no está confinado por el SO: la salida no es un túnel local "
                       "(proxy remoto) o VIGIA_CONFINE_WORKER=false.")
                      if mode == "appcontainer" else
                      "Aislamiento externo (cortafuegos o espacio de nombres de red) verificado con la sonda."
                      if mode == "external" else "Sin aislamiento preventivo: solo detección."),
            "detail": "Con salida dedicada, un escaneo se rechaza si este aislamiento no se verifica en ese momento."}


def _worker_confinable(s) -> bool:  # noqa: ANN001
    import sys as _sys

    from vigia.security.egress import ProxyError, Upstream
    from vigia.security.isolation import resolve_mode
    if _sys.platform != "win32" or not s.confine_worker or not s.http_proxy:
        return False
    try:
        return Upstream.parse(s.http_proxy).transport == "loopback" and resolve_mode(s.egress_isolation) == "appcontainer"
    except ProxyError:
        return False


def _recent_leaks(limit: int = 20) -> dict:
    try:
        from vigia.db import ScanEvent, SessionLocal
        with SessionLocal() as db:
            rows = (db.query(ScanEvent).filter(ScanEvent.module == "egress", ScanEvent.level == "error")
                    .order_by(ScanEvent.id.desc()).limit(limit).all())
            items = [{"scan_id": r.scan_id, "ts": r.ts.isoformat() if r.ts else None, "message": r.message}
                     for r in rows if "Kill switch" in (r.message or "")]
    except Exception:  # noqa: BLE001
        items = []
    return {"count": len(items), "recent": items[:5]}


def _last_audit(s) -> dict | None:  # noqa: ANN001
    import json
    try:
        data = json.loads((s.data_dir / "reports" / "netaudit-latest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    obs = data.get("observed", {})
    return {"ts": data.get("ts"), "profile": data.get("profile"),
            "target_connections": obs.get("target_connections"),
            "home_ip_seen_by_target": len(obs.get("home_ip_seen_by_target") or []),
            "names_sent_to_egress_provider": len(obs.get("names_sent_to_egress_provider") or []),
            "local_lookups_of_target_names": len(obs.get("local_lookups_of_target_names") or []),
            "ok": data.get("ok")}


def protection_summary(st: dict) -> dict:
    """Overall level. Never 'complete' while any limitation applies."""
    e, iso, dns = st["egress"], st["isolation"], st["dns"]
    limits = []
    if not e["configured"]:
        return {"level": "none", "label": "Sin salida dedicada: el objetivo ve tu IP doméstica", "limitations": [
            "No hay túnel SSH ni proxy de salida configurado (Configuración → Conexión protegida)"]}
    if e.get("reachable") is not True:
        limits.append("la salida no responde (los escaneos se rechazan)")
    if not dns.get("remote"):
        limits.append("DNS de objetivos local")
    if e.get("transport") == "plaintext":
        limits.append("proxy en claro: tu ISP ve destinos y peticiones")
    if not iso["preventive"]:
        limits.append("sin aislamiento preventivo (modo detect)")
    elif not iso["verified"]:
        limits.append("aislamiento preventivo aún no verificado en este equipo")
    if iso["mode"] == "appcontainer" and not iso.get("worker_confined"):
        limits.append("el proceso de Vigía no está confinado por el SO (proxy remoto: solo por código)")
    if iso["mode"] == "appcontainer":
        limits.append("ZAP y opengrep no pueden ejecutarse aislados sin administrador (se bloquean)")
    if not st["kill_switch"]["enabled"]:
        limits.append("kill switch desactivado")
    if st["leaks"]["count"]:
        limits.append(f"{st['leaks']['count']} intentos de salida directa detectados recientemente")
    la = st.get("last_audit")
    if not la:
        limits.append("no hay auditoría de red registrada")
    elif la.get("home_ip_seen_by_target") or la.get("names_sent_to_egress_provider"):
        limits.append("la última auditoría detectó fugas")
    blocking = [x for x in limits if "no responde" in x or "fugas" in x or "en claro" in x or "local" in x]
    level = "complete" if not limits else ("partial" if not blocking else "weak")
    label = {"complete": "Protección verificada sin limitaciones conocidas",
             "partial": "Protección parcial: ver limitaciones", "weak": "Protección insuficiente"}[level]
    return {"level": level, "label": label, "limitations": limits}


def _browser() -> tuple[bool, str]:
    try:
        from vigia.tools.browser import availability
        return availability()
    except Exception as e:  # noqa: BLE001
        return False, f"no disponible: {e}"


# ---------------------------------------------------------------------------------------------- on-demand verification
def _checks_file():  # noqa: ANN202
    return get_settings().data_dir / "privacy-checks.jsonl"


def run_check() -> dict:
    """Verify, right now, what a scan would rely on: preventive isolation, the egress (opening the managed SSH tunnel
    with strict host-key verification, or reaching the proxy) and remote DNS through it. Recorded for the history."""
    import asyncio
    import json
    import time

    from vigia.security.egress import configured_upstream, egress_override, observe_egress_ip
    from vigia.security.isolation import check as isolation_check
    from vigia.security.resolver import build_resolver
    from vigia.security.sshtunnel import Tunnel, TunnelConfig, TunnelError
    s = get_settings()
    res: dict = {"ts": time.time(), "isolation": isolation_check(), "egress": None, "dns": None, "observed_ip": None}
    wd = s.data_dir / "workspaces" / "_privacy-check"
    tunnel = None
    try:
        cfg = TunnelConfig.from_settings()
        if cfg is not None:
            tunnel = Tunnel(cfg).start(wd)
            res["egress"] = {"ok": True, "kind": "ssh", "detail": f"Túnel SSH establecido con {cfg.display}; identidad "
                                                                  "del servidor verificada"}
        elif s.http_proxy:
            from vigia.security.egress import proxy_reachable
            ok, detail = proxy_reachable(s.http_proxy)
            res["egress"] = {"ok": ok, "kind": "proxy", "detail": detail}
        else:
            res["egress"] = {"ok": False, "kind": "none", "detail": "Sin salida dedicada: el objetivo vería tu IP"}
        if res["egress"]["ok"]:
            with egress_override(tunnel.socks_url if tunnel else None):
                up = configured_upstream()
                r = build_resolver(s.dns_resolver, up)
                try:
                    asyncio.run(asyncio.wait_for(r.selftest(), 25))
                    res["dns"] = {"ok": bool(getattr(r, "remote", False)), "detail": r.description}
                except Exception as e:  # noqa: BLE001
                    res["dns"] = {"ok": False, "detail": f"{r.description}: {e}"}
                if s.egress_check_url:
                    res["observed_ip"] = observe_egress_ip()
    except TunnelError as e:
        res["egress"] = {"ok": False, "kind": "ssh", "detail": str(e)}
    finally:
        if tunnel is not None:
            tunnel.stop()
    res["ok"] = bool(res["isolation"].get("ok") and (res["egress"] or {}).get("ok") and (res["dns"] or {}).get("ok"))
    try:
        p = _checks_file()
        lines = p.read_text(encoding="utf-8").splitlines()[-49:] if p.exists() else []
        lines.append(json.dumps(res, ensure_ascii=False, default=str))
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError:
        pass
    return res


def check_history(limit: int = 20) -> list[dict]:
    import json
    try:
        lines = _checks_file().read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for line in reversed(lines[-limit:]):
        try:
            d = json.loads(line)
        except ValueError:
            continue
        out.append({"ts": d.get("ts"), "ok": d.get("ok"), "isolation": (d.get("isolation") or {}).get("ok"),
                    "egress": d.get("egress"), "dns": d.get("dns"), "observed_ip": d.get("observed_ip")})
    return out


def tunnel_info() -> dict:
    from vigia.security.sshtunnel import TunnelConfig, TunnelError, ssh_binary
    try:
        cfg = TunnelConfig.from_settings()
    except TunnelError as e:
        return {"configured": True, "ok": False, "detail": str(e)}
    if cfg is None:
        return {"configured": False, "ssh_client": bool(ssh_binary())}
    return {"configured": True, "destination": cfg.display, "known_hosts": str(cfg.known_hosts),
            "known_hosts_exists": cfg.known_hosts.exists(), "host_key_registered": cfg.known_host_entry(),
            "identity": bool(cfg.identity), "ssh_client": bool(ssh_binary())}
