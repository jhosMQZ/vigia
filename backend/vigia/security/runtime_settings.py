"""Privacy settings editable from the UI (admin only), persisted in ``data/settings.json``.

Only a whitelist of egress/privacy keys can be stored here. Environment variables always win (a key set as
``VIGIA_<KEY>`` is reported as "env" and cannot be changed from the UI), so a deployment pinned by configuration
management cannot be weakened from the browser. Every value is validated before it is saved; changes apply to new
scans.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

EDITABLE: dict[str, type] = {
    "http_proxy": str, "ssh_tunnel": str, "ssh_known_hosts": str, "ssh_identity": str, "dns_resolver": str,
    "egress_isolation": str, "egress_check_url": str, "require_proxy": bool, "confine_worker": bool,
    "egress_kill_switch": bool,
}


class SettingsError(ValueError):
    pass


def _path() -> Path:
    from vigia.config import HOME
    data = Path(os.environ.get("VIGIA_DATA_DIR") or (HOME / "data"))
    if not data.is_absolute():
        data = HOME / data
    return data / "settings.json"


def load() -> dict[str, Any]:
    try:
        raw = json.loads(_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in raw.items() if k in EDITABLE and isinstance(v, (EDITABLE[k], type(None)))}


def env_locked(key: str) -> bool:
    return f"VIGIA_{key.upper()}" in os.environ


def validate(values: dict[str, Any]) -> dict[str, Any]:
    from vigia.security.egress import ProxyError, validate_proxy
    from vigia.security.isolation import MODES
    from vigia.security.sshtunnel import DEST_RE
    out: dict[str, Any] = {}
    for k, v in values.items():
        if k not in EDITABLE:
            raise SettingsError(f"«{k}» no se puede modificar desde la interfaz")
        if env_locked(k):
            raise SettingsError(f"«{k}» está fijado por la variable de entorno VIGIA_{k.upper()}")
        if v in ("", None):
            out[k] = None
            continue
        if not isinstance(v, EDITABLE[k]):
            raise SettingsError(f"Valor no válido para «{k}»")
        if k == "http_proxy":
            try:
                validate_proxy(v)
            except ProxyError as e:
                raise SettingsError(str(e)) from e
        elif k == "ssh_tunnel" and not DEST_RE.match(v.strip()):
            raise SettingsError("El túnel SSH debe tener la forma usuario@servidor[:puerto]")
        elif k in ("ssh_known_hosts", "ssh_identity") and not Path(v).is_file():
            raise SettingsError(f"No existe el fichero {v}")
        elif k == "dns_resolver" and not (v in ("auto", "system") or re.match(r"^https://[^\s/]+/\S*$", v)
                                          or re.match(r"^tcp://[0-9A-Fa-f:.\[\]]+(:\d{1,5})?$", v)):
            raise SettingsError("Resolutor DNS: usa auto, system, https://…/dns-query o tcp://IP:53")
        elif k == "egress_isolation" and v not in MODES:
            raise SettingsError(f"Modo de aislamiento no válido (usa {', '.join(MODES)})")
        elif k == "egress_check_url" and not re.match(r"^https://\S+$", v):
            raise SettingsError("El endpoint de eco de IP debe ser https://")
        out[k] = v.strip() if isinstance(v, str) else v
    return out


def save(values: dict[str, Any]) -> dict[str, Any]:
    clean = validate(values)
    current = load()
    current.update(clean)
    current = {k: v for k, v in current.items() if v is not None}
    if current.get("http_proxy") and current.get("ssh_tunnel"):
        raise SettingsError("Elige un único tipo de salida: túnel SSH gestionado o proxy, no ambos")
    if current.get("ssh_tunnel") and not (current.get("ssh_known_hosts") or env_locked("ssh_known_hosts")):
        raise SettingsError("El túnel SSH necesita el fichero de claves conocidas del servidor (known_hosts)")
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(current, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(p)
    from vigia.config import get_settings
    from vigia.security.resolver import reset_default_resolver
    get_settings.cache_clear()
    reset_default_resolver()
    return current


def describe() -> list[dict[str, Any]]:
    from vigia.config import get_settings
    s = get_settings()
    stored = load()
    out = []
    for k in EDITABLE:
        source = "env" if env_locked(k) else ("ui" if k in stored else "default")
        val = getattr(s, k)
        if k == "http_proxy" and val:
            from vigia.security.egress import ProxyError, Upstream
            try:
                val = Upstream.parse(val).display  # never return proxy credentials
            except ProxyError:
                val = "(no válido)"
        out.append({"key": k, "value": val, "source": source, "editable": source != "env"})
    return out
