"""Preventive network isolation policy for scans that use a dedicated egress (``VIGIA_EGRESS_ISOLATION``).

Modes:
  * ``auto`` (default) — ``appcontainer`` on Windows, ``external`` elsewhere;
  * ``appcontainer`` — every engine and Chromium run inside Vigía's network-less AppContainer (loopback only, enforced
    by the Windows Filtering Platform before any packet leaves). Verified per scan with an in-container probe;
  * ``external`` — the operator provides the isolation (Linux network namespace / container with only the tunnel,
    or firewall rules). Verified per scan with the same probe run as a normal process: direct TCP, UDP and OS DNS
    must fail;
  * ``detect`` — explicit opt-out: no preventive isolation, only the kill switch (detective). The panel and every scan
    say so; it is never reported as protected.

If the selected preventive mode does not verify, the scan is refused before touching any target.
What this does *not* cover in ``appcontainer`` mode: Vigía's own process (native modules + gateway). Its traffic is
forced through the gateway by code and tested, but not confined by the OS — see docs/06-auditoria-red.md.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from vigia.config import get_settings

MODES = ("auto", "appcontainer", "external", "detect")


def resolve_mode(setting: str | None = None) -> str:
    m = (setting or get_settings().egress_isolation or "auto").strip().lower()
    if m not in MODES:
        m = "auto"
    if m == "auto":
        return "appcontainer" if sys.platform == "win32" else "external"
    return m


def _status_file() -> Path:
    return get_settings().data_dir / "isolation-status.json"


def check(setting: str | None = None, workdir: Path | None = None) -> dict:
    """Run the isolation probe for the configured mode and persist the result for the privacy panel."""
    mode = resolve_mode(setting)
    res: dict = {"mode": mode, "ts": time.time(), "platform": sys.platform, "preventive": mode != "detect"}
    if mode == "detect":
        res.update(ok=False, verified=False,
                   detail="Sin aislamiento preventivo (VIGIA_EGRESS_ISOLATION=detect): solo el kill switch detectivo")
    else:
        from vigia.security import appcontainer as ac
        wd = (workdir or get_settings().data_dir / "workspaces" / "_isolation") / str(int(time.time() * 1000))
        python = str(Path(sys._base_executable).resolve())  # type: ignore[attr-defined]
        inside = mode == "appcontainer" and ac.in_container()  # confined worker: the probe inherits its container
        res["confined_worker"] = inside
        try:
            if mode == "appcontainer" and not inside:
                ac.container()
            out = ac.self_test(python, wd, contained=(mode == "appcontainer" and not inside))
        except Exception as e:  # noqa: BLE001 - any failure means "not verified"
            out = {"ok": False, "results": {}, "detail": f"{type(e).__name__}: {e}"}
        res.update(ok=bool(out.get("ok")), verified=bool(out.get("ok")), results=out.get("results", {}),
                   detail=out.get("detail", ""))
        try:
            import shutil
            shutil.rmtree(wd, ignore_errors=True)
        except OSError:
            pass
    try:
        _status_file().write_text(json.dumps(res, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass
    return res


def last_status() -> dict | None:
    try:
        return json.loads(_status_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
