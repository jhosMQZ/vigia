"""Registry of external engines: discovery, version detection and version policy (deny-list).

The registry never pretends an engine exists: status is derived from an executable that was actually
found and a version string that was actually printed by it.
"""
from __future__ import annotations

import json
import re
import shutil
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from vigia.config import get_settings
from vigia.core.toolrunner import RunLimits, ToolRunner

IS_WINDOWS = sys.platform == "win32"
EXE = ".exe" if IS_WINDOWS else ""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    title: str
    category: str  # recon | dast | sast | secrets | sca | iac | tls | infra
    license: str
    kind: str  # binary | python | daemon | script
    binaries: tuple[str, ...]
    version_args: tuple[str, ...] = ("--version",)
    version_regex: str = r"(\d+\.\d+(?:\.\d+)?)"
    denylist: dict[str, str] = field(default_factory=dict)  # version -> reason
    min_version: str | None = None
    lab_only: bool = False
    notes: str = ""
    py_module: str | None = None  # python engines whose entry point is not a native .exe on Windows
    inherit_env: tuple[str, ...] = ()  # documented, non-secret variables an engine cannot run without


TOOLS: dict[str, ToolSpec] = {t.name: t for t in (
    ToolSpec("nmap", "Nmap", "infra", "NPSL (proceso externo, no se redistribuye)", "binary", ("nmap",),
             ("--version",), r"Nmap version (\d+\.\d+)",
             notes="Requiere instalación del usuario (y Npcap en Windows). Vigía incluye un escáner TCP connect propio."),
    ToolSpec("nuclei", "Nuclei", "dast", "MIT", "binary", ("nuclei",), ("-version",), r"Engine Version:\s*v?(\d+\.\d+\.\d+)",
             min_version="3.0.0"),
    ToolSpec("zap", "ZAP by Checkmarx", "dast", "Apache-2.0", "daemon", (), notes="Se integra vía API REST de un demonio ZAP."),
    ToolSpec("opengrep", "Opengrep", "sast", "LGPL-2.1", "binary", ("opengrep",), ("--version",), r"(\d+\.\d+\.\d+)",
             inherit_env=("USERPROFILE",) if IS_WINDOWS else (),
             notes="En Windows el binario aborta (0xC0000409) si USERPROFILE no es el perfil real; solo se hereda esa variable."),
    ToolSpec("semgrep", "Semgrep CE", "sast", "LGPL-2.1 (motor); reglas con licencia propia", "binary", ("semgrep",),
             ("--version",), r"(\d+\.\d+\.\d+)", notes="Vigía no redistribuye reglas de Semgrep."),
    ToolSpec("trivy", "Trivy", "sca", "Apache-2.0", "binary", ("trivy",), ("--version",), r"Version:\s*v?(\d+\.\d+\.\d+)",
             denylist={"0.69.4": "Release maliciosa (CVE-2026-33634, GHSA-69fq-xp46-6x23)",
                       "0.69.5": "Imagen comprometida en el incidente de marzo de 2026 (GHSA-69fq-xp46-6x23)",
                       "0.69.6": "Imagen comprometida en el incidente de marzo de 2026 (GHSA-69fq-xp46-6x23)"}),
    ToolSpec("betterleaks", "Betterleaks", "secrets", "MIT", "binary", ("betterleaks",), ("version",), r"v?(\d+\.\d+\.\d+)"),
    ToolSpec("gitleaks", "Gitleaks", "secrets", "MIT", "binary", ("gitleaks",), ("version",), r"v?(\d+\.\d+\.\d+)",
             notes="En modo mantenimiento; se prefiere Betterleaks si ambos existen."),
    ToolSpec("bandit", "Bandit", "sast", "Apache-2.0", "python", ("bandit",), ("--version",), r"bandit (\d+\.\d+\.\d+)"),
    ToolSpec("checkov", "Checkov", "iac", "Apache-2.0", "python", ("checkov",), ("--version",), r"(\d+\.\d+\.\d+)",
             py_module="checkov.main"),
    ToolSpec("sslyze", "SSLyze", "tls", "AGPL-3.0 (proceso externo)", "python", ("sslyze",), ("--help",),
             r"SSLyze version (\d+\.\d+\.\d+)|(\d+\.\d+\.\d+)"),
    ToolSpec("testssl", "testssl.sh", "tls", "GPL-2.0 (proceso externo)", "script", ("testssl.sh",), ("--version",),
             r"testssl\.sh\s+(?:version\s+)?(\d+\.\d+[\w.\-]*)", notes="Requiere bash y OpenSSL (Linux/WSL)."),
    ToolSpec("subfinder", "Subfinder", "recon", "MIT", "binary", ("subfinder",), ("-version",),
             r"Current Version:\s*v?(\d+\.\d+\.\d+)"),
    ToolSpec("ffuf", "ffuf", "recon", "MIT", "binary", ("ffuf",), ("-V",), r"ffuf version:\s*v?(\d+\.\d+\.\d+)"),
    ToolSpec("nikto", "Nikto", "dast", "GPL-2.0 (proceso externo)", "script", ("nikto", "nikto.pl"), ("-Version",),
             r"Nikto\s+(?:v)?(\d+\.\d+\.\d+)"),
    ToolSpec("metasploit", "Metasploit Framework (RPC)", "lab", "BSD-3", "daemon", (), lab_only=True,
             notes="Solo módulos auxiliary/scanner y check, en alcances marcados como laboratorio."),
)}


@dataclass
class ToolStatus:
    name: str
    title: str
    category: str
    license: str
    kind: str
    status: str  # available | missing | blocked | error | unconfigured
    version: str | None = None
    path: str | None = None
    reason: str | None = None
    lab_only: bool = False
    notes: str = ""
    argv_prefix: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _vtuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def candidate_commands(spec: ToolSpec) -> list[list[str]]:
    """Possible argv prefixes for an engine, most specific first."""
    s = get_settings()
    out: list[list[str]] = []
    if spec.kind == "python" and spec.py_module:
        py = s.tool_py_dir / spec.name / ("Scripts/python.exe" if IS_WINDOWS else "bin/python")
        if py.is_file():
            out.append([str(py), "-m", spec.py_module])
    for p in candidate_paths(spec):
        if not p.is_file():
            continue
        if p.suffix in (".sh", ".pl"):
            interp = shutil.which("bash" if p.suffix == ".sh" else "perl")
            if interp:
                out.append([interp, str(p)])
        elif not IS_WINDOWS or p.suffix.lower() == ".exe":
            out.append([str(p)])
    return out


def candidate_paths(spec: ToolSpec) -> list[Path]:
    s = get_settings()
    out: list[Path] = []
    for b in spec.binaries:
        name = b if b.endswith((".sh", ".pl")) else b + EXE
        out.append(s.tool_bin_dir / spec.name / name)
        if spec.kind == "python":
            out.append(s.tool_py_dir / spec.name / ("Scripts" if IS_WINDOWS else "bin") / name)
    if s.tool_allow_path_lookup:
        for b in spec.binaries:
            found = shutil.which(b)
            if found:
                out.append(Path(found))
    return out


class Registry:
    _cache: dict[str, tuple[float, ToolStatus]] = {}
    _lock = threading.Lock()
    TTL = 600.0

    def __init__(self) -> None:
        s = get_settings()
        import os
        probe_root = (Path(os.environ["TEMP"]) / "vigia-probe" if os.environ.get("VIGIA_CONFINED_SCAN") == "1"
                      else s.data_dir / "workspaces" / "_probe")  # a confined scan may only write its own workspace
        self.runner = ToolRunner(probe_root, RunLimits(timeout=60, max_memory_mb=1024,
                                                                                 max_output_mb=4))
        self.extra_deny = self._load_extra_denylist(s.tools_dir / "denylist.json")

    @staticmethod
    def _load_extra_denylist(path: Path) -> dict[str, dict[str, str]]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return {k: dict(v) for k, v in data.items() if isinstance(v, dict)}
        except (OSError, ValueError):
            return {}

    def status(self, name: str, refresh: bool = False) -> ToolStatus:
        with self._lock:
            hit = self._cache.get(name)
            if hit and not refresh and time.monotonic() - hit[0] < self.TTL:
                return hit[1]
        st = self._probe(TOOLS[name])
        with self._lock:
            self._cache[name] = (time.monotonic(), st)
        return st

    def all(self, refresh: bool = False) -> list[ToolStatus]:
        return [self.status(n, refresh) for n in TOOLS]

    @staticmethod
    def env_for(name: str) -> dict[str, str]:
        """Extra environment an engine needs (explicit allow-list per engine, never secrets)."""
        import os
        return {k: os.environ[k] for k in TOOLS[name].inherit_env if k in os.environ}

    def limits_for(self, name: str, **kw) -> RunLimits:  # noqa: ANN003
        s = get_settings()
        base = dict(timeout=s.tool_default_timeout, max_memory_mb=s.tool_max_memory_mb, max_output_mb=s.tool_max_output_mb)
        base.update(kw)
        lim = RunLimits(**base)
        lim.extra_env = {**self.env_for(name), **lim.extra_env}
        return lim

    def command(self, name: str) -> list[str] | None:
        """argv prefix to invoke an available engine, or None."""
        st = self.status(name)
        return list(st.argv_prefix) if st.status == "available" and st.argv_prefix else None

    def _probe(self, spec: ToolSpec) -> ToolStatus:
        base = dict(name=spec.name, title=spec.title, category=spec.category, license=spec.license, kind=spec.kind,
                    lab_only=spec.lab_only, notes=spec.notes)
        if spec.kind == "daemon":
            return self._probe_daemon(spec, base)
        for prefix in candidate_commands(spec):
            path = prefix[-1] if prefix[-2:-1] != ["-m"] else prefix[0]
            res = self.runner.run(f"probe-{spec.name}", [*prefix, *spec.version_args],
                                  limits=RunLimits(timeout=180 if spec.kind == "python" else 60,
                                                   max_memory_mb=1024, max_output_mb=4,
                                                   extra_env=self.env_for(spec.name)))
            out = (res.stdout + b"\n" + res.stderr).decode("utf-8", errors="replace")
            if res.workdir:
                self.runner.cleanup(res.workdir)
            m = re.search(spec.version_regex, out)
            if not m:
                return ToolStatus(**base, status="error", path=path,
                                  reason=f"No se pudo determinar la versión ({res.status}: {out.strip()[:160]})")
            version = next((g for g in m.groups() if g), m.group(0))
            deny = {**spec.denylist, **self.extra_deny.get(spec.name, {})}
            if version in deny:
                return ToolStatus(**base, status="blocked", version=version, path=path,
                                  reason=f"Versión bloqueada: {deny[version]}")
            if spec.min_version and _vtuple(version) < _vtuple(spec.min_version):
                return ToolStatus(**base, status="blocked", version=version, path=path,
                                  reason=f"Versión inferior a la mínima soportada ({spec.min_version})")
            return ToolStatus(**base, status="available", version=version, path=path, argv_prefix=prefix)
        return ToolStatus(**base, status="missing", reason="No instalado (ver `vigia tools install`)")

    def _probe_daemon(self, spec: ToolSpec, base: dict) -> ToolStatus:
        s = get_settings()
        if spec.name == "zap":
            from vigia.tools.zap import local_install, local_version, zap_version
            if not s.zap_api_url:
                inst = local_install()
                if inst:
                    return ToolStatus(**base, status="available", version=local_version(), path=str(inst[1]),
                                      reason="Demonio local bajo demanda (JRE incluido)", argv_prefix=[str(inst[0])])
                return ToolStatus(**base, status="unconfigured",
                                  reason="Instala ZAP (vigia tools install zap jre) o define VIGIA_ZAP_API_URL")
            try:
                v = zap_version(s.zap_api_url, s.zap_api_key)
                return ToolStatus(**base, status="available", version=v, path=s.zap_api_url)
            except Exception as e:  # noqa: BLE001 - report the real error to the operator
                return ToolStatus(**base, status="error", path=s.zap_api_url, reason=f"ZAP no responde: {e}")
        return ToolStatus(**base, status="unconfigured", reason="Integración solo para laboratorio (fase 12)")


_registry: Registry | None = None


def get_registry() -> Registry:
    global _registry
    if _registry is None:
        _registry = Registry()
    return _registry
