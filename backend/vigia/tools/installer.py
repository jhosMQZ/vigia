"""Supply-chain-aware installer for external engines.

* Binaries: downloaded over verified TLS from the pinned release URL only (redirects restricted to GitHub
  release hosts), size and SHA-256 checked against ``manifest.json`` before anything is extracted;
  archives are unpacked with the safe extractor; only the executable and licence files are kept.
* Python engines: one isolated virtualenv per engine under ``tools/py/<name>``, installed from a lock
  file with ``--require-hashes`` (every wheel/sdist hash pinned).
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

import httpx

from vigia.config import get_settings
from vigia.security.extract import Limits, force_rmtree, safe_extract_tar, safe_extract_zip

MANIFEST = Path(__file__).with_name("manifest.json")
LOCKS = Path(__file__).with_name("locks")
ALLOWED_DOWNLOAD_HOSTS = {"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com",
                          "github-releases.githubusercontent.com"}
# name -> (console script, module used when the console script is not a native executable)
PYTHON_TOOLS = {"bandit": ("bandit", None), "checkov": ("checkov", "checkov.main"), "sslyze": ("sslyze", None),
                "pip-audit": ("pip-audit", None)}


class InstallError(Exception):
    pass


def platform_key() -> str:
    osname = {"win32": "windows", "linux": "linux", "darwin": "darwin"}.get(sys.platform, sys.platform)
    mach = platform.machine().lower()
    arch = {"amd64": "amd64", "x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(mach, mach)
    return f"{osname}-{arch}"


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def _download(url: str, dest: Path, expected_size: int, expected_sha: str, log: Callable[[str], None]) -> None:
    if urlsplit(url).hostname not in ALLOWED_DOWNLOAD_HOSTS or not url.startswith("https://"):
        raise InstallError(f"URL de descarga no permitida: {url}")
    h = hashlib.sha256()
    size = 0
    part = dest.with_suffix(dest.suffix + ".part")
    from vigia.security.egress import egress_client
    with egress_client(verify=True, follow_redirects=False,
                       timeout=httpx.Timeout(60, connect=20)) as client:  # via a single-use egress gateway if configured
        current = url
        for _ in range(5):
            with client.stream("GET", current) as resp:
                if resp.status_code in (301, 302, 303, 307, 308):
                    nxt = resp.headers.get("location", "")
                    if not nxt.startswith("https://") or urlsplit(nxt).hostname not in ALLOWED_DOWNLOAD_HOSTS:
                        raise InstallError(f"Redirección a un host no permitido: {urlsplit(nxt).hostname}")
                    current = nxt
                    continue
                if resp.status_code != 200:
                    raise InstallError(f"HTTP {resp.status_code} al descargar {url}")
                with open(part, "wb") as fh:
                    for chunk in resp.iter_bytes(1 << 16):
                        size += len(chunk)
                        if size > expected_size:
                            raise InstallError("El artefacto supera el tamaño fijado en el manifiesto")
                        h.update(chunk)
                        fh.write(chunk)
                break
        else:
            raise InstallError("Demasiadas redirecciones")
    if size != expected_size:
        part.unlink(missing_ok=True)
        raise InstallError(f"Tamaño inesperado: {size} != {expected_size}")
    digest = h.hexdigest()
    if digest != expected_sha.lower():
        part.unlink(missing_ok=True)
        raise InstallError(f"SHA-256 NO coincide (esperado {expected_sha}, obtenido {digest}). Instalación abortada.")
    part.replace(dest)
    log(f"  verificado SHA-256 {digest[:16]}… ({size / 1048576:.1f} MB)")


def install_binary(name: str, log: Callable[[str], None] = print, force: bool = False) -> Path:
    s = get_settings()
    manifest = load_manifest()
    tool = manifest["tools"].get(name)
    if not tool:
        raise InstallError(f"{name} no está en el manifiesto")
    if tool.get("kind") == "git":
        return install_git(name, tool, log, force)
    plat = platform_key()
    art = tool["platforms"].get(plat) or tool["platforms"].get("any")
    if not art:
        raise InstallError(f"{name} no tiene artefacto fijado para {plat}")
    target_dir = s.tool_bin_dir / name
    marker = target_dir / ".vigia-install.json"
    if marker.exists() and not force:
        info = json.loads(marker.read_text(encoding="utf-8"))
        if info.get("sha256") == art["sha256"]:
            log(f"{name} {tool['version']} ya instalado")
            return target_dir / art["binary"]
    log(f"Instalando {name} {tool['version']} ({plat})")
    cache = s.data_dir / "cache" / "downloads"
    cache.mkdir(parents=True, exist_ok=True)
    fname = Path(urlsplit(art["url"]).path).name
    blob = cache / f"{art['sha256'][:16]}-{fname}"
    if not blob.exists():
        _download(art["url"], blob, art["size"], art["sha256"], log)
    else:  # re-verify cached artefact
        if hashlib.sha256(blob.read_bytes()).hexdigest() != art["sha256"]:
            blob.unlink()
            raise InstallError("El artefacto en caché no coincide con el SHA-256; se eliminó. Repite la instalación.")
    with tempfile.TemporaryDirectory(dir=cache) as tmpd:
        tmp = Path(tmpd)
        lim = Limits(max_files=20000, max_total_bytes=2048 * 1024 * 1024, max_file_bytes=900 * 1024 * 1024,
                     max_ratio=1000)
        if fname.endswith(".zip"):
            safe_extract_zip(blob, tmp / "x", lim, skip_dirs=set())
        elif fname.endswith((".tar.gz", ".tgz")):
            safe_extract_tar(blob, tmp / "x", lim)
        else:
            (tmp / "x").mkdir()
            shutil.copyfile(blob, tmp / "x" / art["binary"])
        found = [p for p in (tmp / "x").rglob("*") if p.is_file() and p.name.lower() == art["binary"].lower()]
        if len(found) != 1:
            raise InstallError(f"No se encontró un único ejecutable {art['binary']} dentro del artefacto")
        if target_dir.exists():
            force_rmtree(target_dir)
        if tool.get("kind") == "archive":
            # full distribution (e.g. ZAP, JRE): keep the directory that contains the entry point
            root = found[0].parent
            if name == "jre" and root.name == "bin":
                root = root.parent
            shutil.copytree(root, target_dir)
            exe = next(p for p in target_dir.rglob("*") if p.is_file() and p.name.lower() == art["binary"].lower())
        else:
            target_dir.mkdir(parents=True)
            shutil.copyfile(found[0], target_dir / art["binary"])
            for lic in (tmp / "x").rglob("*"):
                if lic.is_file() and lic.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE")):
                    shutil.copyfile(lic, target_dir / lic.name)
            exe = target_dir / art["binary"]
    if os.name != "nt":
        exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    marker.write_text(json.dumps({"name": name, "version": tool["version"], "sha256": art["sha256"], "url": art["url"],
                                  "platform": plat, "verified_by": art["verified_by"],
                                  "installed_at": datetime.now(timezone.utc).isoformat()}, indent=2), encoding="utf-8")
    log(f"  instalado en {exe}")
    return exe


def install_git(name: str, tool: dict, log: Callable[[str], None], force: bool) -> Path:
    """Shallow clone of a pinned tag, accepted only if HEAD is exactly the pinned commit."""
    s = get_settings()
    spec = tool["git"]
    target = s.tool_bin_dir / name
    marker = target / ".vigia-install.json"
    if marker.exists() and not force:
        if json.loads(marker.read_text(encoding="utf-8")).get("commit") == spec["commit"]:
            log(f"{name} {tool['version']} ya instalado")
            return target
    git = shutil.which("git")
    if not git:
        raise InstallError("git no está disponible")
    log(f"Instalando {name} {tool['version']} (git {spec['tag']} @ {spec['commit'][:12]})")
    tmp = target.with_name(target.name + ".tmp")
    for d in (tmp, target):
        if d.exists():
            force_rmtree(d)
    env = {"PATH": os.environ.get("PATH", ""), "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": os.devnull, "HOME": str(tmp.parent), "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")}
    cmd = [git, "-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "-c", "core.symlinks=false",
           "-c", "core.hooksPath=" + os.devnull, "-c", "transfer.fsckObjects=true", "clone", "--depth", "1",
           "--branch", spec["tag"], "--single-branch", "--no-tags", "--", spec["url"], str(tmp)]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=1800)  # noqa: S603
    if proc.returncode != 0:
        force_rmtree(tmp)
        raise InstallError(f"git clone falló: {proc.stderr.strip()[-400:]}")
    head = subprocess.run([git, "-C", str(tmp), "rev-parse", "HEAD"], capture_output=True, text=True, env=env,  # noqa: S603
                          timeout=60).stdout.strip()
    if head != spec["commit"]:
        force_rmtree(tmp)
        raise InstallError(f"El commit del tag no coincide con el fijado ({head} != {spec['commit']}). Abortado.")
    force_rmtree(tmp / ".git")
    tmp.replace(target)
    marker.write_text(json.dumps({"name": name, "version": tool["version"], "commit": head, "url": spec["url"],
                                  "installed_at": datetime.now(timezone.utc).isoformat()}, indent=2), encoding="utf-8")
    log(f"  verificado commit {head[:12]}; instalado en {target}")
    return target


def install_python_tool(name: str, log: Callable[[str], None] = print, force: bool = False) -> Path:
    s = get_settings()
    plat_lock = LOCKS / f"{name}.{sys.platform.replace('win32', 'windows')}.lock"
    lock = plat_lock if plat_lock.exists() else LOCKS / f"{name}.lock"
    if not lock.exists():
        raise InstallError(f"No hay fichero de bloqueo para {name} ({lock.name})")
    venv = s.tool_py_dir / name
    bindir = venv / ("Scripts" if os.name == "nt" else "bin")
    script, module = PYTHON_TOOLS[name]
    exe = bindir / (script + (".exe" if os.name == "nt" else ""))
    if module:
        exe = bindir / ("python.exe" if os.name == "nt" else "python")
    marker = venv / ".vigia-install.json"
    lock_sha = hashlib.sha256(lock.read_bytes()).hexdigest()
    if exe.exists() and marker.exists() and not force:
        if json.loads(marker.read_text(encoding="utf-8")).get("lock_sha256") == lock_sha:
            log(f"{name} ya instalado")
            return exe
    log(f"Instalando {name} en entorno aislado {venv} (hashes obligatorios)")
    if venv.exists():
        shutil.rmtree(venv)
    uv = shutil.which("uv")
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith(("PIP_", "UV_INDEX", "UV_EXTRA"))}
    py = f"{sys.version_info.major}.{sys.version_info.minor}"
    if uv:
        cmds = [[uv, "venv", "--python", py, str(venv)],
                [uv, "pip", "install", "--python", str(bindir / ("python.exe" if os.name == "nt" else "python")),
                 "--require-hashes", "--no-deps", "-r", str(lock)]]
    else:
        cmds = [[sys.executable, "-m", "venv", str(venv)],
                [str(bindir / "python"), "-m", "pip", "install", "--require-hashes", "--no-deps", "-r", str(lock)]]
    for cmd in cmds:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=1800)  # noqa: S603
        if proc.returncode != 0:
            raise InstallError(f"Falló `{' '.join(cmd[:3])}`: {proc.stderr.strip()[-800:]}")
    if not exe.exists():
        raise InstallError(f"No se generó el ejecutable {exe}")
    marker.write_text(json.dumps({"name": name, "lock_sha256": lock_sha,
                                  "installed_at": datetime.now(timezone.utc).isoformat()}, indent=2), encoding="utf-8")
    log(f"  instalado en {exe}")
    return exe


def install_browser(log: Callable[[str], None] = print) -> str:
    """Download Chromium for Playwright into tools/playwright (isolated from any system browser)."""
    import subprocess
    import sys as _sys
    s = get_settings()
    dest = s.tools_dir / "playwright"
    dest.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "PLAYWRIGHT_BROWSERS_PATH": str(dest)}
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "NO_PROXY", "no_proxy"):
        env.pop(k, None)  # never the operator's environment proxies
    gw = None
    if s.http_proxy:  # with an egress, the download also leaves through it (single-use public-lane gateway)
        from vigia.security.egress import Upstream
        from vigia.security.gateway import EgressGateway, PublicPolicy
        from vigia.security.resolver import default_resolver
        gw = EgressGateway(PublicPolicy(default_resolver()), Upstream.parse(s.http_proxy), lane="public").start()
        env["HTTPS_PROXY"] = env["HTTP_PROXY"] = gw.http_url
    log(f"Descargando Chromium en {dest}" + (" a través de la salida configurada" if gw else ""))
    try:
        proc = subprocess.run([_sys.executable, "-m", "playwright", "install", "chromium"],  # noqa: S603
                              env=env, capture_output=True, text=True, timeout=1800)
    finally:
        if gw is not None:
            gw.stop()
    if proc.returncode != 0:
        raise InstallError(f"playwright install falló: {proc.stderr.strip()[-400:]}")
    log("  Chromium instalado")
    return str(dest)


def install(names: list[str] | None = None, log: Callable[[str], None] = print, force: bool = False) -> dict[str, str]:
    manifest = load_manifest()
    names = names or (list(manifest["tools"]) + [n for n in PYTHON_TOOLS if (LOCKS / f"{n}.lock").exists()])
    results: dict[str, str] = {}
    for n in names:
        try:
            if n == "browser":
                results[n] = install_browser(log)
            elif n in manifest["tools"]:
                results[n] = str(install_binary(n, log, force))
            elif n in PYTHON_TOOLS:
                results[n] = str(install_python_tool(n, log, force))
            else:
                results[n] = "ERROR: desconocido"
        except (InstallError, httpx.HTTPError, OSError, subprocess.SubprocessError) as e:
            results[n] = f"ERROR: {e}"
            log(f"  ERROR {n}: {e}")
    return results
