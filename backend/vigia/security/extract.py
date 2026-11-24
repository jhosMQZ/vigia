"""Safe ingestion of untrusted archives, folders and git repositories.

Threats handled:
  * zip-slip / tar-slip (absolute paths, ``..``, drive letters, UNC, Windows reserved names);
  * zip bombs (true decompressed size is counted while streaming, never trusted from headers;
    total-size, per-file, file-count and compression-ratio limits);
  * symlinks / hardlinks / device files (never materialised);
  * nested archives are stored as plain files, never extracted recursively;
  * git: only allow-listed HTTPS hosts, no hooks, no submodules, no symlinks, isolated config,
    bounded time and size; nothing from the analysed project is ever executed.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit


class UnsafeArchive(Exception):
    """The archive or source violates an ingestion rule."""


_WIN_RESERVED = re.compile(r"^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$", re.I)
_BAD_CHARS = re.compile(r'[\x00-\x1f<>:"|?*]')

# Directories never imported for analysis (dependencies, build output, VCS internals are re-derived).
DEFAULT_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache",
                     ".gradle", ".idea", ".vs", "bower_components", ".next", ".nuxt", ".terraform", "vendor/bundle"}


@dataclass
class Limits:
    max_files: int = 20000
    max_total_bytes: int = 500 * 1024 * 1024
    max_file_bytes: int = 50 * 1024 * 1024
    max_ratio: float = 200.0  # decompressed / compressed, per member and overall
    max_path_len: int = 400
    max_depth: int = 40


@dataclass
class IngestStats:
    files: int = 0
    bytes: int = 0
    skipped: list[str] = field(default_factory=list)
    sha256: str = ""

    def skip(self, name: str, why: str) -> None:
        if len(self.skipped) < 200:
            self.skipped.append(f"{name}: {why}")


def safe_member_path(name: str, limits: Limits) -> PurePosixPath:
    """Validate an archive member name and return a safe relative POSIX path."""
    n = name.replace("\\", "/")
    if not n or n.startswith("/") or re.match(r"^[a-zA-Z]:", n) or n.startswith("//"):
        raise UnsafeArchive(f"Ruta absoluta en el archivo: {name!r}")
    if len(n) > limits.max_path_len:
        raise UnsafeArchive(f"Ruta demasiado larga: {name[:80]!r}…")
    parts = [p for p in n.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise UnsafeArchive(f"Ruta con '..' (zip-slip): {name!r}")
    if len(parts) > limits.max_depth:
        raise UnsafeArchive(f"Anidamiento excesivo: {name[:80]!r}")
    for p in parts:
        if _BAD_CHARS.search(p) or _WIN_RESERVED.match(p) or p.endswith((" ", ".")):
            raise UnsafeArchive(f"Nombre de fichero no portable o peligroso: {name!r}")
    if not parts:
        raise UnsafeArchive(f"Nombre vacío: {name!r}")
    return PurePosixPath(*parts)


def _within(base: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _copy_stream(src, dst_path: Path, limits: Limits, stats: IngestStats, compressed: int | None) -> None:
    written = 0
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    with open(dst_path, "xb") as out:  # 'x' never overwrites or follows a pre-existing link
        while True:
            chunk = src.read(1 << 16)
            if not chunk:
                break
            written += len(chunk)
            if written > limits.max_file_bytes:
                raise UnsafeArchive(f"Fichero demasiado grande al descomprimir: {dst_path.name}")
            if stats.bytes + written > limits.max_total_bytes:
                raise UnsafeArchive("Tamaño total descomprimido excedido (posible zip bomb)")
            if compressed is not None and written > 1 << 20 and written / max(compressed, 1) > limits.max_ratio:
                raise UnsafeArchive(f"Ratio de compresión anómalo en {dst_path.name} (posible zip bomb)")
            out.write(chunk)
    stats.bytes += written


def safe_extract_zip(archive: Path, dest: Path, limits: Limits | None = None,
                     skip_dirs: set[str] | None = None) -> IngestStats:
    limits = limits or Limits()
    skip_dirs = DEFAULT_SKIP_DIRS if skip_dirs is None else skip_dirs
    stats = IngestStats(sha256=_hash_file(archive))
    dest.mkdir(parents=True, exist_ok=True)
    try:
        zf = zipfile.ZipFile(archive)
    except zipfile.BadZipFile as e:
        raise UnsafeArchive(f"ZIP inválido: {e}") from e
    with zf:
        infos = zf.infolist()
        if len(infos) > limits.max_files * 2:
            raise UnsafeArchive(f"Demasiadas entradas en el ZIP ({len(infos)})")
        declared = sum(i.file_size for i in infos)
        packed = sum(i.compress_size for i in infos) or 1
        if declared > limits.max_total_bytes:
            raise UnsafeArchive("El tamaño declarado excede el límite")
        if declared > 50 * 1024 * 1024 and declared / packed > limits.max_ratio:
            raise UnsafeArchive("Ratio de compresión global anómalo (posible zip bomb)")
        for info in infos:
            if info.flag_bits & 0x1:
                raise UnsafeArchive("ZIP cifrado no soportado")
            rel = safe_member_path(info.filename, limits)
            mode = (info.external_attr >> 16) & 0xFFFF
            if info.is_dir():
                continue
            if stat.S_ISLNK(mode) or (mode and not stat.S_ISREG(mode) and stat.S_IFMT(mode)):
                stats.skip(info.filename, "enlace simbólico o fichero especial ignorado")
                continue
            if any(p in skip_dirs for p in rel.parts[:-1]):
                continue
            if stats.files >= limits.max_files:
                raise UnsafeArchive(f"Demasiados ficheros (límite {limits.max_files})")
            target = dest.joinpath(*rel.parts)
            if not _within(dest, target):
                raise UnsafeArchive(f"Destino fuera del directorio: {info.filename!r}")
            if target.exists():
                stats.skip(info.filename, "entrada duplicada ignorada")
                continue
            with zf.open(info) as src:
                _copy_stream(src, target, limits, stats, info.compress_size)
            stats.files += 1
    return stats


def safe_extract_tar(archive: Path, dest: Path, limits: Limits | None = None) -> IngestStats:
    limits = limits or Limits()
    stats = IngestStats(sha256=_hash_file(archive))
    dest.mkdir(parents=True, exist_ok=True)
    try:
        tf = tarfile.open(archive, "r:*")
    except tarfile.TarError as e:
        raise UnsafeArchive(f"TAR inválido: {e}") from e
    with tf:
        for m in tf:
            rel = safe_member_path(m.name, limits)
            if m.isdir():
                continue
            if not m.isreg():
                stats.skip(m.name, "enlace o fichero especial ignorado")
                continue
            if stats.files >= limits.max_files:
                raise UnsafeArchive(f"Demasiados ficheros (límite {limits.max_files})")
            target = dest.joinpath(*rel.parts)
            if not _within(dest, target) or target.exists():
                raise UnsafeArchive(f"Entrada inválida o duplicada: {m.name!r}")
            src = tf.extractfile(m)
            if src is None:
                continue
            with src:
                _copy_stream(src, target, limits, stats, None)
            stats.files += 1
    return stats


def safe_copy_tree(src: Path, dest: Path, limits: Limits | None = None,
                   skip_dirs: set[str] | None = None) -> IngestStats:
    """Copy a local folder without following symlinks/junctions and within limits."""
    limits = limits or Limits()
    skip_dirs = DEFAULT_SKIP_DIRS if skip_dirs is None else skip_dirs
    src = src.resolve()
    if not src.is_dir():
        raise UnsafeArchive(f"La carpeta no existe: {src}")
    stats = IngestStats()
    h = hashlib.sha256()
    dest.mkdir(parents=True, exist_ok=True)
    for root, dirs, files in os.walk(src, followlinks=False):
        rootp = Path(root)
        keep = []
        for d in sorted(dirs):
            dp = rootp / d
            if d in skip_dirs or dp.is_symlink() or _is_junction(dp):
                continue
            keep.append(d)
        dirs[:] = keep
        for f in sorted(files):
            fp = rootp / f
            rel = fp.relative_to(src)
            if fp.is_symlink() or not fp.is_file():
                stats.skip(str(rel), "enlace o fichero especial ignorado")
                continue
            if stats.files >= limits.max_files:
                raise UnsafeArchive(f"Demasiados ficheros (límite {limits.max_files})")
            size = fp.stat().st_size
            if size > limits.max_file_bytes:
                stats.skip(str(rel), "fichero demasiado grande")
                continue
            target = dest / rel
            with open(fp, "rb") as fh:
                _copy_stream(fh, target, limits, stats, None)
            h.update(str(rel).encode() + b"\0" + str(size).encode())
            stats.files += 1
    stats.sha256 = h.hexdigest()
    return stats


def _is_junction(p: Path) -> bool:
    try:
        return bool(getattr(os.path, "isjunction", lambda _: False)(p))
    except OSError:
        return True


DEFAULT_GIT_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org")


def validate_git_url(url: str, allowed_hosts: tuple[str, ...] | list[str]) -> str:
    parts = urlsplit(url.strip())
    if parts.scheme != "https":
        raise UnsafeArchive("Solo se admiten repositorios git por HTTPS")
    if parts.username or parts.password:
        raise UnsafeArchive("No incluyas credenciales en la URL del repositorio")
    host = (parts.hostname or "").lower()
    if not host or not any(host == h or host.endswith("." + h) for h in allowed_hosts):
        raise UnsafeArchive(f"Host git no permitido: {host or '(vacío)'}. Permitidos: {', '.join(allowed_hosts)}")
    if parts.port not in (None, 443):
        raise UnsafeArchive("Puerto no permitido para git")
    if not re.match(r"^/[\w.\-~/]+$", parts.path or ""):
        raise UnsafeArchive("Ruta de repositorio inválida")
    if parts.query or parts.fragment:
        raise UnsafeArchive("La URL del repositorio no puede tener query ni fragmento")
    return f"https://{host}{parts.path}"


def safe_git_clone(url: str, dest: Path, allowed_hosts: tuple[str, ...] | list[str] = DEFAULT_GIT_HOSTS,
                   timeout: int = 300, ref: str | None = None, limits: Limits | None = None) -> IngestStats:
    clean = validate_git_url(url, allowed_hosts)
    if ref is not None and not re.match(r"^[\w.\-/]{1,120}$", ref):
        raise UnsafeArchive("Rama o tag inválido")
    git = shutil.which("git")
    if not git:
        raise UnsafeArchive("git no está instalado en el servidor")
    tmp = dest.with_name(dest.name + ".clone")
    if tmp.exists():
        force_rmtree(tmp)
    env = {"PATH": os.environ.get("PATH", ""), "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_ASKPASS": "", "SSH_ASKPASS": "", "GIT_LFS_SKIP_SMUDGE": "1",
           "HOME": str(tmp.parent), "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")}
    cmd = [git, "-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "-c", "core.symlinks=false",
           "-c", "core.hooksPath=" + os.devnull, "-c", "submodule.recurse=false", "-c", "http.followRedirects=false",
           "-c", "core.fsmonitor=false", "-c", "transfer.fsckObjects=true",
           "clone", "--depth", "1", "--no-tags", "--single-branch", "--no-recurse-submodules"]
    if ref:
        cmd += ["--branch", ref]
    cmd += ["--", clean, str(tmp)]
    try:
        proc = subprocess.run(cmd, env=env, capture_output=True, timeout=timeout, text=True, shell=False)  # noqa: S603
    except subprocess.TimeoutExpired as e:
        force_rmtree(tmp)
        raise UnsafeArchive("git clone superó el tiempo máximo") from e
    if proc.returncode != 0:
        force_rmtree(tmp)
        raise UnsafeArchive(f"git clone falló: {proc.stderr.strip()[-400:]}")
    try:
        stats = safe_copy_tree(tmp, dest, limits, skip_dirs=DEFAULT_SKIP_DIRS | {".git"})
        rev = subprocess.run([git, "-C", str(tmp), "rev-parse", "HEAD"], env=env, capture_output=True, text=True,  # noqa: S603
                             timeout=30)
        if rev.returncode == 0:
            stats.sha256 = rev.stdout.strip()
    finally:
        force_rmtree(tmp)
    return stats


def force_rmtree(path: Path) -> None:
    """rmtree that also removes read-only files (git objects on Windows) and never raises."""
    def _onexc(func, p, _exc):  # noqa: ANN001
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass
    if not Path(path).exists():
        return
    try:
        shutil.rmtree(path, onexc=_onexc)  # type: ignore[call-arg]  # py>=3.12
    except TypeError:
        shutil.rmtree(path, onerror=_onexc)
