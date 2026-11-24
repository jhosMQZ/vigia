"""Managed SSH tunnel: the recommended egress (``VIGIA_SSH_TUNNEL=user@host[:port]``).

Vigía starts the system OpenSSH client as ``ssh -N -D 127.0.0.1:<port>`` for each scan and closes it when the scan
ends. The tunnel's local SOCKS5 endpoint becomes the upstream of the egress gateway; because it is on loopback the
whole scan can run confined in its AppContainer (vigia.core.scanproc), so the ssh client is the only process allowed
to reach the Internet.

Server identity is verified strictly — never trust-on-first-use:
  * ``VIGIA_SSH_KNOWN_HOSTS`` is mandatory and must already contain the server's key (``ssh-keyscan`` +
    out-of-band verification of the fingerprint, see docs/05-privacidad.md);
  * ``StrictHostKeyChecking=yes``, ``UpdateHostKeys=no``, ``BatchMode=yes`` (no prompts), ``-F none`` (the user's
    ssh_config, aliases, ProxyCommand… are ignored), ``ExitOnForwardFailure=yes`` and keep-alives so a dead link is
    noticed and the scan stops (fail-closed: the gateway reports the egress down, there is no direct fallback).
"""
from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

DEST_RE = re.compile(r"^(?P<user>[A-Za-z0-9_][A-Za-z0-9._-]{0,63})@(?P<host>[A-Za-z0-9][A-Za-z0-9.-]{0,252}|\[[0-9A-Fa-f:.]+\])(?::(?P<port>\d{1,5}))?$")


class TunnelError(Exception):
    pass


def ssh_binary() -> Path | None:
    if sys.platform == "win32":
        p = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "OpenSSH" / "ssh.exe"
        if p.exists():
            return p
    found = shutil.which("ssh")
    return Path(found) if found else None


@dataclass
class TunnelConfig:
    user: str
    host: str
    port: int
    known_hosts: Path
    identity: Path | None = None

    @classmethod
    def from_settings(cls) -> "TunnelConfig | None":
        from vigia.config import get_settings
        s = get_settings()
        if not s.ssh_tunnel:
            return None
        m = DEST_RE.match(s.ssh_tunnel.strip())
        if not m:
            raise TunnelError("VIGIA_SSH_TUNNEL debe tener la forma usuario@servidor[:puerto]")
        if not s.ssh_known_hosts:
            raise TunnelError("VIGIA_SSH_KNOWN_HOSTS es obligatorio: Vigía nunca acepta la clave del servidor a ciegas")
        return cls(m["user"], m["host"].strip("[]"), int(m["port"] or 22), Path(s.ssh_known_hosts),
                   Path(s.ssh_identity) if s.ssh_identity else None)

    @property
    def display(self) -> str:
        h = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.user}@{h}:{self.port}"

    def known_host_entry(self) -> bool:
        """The known_hosts file has an entry for this host (plain or [host]:port form; hashed entries also count)."""
        try:
            text = self.known_hosts.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        names = {self.host} if self.port == 22 else set()
        names.add(f"[{self.host}]:{self.port}")
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            first = line.split()[0]
            if first.startswith("|1|") or any(n in first.split(",") for n in names):
                return True
        return False


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class Tunnel:
    cfg: TunnelConfig
    local_port: int = 0
    proc: subprocess.Popen | None = None
    log: list[str] = field(default_factory=list)
    _job: object | None = None
    _logfile: Path | None = None

    @property
    def socks_url(self) -> str:
        return f"socks5://127.0.0.1:{self.local_port}"

    @property
    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self, workdir: Path, timeout: float = 25.0) -> "Tunnel":
        ssh = ssh_binary()
        if ssh is None:
            raise TunnelError("No se encuentra el cliente OpenSSH (ssh)")
        if not self.cfg.known_hosts.exists():
            raise TunnelError(f"No existe el fichero de claves conocidas {self.cfg.known_hosts}")
        if not self.cfg.known_host_entry():
            raise TunnelError(f"{self.cfg.known_hosts} no contiene la clave de {self.cfg.display}: añádela tras verificar "
                              "su huella por un canal independiente (Vigía no acepta claves nuevas automáticamente)")
        self.local_port = _free_port()
        workdir.mkdir(parents=True, exist_ok=True)
        self._logfile = workdir / "ssh-tunnel.log"
        argv = [str(ssh), "-N", "-F", "none", "-D", f"127.0.0.1:{self.local_port}",
                # quoted: the value is a whitespace-separated list for OpenSSH and Windows profiles contain spaces
                "-o", "StrictHostKeyChecking=yes", "-o", f'UserKnownHostsFile="{self.cfg.known_hosts}"',
                "-o", "GlobalKnownHostsFile=none", "-o", "UpdateHostKeys=no", "-o", "CheckHostIP=no",
                "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=10",
                "-o", "ServerAliveCountMax=3", "-o", "ConnectTimeout=10", "-o", "PermitLocalCommand=no",
                "-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "ClearAllForwardings=no",
                "-p", str(self.cfg.port)]
        if self.cfg.identity:
            argv += ["-o", "IdentitiesOnly=yes", "-i", str(self.cfg.identity)]
        argv += ["--", f"{self.cfg.user}@{self.cfg.host}"]  # "--": the destination can never be read as an option
        creation = 0
        job = None
        if sys.platform == "win32":
            from vigia.core.toolrunner import _CREATE_NEW_PROCESS_GROUP, _CREATE_NO_WINDOW, _CREATE_SUSPENDED, _Job
            creation = _CREATE_SUSPENDED | _CREATE_NEW_PROCESS_GROUP | _CREATE_NO_WINDOW
            job = _Job(256)
        logf = open(self._logfile, "wb")  # noqa: SIM115 - inherited by ssh; closed below
        try:
            self.proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=logf, stderr=logf,  # noqa: S603
                                         creationflags=creation, close_fds=True)
            if job is not None:
                job.assign_and_resume(self.proc)
                self._job = job
        finally:
            logf.close()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                break
            try:
                with socket.create_connection(("127.0.0.1", self.local_port), timeout=0.5):
                    pass
                if self._socks_ready():
                    return self
            except OSError:
                pass
            time.sleep(0.3)
        reason = self._explain()
        self.stop()
        raise TunnelError(reason)

    def _socks_ready(self) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", self.local_port), timeout=2) as s:
                s.sendall(b"\x05\x01\x00")
                return s.recv(2) == b"\x05\x00"
        except OSError:
            return False

    def _explain(self) -> str:
        try:
            text = self._logfile.read_text(encoding="utf-8", errors="replace") if self._logfile else ""
        except OSError:
            text = ""
        if "REMOTE HOST IDENTIFICATION HAS CHANGED" in text or "Host key verification failed" in text:
            return (f"La identidad del servidor SSH {self.cfg.display} no coincide con la registrada en "
                    f"{self.cfg.known_hosts}: no se establece el túnel (posible suplantación o clave cambiada)")
        if "Permission denied" in text:
            return f"El servidor SSH {self.cfg.display} rechazó la autenticación (clave de usuario)"
        if "Connection refused" in text or "timed out" in text.lower():
            return f"No se pudo conectar con el servidor SSH {self.cfg.display}"
        return f"El túnel SSH hacia {self.cfg.display} no se estableció: {text.strip()[-300:] or 'sin detalle'}"

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self._job is not None:
            self._job.close()  # KILL_ON_JOB_CLOSE: nothing of the ssh tree survives
            self._job = None

    def __enter__(self) -> "Tunnel":
        return self

    def __exit__(self, *exc) -> None:  # noqa: ANN002
        self.stop()


def check(workdir: Path) -> dict:
    """Open the configured tunnel, prove it forwards (SOCKS handshake) and close it. For the privacy panel."""
    started = time.time()
    try:
        cfg = TunnelConfig.from_settings()
    except TunnelError as e:
        return {"ok": False, "configured": True, "detail": str(e), "ts": started}
    if cfg is None:
        return {"ok": False, "configured": False, "detail": "VIGIA_SSH_TUNNEL no está configurado", "ts": started}
    try:
        with Tunnel(cfg).start(workdir) as t:
            return {"ok": True, "configured": True, "destination": cfg.display, "ts": started,
                    "detail": f"Túnel establecido con {cfg.display}; identidad del servidor verificada contra "
                              f"{cfg.known_hosts.name}", "seconds": round(time.time() - started, 1),
                    "local": t.socks_url}
    except TunnelError as e:
        return {"ok": False, "configured": True, "destination": cfg.display, "detail": str(e), "ts": started}
