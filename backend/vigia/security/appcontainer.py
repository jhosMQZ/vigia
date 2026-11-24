"""Preventive OS network isolation for engines on Windows: AppContainer (no administrator rights needed).

A process started inside a capability-less AppContainer is denied any network access by the Windows Filtering
Platform *before* a packet leaves: TCP/UDP to any non-local address, IPv4 and IPv6, and name resolution through the
OS resolver. Child processes inherit the AppContainer token, so an engine cannot escape by spawning helpers.
Vigía grants the container exactly one thing: loopback (``CheckNetIsolation LoopbackExempt``, allowed for a
profile owned by the current user), which is how engines reach Vigía's egress gateway — the only way out.

File access: AppContainers cannot read the user's files by default; Vigía grants the container SID read/execute on
the engine directories and read/write only on the per-scan sandbox.

``self_test()`` proves the isolation at run time with a probe inside the container (direct TCP to TEST-NET, UDP,
IPv6, OS DNS must fail; loopback must work). Scans with a dedicated egress refuse to start if it does not pass.
"""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import threading
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"
CONTAINER = "vigia.engines"
# No capabilities at all (verified: the isolatedWin32-* file-system capabilities that would let Java/Node list the
# volume root are rejected for an ordinary AppContainer, ERROR_INVALID_PARAMETER). Engines that must canonicalise
# paths by listing C:\ (the ZAP JVM) therefore cannot run inside the container without an administrator.
FS_CAPABILITIES: tuple[str, ...] = ()
_lock = threading.Lock()
_granted: set[str] = set()


class IsolationError(Exception):
    pass


if IS_WINDOWS:
    _userenv = ctypes.WinDLL("userenv")
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi = ctypes.WinDLL("advapi32", use_last_error=True)

    class _SECURITY_CAPABILITIES(ctypes.Structure):
        _fields_ = [("AppContainerSid", ctypes.c_void_p), ("Capabilities", ctypes.c_void_p),
                    ("CapabilityCount", wintypes.DWORD), ("Reserved", wintypes.DWORD)]

    class _STARTUPINFOW(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
                    ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                    ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
                    ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD),
                    ("dwFlags", wintypes.DWORD), ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                    ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
                    ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]

    class _STARTUPINFOEXW(ctypes.Structure):
        _fields_ = [("StartupInfo", _STARTUPINFOW), ("lpAttributeList", ctypes.c_void_p)]

    class _SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

    class _PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE), ("dwProcessId", wintypes.DWORD),
                    ("dwThreadId", wintypes.DWORD)]

    _k32.CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
                                    wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
                                    ctypes.c_void_p, ctypes.c_void_p]
    _k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    _k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]


def _hr_ok(hr: int) -> bool:
    return (hr & 0xFFFFFFFF) == 0


@dataclass
class Container:
    name: str
    sid: str
    _psid: ctypes.c_void_p

    @property
    def available(self) -> bool:
        return True


_container: Container | None = None


def container() -> Container:
    """Create (or reuse) the user's AppContainer profile and its loopback exemption."""
    global _container
    if IS_WINDOWS and in_container():
        raise IsolationError("ya se está dentro de un AppContainer: los procesos hijos lo heredan")
    if not IS_WINDOWS:
        raise IsolationError("AppContainer solo existe en Windows (en Linux usa el despliegue con red aislada)")
    with _lock:
        if _container is not None:
            return _container
        psid = ctypes.c_void_p()
        hr = _userenv.CreateAppContainerProfile(ctypes.c_wchar_p(CONTAINER), ctypes.c_wchar_p("Vigía engines"),
                                                ctypes.c_wchar_p("Motores de Vigía sin red salvo loopback"),
                                                None, 0, ctypes.byref(psid))
        if (hr & 0xFFFFFFFF) == 0x800700B7:  # already exists
            hr = _userenv.DeriveAppContainerSidFromAppContainerName(ctypes.c_wchar_p(CONTAINER), ctypes.byref(psid))
        if not _hr_ok(hr):
            raise IsolationError(f"No se pudo crear el AppContainer (HRESULT 0x{hr & 0xFFFFFFFF:08x})")
        s = wintypes.LPWSTR()
        if not _advapi.ConvertSidToStringSidW(psid, ctypes.byref(s)):
            raise IsolationError("ConvertSidToStringSid falló")
        c = Container(CONTAINER, s.value, psid)
        _ensure_loopback(c)
        _container = c
        return c


_caps_cache = None


def _capabilities():  # noqa: ANN202
    global _caps_cache
    if _caps_cache is not None:
        return _caps_cache
    kb = ctypes.WinDLL("kernelbase")
    sids = []
    for name in FS_CAPABILITIES:
        gs, gc, cs, cc = ctypes.c_void_p(), wintypes.DWORD(), ctypes.c_void_p(), wintypes.DWORD()
        if kb.DeriveCapabilitySidsFromName(ctypes.c_wchar_p(name), ctypes.byref(gs), ctypes.byref(gc),
                                           ctypes.byref(cs), ctypes.byref(cc)) and cc.value:
            sids.append(ctypes.cast(cs, ctypes.POINTER(ctypes.c_void_p))[0])
    arr = (_SID_AND_ATTRIBUTES * len(sids))(*[_SID_AND_ATTRIBUTES(sd, 0x4) for sd in sids])  # SE_GROUP_ENABLED
    _caps_cache = arr
    return arr


def _checknet(*args: str) -> str:
    exe = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "CheckNetIsolation.exe"
    r = subprocess.run([str(exe), *args], capture_output=True, timeout=30)  # noqa: S603 - fixed system binary
    return (r.stdout + r.stderr).decode("utf-8", errors="replace")


def _ensure_loopback(c: Container) -> None:
    if c.sid.lower() in _checknet("LoopbackExempt", "-s").lower():
        return
    _checknet("LoopbackExempt", "-a", f"-p={c.sid}")
    if c.sid.lower() not in _checknet("LoopbackExempt", "-s").lower():
        raise IsolationError("No se pudo conceder loopback al AppContainer (los motores no alcanzarían la pasarela)")


def grant(path: Path, write: bool = False) -> None:
    """Give the container read/execute (or modify) on a directory tree owned by the user."""
    c = container()
    key = f"{path.resolve()}|{write}"
    if key in _granted:
        return
    perm = "(OI)(CI)(M)" if write else "(OI)(CI)(RX)"
    # /T: apply explicitly to every existing file (plain propagation can be left incomplete if interrupted)
    r = subprocess.run(["icacls", str(path), "/grant", f"*{c.sid}:{perm}", "/T", "/Q", "/C"],  # noqa: S603,S607
                       capture_output=True, timeout=900)
    if r.returncode != 0:
        raise IsolationError(f"No se pudo dar acceso al AppContainer en {path}: "
                             f"{(r.stdout + r.stderr).decode('utf-8', 'replace')[:300]}")
    _granted.add(key)


def _env_block(env: dict[str, str]) -> ctypes.Array:
    text = "".join(f"{k}={v}\0" for k, v in sorted(env.items(), key=lambda kv: kv[0].upper())) + "\0"
    return ctypes.create_unicode_buffer(text, len(text))


class ContainerProcess:
    """Minimal Popen-compatible handle for a process created inside the AppContainer (created suspended)."""

    def __init__(self, pi, keep: list) -> None:  # noqa: ANN001
        self._handle = pi.hProcess
        self._thread = pi.hThread
        self.pid = pi.dwProcessId
        self.returncode: int | None = None
        self._keep = keep  # attribute list / env buffers must outlive CreateProcess

    def resume(self) -> None:
        _k32.ResumeThread(wintypes.HANDLE(self._thread))

    def poll(self) -> int | None:
        if self.returncode is None and _k32.WaitForSingleObject(self._handle, 0) == 0:
            code = wintypes.DWORD()
            _k32.GetExitCodeProcess(self._handle, ctypes.byref(code))
            self.returncode = code.value
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        ms = 0xFFFFFFFF if timeout is None else int(timeout * 1000)
        if _k32.WaitForSingleObject(self._handle, ms) != 0:
            raise subprocess.TimeoutExpired("appcontainer", timeout or 0)
        return self.poll()  # type: ignore[return-value]

    def kill(self) -> None:
        if self.poll() is None:
            _k32.TerminateProcess(self._handle, 1)

    def close(self) -> None:
        for h in (self._handle, self._thread):
            if h:
                _k32.CloseHandle(h)
        self._handle = self._thread = None


def _crt_fd_table(handles: list) -> ctypes.Array:
    """lpReserved2 block that hands extra CRT file descriptors (3, 4, …) to the child (MSVC CRT protocol)."""
    import struct
    n = len(handles)
    flags = bytes(0x09 if h else 0 for h in handles)  # FOPEN | FPIPE
    blob = struct.pack("<I", n) + flags + b"".join(struct.pack("<Q", int(h or 0)) for h in handles)
    return ctypes.create_string_buffer(blob, len(blob))


def spawn(argv: list[str], *, env: dict[str, str], cwd: str, stdout_fd: int | None = None, stderr_fd: int | None = None,
          stdin_fd: int | None = None, suspended: bool = True, handles: tuple | None = None,
          extra_handles: list | None = None, container_override: "Container | None" = None) -> ContainerProcess:
    """CreateProcess inside the AppContainer with redirected handles. The caller assigns the job and resumes."""
    import msvcrt
    nested = in_container()  # already confined: children inherit the container (a new one cannot be requested)
    c = None if nested else (container_override or container())
    if "LOCALAPPDATA" not in {k.upper() for k in env}:
        raise IsolationError("El entorno del AppContainer necesita LOCALAPPDATA")
    lad = next(v for k, v in env.items() if k.upper() == "LOCALAPPDATA")
    # Windows redirects TEMP/TMP of the container to <LOCALAPPDATA>\Packages\<name>\AC\Temp
    for name in {CONTAINER, getattr(c, "name", CONTAINER)}:
        (Path(lad) / "Packages" / name / "AC" / "Temp").mkdir(parents=True, exist_ok=True)
    caps = _capabilities()
    sc = None
    size = ctypes.c_size_t()
    _k32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
    attrs = ctypes.create_string_buffer(size.value)
    if not _k32.InitializeProcThreadAttributeList(attrs, 1, 0, ctypes.byref(size)):
        raise IsolationError("InitializeProcThreadAttributeList falló")
    if c is not None:
        sc = _SECURITY_CAPABILITIES(c._psid, ctypes.cast(caps, ctypes.c_void_p) if len(caps) else None, len(caps), 0)
        if not _k32.UpdateProcThreadAttribute(attrs, 0, 0x00020009, ctypes.byref(sc), ctypes.sizeof(sc), None, None):
            raise IsolationError("UpdateProcThreadAttribute(SECURITY_CAPABILITIES) falló")
    if handles is None:  # (stdin, stdout, stderr) as raw HANDLEs, or CRT file descriptors
        hs = []
        for fd in (stdin_fd, stdout_fd, stderr_fd):
            hs.append(None if fd is None else msvcrt.get_osfhandle(fd))
        handles = tuple(hs)
    for h in handles:
        if h is not None:
            os.set_handle_inheritable(int(h), True)
    si = _STARTUPINFOEXW()
    si.StartupInfo.cb = ctypes.sizeof(_STARTUPINFOEXW)
    si.StartupInfo.dwFlags = 0x100  # STARTF_USESTDHANDLES
    si.StartupInfo.hStdInput, si.StartupInfo.hStdOutput, si.StartupInfo.hStdError = [
        int(h) if h is not None else None for h in handles]
    si.lpAttributeList = ctypes.cast(attrs, ctypes.c_void_p) if c is not None else None
    if c is None:
        si.StartupInfo.cb = ctypes.sizeof(_STARTUPINFOW)
    crt = None
    if extra_handles:  # e.g. Chromium --remote-debugging-pipe reads fd 3 and writes fd 4
        for h in extra_handles:
            os.set_handle_inheritable(int(h), True)
        crt = _crt_fd_table(list(si.StartupInfo.hStdInput and [si.StartupInfo.hStdInput] or [None])
                            + [si.StartupInfo.hStdOutput, si.StartupInfo.hStdError] + list(extra_handles))
        si.StartupInfo.cbReserved2 = len(crt)
        si.StartupInfo.lpReserved2 = ctypes.cast(crt, ctypes.c_void_p)
    pi = _PROCESS_INFORMATION()
    cmdline = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
    envb = _env_block(env)
    flags = (0x00080000 if c is not None else 0) | 0x00000400 | 0x08000000 | 0x00000200 | (0x4 if suspended else 0)
    # EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP | SUSPENDED
    ok = _k32.CreateProcessW(argv[0], cmdline, None, None, True, flags, ctypes.cast(envb, ctypes.c_void_p), cwd,
                             ctypes.byref(si), ctypes.byref(pi))
    _k32.DeleteProcThreadAttributeList(attrs)
    if not ok:
        raise OSError(ctypes.get_last_error(), f"CreateProcessW en AppContainer: {argv[0]}")
    return ContainerProcess(pi, [attrs, envb, sc, crt, caps])


# ---------------------------------------------------------------------------------------------- self-test
PROBE = r'''
import socket, sys, json
res = {}
def tcp(addr, fam=socket.AF_INET):
    s = socket.socket(fam, socket.SOCK_STREAM); s.settimeout(3)
    try:
        s.connect(addr); return "connected"
    except socket.timeout:
        return "timeout"  # the SYN left the machine: NOT blocked
    except OSError as e:
        return f"blocked:{getattr(e, 'winerror', None) or e.errno}"
    finally:
        s.close()
res["tcp_testnet"] = tcp(("192.0.2.1", 80))
res["tcp_ipv6"] = tcp(("2001:db8::1", 80, 0, 0), socket.AF_INET6)
# UDP: WFP drops datagrams silently (sendto "succeeds"), so ask the system DNS server and wait for an answer.
dns = sys.argv[2] if len(sys.argv) > 2 else ""
if dns:
    q = bytes.fromhex("123401000001000000000000") + b"\x07example\x03com\x00" + bytes.fromhex("00010001")
    u = socket.socket(socket.AF_INET6 if ":" in dns else socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(3)
    try:
        u.sendto(q, (dns, 53)); u.recvfrom(512); res["udp_dns_server"] = "reply"
    except OSError as e:
        res["udp_dns_server"] = f"blocked:{getattr(e, 'winerror', None) or e}"
else:
    res["udp_dns_server"] = "untested"
try:
    socket.getaddrinfo("example.com", 80); res["os_dns"] = "resolved"
except OSError as e:
    res["os_dns"] = f"blocked:{getattr(e, 'winerror', None) or e.errno}"
res["loopback"] = tcp(("127.0.0.1", int(sys.argv[1])))
print(json.dumps(res))
'''


def system_dns_server() -> str:
    if os.environ.get("VIGIA_SYSTEM_DNS_SERVER"):  # given by the parent to a confined worker (no registry access)
        return os.environ["VIGIA_SYSTEM_DNS_SERVER"]
    try:
        import dns.resolver
        ns = [n for n in dns.resolver.Resolver().nameservers if not str(n).lower().startswith("fe80")]
        return str(ns[0]) if ns else ""
    except Exception:  # noqa: BLE001
        return ""


def self_test(python: str, workdir: Path, contained: bool = True) -> dict:
    """Run the probe inside the container. Returns {ok, results, detail}."""
    import json
    import socket
    import tempfile
    workdir.mkdir(parents=True, exist_ok=True)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]
    srv.settimeout(45)

    def _accept() -> None:
        try:
            srv.accept()[0].close()
        except OSError:
            pass
    threading.Thread(target=_accept, daemon=True).start()
    probe = workdir / "isolation_probe.py"
    probe.write_text(PROBE, encoding="utf-8")
    out, err = workdir / "probe.out", workdir / "probe.err"
    try:
        if contained:
            grant(workdir, write=True)
            grant_persistent(Path(python).resolve().parent)
        workdir.mkdir(parents=True, exist_ok=True)
        with open(out, "wb") as fo, open(err, "wb") as fe:
            env = {"SYSTEMROOT": os.environ.get("SYSTEMROOT", r"C:\Windows"), "PYTHONUTF8": "1",
                   "TEMP": str(workdir), "TMP": str(workdir), "LOCALAPPDATA": str(workdir)}  # required by AppContainer
            argv = [python, "-I", "-S", str(probe), str(port), system_dns_server()]
            if contained:
                p = spawn(argv, env=env, cwd=str(workdir), stdout_fd=fo.fileno(), stderr_fd=fe.fileno(), suspended=False)
                try:
                    p.wait(40)
                except subprocess.TimeoutExpired:
                    p.kill()
                finally:
                    p.close()
            else:  # "external" isolation (firewall rules / network namespace): the probe runs as a normal process
                subprocess.run(argv, stdout=fo, stderr=fe, env={**os.environ, **env}, cwd=str(workdir),  # noqa: S603
                               timeout=40)
        text = out.read_text(encoding="utf-8", errors="replace").strip()
        results = json.loads(text.splitlines()[-1]) if text else {}
    except (OSError, IsolationError, ValueError) as e:
        return {"ok": False, "results": {}, "detail": f"la sonda de aislamiento no pudo ejecutarse: {e}; "
                f"{err.read_text(errors='replace')[:300] if err.exists() else ''}"}
    finally:
        srv.close()
        _ = tempfile
    blocked = all(str(results.get(k, "")).startswith("blocked") for k in ("tcp_testnet", "tcp_ipv6", "udp_dns_server",
                                                                          "os_dns"))
    ok = blocked and results.get("loopback") == "connected"
    return {"ok": ok, "results": results,
            "detail": ("aislamiento preventivo verificado: TCP/UDP/IPv6/DNS del sistema bloqueados por el kernel, "
                       "loopback permitido") if ok else f"aislamiento NO verificado: {results}"}


# ---------------------------------------------------------------------------------------------- asyncio subprocess
class _AsyncContainerProc:
    """What asyncio.create_subprocess_exec returns, for a process running inside the AppContainer."""

    def __init__(self, proc: ContainerProcess, stdin, stdout) -> None:  # noqa: ANN001
        self._p = proc
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = None
        self.pid = proc.pid

    @property
    def returncode(self) -> int | None:
        return self._p.poll()

    async def wait(self) -> int:
        import asyncio
        while self._p.poll() is None:
            await asyncio.sleep(0.1)
        return self._p.returncode  # type: ignore[return-value]

    async def communicate(self, input=None):  # noqa: ANN001, A002
        await self.wait()
        return None, None

    def kill(self) -> None:
        self._p.kill()

    terminate = kill


async def create_subprocess_exec(program: str, *args: str, env: dict[str, str], cwd: str, stderr_path: Path,
                                 limit: int = 32768, job=None) -> _AsyncContainerProc:  # noqa: ANN001
    """asyncio-compatible launcher (stdin/stdout pipes) that starts ``program`` inside the AppContainer."""
    import asyncio
    from asyncio import windows_utils
    loop = asyncio.get_running_loop()
    out_r, out_w = windows_utils.pipe(overlapped=(True, False), duplex=False)
    in_r, in_w = windows_utils.pipe(overlapped=(False, True), duplex=True)  # as asyncio.windows_utils.Popen
    err = open(stderr_path, "ab")  # noqa: SIM115 - closed below
    import msvcrt
    try:
        proc = spawn([program, *args], env=env, cwd=cwd, suspended=job is not None,
                     handles=(in_r, out_w, msvcrt.get_osfhandle(err.fileno())))
    finally:
        _k32.CloseHandle(wintypes.HANDLE(out_w))
        _k32.CloseHandle(wintypes.HANDLE(in_r))
        err.close()
    if job is not None:
        job.assign_and_resume(proc)
    reader = asyncio.StreamReader(limit=limit, loop=loop)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader, loop=loop),
                                 windows_utils.PipeHandle(out_r))
    wt, wp = await loop.connect_write_pipe(lambda: asyncio.streams.FlowControlMixin(loop=loop),
                                           windows_utils.PipeHandle(in_w))
    writer = asyncio.StreamWriter(wt, wp, None, loop)
    return _AsyncContainerProc(proc, writer, reader)


# ---------------------------------------------------------------------------------------------- engine preparation
def _marker() -> Path:
    from vigia.config import get_settings
    return get_settings().tools_dir / f".appcontainer-{container().sid[-12:]}.granted"


def grant_persistent(path: Path, write: bool = False) -> None:
    """grant() once per directory and SID (recorded in tools/), new files inherit the ACE."""
    path = path.resolve()
    key = f"{'M' if write else 'RX'} {path}".lower()
    m = _marker()
    try:
        done = set(m.read_text(encoding="utf-8").splitlines()) if m.exists() else set()
    except OSError:
        done = set()
    if key in done:
        _granted.add(f"{path}|{write}")
        return
    grant(path, write=write)
    try:
        with open(m, "a", encoding="utf-8") as fh:
            fh.write(key + "\n")
    except OSError:
        pass


def python_home(exe: Path) -> Path | None:
    """Base interpreter directory of a venv python (pyvenv.cfg 'home')."""
    cfg = exe.parent.parent / "pyvenv.cfg" if exe.parent.name.lower() == "scripts" else exe.parent / "pyvenv.cfg"
    try:
        for line in cfg.read_text(encoding="utf-8").splitlines():
            k, _, v = line.partition("=")
            if k.strip().lower() == "home":
                return Path(v.strip())
    except OSError:
        return None
    return None


def prepare(argv: list[str], *, read: list[Path], write: list[Path]) -> None:
    """Give the container exactly the file access an engine run needs."""
    if in_container():
        return  # confined scan worker: its per-scan container was prepared by the parent
    from vigia.config import get_settings
    s = get_settings()
    roots = {s.tools_dir.resolve()}
    for a in argv[:2]:
        p = Path(a)
        if p.is_absolute() and p.exists():
            roots.add(p.parent.resolve())
            home = python_home(p) if p.name.lower().startswith("python") else None
            if home:
                roots.add(home.resolve())
    for r in roots | {x.resolve() for x in read if x and x.exists()}:
        grant_persistent(r)
    for w in write:
        if w and w.exists():
            grant_persistent(w, write=True)


# ---------------------------------------------------------------------------------------------- per-scan containers
ALL_APP_PACKAGES = "S-1-15-2-1"  # group present in every AppContainer token: used only for non-secret code/binaries


def in_container() -> bool:
    """Is the current process itself running inside an AppContainer (e.g. a confined scan worker)?"""
    if not IS_WINDOWS:
        return False
    tok = wintypes.HANDLE()
    if not _advapi.OpenProcessToken(wintypes.HANDLE(-1), 0x0008, ctypes.byref(tok)):  # TOKEN_QUERY
        return False
    try:
        val, ret = wintypes.DWORD(), wintypes.DWORD()
        ok = _advapi.GetTokenInformation(tok, 29, ctypes.byref(val), 4, ctypes.byref(ret))  # TokenIsAppContainer
        return bool(ok and val.value)
    finally:
        _k32.CloseHandle(tok)


def grant_code_readable(path: Path) -> None:
    """Read/execute for every AppContainer on non-secret code (engines, venv, Vigía's sources). Once per tree."""
    path = path.resolve()
    from vigia.config import get_settings
    marker = get_settings().tools_dir / ".appcontainer-allpackages.granted"
    key = str(path).lower()
    try:
        done = set(marker.read_text(encoding="utf-8").splitlines()) if marker.exists() else set()
    except OSError:
        done = set()
    if key in done:
        return
    r = subprocess.run(["icacls", str(path), "/grant", f"*{ALL_APP_PACKAGES}:(OI)(CI)(RX)", "/T", "/Q", "/C"],  # noqa: S603,S607
                       capture_output=True, timeout=1800)
    if r.returncode != 0:
        raise IsolationError(f"No se pudo dar lectura a los contenedores en {path}")
    with open(marker, "a", encoding="utf-8") as fh:
        fh.write(key + "\n")


if IS_WINDOWS:
    class _TRUSTEE_W(ctypes.Structure):
        _fields_ = [("pMultipleTrustee", ctypes.c_void_p), ("MultipleTrusteeOperation", ctypes.c_int),
                    ("TrusteeForm", ctypes.c_int), ("TrusteeType", ctypes.c_int), ("ptstrName", ctypes.c_void_p)]

    class _EXPLICIT_ACCESS_W(ctypes.Structure):
        _fields_ = [("grfAccessPermissions", wintypes.DWORD), ("grfAccessMode", ctypes.c_int),
                    ("grfInheritance", wintypes.DWORD), ("Trustee", _TRUSTEE_W)]

    _advapi.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p,
                                              ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    _advapi.SetEntriesInAclW.argtypes = [wintypes.ULONG, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    _advapi.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    _advapi.SetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, wintypes.BOOL, ctypes.c_void_p, wintypes.BOOL]
    _k32.LocalFree.argtypes = [ctypes.c_void_p]

MODIFY_MASK = 0x001301BF  # read + write + execute + delete
READ_EXEC_MASK = 0x001200A9


def set_ace(path: Path, psid, *, mask: int, inherit: bool, revoke: bool = False) -> None:  # noqa: ANN001
    """Add (or revoke) one ACE on a single file/directory WITHOUT propagating to existing children (SetFileSecurity).
    With ``inherit`` the ACE is inheritable, so files the container creates afterwards get it."""
    pdacl, psd, newdacl = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    rc = _advapi.GetNamedSecurityInfoW(str(path), 1, 4, None, None, ctypes.byref(pdacl), None, ctypes.byref(psd))
    if rc != 0:
        raise IsolationError(f"GetNamedSecurityInfo {path}: {rc}")
    try:
        ea = _EXPLICIT_ACCESS_W(mask, 4 if revoke else 1, 0 if revoke else (0x3 if inherit else 0),
                                _TRUSTEE_W(None, 0, 0, 0, psid))  # GRANT_ACCESS / REVOKE_ACCESS, TRUSTEE_IS_SID
        rc = _advapi.SetEntriesInAclW(1, ctypes.byref(ea), pdacl, ctypes.byref(newdacl))
        if rc != 0:
            raise IsolationError(f"SetEntriesInAcl {path}: {rc}")
        sd = ctypes.create_string_buffer(64)
        _advapi.InitializeSecurityDescriptor(sd, 1)
        _advapi.SetSecurityDescriptorDacl(sd, True, newdacl, False)
        if not _advapi.SetFileSecurityW(str(path), 4, sd):
            raise IsolationError(f"SetFileSecurity {path}: {ctypes.get_last_error()}")
    finally:
        for h in (newdacl, psd):
            if h:
                _k32.LocalFree(h)


class ScanContainer:
    """A fresh AppContainer for one scan (worker + engines): created, given loopback and exactly the files the scan
    needs, then revoked and deleted at the end."""

    def __init__(self, name: str):
        self.name = name
        self.sid = ""
        self._psid = ctypes.c_void_p()
        self._aces: list[tuple[Path, int]] = []
        self._trees: list[Path] = []

    def __enter__(self) -> "ScanContainer":
        hr = _userenv.CreateAppContainerProfile(ctypes.c_wchar_p(self.name), ctypes.c_wchar_p(self.name),
                                                ctypes.c_wchar_p("Vigia: escaneo confinado"), None, 0,
                                                ctypes.byref(self._psid))
        if (hr & 0xFFFFFFFF) == 0x800700B7:
            hr = _userenv.DeriveAppContainerSidFromAppContainerName(ctypes.c_wchar_p(self.name),
                                                                   ctypes.byref(self._psid))
        if not _hr_ok(hr):
            raise IsolationError(f"No se pudo crear el AppContainer del escaneo (0x{hr & 0xFFFFFFFF:08x})")
        s = wintypes.LPWSTR()
        _advapi.ConvertSidToStringSidW(self._psid, ctypes.byref(s))
        self.sid = s.value
        _ensure_loopback(Container(self.name, self.sid, self._psid))
        return self

    @property
    def container(self) -> Container:
        return Container(self.name, self.sid, self._psid)

    def allow(self, path: Path, *, write: bool, inherit: bool = False) -> None:
        if not path.exists():
            return
        mask = MODIFY_MASK if write else READ_EXEC_MASK
        set_ace(path, self._psid, mask=mask, inherit=inherit)
        self._aces.append((path, mask))

    def allow_tree(self, path: Path) -> None:
        """Read access to an existing tree (applied to every file; removed at the end)."""
        subprocess.run(["icacls", str(path), "/grant", f"*{self.sid}:(OI)(CI)(RX)", "/T", "/Q", "/C"],  # noqa: S603,S607
                       capture_output=True, timeout=900)
        self._trees.append(path)

    def __exit__(self, *exc) -> None:  # noqa: ANN002
        for tree in self._trees:
            subprocess.run(["icacls", str(tree), "/remove:g", f"*{self.sid}", "/T", "/Q", "/C"],  # noqa: S603,S607
                           capture_output=True, timeout=900)
        for path, mask in reversed(self._aces):
            try:
                set_ace(path, self._psid, mask=mask, inherit=False, revoke=True)
            except (IsolationError, OSError):
                pass
        try:
            _checknet("LoopbackExempt", "-d", f"-p={self.sid}")
        except (OSError, subprocess.SubprocessError):
            pass
        _userenv.DeleteAppContainerProfile(ctypes.c_wchar_p(self.name))


def use_container_pipes() -> None:
    """Inside an AppContainer only the container private pipe namespace (LOCAL prefix) may be used: asyncio
    subprocess pipes (and therefore Playwright's driver) are redirected there. Verified: plain names → error 5."""
    if not IS_WINDOWS or not in_container():
        return
    import _winapi
    import itertools
    import tempfile
    from asyncio import windows_utils
    if getattr(windows_utils, "_vigia_local_pipes", False):
        return
    counter = itertools.count()

    def pipe(*, duplex=False, overlapped=(True, True), bufsize=windows_utils.BUFSIZE):  # noqa: ANN001, ANN202
        # same as CPython's windows_utils.pipe; FILE_FLAG_FIRST_PIPE_INSTANCE makes a pre-created name fail
        address = tempfile.mktemp(prefix="\\\\.\\pipe\\LOCAL\\python-pipe-{:d}-{:d}-".format(  # nosec B306
            os.getpid(), next(counter)))
        if duplex:
            openmode, access, obsize, ibsize = (_winapi.PIPE_ACCESS_DUPLEX, _winapi.GENERIC_READ | _winapi.GENERIC_WRITE,
                                                bufsize, bufsize)
        else:
            openmode, access, obsize, ibsize = _winapi.PIPE_ACCESS_INBOUND, _winapi.GENERIC_WRITE, 0, bufsize
        openmode |= _winapi.FILE_FLAG_FIRST_PIPE_INSTANCE
        if overlapped[0]:
            openmode |= _winapi.FILE_FLAG_OVERLAPPED
        flags = _winapi.FILE_FLAG_OVERLAPPED if overlapped[1] else 0
        h1 = h2 = None
        try:
            h1 = _winapi.CreateNamedPipe(address, openmode, _winapi.PIPE_WAIT, 1, obsize, ibsize,
                                         _winapi.NMPWAIT_WAIT_FOREVER, _winapi.NULL)
            h2 = _winapi.CreateFile(address, access, 0, _winapi.NULL, _winapi.OPEN_EXISTING, flags, _winapi.NULL)
            ov = _winapi.ConnectNamedPipe(h1, overlapped=True)
            ov.GetOverlappedResult(True)
            return h1, h2
        except BaseException:
            for h in (h1, h2):
                if h is not None:
                    _winapi.CloseHandle(h)
            raise
    windows_utils.pipe = pipe
    windows_utils._vigia_local_pipes = True
