"""Isolated execution of external security engines.

Every external process is started:
  * from an absolute executable path resolved by the tool registry (never via a shell, never via PATH lookup
    of a user-supplied name);
  * with a minimal environment (no inherited secrets, proxies or tokens), HOME/TEMP redirected into a
    per-run sandbox directory;
  * inside a resource envelope: wall-clock timeout, resident memory limit for the whole process tree,
    stdout/stderr size cap, cancellation;
  * on Windows inside a Job Object (KILL_ON_JOB_CLOSE + memory limit; the process starts suspended so no
    child can escape before it is assigned); on POSIX in a new session with setrlimit (AS, CPU, NOFILE, CORE).
When the run ends for any reason the whole process tree is terminated.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import psutil

IS_WINDOWS = sys.platform == "win32"


@dataclass
class ToolResult:
    tool: str
    command: list[str]
    status: str  # ok | failed | timeout | killed | cancelled | error
    exit_code: int | None = None
    duration: float = 0.0
    max_rss_mb: float = 0.0
    cpu_seconds: float = 0.0
    stdout: bytes = b""
    stderr: bytes = b""
    stdout_truncated: bool = False
    workdir: Path | None = None
    error: str | None = None
    net_violations: list = field(default_factory=list)  # vigia.security.netwatch.NetViolation (kill switch)

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def stderr_tail(self) -> str:
        return self.stderr[-4000:].decode("utf-8", errors="replace")

    @property
    def text(self) -> str:
        return self.stdout.decode("utf-8", errors="replace")


@dataclass
class RunLimits:
    timeout: float = 900.0
    max_memory_mb: int = 2048
    max_output_mb: int = 64
    max_cpu_seconds: int | None = None  # POSIX RLIMIT_CPU
    extra_env: dict[str, str] = field(default_factory=dict)
    netwatch: bool = False  # egress kill switch: terminate the tree if it opens a socket outside loopback
    isolate: bool = False  # preventive: run inside the network-less AppContainer (loopback only) on Windows
    read_paths: list = field(default_factory=list)  # extra directories the isolated engine must read


# ------------------------------------------------------------------ Windows Job Objects
if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _ntdll = ctypes.WinDLL("ntdll")

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in ("ReadOperationCount", "WriteOperationCount",
                                                     "OtherOperationCount", "ReadTransferCount",
                                                     "WriteTransferCount", "OtherTransferCount")]

    class _BASIC_LIMIT(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                    ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class _EXT_LIMIT(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", _BASIC_LIMIT), ("IoInfo", _IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

    _JobObjectExtendedLimitInformation = 9
    _LIMIT_KILL_ON_JOB_CLOSE = 0x2000
    _LIMIT_JOB_MEMORY = 0x200
    _LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x400
    _CREATE_SUSPENDED = 0x4
    _CREATE_NEW_PROCESS_GROUP = 0x200
    _CREATE_NO_WINDOW = 0x08000000

    _k32.CreateJobObjectW.restype = wintypes.HANDLE
    _k32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    _k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    _k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _k32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]

    class _Job:
        def __init__(self, memory_mb: int):
            self.handle = _k32.CreateJobObjectW(None, None)
            if not self.handle:
                raise OSError(ctypes.get_last_error(), "CreateJobObject")
            info = _EXT_LIMIT()
            info.BasicLimitInformation.LimitFlags = (_LIMIT_KILL_ON_JOB_CLOSE | _LIMIT_JOB_MEMORY
                                                     | _LIMIT_DIE_ON_UNHANDLED_EXCEPTION)
            info.JobMemoryLimit = memory_mb * 1024 * 1024
            if not _k32.SetInformationJobObject(self.handle, _JobObjectExtendedLimitInformation,
                                                ctypes.byref(info), ctypes.sizeof(info)):
                raise OSError(ctypes.get_last_error(), "SetInformationJobObject")

        def assign_and_resume(self, proc: subprocess.Popen) -> None:
            h = int(proc._handle)  # type: ignore[attr-defined]
            if not _k32.AssignProcessToJobObject(self.handle, h):
                err = ctypes.get_last_error()
                proc.kill()
                raise OSError(err, "AssignProcessToJobObject")
            _ntdll.NtResumeProcess(h)

        def terminate(self) -> None:
            if self.handle:
                _k32.TerminateJobObject(self.handle, 1)

        def close(self) -> None:
            if self.handle:
                _k32.CloseHandle(self.handle)  # KILL_ON_JOB_CLOSE: anything left dies here
                self.handle = None


def _posix_preexec(limits: RunLimits) -> Callable[[], None]:
    def _apply() -> None:  # runs in the child after fork
        import resource
        mem = limits.max_memory_mb * 1024 * 1024
        for res, val in ((resource.RLIMIT_AS, mem * 2), (resource.RLIMIT_CORE, 0), (resource.RLIMIT_NOFILE, 4096)):
            try:
                resource.setrlimit(res, (val, val))
            except (ValueError, OSError):
                pass
        if limits.max_cpu_seconds:
            resource.setrlimit(resource.RLIMIT_CPU, (limits.max_cpu_seconds, limits.max_cpu_seconds + 5))
        os.umask(0o077)
        try:  # Linux: die with the worker (no orphaned engines if Vigía crashes); PR_SET_PDEATHSIG = 1
            import ctypes
            import signal
            ctypes.CDLL("libc.so.6", use_errno=True).prctl(1, signal.SIGKILL)
        except (OSError, AttributeError):
            pass
    return _apply


def _spawn_isolated(argv: list[str], env: dict[str, str], cwd: Path, wd: Path, fo, fe, stdin: bytes | None,  # noqa: ANN001
                    lim: RunLimits):
    """Start the engine suspended inside the AppContainer (no network but loopback); the caller assigns the job."""
    from vigia.security import appcontainer as ac
    ac.prepare(argv, read=[Path(p) for p in lim.read_paths] + ([cwd] if cwd != wd else []), write=[wd.parent])
    stdin_fd = None
    if stdin is not None:
        (wd / "stdin.bin").write_bytes(stdin)
        stdin_fd = os.open(wd / "stdin.bin", os.O_RDONLY | getattr(os, "O_BINARY", 0))
    env = {**env, "LOCALAPPDATA": env.get("LOCALAPPDATA") or str(wd / "home" / "LocalAppData")}
    Path(env["LOCALAPPDATA"]).mkdir(parents=True, exist_ok=True)
    try:
        return ac.spawn(argv, env=env, cwd=str(cwd), stdout_fd=fo.fileno(), stderr_fd=fe.fileno(), stdin_fd=stdin_fd,
                        suspended=True)
    finally:
        if stdin_fd is not None:
            os.close(stdin_fd)


def minimal_env(sandbox: Path, tool_dirs: list[Path], extra: dict[str, str] | None = None) -> dict[str, str]:
    """Environment for external tools: no secrets, no inherited proxies, home/temp inside the sandbox.

    The only proxy variables an engine ever sees are the ones Vigía sets explicitly in ``extra`` (its own loopback
    egress gateway), never the operator's environment."""
    home = sandbox / "home"
    tmp = sandbox / "tmp"
    home.mkdir(parents=True, exist_ok=True)
    tmp.mkdir(parents=True, exist_ok=True)
    if IS_WINDOWS:
        sysroot = os.environ.get("SYSTEMROOT", r"C:\Windows")
        path = [str(d) for d in tool_dirs] + [rf"{sysroot}\System32", sysroot]
        env = {"SYSTEMROOT": sysroot, "WINDIR": sysroot, "COMSPEC": rf"{sysroot}\System32\cmd.exe",
               "PATHEXT": ".COM;.EXE;.BAT;.CMD", "USERPROFILE": str(home), "APPDATA": str(home / "AppData"),
               "LOCALAPPDATA": str(home / "LocalAppData"), "HOMEDRIVE": str(home.drive), "HOMEPATH": str(home)[2:],
               "NUMBER_OF_PROCESSORS": os.environ.get("NUMBER_OF_PROCESSORS", "2"),
               "PROCESSOR_ARCHITECTURE": os.environ.get("PROCESSOR_ARCHITECTURE", "AMD64")}
    else:
        path = [str(d) for d in tool_dirs] + ["/usr/local/bin", "/usr/bin", "/bin"]
        env = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    env.update({"PATH": os.pathsep.join(path), "HOME": str(home), "TMP": str(tmp), "TEMP": str(tmp),
                "TMPDIR": str(tmp), "XDG_CONFIG_HOME": str(home / ".config"), "XDG_CACHE_HOME": str(home / ".cache"),
                "NO_COLOR": "1", "TERM": "dumb", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUTF8": "1"})
    for k, v in (extra or {}).items():
        if k.upper() in ("PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "PYTHONPATH"):
            continue  # never let adapters override loader / search paths
        env[k] = v
    return env


class ToolRunner:
    def __init__(self, sandbox_root: Path, defaults: RunLimits | None = None,
                 cancel_event: threading.Event | None = None):
        self.sandbox_root = Path(sandbox_root)
        self.defaults = defaults or RunLimits()
        self.cancel_event = cancel_event or threading.Event()
        self.sandbox_root.mkdir(parents=True, exist_ok=True)

    def new_workdir(self, tool: str) -> Path:
        d = self.sandbox_root / f"{tool}-{uuid.uuid4().hex[:10]}"
        (d / "out").mkdir(parents=True, exist_ok=True)
        return d

    def run(self, tool: str, argv: list[str], *, limits: RunLimits | None = None, cwd: Path | None = None,
            workdir: Path | None = None, tool_dirs: list[Path] | None = None, stdin: bytes | None = None) -> ToolResult:
        lim = limits or self.defaults
        exe = Path(argv[0])
        if not exe.is_absolute() or not exe.exists():
            return ToolResult(tool, argv, "error", error=f"Ejecutable no encontrado o ruta no absoluta: {argv[0]}")
        if any("\x00" in a for a in argv):
            return ToolResult(tool, argv, "error", error="Argumento con byte nulo")
        wd = workdir or self.new_workdir(tool)
        env = minimal_env(wd, [exe.parent] + list(tool_dirs or []), lim.extra_env)
        out_path, err_path = wd / "stdout.bin", wd / "stderr.bin"
        res = ToolResult(tool, argv, "error", workdir=wd)
        if self.cancel_event.is_set():
            res.status, res.error = "cancelled", "Cancelado antes de iniciar"
            return res
        job = None
        t0 = time.monotonic()
        with open(out_path, "wb") as fo, open(err_path, "wb") as fe:
            kwargs: dict = dict(stdout=fo, stderr=fe, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                cwd=str(cwd or wd), env=env, shell=False, close_fds=True)
            if IS_WINDOWS:
                kwargs["creationflags"] = _CREATE_SUSPENDED | _CREATE_NEW_PROCESS_GROUP | _CREATE_NO_WINDOW
            else:
                kwargs["start_new_session"] = True
                kwargs["preexec_fn"] = _posix_preexec(lim)
            try:
                if IS_WINDOWS:
                    job = _Job(lim.max_memory_mb)
                if lim.isolate:
                    proc = _spawn_isolated(argv, env, cwd or wd, wd, fo, fe, stdin, lim)
                    stdin = None  # already provided through a file
                else:
                    proc = subprocess.Popen(argv, **kwargs)  # noqa: S603 - argv list, absolute exe, no shell
                if job is not None:
                    job.assign_and_resume(proc)
            except OSError as e:
                if job is not None:
                    job.close()
                res.error = f"No se pudo iniciar {tool}: {e}"
                return res
            if stdin is not None and proc.stdin:
                try:
                    proc.stdin.write(stdin)
                    proc.stdin.close()
                except OSError:
                    pass
            reason = self._watch(proc, lim, out_path, err_path, res, t0)
            if reason:
                self._kill_tree(proc, job)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._kill_tree(proc, job)
            if job is not None:
                job.close()
            if hasattr(proc, "close"):
                proc.close()
        res.duration = round(time.monotonic() - t0, 3)
        res.exit_code = proc.returncode
        cap = lim.max_output_mb * 1024 * 1024
        res.stdout = out_path.read_bytes()[:cap]
        res.stdout_truncated = out_path.stat().st_size > cap
        res.stderr = err_path.read_bytes()[-64_000:]
        if reason:
            res.status = reason
            res.error = {"timeout": f"Superó el tiempo máximo ({lim.timeout:.0f}s)",
                         "killed": res.error or "Detenido por exceder límites de recursos",
                         "cancelled": "Cancelado por el usuario"}.get(reason, reason)
        else:
            res.status = "ok" if proc.returncode == 0 else "failed"
        return res

    def _watch(self, proc: subprocess.Popen, lim: RunLimits, out_path: Path, err_path: Path, res: ToolResult,
               t0: float) -> str | None:
        try:
            ps = psutil.Process(proc.pid)
        except psutil.Error:
            ps = None
        cap = lim.max_output_mb * 1024 * 1024
        while proc.poll() is None:
            if self.cancel_event.is_set():
                return "cancelled"
            if time.monotonic() - t0 > lim.timeout:
                return "timeout"
            if lim.netwatch:
                from vigia.security.netwatch import scan as net_scan
                found = net_scan([proc.pid])
                if found:
                    res.net_violations = found
                    res.error = ("Kill switch de salida: el motor abrió una conexión fuera del túnel y se ha detenido "
                                 f"({found[0]})")
                    return "killed"
            if ps is not None:
                rss, cpu = 0, 0.0
                try:
                    for p in [ps] + ps.children(recursive=True):
                        try:
                            rss += p.memory_info().rss
                            t = p.cpu_times()
                            cpu += t.user + t.system
                        except psutil.Error:
                            continue
                except psutil.Error:
                    pass
                res.max_rss_mb = max(res.max_rss_mb, round(rss / 1048576, 1))
                res.cpu_seconds = max(res.cpu_seconds, round(cpu, 2))
                if rss > lim.max_memory_mb * 1024 * 1024:
                    res.error = f"Memoria excedida ({res.max_rss_mb} MB > {lim.max_memory_mb} MB)"
                    return "killed"
            try:
                if out_path.stat().st_size > cap * 1.05 or err_path.stat().st_size > cap:
                    res.error = f"Salida excedida (> {lim.max_output_mb} MB)"
                    return "killed"
            except OSError:
                pass
            time.sleep(0.2)
        return None

    @staticmethod
    def _kill_tree(proc: subprocess.Popen, job) -> None:  # noqa: ANN001
        if job is not None:
            job.terminate()
        try:
            parent = psutil.Process(proc.pid)
            procs = parent.children(recursive=True) + [parent]
        except psutil.Error:
            procs = []
        for p in procs:
            try:
                p.kill()
            except psutil.Error:
                pass
        psutil.wait_procs(procs, timeout=5)
        if not IS_WINDOWS:
            try:
                os.killpg(proc.pid, 9)
            except OSError:
                pass

    def spawn(self, tool: str, argv: list[str], *, limits: RunLimits | None = None,
              workdir: Path | None = None) -> "Daemon":
        """Start a long-running engine (e.g. ZAP daemon) under the same isolation; caller must stop() it."""
        lim = limits or self.defaults
        exe = Path(argv[0])
        if not exe.is_absolute() or not exe.exists():
            raise FileNotFoundError(argv[0])
        wd = workdir or self.new_workdir(tool)
        env = minimal_env(wd, [exe.parent], lim.extra_env)
        log = open(wd / "daemon.log", "wb")  # noqa: SIM115 - closed in Daemon.stop
        kwargs: dict = dict(stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, cwd=str(wd), env=env,
                            shell=False, close_fds=True)
        job = None
        if IS_WINDOWS:
            kwargs["creationflags"] = _CREATE_SUSPENDED | _CREATE_NEW_PROCESS_GROUP | _CREATE_NO_WINDOW
            job = _Job(lim.max_memory_mb)
        else:
            kwargs["start_new_session"] = True
            kwargs["preexec_fn"] = _posix_preexec(lim)
        if lim.isolate:
            proc = _spawn_isolated(argv, env, wd, wd, log, log, None, lim)
        else:
            proc = subprocess.Popen(argv, **kwargs)  # noqa: S603
        if job is not None:
            job.assign_and_resume(proc)
        d = Daemon(tool, proc, job, log, wd, self)
        if lim.netwatch:
            from vigia.security.netwatch import NetWatchThread

            def _violation(found) -> None:  # noqa: ANN001
                d.net_violations.extend(found)
                ToolRunner._kill_tree(d.proc, d.job)
            d.watch = NetWatchThread(lambda: [proc.pid], _violation).start()
        return d

    def cleanup(self, workdir: Path) -> None:
        if workdir and self.sandbox_root in workdir.parents:
            shutil.rmtree(workdir, ignore_errors=True)


class Daemon:
    """Handle for a long-running isolated engine process."""

    def __init__(self, tool: str, proc: subprocess.Popen, job, log, workdir: Path, runner: ToolRunner):  # noqa: ANN001
        self.tool, self.proc, self.job, self.log, self.workdir, self.runner = tool, proc, job, log, workdir, runner
        self.net_violations: list = []
        self.watch = None

    @property
    def alive(self) -> bool:
        return self.proc.poll() is None

    def log_tail(self, n: int = 4000) -> str:
        try:
            return (self.workdir / "daemon.log").read_bytes()[-n:].decode("utf-8", errors="replace")
        except OSError:
            return ""

    def stop(self) -> None:
        if self.watch is not None:
            self.watch.stop()
        ToolRunner._kill_tree(self.proc, self.job)
        if self.job is not None:
            self.job.close()
        try:
            self.log.close()
        except OSError:
            pass
