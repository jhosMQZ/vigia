"""Kill switch for engines: detect any socket an engine's process tree opens outside loopback.

With an egress configured, engines may only talk to Vigía's loopback gateway / DNS stub (and ZAP to its own API on
loopback). This monitor polls the OS socket table (psutil, no privileges needed on Windows/Linux) for the whole
process tree and reports:
  * TCP sockets whose remote address is not loopback (a direct connection: home IP exposed);
  * UDP sockets bound to a non-loopback address (able to send datagrams — DNS, QUIC, STUN — outside the tunnel).

Limits (stated, not hidden): it is *detective* — it polls every ``interval`` seconds, so a very short-lived socket
can be missed; and lookups delegated to the OS resolver service (Windows Dnscache/svchost, systemd-resolved) are
made by another process. The preventive controls (proxy flags, DNS stub, JVM hosts file, Chromium host-resolver
rules) are the first line; hard enforcement needs a network namespace / firewall (see docs/06-auditoria-red.md).
"""
from __future__ import annotations

import ipaddress
import socket
import threading
import time
from dataclasses import asdict, dataclass
from typing import Callable, Iterable

import psutil


def is_loopback(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a.is_loopback


@dataclass
class NetViolation:
    pid: int
    process: str
    proto: str
    local: str
    remote: str
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)

    def __str__(self) -> str:
        return f"{self.process} (pid {self.pid}) {self.proto} {self.local} → {self.remote or '*'}: {self.detail}"


def tree_pids(roots: Iterable[int]) -> dict[int, str]:
    out: dict[int, str] = {}
    for pid in roots:
        try:
            p = psutil.Process(pid)
            for proc in [p] + p.children(recursive=True):
                try:
                    out[proc.pid] = proc.name()
                except psutil.Error:
                    out[proc.pid] = "?"
        except psutil.Error:
            continue
    return out


def scan(roots: Iterable[int]) -> list[NetViolation]:
    """One pass over the socket table for the given process trees."""
    pids = tree_pids(roots)
    if not pids:
        return []
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.Error, OSError):
        return []
    out: list[NetViolation] = []
    for c in conns:
        if c.pid not in pids:
            continue
        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
        if c.type == socket.SOCK_STREAM:
            if c.raddr and not is_loopback(c.raddr.ip):
                out.append(NetViolation(c.pid, pids[c.pid], "tcp", laddr, raddr,
                                        "conexión TCP directa fuera del túnel"))
        elif c.type == socket.SOCK_DGRAM:
            if c.laddr and not is_loopback(c.laddr.ip):
                out.append(NetViolation(c.pid, pids[c.pid], "udp", laddr, raddr,
                                        "socket UDP no ligado a loopback (DNS/QUIC/STUN fuera del túnel)"))
    return out


class NetWatchThread:
    """Background poller for process trees not owned by ToolRunner.run (ZAP daemon, Playwright's Chromium)."""

    def __init__(self, roots: Callable[[], Iterable[int]], on_violation: Callable[[list[NetViolation]], None], *,
                 interval: float = 0.2):
        self.roots = roots
        self.on_violation = on_violation
        self.interval = interval
        self.violations: list[NetViolation] = []
        self.polls = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="vigia-netwatch", daemon=True)

    def start(self) -> "NetWatchThread":
        self._thread.start()
        return self

    def _run(self) -> None:
        while not self._stop.is_set():
            v = scan(list(self.roots()))
            self.polls += 1
            if v:
                self.violations.extend(v)
                try:
                    self.on_violation(v)
                except Exception:  # noqa: BLE001
                    pass
            self._stop.wait(self.interval)

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(5)


def wait_quiet(roots: Iterable[int], seconds: float = 0.5) -> list[NetViolation]:
    """Poll for ``seconds`` (helper for tests/audit)."""
    end = time.monotonic() + seconds
    found: list[NetViolation] = []
    while time.monotonic() < end:
        found += scan(roots)
        time.sleep(0.1)
    return found
