"""Egress gateway: the single loopback choke point every engine (and, with an egress, every native module) uses.

One listener on 127.0.0.1 speaks HTTP CONNECT, absolute-form HTTP forwarding and SOCKS5 (auto-detected by the
first byte). For every connection it:
  1. applies the lane policy — *scope* (ScopeGuard: host in scope, port allowed, exclusions, every resolved IP
     validated; IP literals only if they are a scope IP or the pinned address of an in-scope name) or *public*
     (Vigía's own third-party traffic: public addresses only, ports 80/443);
  2. resolves names with the guard's resolver (remote DoH through the egress when configured) and pins the IP;
  3. connects to that IP **only** through the upstream egress. If the upstream is down the client gets an error
     and ``on_egress_down`` fires — there is no direct fallback.

An optional DNS stub (UDP+TCP on loopback) answers engines' own resolvers (nuclei/subfinder ``-r``) with the same
pinned addresses for in-scope names and REFUSED for everything else, so engines never query the local resolver.
Every decision is recorded (``records`` and the JSONL ``trace_path``).

Access control (the gateway is a way out to the Internet, so it is not open to the machine):
  * per-run random credentials (HTTP ``Proxy-Authorization: Basic`` / SOCKS5 RFC 1929), compared in constant time
    and destroyed when the gateway stops;
  * process attribution: the OS socket table must show that the connecting socket belongs to Vigía itself or to one
    of its descendant processes (engines, Chromium) — another local program is refused even with the credentials;
  * limits: concurrent connections, new connections per second, plain-HTTP method allow-list, tunnel lifetime.
"""
from __future__ import annotations

import asyncio
import base64
import hmac
import ipaddress
import json
import os
import secrets
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset

from vigia.security.errors import EgressDown, StopScan, UpstreamRefused
from vigia.security.scope import ScopeGuard, ScopeViolation, ip_block_reason

HOP_BY_HOP = {b"connection", b"proxy-connection", b"keep-alive", b"proxy-authorization", b"proxy-authenticate", b"te",
              b"trailer", b"upgrade", b"expect"}
MAX_HEAD = 64 * 1024


@dataclass
class Decision:
    ip: str
    port: int
    host: str  # name the client asked for (or the IP)


class ScopePolicy:
    name = "scope"

    def __init__(self, guard: ScopeGuard):
        self.guard = guard

    async def decide(self, host: str, port: int) -> Decision:
        if _is_ip(host):
            chk = await self.guard.check_ip_literal(host, port)
        else:
            chk = await self.guard.check_host_port(host, port)
        return Decision(str(chk.pinned_ip), port, host)

    async def decide_url(self, url: str) -> Decision:
        p = urlsplit(url)
        host = (p.hostname or "").lower()
        port = p.port or 80
        if _is_ip(host):
            chk = await self.guard.check_ip_literal(host, port)
            if self.guard.is_excluded(host, p.path or "/", url):
                raise ScopeViolation(f"{url} está en la lista de exclusiones")
            return Decision(str(chk.pinned_ip), port, host)
        chk = await self.guard.check_url(url)
        return Decision(str(chk.pinned_ip), chk.port, host)

    def allows_name(self, name: str) -> bool:
        return self.guard.host_matches(name) and not self.guard.is_excluded(name)

    async def addresses(self, name: str) -> list[Any]:
        await self.guard.check_host_port(name, (sorted(self.guard.allowed_ports)[0] if self.guard.allowed_ports else 443))
        return await self.guard.resolve(name)

    @property
    def resolver(self) -> Any:
        from vigia.security.resolver import default_resolver
        return self.guard.resolver or default_resolver()


class PublicPolicy:
    """Vigía's own third-party traffic (intel lookups, CT logs, engines' passive sources)."""
    name = "public"
    PORTS = {80, 443}

    def __init__(self, resolver: Any):
        self.resolver = resolver
        self._cache: dict[str, list[Any]] = {}

    async def _ips(self, host: str) -> list[Any]:
        if _is_ip(host):
            return [ipaddress.ip_address(host.strip("[]"))]
        if host not in self._cache:
            from vigia.security.resolver import ResolutionError
            try:
                self._cache[host] = sorted(await self.resolver.addresses(host), key=lambda a: a.version)
            except ResolutionError as e:
                raise ScopeViolation(f"No se pudo resolver {host}: {e}") from e
        return self._cache[host]

    async def decide(self, host: str, port: int) -> Decision:
        if port not in self.PORTS:
            raise ScopeViolation(f"carril público: solo puertos 80/443 (pedido {port})")
        ips = await self._ips(host)
        for ip in ips:
            reason = ip_block_reason(ip, allow_private=False)
            if reason or ip.is_loopback:
                raise ScopeViolation(f"carril público: {host} → {reason or 'loopback'}")
        return Decision(str(ips[0]), port, host)

    async def decide_url(self, url: str) -> Decision:
        p = urlsplit(url)
        return await self.decide((p.hostname or "").lower(), p.port or 80)

    def allows_name(self, name: str) -> bool:
        return False

    async def addresses(self, name: str) -> list[Any]:
        raise ScopeViolation("el carril público no ofrece DNS")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


class EgressGateway:
    def __init__(self, policy: ScopePolicy | PublicPolicy, upstream: Any | None, *, lane: str | None = None,
                 dns_stub: bool = False, trace_path: Path | None = None,
                 on_egress_down: Callable[[str], None] | None = None, connect_timeout: float = 15.0,
                 idle_timeout: float = 90.0, max_records: int = 50000, auth: bool = True, attribution: bool = True,
                 allowed_methods: set[str] | None = None, max_concurrent: int = 400, max_new_per_s: float = 300.0,
                 max_tunnel_s: float = 1800.0):
        from vigia.security.egress import DirectEgress
        self.policy = policy
        self.upstream = upstream or DirectEgress()
        self.lane = lane or policy.name
        self.dns_stub = dns_stub
        self.trace_path = trace_path
        self.on_egress_down = on_egress_down
        self.connect_timeout = connect_timeout
        self.idle_timeout = idle_timeout
        self.max_records = max_records
        self.records: list[dict[str, Any]] = []
        self.egress_down: str | None = None
        self.token = secrets.token_hex(8)  # marks the gateway's own error replies (a target cannot forge them)
        self.auth = auth
        self.attribution = attribution
        self.username = "vigia"
        self.password = secrets.token_urlsafe(24)  # per run; replaced by an unknown value on stop()
        self.allowed_methods = {m.upper() for m in (allowed_methods or {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"})}
        self.max_concurrent = max_concurrent
        self.max_new_per_s = max_new_per_s
        self.max_tunnel_s = max_tunnel_s
        self._active = 0
        self._bucket = (float(max(1.0, max_new_per_s)), time.monotonic())
        self._pids_cache: tuple[float, set[int]] = (0.0, set())
        self.stopped = False
        self.port = 0
        self.dns_port = 0
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._servers: list[Any] = []
        self._tasks: set[asyncio.Task] = set()
        self._lock = threading.Lock()
        self._start_error: BaseException | None = None

    # ------------------------------------------------------------------ lifecycle
    @property
    def _cred(self) -> str:
        return f"{self.username}:{self.password}@" if self.auth else ""

    @property
    def http_url(self) -> str:
        """Proxy URL for clients (carries this run's credentials)."""
        return f"http://{self._cred}127.0.0.1:{self.port}"

    @property
    def socks_url(self) -> str:
        return f"socks5://{self._cred}127.0.0.1:{self.port}"

    @property
    def server(self) -> str:
        return f"http://127.0.0.1:{self.port}"  # without credentials (for clients that take them separately)

    @property
    def alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def egress_display(self) -> str:
        return getattr(self.upstream, "display", "direct")

    def start(self) -> "EgressGateway":
        self._thread = threading.Thread(target=self._run, name=f"vigia-gateway-{self.lane}", daemon=True)
        self._thread.start()
        if not self._ready.wait(15) or self._start_error is not None:
            raise RuntimeError(f"No se pudo iniciar la pasarela de salida: {self._start_error}")
        return self

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        loop.set_exception_handler(lambda lp, c: None if isinstance(c.get("exception"), (ConnectionError, OSError))
                                   else lp.default_exception_handler(c))
        try:
            loop.run_until_complete(self._bind())
        except BaseException as e:  # noqa: BLE001
            self._start_error = e
            self._ready.set()
            return
        self._ready.set()
        try:
            loop.run_forever()
        finally:
            for t in list(self._tasks):
                t.cancel()
            loop.run_until_complete(asyncio.gather(*self._tasks, return_exceptions=True))
            loop.close()

    async def _bind(self) -> None:
        srv = await asyncio.start_server(self._client, "127.0.0.1", 0, limit=MAX_HEAD)
        self._servers.append(srv)
        self.port = srv.sockets[0].getsockname()[1]
        if self.dns_stub:
            loop = asyncio.get_running_loop()
            for _ in range(20):
                transport, _ = await loop.create_datagram_endpoint(lambda: _DnsUdp(self), local_addr=("127.0.0.1", 0))
                port = transport.get_extra_info("sockname")[1]
                try:
                    tsrv = await asyncio.start_server(self._dns_tcp, "127.0.0.1", port)
                except OSError:
                    transport.close()
                    continue
                self._servers += [transport, tsrv]
                self.dns_port = port
                break
            else:
                raise OSError("no se pudo reservar un puerto para el stub DNS")

    def stop(self) -> None:
        loop = self._loop
        if loop is None or not loop.is_running():
            return

        self.stopped = True
        self.password = secrets.token_urlsafe(24)  # destroy this run's credentials: nobody knows the new value

        def _close() -> None:
            for s in self._servers:
                s.close()
            for t in list(self._tasks):
                t.cancel()
            loop.call_later(0.05, loop.stop)
        loop.call_soon_threadsafe(_close)
        if self._thread is not None:
            self._thread.join(10)

    def __enter__(self) -> "EgressGateway":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    # ------------------------------------------------------------------ records
    def _record(self, **rec: Any) -> None:
        rec = {"ts": round(time.time(), 3), "lane": self.lane, "egress": self.egress_display, **rec}
        with self._lock:
            if len(self.records) < self.max_records:
                self.records.append(rec)
        if self.trace_path:
            try:
                with open(self.trace_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            except OSError:
                pass

    def summary(self) -> dict[str, Any]:
        with self._lock:
            recs = list(self.records)
        allowed = [r for r in recs if r.get("decision") == "allowed"]
        refused = [r for r in recs if r.get("decision") == "refused"]
        return {"lane": self.lane, "egress": self.egress_display, "connections": len(allowed), "refused": len(refused),
                "errors": sum(1 for r in recs if r.get("decision") == "error"),
                "dns_answered": sum(1 for r in recs if r.get("proto") == "dns" and r.get("decision") == "allowed"),
                "dns_refused": sum(1 for r in recs if r.get("proto") == "dns" and r.get("decision") == "refused"),
                "egress_down": self.egress_down,
                "refused_samples": [f"{r.get('dest')}: {r.get('reason')}" for r in refused[:10]]}

    def _down(self, reason: str) -> None:
        if self.egress_down is None:
            self.egress_down = reason
            if self.on_egress_down:
                try:
                    self.on_egress_down(reason)
                except Exception:  # noqa: BLE001
                    pass

    # ------------------------------------------------------------------ access control
    def _allowed_pids(self) -> set[int]:
        import psutil
        ts, cached = self._pids_cache
        if time.monotonic() - ts < 0.5 and cached:
            return cached
        me = os.getpid()
        pids = {me}
        try:
            pids |= {p.pid for p in psutil.Process(me).children(recursive=True)}
        except psutil.Error:
            pass
        self._pids_cache = (time.monotonic(), pids)
        return pids

    def _owner(self, client_port: int, kind: str) -> int | None:
        import psutil
        try:
            conns = psutil.net_connections(kind=kind)
        except (psutil.Error, OSError):
            return None
        for c in conns:
            if not c.laddr or c.laddr.port != client_port:
                continue
            if kind.startswith("tcp"):
                if c.raddr and c.raddr.port in (self.port, self.dns_port) and c.laddr.ip.startswith(("127.", "::1")):
                    return c.pid
            elif c.laddr.ip in ("127.0.0.1", "0.0.0.0", "::", "::1"):  # nosec B104 - comparing a socket address, not binding
                return c.pid
        return None

    async def _authorized_process(self, peer: Any, kind: str = "tcp4") -> tuple[bool, str]:
        """Is the connecting socket owned by Vigía or one of its descendants? (OS socket table, no privileges)."""
        if not self.attribution:
            return True, "atribución desactivada"
        from vigia.security.appcontainer import in_container
        if in_container():
            # confined scan worker: the OS only lets processes of this same AppContainer reach its loopback ports
            # (verified: connections from outside the container time out), i.e. this worker and its engines
            return True, "mismo AppContainer (aislamiento de loopback del sistema)"
        port = peer[1] if peer else 0
        loop = asyncio.get_running_loop()
        for attempt in range(3):
            pid = await loop.run_in_executor(None, self._owner, port, kind)
            if pid is not None:
                if pid in self._allowed_pids() or pid in await loop.run_in_executor(None, self._refresh_pids):
                    return True, f"pid {pid}"
                return False, f"proceso local no autorizado (pid {pid}) intentó usar la pasarela"
            await asyncio.sleep(0.02 * (attempt + 1))
        return False, "no se pudo atribuir la conexión a un proceso de Vigía"

    def _refresh_pids(self) -> set[int]:
        self._pids_cache = (0.0, set())
        return self._allowed_pids()

    def _take_token(self) -> bool:
        tokens, ts = self._bucket
        now = time.monotonic()
        tokens = min(self.max_new_per_s, tokens + (now - ts) * self.max_new_per_s)
        if tokens < 1:
            self._bucket = (tokens, now)
            return False
        self._bucket = (tokens - 1, now)
        return True

    def _check_basic(self, header: bytes | None) -> bool:
        if not self.auth:
            return True
        if not header or not header.lower().startswith(b"basic "):
            return False
        try:
            user, _, pw = base64.b64decode(header[6:].strip()).decode("utf-8").partition(":")
        except (ValueError, UnicodeDecodeError):
            return False
        return (not self.stopped and hmac.compare_digest(user, self.username)
                and hmac.compare_digest(pw, self.password))

    # ------------------------------------------------------------------ core decision + upstream
    async def _open(self, proto: str, dest: str, decide: Callable[[], Any]) -> tuple[Any, Any, Decision] | str:
        """Returns (reader, writer, decision) or an error kind: forbidden | egress_down | refused | unreachable | timeout."""
        try:
            d = await decide()
        except ScopeViolation as e:
            self._record(proto=proto, dest=dest, decision="refused", reason=str(e)[:300])
            return "forbidden"
        except StopScan as e:
            self._record(proto=proto, dest=dest, decision="error", reason=str(e)[:300])
            self._down(str(e))
            return "egress_down"
        try:
            r, w = await self.upstream.open(d.ip, d.port, timeout=self.connect_timeout)
        except EgressDown as e:
            self._record(proto=proto, dest=dest, ip=d.ip, port=d.port, decision="error", reason=str(e)[:300])
            self._down(str(e))
            return "egress_down"
        except UpstreamRefused as e:
            self._record(proto=proto, dest=dest, ip=d.ip, port=d.port, decision="allowed", outcome=e.kind,
                         reason=str(e)[:200])
            return e.kind
        self._record(proto=proto, dest=dest, ip=d.ip, port=d.port, decision="allowed", outcome="open")
        return r, w, d

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        self._active += 1
        try:
            peer = writer.get_extra_info("peername")
            if self._active > self.max_concurrent or not self._take_token():
                self._record(proto="access", dest=str(peer), decision="refused", reason="límite de conexiones de la pasarela")
                return
            ok, who = await self._authorized_process(peer)
            if not ok:
                self._record(proto="access", dest=str(peer), decision="refused", reason=who)
                return
            first = await asyncio.wait_for(reader.readexactly(1), 30)
            if first == b"\x05":
                await self._socks(reader, writer)
            else:
                await self._http(first, reader, writer)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError, asyncio.LimitOverrunError):
            pass
        except asyncio.CancelledError:
            pass
        finally:
            self._active -= 1
            _close(writer)
            if task is not None:
                self._tasks.discard(task)

    # ------------------------------------------------------------------ SOCKS5
    async def _socks(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        n = (await r.readexactly(1))[0]
        methods = await r.readexactly(n)
        want = 2 if self.auth else 0
        if want not in methods:
            self._record(proto="socks5", dest="-", decision="refused", reason="cliente SOCKS sin credenciales")
            w.write(b"\x05\xff")
            await w.drain()
            return
        w.write(bytes([5, want]))
        await w.drain()
        if self.auth:  # RFC 1929
            await r.readexactly(1)
            user = (await r.readexactly((await r.readexactly(1))[0])).decode("utf-8", "replace")
            pw = (await r.readexactly((await r.readexactly(1))[0])).decode("utf-8", "replace")
            good = (not self.stopped and hmac.compare_digest(user, self.username)
                    and hmac.compare_digest(pw, self.password))
            w.write(b"\x01" + (b"\x00" if good else b"\x01"))
            await w.drain()
            if not good:
                self._record(proto="socks5", dest="-", decision="refused", reason="credenciales SOCKS inválidas")
                return
        ver, cmd, _, atyp = await r.readexactly(4)
        if atyp == 1:
            host = str(ipaddress.IPv4Address(await r.readexactly(4)))
        elif atyp == 4:
            host = str(ipaddress.IPv6Address(await r.readexactly(16)))
        elif atyp == 3:
            raw = await r.readexactly((await r.readexactly(1))[0])
            try:
                host = raw.decode("idna").lower()
            except UnicodeError:
                host = raw.decode("latin-1").lower()
        else:
            w.write(b"\x05\x08\x00\x01" + b"\x00" * 6)
            return
        port = struct.unpack("!H", await r.readexactly(2))[0]
        dest = f"{host}:{port}"
        if cmd != 1:  # BIND / UDP ASSOCIATE: never (UDP would bypass the tunnel)
            self._record(proto="socks5", dest=dest, decision="refused", reason=f"comando SOCKS {cmd} no permitido (UDP/BIND)")
            w.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return
        res = await self._open("socks5", dest, lambda: self.policy.decide(host, port))
        if isinstance(res, str):
            code = {"forbidden": 2, "egress_down": 1, "refused": 5, "unreachable": 4, "timeout": 6}.get(res, 4)
            w.write(bytes([5, code, 0, 1]) + b"\x00" * 6)
            await w.drain()
            return
        ur, uw, _ = res
        w.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
        await w.drain()
        await self._splice(r, w, ur, uw)

    # ------------------------------------------------------------------ HTTP (CONNECT + absolute-form)
    async def _http(self, first: bytes, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        head = first + await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 30)
        line, _, rest = head.partition(b"\r\n")
        try:
            method, target, version = line.decode("latin-1").split(" ", 2)
        except ValueError:
            await _reply(w, 400, "Bad Request", token=self.token)
            return
        auth_hdr = None
        for hl in rest.split(b"\r\n"):
            k, _, v = hl.partition(b":")
            if k.strip().lower() == b"proxy-authorization":
                auth_hdr = v.strip()
        if not self._check_basic(auth_hdr):
            self._record(proto="http", dest=target[:200], decision="refused",
                         reason="sin credenciales de la pasarela" if auth_hdr is None else "credenciales inválidas")
            w.write(f"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"vigia\"\r\n"
                    f"Content-Length: 0\r\nConnection: close\r\nX-Vigia-Gateway: {self.token} Auth Required\r\n\r\n"
                    .encode())
            await w.drain()
            return
        if method.upper() not in self.allowed_methods and method.upper() != "CONNECT":
            self._record(proto="forward", dest=target[:200], decision="refused", reason=f"método {method} no permitido")
            await _reply(w, 405, "Method Not Allowed", f"Vigía: método {method} no permitido", self.token)
            return
        if method.upper() == "CONNECT":
            host, port = _split_hostport(target, 443)
            if host is None:
                await _reply(w, 400, "Bad Request", token=self.token)
                return
            res = await self._open("connect", f"{host}:{port}", lambda: self.policy.decide(host, port))
            if isinstance(res, str):
                await _reply_kind(w, res, self.token)
                return
            ur, uw, _ = res
            w.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await w.drain()
            await self._splice(r, w, ur, uw)
            return
        if not target.lower().startswith("http://"):
            await _reply(w, 400, "Bad Request", token=self.token)  # origin-form / https absolute-form: not a forward-proxy request
            return
        url = target
        res = await self._open("forward", url[:300], lambda: self.policy.decide_url(url))
        if isinstance(res, str):
            await _reply_kind(w, res, self.token)
            return
        ur, uw, _ = res
        p = urlsplit(url)
        path = (p.path or "/") + (f"?{p.query}" if p.query else "")
        headers = []
        length = 0
        chunked = False
        for hl in rest.split(b"\r\n"):
            if not hl:
                continue
            k, _, v = hl.partition(b":")
            lk = k.strip().lower()
            if lk in HOP_BY_HOP:
                continue
            if lk == b"content-length":
                length = int(v.strip() or 0)
            if lk == b"transfer-encoding" and b"chunked" in v.lower():
                chunked = True
            headers.append(hl)
        out = f"{method} {path} {version}\r\n".encode("latin-1") + b"\r\n".join(headers) + b"\r\nConnection: close\r\n\r\n"
        try:
            uw.write(out)
            if chunked:
                while True:
                    sline = await asyncio.wait_for(r.readuntil(b"\r\n"), self.idle_timeout)
                    uw.write(sline)
                    size = int(sline.split(b";")[0].strip(), 16)
                    if size == 0:
                        while True:
                            t = await asyncio.wait_for(r.readuntil(b"\r\n"), self.idle_timeout)
                            uw.write(t)
                            if t == b"\r\n":
                                break
                        break
                    uw.write(await asyncio.wait_for(r.readexactly(size + 2), self.idle_timeout))
            elif length:
                uw.write(await asyncio.wait_for(r.readexactly(length), self.idle_timeout))
            await uw.drain()
            await self._pipe(ur, w)  # one request per proxied connection: the response, then close
        finally:
            _close(uw)

    # ------------------------------------------------------------------ piping
    async def _pipe(self, src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> int:
        n = 0
        try:
            while True:
                data = await asyncio.wait_for(src.read(65536), self.idle_timeout)
                if not data:
                    break
                n += len(data)
                dst.write(data)
                await dst.drain()
        except (OSError, asyncio.TimeoutError, ConnectionError):
            pass
        finally:
            try:
                if dst.can_write_eof():
                    dst.write_eof()
            except (OSError, RuntimeError):
                pass
        return n

    async def _splice(self, cr: asyncio.StreamReader, cw: asyncio.StreamWriter, ur: asyncio.StreamReader,
                      uw: asyncio.StreamWriter) -> None:
        try:
            await asyncio.wait_for(asyncio.gather(self._pipe(cr, uw), self._pipe(ur, cw)), self.max_tunnel_s)
        except asyncio.TimeoutError:
            pass
        finally:
            _close(uw)

    # ------------------------------------------------------------------ DNS stub
    async def dns_answer(self, data: bytes) -> bytes | None:
        try:
            q = dns.message.from_wire(data)
        except Exception:  # noqa: BLE001 - malformed query: ignore
            return None
        resp = dns.message.make_response(q)
        if not q.question:
            resp.set_rcode(dns.rcode.FORMERR)
            return resp.to_wire()
        question = q.question[0]
        name = question.name.to_text().rstrip(".").lower()
        rdtype = question.rdtype
        dest = f"{name}/{dns.rdatatype.to_text(rdtype)}"
        if not self.policy.allows_name(name):
            self._record(proto="dns", dest=dest, decision="refused", reason="nombre fuera de alcance: no se consulta")
            resp.set_rcode(dns.rcode.REFUSED)
            return resp.to_wire()
        try:
            if rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                ips = await self.policy.addresses(name)
                fam = 4 if rdtype == dns.rdatatype.A else 6
                vals = [str(ip) for ip in ips if ip.version == fam]
                if vals:
                    resp.answer.append(dns.rrset.from_text(question.name, 60, "IN", dns.rdatatype.to_text(rdtype), *vals))
            else:
                upstream = await self.policy.resolver.query(name, rdtype)
                resp.set_rcode(upstream.rcode())
                resp.answer = list(upstream.answer)
            self._record(proto="dns", dest=dest, decision="allowed", outcome=dns.rcode.to_text(resp.rcode()))
        except ScopeViolation as e:
            self._record(proto="dns", dest=dest, decision="refused", reason=str(e)[:200])
            resp.set_rcode(dns.rcode.NXDOMAIN if "NXDOMAIN" in str(e) else dns.rcode.REFUSED)
        except StopScan as e:
            self._down(str(e))
            resp.set_rcode(dns.rcode.SERVFAIL)
        except Exception as e:  # noqa: BLE001
            self._record(proto="dns", dest=dest, decision="error", reason=f"{type(e).__name__}: {e}"[:200])
            resp.set_rcode(dns.rcode.SERVFAIL)
        return resp.to_wire()

    async def _dns_tcp(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        ok, who = await self._authorized_process(w.get_extra_info("peername"))
        if not ok:
            self._record(proto="dns", dest="tcp", decision="refused", reason=who)
            _close(w)
            return
        try:
            while True:
                n = struct.unpack("!H", await asyncio.wait_for(r.readexactly(2), 30))[0]
                out = await self.dns_answer(await r.readexactly(n))
                if out is None:
                    break
                w.write(struct.pack("!H", len(out)) + out)
                await w.drain()
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
            pass
        finally:
            _close(w)


class _DnsUdp(asyncio.DatagramProtocol):
    def __init__(self, gw: EgressGateway):
        self.gw = gw
        self.transport: Any = None

    def connection_made(self, transport: Any) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Any) -> None:
        async def _go() -> None:
            ok, who = await self.gw._authorized_process(addr, "udp4")
            if not ok:
                self.gw._record(proto="dns", dest="udp", decision="refused", reason=who)
                return
            out = await self.gw.dns_answer(data)
            if out is not None and self.transport is not None:
                if len(out) > 1232:  # force TCP retry
                    m = dns.message.from_wire(out)
                    m.answer = []
                    m.flags |= dns.flags.TC
                    out = m.to_wire()
                self.transport.sendto(out, addr)
        t = asyncio.ensure_future(_go())
        self.gw._tasks.add(t)
        t.add_done_callback(self.gw._tasks.discard)


def _split_hostport(target: str, default: int) -> tuple[str | None, int]:
    t = target.strip()
    if t.startswith("["):
        host, _, rest = t[1:].partition("]")
        port = rest.lstrip(":")
    else:
        host, _, port = t.rpartition(":") if t.count(":") == 1 else (t, "", "")
    try:
        return (host.lower() or None), int(port) if port else default
    except ValueError:
        return None, default


async def _reply(w: asyncio.StreamWriter, status: int, reason: str, body: str = "", token: str = "") -> None:
    data = body.encode()
    w.write(f"HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {len(data)}\r\n"
            f"Connection: close\r\nX-Vigia-Gateway: {token} {reason}\r\n\r\n".encode() + data)
    try:
        await w.drain()
    except (OSError, ConnectionError):
        pass


async def _reply_kind(w: asyncio.StreamWriter, kind: str, token: str = "") -> None:
    status, reason, body = {
        "forbidden": (403, "Forbidden", "Vigía: destino fuera del alcance autorizado"),
        "egress_down": (502, "Egress Down", "Vigía: la salida configurada no responde; no hay conexión directa de reserva"),
        "refused": (502, "Connection Refused", "Vigía: el destino rechazó la conexión"),
        "timeout": (504, "Gateway Timeout", "Vigía: el destino no respondió"),
    }.get(kind, (502, "Bad Gateway", f"Vigía: destino inalcanzable ({kind})"))
    await _reply(w, status, reason, body, token)


def _close(w: asyncio.StreamWriter) -> None:
    try:
        w.close()
    except (OSError, RuntimeError):
        pass


async def open_via_gateway(gateway_port: int, host: str, port: int, timeout: float = 10.0, *,
                           username: str | None = None, password: str | None = None
                           ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Raw TCP stream to host:port through the loopback gateway (SOCKS5). Raises UpstreamRefused (closed/filtered,
    out of scope) or EgressDown (gateway or egress down: the scan must stop, never fall back to direct)."""
    from vigia.security.egress import socks5_handshake
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", gateway_port, limit=1 << 16), timeout)
    except (OSError, asyncio.TimeoutError) as e:
        raise EgressDown(f"la pasarela de salida no responde: {e}") from e
    try:
        await asyncio.wait_for(socks5_handshake(r, w, host, port, username=username, password=password,
                                                failure_is_egress_down=True), timeout + 5)
    except asyncio.TimeoutError as e:
        _close(w)
        raise UpstreamRefused("timeout", f"sin respuesta de {host}:{port}") from e
    except (asyncio.IncompleteReadError, ConnectionError) as e:
        _close(w)
        if isinstance(e, UpstreamRefused):
            raise
        raise UpstreamRefused("protocol", f"la pasarela cerró la conexión hacia {host}:{port}") from e
    except BaseException:
        _close(w)
        raise
    return r, w
