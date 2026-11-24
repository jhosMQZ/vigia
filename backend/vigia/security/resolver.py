"""Name resolution for the scanner: local (system) or remote through the egress (no DNS leak).

Modes (``VIGIA_DNS_RESOLVER``):
  * ``auto`` (default) — remote DoH through the egress when ``VIGIA_HTTP_PROXY`` is set, system resolver otherwise;
  * ``system`` — the OS resolver (your DNS provider, usually the ISP, sees every target name);
  * ``https://…/dns-query`` — DNS-over-HTTPS (RFC 8484), the HTTPS connection tunnelled through the egress;
  * ``tcp://IP:53`` — classic DNS over TCP through the egress tunnel (e.g. a resolver on the egress host itself).

Remote queries carry EDNS Client Subnet 0/0 (RFC 7871 §7.1.2: "do not use my subnet") and EDNS padding, so neither
your network nor the resolver's address leaks to the target's authoritative servers. A remote resolver failure
never falls back to the local one.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import struct
import time
from functools import lru_cache
from typing import Any, Callable
from urllib.parse import urlsplit

import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.resolver

from vigia.security.errors import EgressDown, UpstreamRefused

IPAddr = ipaddress.IPv4Address | ipaddress.IPv6Address
DEFAULT_DOH = "https://1.1.1.1/dns-query"
SELFTEST_NAME = "example.com"  # IANA-reserved, stable, always resolvable


class ResolutionError(Exception):
    def __init__(self, message: str, *, nxdomain: bool = False):
        super().__init__(message)
        self.nxdomain = nxdomain


def _parse_ip(s: str) -> IPAddr | None:
    try:
        ip = ipaddress.ip_address(s.split("%")[0])
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


class SystemResolver:
    """The OS resolver (getaddrinfo) for addresses; dnspython with the system configuration for records."""
    remote = False

    def __init__(self) -> None:
        self.description = "resolutor del sistema (local)"

    async def addresses(self, host: str) -> list[IPAddr]:
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout=10)
        except socket.gaierror as e:
            raise ResolutionError(str(e), nxdomain=e.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5),
                                                                11001)) from e
        except asyncio.TimeoutError as e:
            raise ResolutionError("tiempo de resolución agotado") from e
        out: list[IPAddr] = []
        for info in infos:
            ip = _parse_ip(info[4][0])
            if ip is not None and ip not in out:
                out.append(ip)
        return out

    async def records(self, name: str, rdtype: str) -> list[str]:
        import dns.asyncresolver
        res = dns.asyncresolver.Resolver()
        res.lifetime = 8
        ans = await res.resolve(name, rdtype)
        return [r.to_text() for r in ans]

    async def selftest(self) -> None:
        await self.addresses(SELFTEST_NAME)


class RemoteResolver:
    """DoH (RFC 8484, POST) or DNS-over-TCP, carried through the egress connector (Upstream or DirectEgress)."""
    remote = True

    def __init__(self, url: str, connector: Any, *, ssl_context: ssl.SSLContext | None = None, timeout: float = 8.0,
                 trace: Callable[[dict], None] | None = None):
        p = urlsplit(url)
        if p.scheme not in ("https", "tcp") or not p.hostname:
            raise ValueError("VIGIA_DNS_RESOLVER debe ser 'auto', 'system', https://…/dns-query o tcp://IP:53")
        self.url = url
        self.kind = "doh" if p.scheme == "https" else "tcp"
        self.host = p.hostname
        self.port = p.port or (443 if self.kind == "doh" else 53)
        self.path = (p.path or "/dns-query") + (f"?{p.query}" if p.query else "")
        self.connector = connector
        self.ssl_context = ssl_context or ssl.create_default_context()
        self.timeout = timeout
        self.trace = trace
        via = getattr(connector, "display", "direct")
        self.description = (f"{'DoH' if self.kind == 'doh' else 'DNS/TCP'} {self.host}:{self.port} "
                            f"a través de {via}" if via != "direct" else f"{'DoH' if self.kind == 'doh' else 'DNS/TCP'} "
                            f"{self.host}:{self.port} (directo)")
        self.queries = 0

    def _make_query(self, name: str, rdtype: int) -> dns.message.Message:
        return dns.message.make_query(name, rdtype, use_edns=0, payload=1232, pad=128,
                                      options=[dns.edns.ECSOption("0.0.0.0", 0)])  # nosec B104 - ECS 0/0: hide the client subnet

    async def _exchange_doh(self, wire: bytes) -> bytes:
        r, w = await self.connector.open(self.host, self.port, timeout=self.timeout)
        try:
            await asyncio.wait_for(w.start_tls(self.ssl_context, server_hostname=self.host), self.timeout)
            hosthdr = f"[{self.host}]" if ":" in self.host else self.host
            head = (f"POST {self.path} HTTP/1.1\r\nHost: {hosthdr}\r\nContent-Type: application/dns-message\r\n"
                    f"Accept: application/dns-message\r\nContent-Length: {len(wire)}\r\nConnection: close\r\n\r\n")
            w.write(head.encode() + wire)
            await w.drain()
            return await asyncio.wait_for(_read_http_body(r), self.timeout)
        finally:
            w.close()

    async def _exchange_tcp(self, wire: bytes) -> bytes:
        r, w = await self.connector.open(self.host, self.port, timeout=self.timeout)
        try:
            w.write(struct.pack("!H", len(wire)) + wire)
            await w.drain()
            n = struct.unpack("!H", await asyncio.wait_for(r.readexactly(2), self.timeout))[0]
            return await asyncio.wait_for(r.readexactly(n), self.timeout)
        finally:
            w.close()

    async def query(self, name: str, rdtype: int | str) -> dns.message.Message:
        rdt = dns.rdatatype.from_text(rdtype) if isinstance(rdtype, str) else rdtype
        q = self._make_query(name, rdt)
        t0 = time.monotonic()
        self.queries += 1
        try:
            raw = await (self._exchange_doh(q.to_wire()) if self.kind == "doh" else self._exchange_tcp(q.to_wire()))
            resp = dns.message.from_wire(raw)
        except EgressDown:
            raise
        except (UpstreamRefused, OSError, ssl.SSLError, asyncio.TimeoutError, asyncio.IncompleteReadError,
                dns.exception.DNSException, ValueError) as e:
            self._log(name, rdt, "error", t0, f"{type(e).__name__}: {e}")
            raise ResolutionError(f"resolutor remoto no disponible ({self.description}): {e or type(e).__name__}") from e
        if resp.id != q.id or not resp.question or resp.question[0].name != q.question[0].name:
            self._log(name, rdt, "error", t0, "respuesta no corresponde a la consulta")
            raise ResolutionError("respuesta DNS que no corresponde a la consulta")
        self._log(name, rdt, dns.rcode.to_text(resp.rcode()), t0)
        return resp

    def _log(self, name: str, rdt: int, outcome: str, t0: float, detail: str = "") -> None:
        if self.trace:
            self.trace({"ts": time.time(), "lane": "dns", "proto": self.kind, "name": name,
                        "type": dns.rdatatype.to_text(rdt), "outcome": outcome, "resolver": f"{self.host}:{self.port}",
                        "egress": getattr(self.connector, "display", "direct"),
                        "ms": int((time.monotonic() - t0) * 1000), **({"detail": detail} if detail else {})})

    async def records(self, name: str, rdtype: str) -> list[str]:
        """dnspython-compatible semantics: raises dns.resolver.NXDOMAIN / NoAnswer."""
        resp = await self.query(name, rdtype)
        rc = resp.rcode()
        if rc == dns.rcode.NXDOMAIN:
            raise dns.resolver.NXDOMAIN(qnames=[dns.name.from_text(name)])
        if rc != dns.rcode.NOERROR:
            raise dns.resolver.NoNameservers()
        rdt = dns.rdatatype.from_text(rdtype)
        out = [rd.to_text() for rrset in resp.answer if rrset.rdtype == rdt for rd in rrset]
        if not out:
            raise dns.resolver.NoAnswer()
        return out

    async def addresses(self, host: str) -> list[IPAddr]:
        res = await asyncio.gather(self.query(host, dns.rdatatype.A), self.query(host, dns.rdatatype.AAAA),
                                   return_exceptions=True)
        for r in res:
            if isinstance(r, EgressDown):
                raise r
        ips: list[IPAddr] = []
        nx = 0
        errors = []
        for r in res:
            if isinstance(r, BaseException):
                errors.append(r)
                continue
            if r.rcode() == dns.rcode.NXDOMAIN:
                nx += 1
                continue
            for rrset in r.answer:
                if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                    for rd in rrset:
                        ip = _parse_ip(rd.address)
                        if ip is not None and ip not in ips:
                            ips.append(ip)
        if not ips:
            if nx:
                raise ResolutionError(f"{host} no existe (NXDOMAIN)", nxdomain=True)
            if errors:
                raise errors[0] if isinstance(errors[0], ResolutionError) else ResolutionError(str(errors[0]))
            raise ResolutionError(f"{host} no tiene registros A/AAAA")
        return ips

    async def selftest(self) -> None:
        resp = await self.query(SELFTEST_NAME, dns.rdatatype.A)
        if resp.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
            raise ResolutionError(f"el resolutor respondió {dns.rcode.to_text(resp.rcode())}")


async def _read_http_body(r: asyncio.StreamReader) -> bytes:
    head = await r.readuntil(b"\r\n\r\n")
    status_line, _, rest = head.partition(b"\r\n")
    try:
        status = int(status_line.split(b" ", 2)[1])
    except (IndexError, ValueError) as e:
        raise ValueError("respuesta HTTP inválida del resolutor DoH") from e
    headers = {}
    for line in rest.split(b"\r\n"):
        k, _, v = line.partition(b":")
        if k:
            headers[k.strip().lower()] = v.strip()
    if status != 200:
        raise ValueError(f"el resolutor DoH respondió HTTP {status}")
    if b"content-length" in headers:
        n = int(headers[b"content-length"])
        if n > 65535:
            raise ValueError("respuesta DoH demasiado grande")
        return await r.readexactly(n)
    if headers.get(b"transfer-encoding", b"").lower() == b"chunked":
        body = b""
        while True:
            size = int((await r.readuntil(b"\r\n")).split(b";")[0], 16)
            if size == 0:
                break
            body += await r.readexactly(size)
            await r.readexactly(2)
            if len(body) > 65535:
                raise ValueError("respuesta DoH demasiado grande")
        return body
    return await r.read(65536)


def build_resolver(spec: str, egress: Any = None, *, ssl_context: ssl.SSLContext | None = None,
                   trace: Callable[[dict], None] | None = None) -> SystemResolver | RemoteResolver:
    """``egress``: proxy URL, an Upstream object, or None (no egress configured)."""
    from vigia.security.egress import DirectEgress, Upstream
    spec = (spec or "auto").strip()
    if spec == "system":
        return SystemResolver()
    if spec == "auto":
        if not egress:
            return SystemResolver()
        spec = DEFAULT_DOH
    connector = Upstream.parse(egress) if isinstance(egress, str) else (egress or DirectEgress())
    return RemoteResolver(spec, connector, ssl_context=ssl_context, trace=trace)


@lru_cache(maxsize=8)
def _cached(spec: str, proxy: str | None) -> SystemResolver | RemoteResolver:
    return build_resolver(spec, proxy)


def default_resolver() -> SystemResolver | RemoteResolver:
    from vigia.config import get_settings
    s = get_settings()
    from vigia.security.egress import effective_proxy_url
    return _cached(s.dns_resolver, effective_proxy_url())


def reset_default_resolver() -> None:
    _cached.cache_clear()
