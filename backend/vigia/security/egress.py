"""Dedicated egress: every outbound byte of a scan leaves through the configured infrastructure.

Layers (docs/05-privacidad.md, docs/06-auditoria-red.md):
  * Upstream — the operator's egress (HTTP CONNECT proxy, HTTPS proxy, SOCKS5; typically the loopback end of an
    SSH ``-D`` tunnel or of a WireGuard/wireproxy client). Vigía speaks the protocol itself and always hands the
    upstream an IP literal that the ScopeGuard has already validated: the proxy's own DNS is never used for targets.
  * Remote DNS (``vigia.security.resolver``) — names are resolved with DoH / DNS-over-TCP *through* the upstream.
  * Gateway (``vigia.security.gateway``) — a loopback forward proxy every engine is pointed at. It enforces the
    scope and only connects through the upstream: if the upstream fails there is no direct fallback.
  * NetWatch (``vigia.security.netwatch``) — kill switch: an engine that opens a socket outside loopback is killed.

Nothing here hides Vigía from the target: the User-Agent is unchanged and the source IP is the real egress IP.
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import socket
import ssl
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from vigia.config import get_settings
from vigia.security.errors import EgressDown, UpstreamRefused

ALLOWED_SCHEMES = ("http", "https", "socks5", "socks5h")
DEFAULT_PORTS = {"http": 8080, "https": 443, "socks5": 1080, "socks5h": 1080}

SOCKS_REPLY = {1: ("failure", "fallo general del servidor SOCKS"), 2: ("forbidden", "conexión no permitida por las reglas del proxy"),
               3: ("unreachable", "red inalcanzable"), 4: ("unreachable", "host inalcanzable"),
               5: ("refused", "conexión rechazada por el destino"), 6: ("timeout", "TTL expirado / sin respuesta"),
               7: ("protocol", "comando SOCKS no soportado"), 8: ("protocol", "tipo de dirección no soportado")}


class ProxyError(Exception):
    pass


def validate_proxy(url: str) -> tuple[str, int]:
    """Validate a proxy URL and return (host, port). Raises ProxyError."""
    parts = urlsplit(url)
    if parts.scheme not in ALLOWED_SCHEMES:
        raise ProxyError(f"Esquema de proxy no soportado: {parts.scheme!r}. Usa {', '.join(ALLOWED_SCHEMES)}")
    if not parts.hostname:
        raise ProxyError("La URL del proxy no tiene host")
    try:
        port = parts.port or DEFAULT_PORTS[parts.scheme]
    except ValueError as e:
        raise ProxyError("Puerto del proxy inválido") from e
    return parts.hostname, port


def is_loopback_host(host: str) -> bool:
    h = host.strip("[]").lower()
    if h == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_loopback


def _socks_addr(host: str) -> bytes:
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        name = host.encode("idna")
        if len(name) > 255:
            raise UpstreamRefused("protocol", "nombre demasiado largo para SOCKS5")
        return b"\x03" + bytes([len(name)]) + name
    return (b"\x01" if ip.version == 4 else b"\x04") + ip.packed


async def socks5_handshake(r: asyncio.StreamReader, w: asyncio.StreamWriter, host: str, port: int, *,
                           username: str | None = None, password: str | None = None,
                           failure_is_egress_down: bool = False) -> None:
    """Client side of RFC 1928 (+ RFC 1929 auth). Raises UpstreamRefused (or EgressDown for the gateway's 0x01)."""
    methods = b"\x00\x02" if username is not None else b"\x00"
    w.write(b"\x05" + bytes([len(methods)]) + methods)
    await w.drain()
    ver, method = await r.readexactly(2)
    if ver != 5:
        raise UpstreamRefused("protocol", "respuesta SOCKS inválida")
    if method == 0x02:
        u, p = (username or "").encode(), (password or "").encode()
        w.write(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        await w.drain()
        _, status = await r.readexactly(2)
        if status != 0:
            raise UpstreamRefused("auth", "el proxy SOCKS rechazó las credenciales")
    elif method != 0x00:
        raise UpstreamRefused("auth", "el proxy SOCKS exige un método de autenticación no soportado")
    w.write(b"\x05\x01\x00" + _socks_addr(host) + port.to_bytes(2, "big"))
    await w.drain()
    ver, rep, _, atyp = await r.readexactly(4)
    if atyp == 1:
        await r.readexactly(6)
    elif atyp == 4:
        await r.readexactly(18)
    elif atyp == 3:
        await r.readexactly((await r.readexactly(1))[0] + 2)
    if rep != 0:
        kind, msg = SOCKS_REPLY.get(rep, ("failure", f"código SOCKS {rep}"))
        if rep == 1 and failure_is_egress_down:
            raise EgressDown("la pasarela de salida informa de que el túnel/proxy no responde")
        raise UpstreamRefused(kind, msg)


async def http_connect_handshake(r: asyncio.StreamReader, w: asyncio.StreamWriter, host: str, port: int, *,
                                 username: str | None = None, password: str | None = None) -> None:
    hp = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    lines = [f"CONNECT {hp} HTTP/1.1", f"Host: {hp}"]
    if username is not None:
        token = base64.b64encode(f"{username}:{password or ''}".encode()).decode()
        lines.append(f"Proxy-Authorization: Basic {token}")
    w.write(("\r\n".join(lines) + "\r\n\r\n").encode())
    await w.drain()
    head = await r.readuntil(b"\r\n\r\n")
    try:
        status = int(head.split(b" ", 2)[1])
    except (IndexError, ValueError) as e:
        raise UpstreamRefused("protocol", "respuesta CONNECT inválida") from e
    if 200 <= status < 300:
        return
    kind = {403: "forbidden", 405: "forbidden", 407: "auth", 504: "timeout"}.get(status, "unreachable")
    raise UpstreamRefused(kind, f"el proxy respondió {status} al CONNECT")


@dataclass(frozen=True)
class Upstream:
    """The operator's egress. ``open()`` returns a raw byte stream to ``host:port`` through it."""
    scheme: str  # http | https | socks5
    host: str
    port: int
    username: str | None = None
    password: str | None = None
    ssl_context: ssl.SSLContext | None = None  # https:// proxies with a private CA (tests)

    @classmethod
    def parse(cls, url: str, ssl_context: ssl.SSLContext | None = None) -> "Upstream":
        host, port = validate_proxy(url)
        p = urlsplit(url)
        scheme = "socks5" if p.scheme == "socks5h" else p.scheme  # Vigía never resolves target names locally
        return cls(scheme, host, port, unquote(p.username) if p.username is not None else None,
                   unquote(p.password) if p.password is not None else None, ssl_context)

    @property
    def display(self) -> str:
        h = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{h}:{self.port}"

    @property
    def transport(self) -> str:
        """loopback (local end of a tunnel) | tls (encrypted to the proxy) | plaintext (readable on the wire)."""
        if is_loopback_host(self.host):
            return "loopback"
        return "tls" if self.scheme == "https" else "plaintext"

    async def _connect_proxy(self, timeout: float) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        try:
            if self.scheme == "https":
                ctx = self.ssl_context or ssl.create_default_context()
                return await asyncio.wait_for(asyncio.open_connection(
                    self.host, self.port, ssl=ctx, server_hostname=self.host, limit=1 << 16), timeout)
            return await asyncio.wait_for(asyncio.open_connection(self.host, self.port, limit=1 << 16), timeout)
        except (OSError, asyncio.TimeoutError, ssl.SSLError) as e:
            raise EgressDown(f"el proxy de salida {self.display} no es accesible: {e or type(e).__name__}") from e

    async def open(self, host: str, port: int, timeout: float = 15.0) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        r, w = await self._connect_proxy(timeout)
        try:
            if self.scheme == "socks5":
                await asyncio.wait_for(socks5_handshake(r, w, host, port, username=self.username,
                                                        password=self.password), timeout)
            else:
                await asyncio.wait_for(http_connect_handshake(r, w, host, port, username=self.username,
                                                              password=self.password), timeout)
        except asyncio.TimeoutError as e:
            w.close()
            raise UpstreamRefused("timeout", f"el proxy no abrió el túnel a {host}:{port} a tiempo") from e
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionResetError) as e:
            w.close()
            raise UpstreamRefused("protocol", f"el proxy cerró la conexión al pedir {host}:{port}") from e
        except BaseException:
            w.close()
            raise
        return r, w


class DirectEgress:
    """No upstream configured: connections leave from the worker's own network (documented, never silent)."""
    display = "direct"
    transport = "direct"

    async def open(self, host: str, port: int, timeout: float = 15.0) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        try:
            return await asyncio.wait_for(asyncio.open_connection(host, port, limit=1 << 16), timeout)
        except asyncio.TimeoutError as e:
            raise UpstreamRefused("timeout", f"sin respuesta de {host}:{port}") from e
        except ConnectionRefusedError as e:
            raise UpstreamRefused("refused", f"{host}:{port} rechazó la conexión") from e
        except OSError as e:
            raise UpstreamRefused("unreachable", f"{host}:{port} inalcanzable: {e}") from e


_override: ContextVar[str | None] = ContextVar("vigia_egress_override", default=None)


def effective_proxy_url() -> str | None:
    """The egress for the current scan: its managed SSH tunnel endpoint if one is open, else VIGIA_HTTP_PROXY."""
    return _override.get() or get_settings().http_proxy


@contextmanager
def egress_override(url: str | None):  # noqa: ANN201
    token = _override.set(url)
    try:
        yield
    finally:
        _override.reset(token)


def configured_upstream() -> Upstream | None:
    url = effective_proxy_url()
    return Upstream.parse(url) if url else None


def proxy_reachable(url: str, timeout: float = 5.0) -> tuple[bool, str]:
    """TCP-connect to the proxy to confirm it is up (so a scan fails at the start, not on every request)."""
    try:
        host, port = validate_proxy(url)
    except ProxyError as e:
        return False, str(e)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"accesible en {host}:{port}"
    except OSError as e:
        return False, f"no accesible en {host}:{port}: {e}"


# ---------------------------------------------------------------------------------------------- visibility model
def visibility(upstream: Upstream | None, dns_remote: bool, dns_desc: str) -> dict:
    """Who can observe what, derived from the real configuration (not from claims)."""
    if upstream is None:
        return {
            "isp": "Todo: IP de cada objetivo, puertos, nombres en SNI/HTTP, peticiones HTTP en claro y "
                   + ("las consultas DNS (resolutor local)." if not dns_remote else "la conexión al resolutor DoH."),
            "egress_provider": "No hay proveedor de salida: el objetivo ve tu IP doméstica.",
            "dns_resolver": dns_desc,
            "target": "Tu IP doméstica, el User-Agent de Vigía y todo el tráfico del análisis.",
        }
    t = upstream.transport
    isp = {
        "loopback": "Solo lo que deje ver el túnel que termina en tu equipo (SSH -D, WireGuard…): con un túnel cifrado, "
                    "la IP del servidor de salida, volumen y horarios. Ningún nombre ni IP de objetivo.",
        "tls": f"La conexión TLS a {upstream.host}:{upstream.port} (y su nombre en SNI), volumen y horarios. "
               "Ningún nombre, IP ni contenido de los objetivos.",
        "plaintext": f"TODO el protocolo del proxy en claro hacia {upstream.host}:{upstream.port}: IP y puerto de cada "
                     "objetivo, el nombre en SNI de cada conexión TLS, las peticiones HTTP completas (cargas incluidas) "
                     "y las credenciales del proxy. Usa un túnel cifrado (SSH -D o WireGuard) o un proxy https://.",
    }[t]
    if not dns_remote:
        isp += " Además, las consultas DNS de los objetivos (resolución local)."
    return {
        "isp": isp,
        "egress_provider": "Tu IP doméstica (te conectas a él), la IP y el puerto de cada objetivo, el SNI de las conexiones "
                           "TLS, el contenido de las peticiones http:// y el volumen. No ve el contenido HTTPS.",
        "dns_resolver": dns_desc,
        "target": "La IP del proveedor de salida, el User-Agent de Vigía, las peticiones y su ritmo, y la huella TLS de "
                  "los motores. No ve tu IP doméstica (verificado por `vigia privacy audit`).",
    }


@dataclass
class EgressStatus:
    configured: bool
    proxy: str | None
    reachable: bool | None
    detail: str
    require_proxy: bool
    observed_ip: str | None = None
    transport: str = "direct"

    def to_dict(self) -> dict:
        shown = None
        if self.proxy:  # never expose proxy credentials embedded in the URL
            try:
                shown = Upstream.parse(self.proxy).display
            except ProxyError:
                shown = "(URL de proxy inválida)"
        return {"configured": self.configured, "proxy": shown, "reachable": self.reachable, "detail": self.detail,
                "require_proxy": self.require_proxy, "observed_ip": self.observed_ip, "transport": self.transport}


def egress_status(check_ip: bool = False) -> EgressStatus:
    s = get_settings()
    if s.ssh_tunnel and not s.http_proxy:
        return EgressStatus(True, None, None, f"Túnel SSH gestionado hacia {s.ssh_tunnel}: se abre al empezar cada "
                            "análisis, con verificación estricta de la clave del servidor, y se cierra al terminar",
                            s.require_proxy, transport="ssh")
    if not s.http_proxy:
        return EgressStatus(False, None, None,
                            "Sin proxy: las conexiones salen por la red local del worker" +
                            (" (VIGIA_REQUIRE_PROXY exige proxy para objetivos públicos)" if s.require_proxy else ""),
                            s.require_proxy)
    try:
        up = Upstream.parse(s.http_proxy)
    except ProxyError as e:
        return EgressStatus(True, s.http_proxy, False, str(e), s.require_proxy, transport="invalid")
    ok, detail = proxy_reachable(s.http_proxy)
    observed = observe_egress_ip() if (check_ip and ok) else None
    return EgressStatus(True, s.http_proxy, ok, detail, s.require_proxy, observed, up.transport)


def observe_egress_ip() -> str | None:
    """Best-effort: ask a configured echo endpoint, through the egress, which public IP it sees. Opt-in only."""
    import httpx

    from vigia import USER_AGENT
    s = get_settings()
    if not s.egress_check_url or not effective_proxy_url():
        return None
    try:
        with egress_client(timeout=15, headers={"User-Agent": USER_AGENT}) as c:
            r = c.get(s.egress_check_url)
            return r.text.strip()[:64] if r.status_code == 200 else None
    except httpx.HTTPError:
        return None


def require_proxy_decision(has_public_target: bool) -> str | None:
    """Return a refusal reason if the egress policy forbids this scan, else None (fail-closed)."""
    s = get_settings()
    url = effective_proxy_url()
    if url:
        try:
            Upstream.parse(url)
        except ProxyError as e:
            return f"VIGIA_HTTP_PROXY no es válido ({e}). No se realiza ninguna conexión directa."
        ok, detail = proxy_reachable(url)
        if not ok:
            return (f"El proxy de salida configurado (VIGIA_HTTP_PROXY) {detail}. No se realiza ninguna conexión "
                    "directa: corrige la infraestructura de salida o retira la configuración del proxy.")
        return None
    if s.require_proxy and has_public_target:
        return ("VIGIA_REQUIRE_PROXY está activado y no hay proxy de salida configurado: se rechazan los análisis "
                "de objetivos públicos para no usar la conexión directa del equipo.")
    return None


async def preflight_tunnel(upstream: Upstream, resolver) -> str | None:  # noqa: ANN001
    """Prove, before touching any target, that the upstream really forwards and that remote DNS answers through it."""
    from vigia.security.resolver import ResolutionError
    try:
        await asyncio.wait_for(resolver.selftest(), 25)
    except EgressDown as e:
        return f"{e}. No se realiza ninguna conexión directa."
    except (ResolutionError, UpstreamRefused, OSError, asyncio.TimeoutError) as e:
        return (f"El resolutor DNS remoto ({resolver.description}) no responde a través del túnel: {e}. "
                "No se recurre al DNS local: corrige VIGIA_DNS_RESOLVER o la salida.")
    return None


# ---------------------------------------------------------------------------------------------- public lane
def egress_client(**kw):  # noqa: ANN003, ANN201
    """httpx.Client for Vigía's own third-party traffic (OSV/NVD/KEV, CT logs, installer downloads, egress-IP echo).

    Without an egress: a plain direct client (documented). With one: the client goes through a *single-use* public-lane
    gateway (credentials + process attribution, public addresses on 80/443 only, names resolved remotely) that is
    destroyed when the client is closed — no egress service is left listening afterwards.
    """
    import httpx
    kw.setdefault("trust_env", False)
    url = effective_proxy_url()
    if not url:
        return httpx.Client(**kw)
    from vigia.security.gateway import EgressGateway, PublicPolicy
    from vigia.security.resolver import default_resolver
    gw = EgressGateway(PublicPolicy(default_resolver()), Upstream.parse(url), lane="public").start()

    class _EgressClient(httpx.Client):
        def close(self) -> None:
            try:
                super().close()
            finally:
                gw.stop()
    client = _EgressClient(proxy=gw.http_url, **kw)
    client.gateway = gw  # type: ignore[attr-defined]
    return client

