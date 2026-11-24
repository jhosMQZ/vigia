"""Scope enforcement — every outbound connection made by the engine passes through ScopeGuard.

Guarantees:
  * only http/https URLs (and explicit host:port pairs for infra) whose host matches a scope target;
  * every resolved IP is validated; metadata/link-local/multicast/reserved ranges are always blocked;
  * private/loopback ranges require both the global setting and the scope flag;
  * resolution results are pinned for the lifetime of the guard (anti DNS-rebinding): the HTTP client
    connects to the validated IP, never re-resolving the name;
  * exclusions (hosts, path prefixes) are honoured;
  * the platform's own listening ports on loopback cannot be targeted.
"""
from __future__ import annotations

import asyncio
import fnmatch
import ipaddress
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

IPAddr = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNet = ipaddress.IPv4Network | ipaddress.IPv6Network


class ScopeViolation(Exception):
    """Raised when a target or request falls outside the authorised scope."""


# Always blocked, regardless of any flag.
_ALWAYS_BLOCKED_NETS: list[IPNet] = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "169.254.0.0/16", "100.100.100.200/32", "224.0.0.0/4", "240.0.0.0/4",
    "255.255.255.255/32", "192.0.0.0/24", "198.18.0.0/15",
    "::/128", "fe80::/10", "ff00::/8", "fd00:ec2::254/128", "64:ff9b::/96",
)]
_METADATA_HOSTNAMES = {
    "metadata.google.internal", "metadata", "metadata.azure.internal", "instance-data",
    "instance-data.ec2.internal", "metadata.packet.net", "metadata.platformequinix.com",
}
# Requires allow_private (global + scope).
_PRIVATE_NETS: list[IPNet] = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "100.64.0.0/10",
    "::1/128", "fc00::/7",
)]

# First-party platforms: can never be a scope target (domain or any subdomain).
THIRD_PARTY_DENY = {
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "youtube.com", "gmail.com",
    "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.com", "meta.com",
    "microsoft.com", "live.com", "outlook.com", "office.com", "office365.com", "microsoftonline.com",
    "windows.net", "azure.com", "bing.com", "apple.com", "icloud.com",
    "amazon.com", "aws.amazon.com", "cloudflare.com", "akamai.com", "akamaihd.net", "fastly.com",
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org", "atlassian.com",
    "twitter.com", "x.com", "linkedin.com", "tiktok.com", "reddit.com", "wikipedia.org",
    "openai.com", "anthropic.com", "claude.ai", "stripe.com", "paypal.com", "salesforce.com",
    "slack.com", "zoom.us", "dropbox.com", "yahoo.com", "baidu.com", "yandex.ru", "mozilla.org",
    "jsdelivr.net", "unpkg.com", "cdnjs.com", "npmjs.com", "npmjs.org", "pypi.org", "docker.io", "docker.com",
}
# Shared hosting suffixes: a specific customer subdomain is allowed, the suffix itself / wildcards are not.
SHARED_HOSTING = {
    "vercel.app", "netlify.app", "herokuapp.com", "azurewebsites.net", "github.io", "gitlab.io",
    "pages.dev", "workers.dev", "amazonaws.com", "cloudfront.net", "appspot.com", "web.app",
    "firebaseapp.com", "onrender.com", "fly.dev", "ngrok.io", "ngrok-free.app", "ngrok.app",
    "railway.app", "deno.dev", "surge.sh", "glitch.me", "replit.app", "blob.core.windows.net",
}

_HOST_RE = re.compile(r"^(?=.{1,253}$)(\*\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?)*$")


def _norm_host(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host


def _parse_ip(host: str) -> IPAddr | None:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def _under(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def ip_block_reason(ip: IPAddr, allow_private: bool) -> str | None:
    """Return why an IP is not connectable, or None if allowed."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    for net in _ALWAYS_BLOCKED_NETS:
        if ip.version == net.version and ip in net:
            return f"{ip} pertenece a un rango siempre bloqueado ({net}: metadatos/link-local/reservado)"
    for net in _PRIVATE_NETS:  # before is_reserved: ::1 lives inside the IETF-reserved ::/8
        if ip.version == net.version and ip in net:
            if not allow_private:
                return f"{ip} es una dirección privada/loopback y el alcance no autoriza redes internas"
            return None
    if ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return f"{ip} es multicast/reservada"
    if ip.is_private and not ip.is_global and not allow_private:
        return f"{ip} no es una dirección global"
    return None


@dataclass
class TargetSpec:
    raw: str
    kind: str  # host | wildcard | ip | cidr
    host: str | None = None
    network: IPNet | None = None
    base_url: str | None = None


@dataclass
class CheckedTarget:
    url: str | None
    scheme: str | None
    host: str
    port: int
    ips: list[IPAddr]

    @property
    def pinned_ip(self) -> IPAddr:
        return self.ips[0]


def validate_target_definition(raw: str) -> TargetSpec:
    """Parse and validate a scope target as typed by the user. Raises ScopeViolation."""
    s = raw.strip()
    if not s or len(s) > 2048:
        raise ScopeViolation("Objetivo vacío o demasiado largo")
    base_url = None
    if "://" in s:
        parts = urlsplit(s)
        if parts.scheme not in ("http", "https"):
            raise ScopeViolation(f"Esquema no permitido: {parts.scheme}")
        if parts.username or parts.password:
            raise ScopeViolation("No se admiten credenciales en la URL del objetivo")
        host = _norm_host(parts.hostname or "")
        base_url = s
    else:
        host = _norm_host(s.split("/")[0])
    if not host:
        raise ScopeViolation("Objetivo sin host")

    # CIDR
    if "/" in s and "://" not in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError as e:
            raise ScopeViolation(f"CIDR inválido: {s}") from e
        if net.num_addresses > 65536:
            raise ScopeViolation("El rango CIDR es demasiado amplio (máx. /16)")
        for blocked in _ALWAYS_BLOCKED_NETS:
            if net.version == blocked.version and net.overlaps(blocked):
                raise ScopeViolation(f"El rango {net} solapa con un rango bloqueado ({blocked})")
        return TargetSpec(raw=s, kind="cidr", network=net)

    ip = _parse_ip(host)
    if ip is not None:
        reason = ip_block_reason(ip, allow_private=True)
        if reason:
            raise ScopeViolation(reason)
        return TargetSpec(raw=s, kind="ip", host=str(ip), base_url=base_url)

    if host in _METADATA_HOSTNAMES or (host.endswith(".internal") and "metadata" in host):
        raise ScopeViolation("Los servicios de metadatos cloud nunca pueden ser objetivo")
    if not _HOST_RE.match(host):
        raise ScopeViolation(f"Nombre de host inválido: {host}")
    wildcard = host.startswith("*.")
    bare = host[2:] if wildcard else host
    if wildcard and bare.count(".") < 1:
        raise ScopeViolation("Comodín demasiado amplio: requiere al menos dominio.tld")
    for d in THIRD_PARTY_DENY:
        if _under(bare, d):
            raise ScopeViolation(f"{host} pertenece a un servicio de terceros ({d}) y no puede añadirse al alcance")
    for d in SHARED_HOSTING:
        if bare == d or (wildcard and _under(bare, d)):
            raise ScopeViolation(f"{host} es un dominio de hosting compartido: indica el subdominio concreto de tu aplicación")
    return TargetSpec(raw=s, kind="wildcard" if wildcard else "host", host=bare, base_url=base_url)


@dataclass
class ScopeGuard:
    targets: list[TargetSpec]
    exclusions: list[str] = field(default_factory=list)
    allow_private: bool = False
    allowed_ports: set[int] | None = None
    blocked_local_ports: set[int] = field(default_factory=set)
    # Name resolution backend (vigia.security.resolver). None = configured default: remote DoH through the egress
    # when a proxy is set, so target names never reach the local/ISP resolver.
    resolver: Any = field(default=None, repr=False)
    _dns_cache: dict[str, tuple[float, list[IPAddr]]] = field(default_factory=dict, repr=False)
    _mutex: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _inflight: dict[tuple[int, str], "asyncio.Future[list[IPAddr]]"] = field(default_factory=dict, repr=False)

    @classmethod
    def build(cls, raw_targets: list[str], exclusions: list[str] | None = None, *, scope_allow_private: bool = False,
              global_allow_private: bool = False, allowed_ports: list[int] | None = None,
              blocked_local_ports: list[int] | None = None) -> "ScopeGuard":
        if not raw_targets:
            raise ScopeViolation("El alcance no contiene objetivos")
        specs = [validate_target_definition(t) for t in raw_targets]
        return cls(targets=specs, exclusions=[e.strip() for e in (exclusions or []) if e.strip()],
                   allow_private=bool(scope_allow_private and global_allow_private),
                   allowed_ports=set(allowed_ports) if allowed_ports else None,
                   blocked_local_ports=set(blocked_local_ports or []))

    # ---------- name / ip matching ----------
    def host_matches(self, host: str) -> bool:
        host = _norm_host(host)
        ip = _parse_ip(host)
        for t in self.targets:
            if ip is not None:
                if t.kind == "ip" and _parse_ip(t.host or "") == ip:
                    return True
                if t.kind == "cidr" and t.network and ip.version == t.network.version and ip in t.network:
                    return True
            else:
                if t.kind == "host" and host == t.host:
                    return True
                if t.kind == "wildcard" and t.host and host.endswith("." + t.host):
                    return True
        return False

    def is_excluded(self, host: str, path: str = "/", url: str | None = None) -> bool:
        host = _norm_host(host)
        for ex in self.exclusions:
            if ex.startswith("/"):
                if fnmatch.fnmatch(path, ex) or path.startswith(ex.rstrip("*")):
                    return True
            elif "://" in ex:
                if url and url.startswith(ex):
                    return True
            elif fnmatch.fnmatch(host, ex.lower()):
                return True
        return False

    # ---------- resolution ----------
    async def resolve(self, host: str) -> list[IPAddr]:
        host = _norm_host(host)
        ip = _parse_ip(host)
        if ip is not None:
            return [ip]
        cached = self._dns_cache.get(host)
        if cached:  # pinned for the guard lifetime (anti-rebinding)
            return cached[1]
        # one in-flight resolution per (event loop, host): the guard is shared by the scan loop and the gateway thread
        loop = asyncio.get_running_loop()
        key = (id(loop), host)
        fut = self._inflight.get(key)
        if fut is None:
            fut = loop.create_task(self._resolve_uncached(host))
            self._inflight[key] = fut
            fut.add_done_callback(lambda _f, k=key: self._inflight.pop(k, None))
        return await asyncio.shield(fut)

    async def _resolve_uncached(self, host: str) -> list[IPAddr]:
        from vigia.security.resolver import ResolutionError, default_resolver
        resolver = self.resolver or default_resolver()
        try:
            ips = list(await asyncio.wait_for(resolver.addresses(host), timeout=25))
        except ResolutionError as e:
            raise ScopeViolation(f"No se pudo resolver {host}: {e}") from e
        except asyncio.TimeoutError as e:
            raise ScopeViolation(f"No se pudo resolver {host}: tiempo agotado ({resolver.description})") from e
        ips.sort(key=lambda a: a.version)  # prefer IPv4
        with self._mutex:  # first validated answer wins and stays pinned (consistent across threads)
            return self._dns_cache.setdefault(host, (time.monotonic(), ips))[1]

    def pinned_names(self, ip: IPAddr) -> list[str]:
        """In-scope names whose pinned resolution contains ``ip`` (lets the gateway accept IP-literal tunnels)."""
        with self._mutex:
            return [h for h, (_, ips) in self._dns_cache.items() if ip in ips]

    async def check_ip_literal(self, ip_text: str, port: int) -> CheckedTarget:
        """A connection requested by IP: in scope if the IP is a scope IP/CIDR or the pinned address of an
        in-scope name already resolved by this guard (that is how the native client and engines reach targets)."""
        ip = _parse_ip(_norm_host(ip_text))
        if ip is None:
            raise ScopeViolation(f"{ip_text} no es una dirección IP")
        if not (0 < port < 65536):
            raise ScopeViolation("Puerto inválido")
        names = [] if self.host_matches(str(ip)) else self.pinned_names(ip)
        if not self.host_matches(str(ip)) and not names:
            raise ScopeViolation(f"{ip} no es un objetivo autorizado ni la IP fijada de un nombre en alcance "
                                 "(posible resolución DNS fuera de Vigía)")
        if self.allowed_ports is not None and port not in self.allowed_ports:
            raise ScopeViolation(f"Puerto {port} no autorizado")
        if self.is_excluded(str(ip)) or any(self.is_excluded(n) for n in names):
            raise ScopeViolation(f"{ip} está excluido")
        reason = ip_block_reason(ip, self.allow_private)
        if reason:
            raise ScopeViolation(reason)
        if ip.is_loopback and port in self.blocked_local_ports:
            raise ScopeViolation(f"{ip}:{port} es la propia plataforma Vigía; no puede analizarse a sí misma")
        return CheckedTarget(url=None, scheme=None, host=names[0] if names else str(ip), port=port, ips=[ip])

    async def _validate_ips(self, host: str, port: int) -> list[IPAddr]:
        ips = await self.resolve(host)
        if not ips:
            raise ScopeViolation(f"{host} no resuelve a ninguna dirección")
        for ip in ips:  # every resolved address must be acceptable, otherwise refuse entirely
            reason = ip_block_reason(ip, self.allow_private)
            if reason:
                raise ScopeViolation(f"{host} → {reason}")
            if ip.is_loopback and port in self.blocked_local_ports:
                raise ScopeViolation(f"{host}:{port} es la propia plataforma Vigía; no puede analizarse a sí misma")
        return ips

    async def check_url(self, url: str) -> CheckedTarget:
        if len(url) > 8192:
            raise ScopeViolation("URL demasiado larga")
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise ScopeViolation(f"Esquema no permitido: {parts.scheme or '(vacío)'}")
        if parts.username or parts.password:
            raise ScopeViolation("URL con credenciales embebidas rechazada")
        host = _norm_host(parts.hostname or "")
        if not host:
            raise ScopeViolation("URL sin host")
        try:
            port = parts.port or (443 if parts.scheme == "https" else 80)
        except ValueError as e:
            raise ScopeViolation("Puerto inválido") from e
        if not self.host_matches(host):
            raise ScopeViolation(f"{host} está fuera del alcance autorizado")
        if self.allowed_ports is not None and port not in self.allowed_ports:
            raise ScopeViolation(f"Puerto {port} no autorizado")
        if self.is_excluded(host, parts.path or "/", url):
            raise ScopeViolation(f"{url} está en la lista de exclusiones")
        ips = await self._validate_ips(host, port)
        return CheckedTarget(url=url, scheme=parts.scheme, host=host, port=port, ips=ips)

    async def check_host_port(self, host: str, port: int) -> CheckedTarget:
        host = _norm_host(host)
        if not (0 < port < 65536):
            raise ScopeViolation("Puerto inválido")
        if not self.host_matches(host):
            raise ScopeViolation(f"{host} está fuera del alcance autorizado")
        if self.allowed_ports is not None and port not in self.allowed_ports:
            raise ScopeViolation(f"Puerto {port} no autorizado")
        if self.is_excluded(host):
            raise ScopeViolation(f"{host} está excluido")
        ips = await self._validate_ips(host, port)
        return CheckedTarget(url=None, scheme=None, host=host, port=port, ips=ips)

    def seed_urls(self) -> list[str]:
        out: list[str] = []
        for t in self.targets:
            if t.base_url:
                out.append(t.base_url)
            elif t.kind in ("host", "ip"):
                h = t.host or ""
                h = f"[{h}]" if ":" in h else h
                out.append(f"https://{h}/")
        return out

    def hosts(self) -> list[str]:
        return [t.host for t in self.targets if t.kind in ("host", "ip") and t.host]
