"""M06 — Infrastructure and services: TCP connect scan, banners, exposed data stores and orchestrators, TLS.

Every connection is validated by the ScopeGuard (host, port and every resolved IP) and goes to the pinned
IP — through the egress gateway when a dedicated egress is configured (``ctx.net_open``), never directly.
Service checks are read-only (banner, PING/stats/version endpoints, FTP anonymous login + QUIT).
"""
from __future__ import annotations

import asyncio
import datetime as dt
import re
import socket
import ssl
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from vigia.core.context import ScanContext
from vigia.core.findings import FindingDraft
from vigia.core.module import Module
from vigia.security.errors import UpstreamRefused
from vigia.security.scope import CheckedTarget, ScopeViolation

WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 9443]
TOP_PORTS = sorted(set(WEB_PORTS + [21, 22, 23, 25, 53, 110, 111, 135, 139, 143, 389, 445, 465, 587, 636, 993, 995, 1080,
                                    1433, 1521, 2049, 2375, 2376, 2379, 3306, 3389, 4443, 5432, 5601, 5672, 5900, 5984,
                                    6379, 6443, 7001, 8081, 8086, 8161, 8500, 9042, 9090, 9092, 9200, 9300, 10250, 10255,
                                    11211, 15672, 27017, 50000]))
EXTENDED_PORTS = sorted(set(TOP_PORTS + list(range(1, 1025)) + [1099, 1723, 2181, 2483, 3000, 3001, 3128, 4000, 4369, 4848,
                                                                 5000, 5001, 5005, 5044, 5555, 5800, 5985, 5986, 6000,
                                                                 6060, 6066, 7000, 7077, 7474, 7687, 8001, 8008, 8009,
                                                                 8042, 8069, 8082, 8088, 8089, 8090, 8091, 8123, 8180,
                                                                 8200, 8280, 8291, 8333, 8834, 8983, 9000, 9001, 9100,
                                                                 9160, 9229, 9418, 9999, 10000, 10443, 11000, 16379,
                                                                 18080, 19999, 20000, 25565, 28017, 30000, 32400, 50070]))
SERVICE_BY_PORT = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 110: "pop3", 139: "netbios", 143: "imap",
                   389: "ldap", 445: "smb", 465: "smtps", 587: "smtp", 636: "ldaps", 993: "imaps", 995: "pop3s",
                   1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker", 2376: "docker-tls", 2379: "etcd",
                   3306: "mysql", 3389: "rdp", 5432: "postgresql", 5601: "kibana", 5672: "amqp", 5900: "vnc", 5984: "couchdb",
                   6379: "redis", 6443: "kubernetes", 8086: "influxdb", 9042: "cassandra", 9092: "kafka", 9200: "elasticsearch",
                   9300: "elasticsearch-transport", 10250: "kubelet", 10255: "kubelet-ro", 11211: "memcached",
                   15672: "rabbitmq-mgmt", 27017: "mongodb", 2181: "zookeeper", 7474: "neo4j", 8500: "consul",
                   9229: "node-inspector", 16379: "redis"}
DB_SERVICES = {"mysql", "postgresql", "mssql", "oracle", "mongodb", "redis", "memcached", "elasticsearch", "couchdb",
               "cassandra", "influxdb", "neo4j", "zookeeper", "kafka", "amqp", "elasticsearch-transport"}
REMOTE_ADMIN = {"ssh", "rdp", "vnc", "telnet"}
TLS_PORTS = {443, 8443, 465, 636, 993, 995, 2376, 4443, 6443, 9443, 10250, 10443}


class InfraModule(Module):
    name = "infra"
    title = "Infraestructura y servicios"
    phase = "recon"
    needs_target = True

    async def run(self, ctx: ScanContext) -> None:
        assert ctx.guard is not None
        ports = {"none": [], "web": WEB_PORTS, "top": TOP_PORTS, "extended": EXTENDED_PORTS}[ctx.cfg.port_set]
        if ctx.guard.allowed_ports is not None:
            ports = [p for p in ports if p in ctx.guard.allowed_ports]
        hosts = list(dict.fromkeys(ctx.guard.hosts()))
        for t in ctx.guard.targets:
            if t.kind == "cidr" and t.network is not None and ctx.cfg.at_least("standard"):
                hosts += [str(ip) for ip in list(t.network.hosts())[:256]]
        tls_targets: set[tuple[str, int]] = set()
        for b in ctx.kb.base_urls:
            from urllib.parse import urlsplit
            p = urlsplit(b)
            if p.scheme == "https" and p.hostname:
                tls_targets.add((p.hostname, p.port or 443))
        for i, host in enumerate(hosts[:256]):
            ctx.check()
            open_ports = await self.scan(ctx, host, ports) if ports else []
            ctx.kb.open_ports[host] = open_ports
            if open_ports:
                ctx.emit("info", self.name, f"{host}: puertos abiertos {', '.join(str(p['port']) for p in open_ports)}",
                         {"puertos": open_ports})
            for svc in open_ports:
                await self.assess(ctx, host, svc)
                if svc["port"] in TLS_PORTS or svc.get("tls"):
                    tls_targets.add((host, svc["port"]))
            ctx.progress(self.name, "running", int(70 * (i + 1) / max(1, len(hosts))))
        for host, port in sorted(tls_targets):
            ctx.check()
            await TlsAnalyzer(ctx, self.name).analyse(host, port)

    # ------------------------------------------------------------------ scanning
    async def scan(self, ctx: ScanContext, host: str, ports: list[int]) -> list[dict[str, Any]]:
        assert ctx.guard is not None
        sem = asyncio.Semaphore(min(100, max(10, ctx.cfg.concurrency * 10)) if not ctx.egress_active
                                else max(4, min(32, ctx.cfg.concurrency * 4)))
        found: list[dict[str, Any]] = []
        interval = 1.0 / max(ctx.cfg.rps * 5, 1)
        connect_timeout = 8.0 if ctx.egress_active else 2.5  # a tunnel adds the round trip to the egress
        not_testable: list[int] = []

        async def one(port: int) -> None:
            async with sem:
                if ctx.stopping:
                    return
                try:
                    target = await ctx.guard.check_host_port(host, port)
                except ScopeViolation:
                    return
                await asyncio.sleep(interval)
                try:
                    reader, writer = await ctx.net_open(str(target.pinned_ip), port, connect_timeout)
                except UpstreamRefused as e:
                    if e.kind in ("forbidden", "auth"):
                        not_testable.append(port)  # the egress proxy refuses tunnels to this port: unknown, not closed
                    return
                except (OSError, asyncio.TimeoutError):
                    return
                banner = b""
                try:
                    banner = await asyncio.wait_for(reader.read(512), 2.0)
                except (OSError, asyncio.TimeoutError):
                    pass
                finally:
                    writer.close()
                    try:
                        await asyncio.wait_for(writer.wait_closed(), 2)
                    except (OSError, asyncio.TimeoutError):
                        pass
                found.append({"port": port, "service": self.identify(port, banner),
                              "banner": banner[:200].decode("latin-1", errors="replace").strip(), "ip": str(target.pinned_ip)})

        await asyncio.gather(*(one(p) for p in ports))
        if not_testable:
            ctx.emit("warn", self.name, f"{host}: la salida configurada no permite túneles a {len(not_testable)} puertos "
                     "(proxy HTTP con CONNECT restringido). No se dan por cerrados; usa un proxy SOCKS5 (p. ej. ssh -D) "
                     "para el escaneo de puertos completo.", {"puertos_no_comprobables": sorted(not_testable)[:200]})
        return sorted(found, key=lambda x: x["port"])

    @staticmethod
    def identify(port: int, banner: bytes) -> str:
        b = banner[:200]
        if b.startswith(b"SSH-"):
            return "ssh"
        if re.match(rb"^220[ -].*(FTP|FileZilla|vsFTPd|ProFTPD|Pure-FTPd)", b, re.I):
            return "ftp"
        if re.match(rb"^220[ -].*(SMTP|ESMTP|Postfix|Exim|Sendmail)", b, re.I):
            return "smtp"
        if b.startswith(b"RFB "):
            return "vnc"
        if b.startswith(b"\xff\xfd") or b.startswith(b"\xff\xfb"):
            return "telnet"
        if len(b) > 5 and b[4] == 0x0a and b"mysql" in b.lower() or (len(b) > 5 and b[4] == 0x0a and port == 3306):
            return "mysql"
        if b.startswith(b"+OK") and port in (110, 995):
            return "pop3"
        if b.startswith(b"* OK"):
            return "imap"
        return SERVICE_BY_PORT.get(port, "http" if port in WEB_PORTS else "desconocido")

    async def _talk(self, ctx: ScanContext, host: str, port: int, send: bytes | None, read: int = 2048,
                    timeout: float = 4.0) -> bytes:
        assert ctx.guard is not None
        target = await ctx.guard.check_host_port(host, port)
        reader, writer = await ctx.net_open(str(target.pinned_ip), port, timeout * (2 if ctx.egress_active else 1))
        try:
            if send:
                writer.write(send)
                await writer.drain()
            data = b""
            try:
                while len(data) < read:
                    chunk = await asyncio.wait_for(reader.read(read - len(data)), timeout)
                    if not chunk:
                        break
                    data += chunk
                    if send and data.endswith((b"\r\n", b"\n")):
                        break
            except asyncio.TimeoutError:
                pass
            return data
        finally:
            writer.close()

    async def _http(self, ctx: ScanContext, host: str, port: int, path: str) -> bytes:
        hosthdr = host if ":" not in host else f"[{host}]"
        req = f"GET {path} HTTP/1.1\r\nHost: {hosthdr}:{port}\r\nUser-Agent: Vigia\r\nConnection: close\r\n\r\n".encode()
        try:
            return await self._talk(ctx, host, port, req, read=8192)
        except (OSError, asyncio.TimeoutError, ScopeViolation):
            return b""

    # ------------------------------------------------------------------ service assessment
    async def assess(self, ctx: ScanContext, host: str, svc: dict[str, Any]) -> None:
        port, name, banner = svc["port"], svc["service"], svc["banner"]
        ev = {"puerto": port, "servicio": name, "banner": banner[:160], "ip": svc.get("ip")}
        if banner and re.search(r"\d+\.\d+", banner) and name in ("ssh", "ftp", "smtp", "mysql", "pop3", "imap"):
            ctx.add(FindingDraft(title=f"Banner con versión en {host}:{port} ({name})", category="service_version_disclosure",
                                 module=self.name, severity="info", confidence="confirmed", native_evidence=True,
                                 asset=f"{host}:{port}", evidence=ev))
        try:
            if name == "redis":
                data = await self._talk(ctx, host, port, b"PING\r\n")
                if data.startswith(b"+PONG"):
                    self._add(ctx, "db_no_auth", f"Redis sin autenticación en {host}:{port}", host, port,
                              {**ev, "respuesta_PING": "+PONG"}, "confirmed")
                    return
            elif name == "memcached":
                data = await self._talk(ctx, host, port, b"version\r\n")
                if data.startswith(b"VERSION"):
                    self._add(ctx, "db_no_auth", f"Memcached accesible sin autenticación en {host}:{port}", host, port,
                              {**ev, "respuesta": data[:40].decode(errors="replace")}, "confirmed")
                    return
            elif name in ("elasticsearch", "couchdb", "influxdb"):
                data = await self._http(ctx, host, port, "/")
                if b"You Know, for Search" in data or b'"couchdb"' in data or b"X-Influxdb" in data:
                    self._add(ctx, "db_no_auth", f"{name} accesible sin autenticación en {host}:{port}", host, port,
                              {**ev, "respuesta": data.split(b"\r\n\r\n", 1)[-1][:300].decode(errors="replace")}, "confirmed")
                    return
            elif name == "mongodb":
                data = await self._http(ctx, host, port, "/")
                if b"MongoDB" in data:
                    self._add(ctx, "exposed_database", f"MongoDB accesible en {host}:{port}", host, port, ev, "confirmed")
                    return
            elif name in ("docker", "etcd", "kubelet-ro", "consul"):
                path = {"docker": "/version", "etcd": "/version", "kubelet-ro": "/pods", "consul": "/v1/agent/self"}[name]
                data = await self._http(ctx, host, port, path)
                sig = {"docker": b"ApiVersion", "etcd": b"etcdserver", "kubelet-ro": b'"kind":"PodList"',
                       "consul": b'"Config"'}[name]
                if sig in data:
                    self._add(ctx, "exposed_container_api", f"API de {name} sin autenticación en {host}:{port}", host,
                              port, {**ev, "ruta": path}, "confirmed")
                    return
            elif name == "kubernetes":
                pass  # TLS endpoint: reported via TLS analysis + generic exposure below
            elif name == "ftp" and ctx.cfg.at_least("standard"):
                await self._ftp_anonymous(ctx, host, port, ev)
            elif name == "node-inspector":
                data = await self._http(ctx, host, port, "/json/version")
                if b"V8-Version" in data or b"Browser" in data:
                    self._add(ctx, "exposed_debug", f"Inspector de Node.js expuesto en {host}:{port}", host, port, ev,
                              "confirmed")
                    return
        except (OSError, asyncio.TimeoutError, ScopeViolation):
            pass
        if name in DB_SERVICES:
            self._add(ctx, "exposed_database", f"Servicio de datos {name} accesible en {host}:{port}", host, port, ev,
                      "confirmed")
        elif name in REMOTE_ADMIN:
            cat = "cleartext_service" if name == "telnet" else "exposed_remote_admin"
            self._add(ctx, cat, f"{name.upper()} accesible en {host}:{port}", host, port, ev, "confirmed")
            if name == "ssh":
                self._ssh_version(ctx, host, port, banner, ev)
        elif name == "smb" or name == "netbios":
            self._add(ctx, "smb_exposed", f"SMB/NetBIOS accesible en {host}:{port}", host, port, ev, "confirmed")
        elif name in ("ftp",):
            self._add(ctx, "cleartext_service", f"FTP sin cifrado en {host}:{port}", host, port, ev, "confirmed")
        elif name in ("ldap", "nfs", "zookeeper", "rabbitmq-mgmt", "kibana", "kubernetes"):
            self._add(ctx, "unnecessary_service", f"Servicio {name} accesible en {host}:{port}", host, port, ev,
                      "confirmed")

    def _add(self, ctx: ScanContext, cat: str, title: str, host: str, port: int, ev: dict, conf: str) -> None:
        ctx.add(FindingDraft(title=title, category=cat, module=self.name, confidence=conf, native_evidence=True,
                             asset=f"{host}:{port}", evidence=ev,
                             description="Accesible desde el punto de ejecución del escáner. Si el escáner está en la misma "
                                         "red interna, valida también la exposición desde Internet."))

    def _ssh_version(self, ctx: ScanContext, host: str, port: int, banner: str, ev: dict) -> None:
        m = re.search(r"OpenSSH_(\d+)\.(\d+)(p\d+)?", banner)
        if not m:
            return
        major, minor = int(m.group(1)), int(m.group(2))
        ver = (major, minor)
        if (8, 5) <= ver <= (9, 7):
            ctx.add(FindingDraft(title=f"OpenSSH {major}.{minor} potencialmente afectado por regreSSHion ({host}:{port})",
                                 category="outdated_component", module=self.name, confidence="suspected",
                                 native_evidence=False, asset=f"{host}:{port}", cve=["CVE-2024-6387"],
                                 cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                 description="La versión anunciada está en el rango afectado por CVE-2024-6387 (sistemas "
                                             "glibc). Las distribuciones aplican parches sin cambiar la versión: verifica "
                                             "el paquete instalado.", evidence=ev, fingerprint_extra="regresshion"))
        elif ver < (8, 0):
            ctx.add(FindingDraft(title=f"OpenSSH {major}.{minor} antiguo en {host}:{port}", category="outdated_component",
                                 module=self.name, confidence="suspected", native_evidence=False, asset=f"{host}:{port}",
                                 severity="medium", evidence=ev, fingerprint_extra="openssh-old"))

    async def _ftp_anonymous(self, ctx: ScanContext, host: str, port: int, ev: dict) -> None:
        assert ctx.guard is not None
        target = await ctx.guard.check_host_port(host, port)
        reader, writer = await ctx.net_open(str(target.pinned_ip), port, 10 if ctx.egress_active else 5)
        try:
            await asyncio.wait_for(reader.readline(), 5)
            writer.write(b"USER anonymous\r\n")
            await writer.drain()
            r1 = await asyncio.wait_for(reader.readline(), 5)
            if r1.startswith(b"331"):
                writer.write(b"PASS vigia@example.com\r\n")
                await writer.drain()
                r1 = await asyncio.wait_for(reader.readline(), 5)
            if r1.startswith(b"230"):
                self._add(ctx, "ftp_anonymous", f"FTP con acceso anónimo en {host}:{port}", host, port,
                          {**ev, "respuesta": r1[:80].decode(errors="replace")}, "confirmed")
            writer.write(b"QUIT\r\n")
            await writer.drain()
        finally:
            writer.close()


class TlsAnalyzer:
    """Native TLS assessment (stdlib ssl + cryptography); connects to the pinned IP with SNI."""

    def __init__(self, ctx: ScanContext, module: str):
        self.ctx = ctx
        self.module = module

    async def _handshake(self, target: CheckedTarget, host: str, ctxssl: ssl.SSLContext) -> dict[str, Any]:
        """TLS handshake over a raw stream to the pinned IP (through the egress when configured)."""
        egress = self.ctx.egress_active
        reader, writer = await self.ctx.net_open(str(target.pinned_ip), target.port, 12 if egress else 6)
        try:
            await asyncio.wait_for(writer.start_tls(ctxssl, server_hostname=host if not _is_ip(host) else None),
                                   12 if egress else 8)
            tls = writer.get_extra_info("ssl_object")
            return {"version": tls.version(), "cipher": tls.cipher(), "cert": tls.getpeercert(binary_form=True)}
        except asyncio.TimeoutError as e:
            raise OSError("tiempo de negociación TLS agotado") from e
        finally:
            writer.close()

    async def analyse(self, host: str, port: int) -> None:
        ctx = self.ctx
        assert ctx.guard is not None
        try:
            target = await ctx.guard.check_host_port(host, port)
        except ScopeViolation:
            return
        info: dict[str, Any] = {"host": host, "port": port, "protocols": {}, "weak_ciphers": []}
        base = None
        try:
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.check_hostname, c.verify_mode = False, ssl.CERT_NONE  # vigia:ignore — análisis TLS: se inspeccionan certificados no válidos a propósito
            base = await self._handshake(target, host, c)
        except (OSError, ssl.SSLError) as e:
            ctx.emit("warn", self.module, f"TLS no disponible en {host}:{port}: {e}")
            return
        info["negotiated"] = {"version": base["version"], "cipher": base["cipher"][0] if base["cipher"] else None}
        # verification against the system trust store
        try:
            v = ssl.create_default_context()
            if _is_ip(host):
                v.check_hostname = False
            await self._handshake(target, host, v)
            verify_error = None
        except ssl.SSLCertVerificationError as e:
            verify_error = e.verify_message or str(e)
        except (OSError, ssl.SSLError) as e:
            verify_error = str(e)
        self._certificate(host, port, base["cert"], verify_error, info)
        # protocol versions
        for name, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
                          ("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.3", ssl.TLSVersion.TLSv1_3)):
            try:
                c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                c.check_hostname, c.verify_mode = False, ssl.CERT_NONE  # vigia:ignore — análisis TLS: se inspeccionan certificados no válidos a propósito
                c.minimum_version = c.maximum_version = ver
                if ver in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
                    c.set_ciphers("ALL:@SECLEVEL=0")
                await self._handshake(target, host, c)
                info["protocols"][name] = True
            except (ssl.SSLError, OSError, ValueError) as e:
                info["protocols"][name] = False if "unsupported" not in str(e).lower() else None
        old = [p for p in ("TLSv1.0", "TLSv1.1") if info["protocols"].get(p)]
        if old:
            ctx.add(FindingDraft(title=f"{' y '.join(old)} habilitado en {host}:{port}", category="tls_old_protocol",
                                 module=self.module, confidence="confirmed", native_evidence=True, asset=f"{host}:{port}",
                                 evidence={"protocolos": info["protocols"]}))
        if info["protocols"].get("TLSv1.2"):
            for label, spec in (("RC4", "RC4"), ("3DES", "3DES:DES-CBC3-SHA"), ("NULL", "eNULL"), ("EXPORT", "EXP"),
                                ("anónimos", "aNULL"), ("sin secreto perfecto hacia adelante (RSA estático)", "kRSA")):
                try:
                    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    c.check_hostname, c.verify_mode = False, ssl.CERT_NONE  # vigia:ignore — análisis TLS: se inspeccionan certificados no válidos a propósito
                    c.minimum_version = c.maximum_version = ssl.TLSVersion.TLSv1_2
                    c.set_ciphers(spec + ":@SECLEVEL=0")
                except ssl.SSLError:
                    continue  # local OpenSSL cannot offer this family: not testable here
                try:
                    hs = await self._handshake(target, host, c)
                    info["weak_ciphers"].append(f"{label}: {hs['cipher'][0]}")
                except (ssl.SSLError, OSError):
                    continue
            if info["weak_ciphers"]:
                ctx.add(FindingDraft(title=f"Suites de cifrado débiles aceptadas en {host}:{port}",
                                     category="tls_weak_cipher", module=self.module, confidence="confirmed",
                                     native_evidence=True, asset=f"{host}:{port}",
                                     evidence={"aceptadas": info["weak_ciphers"]}))
        ctx.kb.tls[f"{host}:{port}"] = info

    def _certificate(self, host: str, port: int, der: bytes | None, verify_error: str | None, info: dict) -> None:
        ctx = self.ctx
        if not der:
            return
        cert = x509.load_der_x509_certificate(der)
        now = dt.datetime.now(dt.timezone.utc)
        not_after = cert.not_valid_after_utc
        subject_cn = next((a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)), "")
        try:
            sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(
                x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []
        key = cert.public_key()
        bits = key.key_size if isinstance(key, (rsa.RSAPublicKey, dsa.DSAPublicKey, ec.EllipticCurvePublicKey)) else None
        sig_alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "?"
        info["certificate"] = {"subject_cn": subject_cn, "issuer": cert.issuer.rfc4514_string()[:200], "sans": sans[:20],
                               "not_after": not_after.isoformat(), "key_bits": bits, "signature": sig_alg,
                               "verify_error": verify_error}
        problems = []
        if not_after < now:
            problems.append(f"caducado el {not_after.date()}")
        if cert.issuer == cert.subject:
            problems.append("autofirmado")
        if not _is_ip(host) and not any(_match_host(host, n) for n in (sans or [subject_cn])):
            problems.append(f"no válido para {host}")
        if isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048:
            problems.append(f"clave RSA de {key.key_size} bits")
        if sig_alg in ("md5", "sha1"):
            problems.append(f"firma {sig_alg.upper()}")
        if verify_error and not problems:
            problems.append(f"no verificable con los certificados raíz del sistema ({verify_error})")
        if problems:
            ctx.add(FindingDraft(title=f"Certificado TLS no válido en {host}:{port}: {problems[0]}", category="cert_invalid",
                                 module=self.module, confidence="confirmed", native_evidence=True, asset=f"{host}:{port}",
                                 description="Problemas: " + "; ".join(problems), evidence=info["certificate"]))
        elif (not_after - now).days < 21:
            ctx.add(FindingDraft(title=f"El certificado de {host}:{port} caduca en {(not_after - now).days} días",
                                 category="cert_expiring", module=self.module, confidence="confirmed", native_evidence=True,
                                 asset=f"{host}:{port}", evidence=info["certificate"]))


def _is_ip(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in host else socket.AF_INET, host)
        return True
    except OSError:
        return False


def _match_host(host: str, pattern: str) -> bool:
    host, pattern = host.lower(), pattern.lower()
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and host.count(".") == pattern.count(".")
    return host == pattern
