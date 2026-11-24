"""M01 — Reconnaissance: DNS, technology fingerprinting, robots/sitemap, admin panels, dev environments.

All network activity stays inside the scope: HTTP goes through the scoped client; DNS queries only ask the
configured resolver about in-scope names (remote DoH through the egress when one is configured — never the local
resolver then); zone-transfer attempts travel through the egress tunnel; certificate-transparency lookups (crt.sh)
are passive, leave through the public lane of the egress, and their results are filtered by scope.
"""
from __future__ import annotations

import asyncio
import re
import struct
import xml.etree.ElementTree as _ET  # noqa: N814 - only for types; parsing uses defusedxml
from typing import Any
from urllib.parse import urljoin, urlsplit

import dns.exception
import dns.message
import dns.rcode
import dns.rdatatype
import dns.resolver
import httpx
from defusedxml.ElementTree import fromstring as safe_xml

from vigia import USER_AGENT
from vigia.config import get_settings
from vigia.core.context import ScanContext
from vigia.core.findings import FindingDraft
from vigia.core.module import Module
from vigia.modules.common import evidence_from, origin, parse_html
from vigia.modules.probe import probe_paths
from vigia.security.http import HttpError
from vigia.security.scope import ScopeViolation

_ = _ET

TECH_HEADERS = [
    ("server", re.compile(r"^(nginx|apache|microsoft-iis|openresty|litespeed|caddy|gunicorn|uvicorn|werkzeug|"
                          r"jetty|tomcat|envoy|cloudflare|kestrel|express)[/ ]?v?([\d.]+)?", re.I)),
    ("x-powered-by", re.compile(r"^(php|asp\.net|express|next\.js|servlet|jsf|plesk|nuxt)[/ ]?v?([\d.]+)?", re.I)),
    ("x-aspnet-version", re.compile(r"^()([\d.]+)")),
    ("x-aspnetmvc-version", re.compile(r"^()([\d.]+)")),
    ("x-generator", re.compile(r"^([A-Za-z][\w .-]+?)\s*v?([\d.]+)?$")),
]
COOKIE_TECH = {"phpsessid": "PHP", "jsessionid": "Java Servlet", "asp.net_sessionid": "ASP.NET", "laravel_session": "Laravel",
               "csrftoken": "Django", "connect.sid": "Express", "_rails_session": "Ruby on Rails",
               "ci_session": "CodeIgniter", "symfony": "Symfony", "wordpress_logged_in": "WordPress", "__cf_bm": "Cloudflare",
               "awsalb": "AWS ALB", "awselb": "AWS ELB", "_shopify_s": "Shopify"}
BODY_TECH = [
    ("WordPress", re.compile(r"/wp-content/|/wp-includes/")), ("Drupal", re.compile(r"Drupal\.settings|/sites/default/files/")),
    ("Joomla", re.compile(r"/media/jui/|Joomla!")), ("Next.js", re.compile(r"__NEXT_DATA__|/_next/static/")),
    ("Nuxt", re.compile(r"__NUXT__|/_nuxt/")), ("Angular", re.compile(r"ng-version=\"([\d.]+)\"")),
    ("React", re.compile(r"data-reactroot|react-dom")), ("Vue.js", re.compile(r"data-v-[0-9a-f]{8}|__vue__")),
    ("Laravel", re.compile(r"laravel_session|csrf-token.*?content=")), ("ASP.NET WebForms", re.compile(r"__VIEWSTATE")),
    ("Svelte", re.compile(r"svelte-[a-z0-9]{6}")), ("Gatsby", re.compile(r"___gatsby")),
    ("Shopify", re.compile(r"cdn\.shopify\.com")), ("Magento", re.compile(r"Mage\.Cookies|/static/version\d+/")),
]
INFRA_HEADERS = {"cf-ray": "Cloudflare", "x-amz-cf-id": "AWS CloudFront", "x-amz-request-id": "AWS S3",
                 "x-vercel-id": "Vercel", "x-nf-request-id": "Netlify", "x-azure-ref": "Azure Front Door",
                 "x-goog-generation": "Google Cloud Storage", "fly-request-id": "Fly.io", "x-github-request-id": "GitHub Pages",
                 "x-served-by": "Fastly", "x-render-origin-server": "Render", "server-timing": None}
# End-of-life / known-vulnerable server versions (built-in, conservative; versions come from banners).
EOL_RULES: list[tuple[str, re.Pattern[str], str, list[str]]] = [
    ("Apache", re.compile(r"^2\.4\.(49|50)$"), "Apache 2.4.49/2.4.50: path traversal y RCE (CVE-2021-41773, CVE-2021-42013)",
     ["CVE-2021-41773", "CVE-2021-42013"]),
    ("Apache", re.compile(r"^2\.[0-2]\."), "Apache HTTP Server 2.0–2.2 sin soporte desde 2017", []),
    ("PHP", re.compile(r"^(5\.|7\.|8\.[01]\.)"), "Rama de PHP sin soporte de seguridad (fin de vida)", []),
    ("Microsoft-IIS", re.compile(r"^([5-7])\."), "IIS ≤7.x corresponde a versiones de Windows Server sin soporte", []),
    ("nginx", re.compile(r"^(0\.|1\.([0-9]|1[0-9])\.)"), "nginx anterior a 1.20 (rama sin soporte)", []),
    ("OpenSSL", re.compile(r"^(0\.9|1\.0|1\.1)"), "OpenSSL 1.1.x o anterior sin soporte", []),
    ("ASP.NET", re.compile(r"^[1-3]\."), "Versión antigua de .NET Framework/ASP.NET", []),
]
ADMIN_PATHS = ["/admin", "/admin/", "/administrator/", "/wp-admin/", "/wp-login.php", "/user/login", "/phpmyadmin/",
               "/pma/", "/adminer.php", "/manager/html", "/jenkins/", "/grafana/login", "/kibana/", "/admin/login",
               "/backend/", "/cpanel", "/webadmin/", "/console/", "/login", "/admin.php", "/django-admin/", "/rails/admin"]
ADMIN_SIG = re.compile(r"phpMyAdmin|Adminer|Tomcat Web Application Manager|Jenkins|Grafana|Kibana|wp-login|"
                       r"Django administration|Administración|Admin(?:istrator)? (?:panel|login)|Iniciar sesión|"
                       r"type=[\"']password[\"']", re.I)
DEV_HOST = re.compile(r"(^|[.-])(dev|develop|development|staging|stage|stg|test|testing|qa|uat|preprod|sandbox|beta)([.-]|$)",
                      re.I)
TAKEOVER_CNAMES = re.compile(r"\.(s3\.amazonaws\.com|s3-website[\w.-]*\.amazonaws\.com|herokuapp\.com|herokudns\.com|"
                             r"github\.io|azurewebsites\.net|cloudapp\.net|trafficmanager\.net|blob\.core\.windows\.net|"
                             r"cloudfront\.net|netlify\.app|vercel\.app|pantheonsite\.io|ghost\.io|myshopify\.com|"
                             r"surge\.sh|bitbucket\.io|zendesk\.com|readthedocs\.io|fly\.dev)\.?$", re.I)


class ReconModule(Module):
    name = "recon"
    title = "Reconocimiento y descubrimiento"
    phase = "recon"
    needs_target = True

    async def run(self, ctx: ScanContext) -> None:
        assert ctx.guard is not None
        seeds = list(dict.fromkeys(ctx.kb.base_urls or ctx.guard.seed_urls()))
        ctx.kb.base_urls = seeds
        await asyncio.gather(self.dns(ctx), *(self.http_fingerprint(ctx, u) for u in seeds))
        ctx.progress(self.name, "running", 50)
        for base in ctx.kb.base_urls:
            ctx.check()
            await self.robots_sitemap(ctx, base)
            if ctx.cfg.at_least("light"):
                await self.admin_panels(ctx, base)
        await self.dev_environment(ctx)

    # ------------------------------------------------------------------ DNS
    async def dns(self, ctx: ScanContext) -> None:
        assert ctx.guard is not None
        names = [t.host for t in ctx.guard.targets if t.kind in ("host", "wildcard") and t.host]
        from vigia.security.resolver import ResolutionError, default_resolver
        res = ctx.resolver or default_resolver()
        for name in names:
            records: dict[str, list[str]] = {}
            for rtype in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA"):
                try:
                    ans = await res.records(name, rtype)
                    records[rtype] = [r[:300] for r in ans][:20]
                except (dns.exception.DNSException, OSError, ResolutionError):
                    continue
            ctx.emit("info", self.name, f"DNS {name}: " + ", ".join(f"{k}={len(v)}" for k, v in records.items()),
                     {"records": records})
            ctx.kb.technologies.setdefault(f"dns:{name}", {"version": None, "evidence": records, "host": name})
            for cname in records.get("CNAME", []):
                if TAKEOVER_CNAMES.search(cname):
                    try:
                        await res.records(cname.rstrip("."), "A")
                    except dns.resolver.NXDOMAIN:
                        ctx.add(FindingDraft(
                            title=f"CNAME de {name} apunta a un recurso inexistente ({cname})", category="subdomain_dangling",
                            module=self.name, confidence="likely", native_evidence=True, asset=name,
                            description="El registro CNAME apunta a un servicio de terceros cuyo nombre no resuelve (NXDOMAIN). "
                                        "Si el recurso puede reclamarse, un tercero controlaría el subdominio.",
                            evidence={"cname": cname, "resolucion": "NXDOMAIN"}))
                    except (dns.exception.DNSException, OSError, ResolutionError):
                        pass
            await self.email_auth(ctx, res, name, records)
            if ctx.cfg.at_least("standard"):
                await self.zone_transfer(ctx, name, records.get("NS", []))
        if ctx.cfg.at_least("standard") and not get_settings().offline:
            await self.cert_transparency(ctx)

    async def email_auth(self, ctx: ScanContext, res, name: str, records: dict[str, list[str]]) -> None:  # noqa: ANN001
        if name.count(".") != 1:  # only for registrable domains (example.com)
            return
        spf = [t for t in records.get("TXT", []) if "v=spf1" in t.lower()]
        problems = []
        if not spf:
            problems.append("no hay registro SPF")
        elif any("+all" in t or "?all" in t for t in spf):
            problems.append("SPF permisivo (+all/?all)")
        from vigia.security.resolver import ResolutionError
        try:
            dmarc = list(await res.records(f"_dmarc.{name}", "TXT"))
        except (dns.exception.DNSException, OSError, ResolutionError):
            dmarc = []
        if not dmarc:
            problems.append("no hay registro DMARC")
        elif any("p=none" in d.lower() for d in dmarc):
            problems.append("DMARC en modo p=none (solo monitorización)")
        if problems and (records.get("MX") or spf):
            ctx.add(FindingDraft(title=f"Autenticación de correo débil en {name}: " + "; ".join(problems),
                                 category="dns_email_auth", module=self.name, confidence="confirmed", native_evidence=True,
                                 asset=name, evidence={"spf": spf, "dmarc": dmarc}))

    async def zone_transfer(self, ctx: ScanContext, name: str, ns_records: list[str], port: int = 53) -> None:
        assert ctx.guard is not None
        for ns in ns_records[:4]:
            ns_host = ns.rstrip(".")
            if not ctx.guard.host_matches(ns_host):
                ctx.emit("debug", self.name, f"AXFR no probado contra {ns_host}: el servidor DNS no está en el alcance")
                continue
            try:
                target = await ctx.guard.check_host_port(ns_host, port)
                names = await axfr(ctx, str(target.pinned_ip), name, port)
            except (dns.exception.DNSException, OSError, EOFError, ScopeViolation, ConnectionError, asyncio.TimeoutError,
                    asyncio.IncompleteReadError, ValueError):
                continue
            if names:
                ctx.add(FindingDraft(title=f"Transferencia de zona permitida en {ns_host} para {name}",
                                     category="dns_zone_transfer", module=self.name, confidence="confirmed",
                                     native_evidence=True, asset=name, evidence={"ns": ns_host, "muestra_registros": names[:30]}))

    async def cert_transparency(self, ctx: ScanContext) -> None:
        assert ctx.guard is not None
        wild = [t.host for t in ctx.guard.targets if t.kind == "wildcard" and t.host]
        proxy = ctx.public_proxy_url()  # through the egress (public lane) when configured, never direct then
        for domain in wild[:3]:
            try:
                async with httpx.AsyncClient(verify=True, trust_env=False, timeout=25, proxy=proxy,
                                             headers={"User-Agent": USER_AGENT}) as c:
                    r = await c.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
                    data = r.json() if r.status_code == 200 else []
            except (httpx.HTTPError, ValueError):
                ctx.emit("warn", self.name, f"crt.sh no disponible para {domain}")
                continue
            subs = set()
            for row in data[:5000]:
                for n in str(row.get("name_value", "")).splitlines():
                    n = n.strip().lower().lstrip("*.")
                    if n.endswith("." + domain) or n == domain:
                        subs.add(n)
            in_scope = sorted(s for s in subs if ctx.guard.host_matches(s) and not ctx.guard.is_excluded(s))
            ctx.emit("info", self.name, f"Transparencia de certificados: {len(subs)} nombres para {domain}, "
                     f"{len(in_scope)} dentro del alcance", {"subdominios": in_scope[:200]})
            for sub in in_scope[:50]:
                url = f"https://{sub}/"
                if url not in ctx.kb.base_urls:
                    ctx.kb.base_urls.append(url)

    # ------------------------------------------------------------------ HTTP fingerprint
    async def http_fingerprint(self, ctx: ScanContext, url: str) -> None:
        try:
            r = await ctx.fetch(url, module=self.name)
        except (HttpError, ScopeViolation) as e:
            if url.startswith("https://"):
                alt = "http://" + url[len("https://"):]
                ctx.emit("warn", self.name, f"{url} no responde por HTTPS ({e}); se prueba HTTP")
                try:
                    r = await ctx.fetch(alt, module=self.name)
                    ctx.kb.base_urls = [alt if u == url else u for u in ctx.kb.base_urls]
                    url = alt
                except (HttpError, ScopeViolation) as e2:
                    ctx.emit("error", self.name, f"El objetivo {url} no responde: {e2}")
                    return
            else:
                ctx.emit("error", self.name, f"El objetivo {url} no responde: {e}")
                return
        if r.url != url and origin(r.url) != origin(url):
            if origin(r.url) not in [origin(b) for b in ctx.kb.base_urls]:
                ctx.kb.base_urls.append(origin(r.url) + "/")
        host = urlsplit(r.url).hostname or ""
        ctx.kb.urls.add(r.url)
        techs: dict[str, dict[str, Any]] = {}
        for hname, rx in TECH_HEADERS:
            val = r.header(hname)
            if val:
                m = rx.search(val.strip())
                if m and m.group(1):
                    name = m.group(1).strip()
                elif hname in ("server", "x-powered-by", "x-generator"):  # unknown product: use its own token
                    tok = re.match(r"\s*([A-Za-z][\w.\-]{1,40})(?:[/ ]v?([\d.]+))?", val)
                    if not tok:
                        continue
                    name, m = tok.group(1), tok
                else:
                    name = hname
                ver = m.group(2) if m and m.lastindex and m.lastindex >= 2 else None
                if hname.startswith("x-aspnet"):
                    name = "ASP.NET MVC" if "mvc" in hname else "ASP.NET"
                techs[name] = {"version": ver, "evidence": f"{hname}: {val}", "host": host}
                for sub in re.findall(r"(OpenSSL|PHP|mod_\w+|Python|OpenSSH)/([\d.]+\w*)", val):
                    techs[sub[0]] = {"version": sub[1], "evidence": f"{hname}: {val}", "host": host}
        for k, tech in INFRA_HEADERS.items():
            if tech and r.header(k):
                techs[tech] = {"version": None, "evidence": f"cabecera {k}", "host": host}
        for c in r.set_cookies:
            cname = c.split("=", 1)[0].strip().lower()
            for prefix, tech in COOKIE_TECH.items():
                if cname.startswith(prefix):
                    techs.setdefault(tech, {"version": None, "evidence": f"cookie {cname}", "host": host})
        body = r.text
        page = parse_html(body, r.url) if "html" in r.content_type else None
        if page is not None:
            gen = page.meta.get("generator")
            if gen:
                m = re.match(r"([A-Za-z][\w .-]*?)\s*v?([\d.]+)?$", gen.strip())
                techs[(m.group(1) if m else gen).strip()] = {"version": m.group(2) if m else None,
                                                             "evidence": f"meta generator: {gen}", "host": host}
            for name, rx in BODY_TECH:
                m = rx.search(body)
                if m:
                    techs.setdefault(name, {"version": m.group(1) if m.groups() else None,
                                            "evidence": f"patrón en HTML: {m.group(0)[:80]}", "host": host})
        for name, info in techs.items():
            ctx.kb.technologies[name] = info
            ctx.add(FindingDraft(title=f"{name}{' ' + info['version'] if info.get('version') else ''} en {host}",
                                 category="tech_fingerprint", module=self.name, severity="info", confidence="confirmed",
                                 native_evidence=True, asset=host, endpoint=r.url, evidence={"origen": info["evidence"]},
                                 fingerprint_extra=name))
            if info.get("version"):
                self._eol(ctx, name, info, r.url, host)
        disclosed = [f"{h}: {r.header(h)}" for h in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                                                      "x-generator") if r.header(h) and re.search(r"\d", r.header(h))]
        if disclosed:
            ctx.add(FindingDraft(title=f"Versión del software divulgada en cabeceras ({host})", category="version_disclosure",
                                 module=self.name, severity="info", confidence="confirmed", native_evidence=True, asset=host,
                                 endpoint=r.url, evidence={"cabeceras": disclosed}))

    def _eol(self, ctx: ScanContext, name: str, info: dict[str, Any], url: str, host: str) -> None:
        for prod, rx, why, cves in EOL_RULES:
            if prod.lower() in name.lower() and rx.search(info["version"]):
                ctx.add(FindingDraft(
                    title=f"{name} {info['version']} desactualizado o vulnerable ({host})", category="outdated_component",
                    module=self.name, confidence="likely", native_evidence=False, asset=host, endpoint=url, cve=cves,
                    description=f"{why}. La versión procede del banner ({info['evidence']}); los backports de "
                                "distribuciones pueden haber corregido fallos sin cambiar la versión anunciada.",
                    evidence={"banner": info["evidence"]}, fingerprint_extra=name,
                    cvss_vector=None if not cves else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    severity="high" if cves else "medium"))

    # ------------------------------------------------------------------ robots / sitemap
    async def robots_sitemap(self, ctx: ScanContext, base: str) -> None:
        interesting = re.compile(r"admin|backup|private|secret|internal|config|debug|test|old|tmp|api|staging|dev", re.I)
        sitemaps = [urljoin(base, "/sitemap.xml")]
        try:
            r = await ctx.fetch(urljoin(base, "/robots.txt"), module=self.name)
            if r.status == 200 and "text/plain" in r.content_type:
                disallow = re.findall(r"(?im)^\s*disallow:\s*(\S+)", r.text)[:200]
                sitemaps += re.findall(r"(?im)^\s*sitemap:\s*(\S+)", r.text)[:10]
                for p in disallow:
                    clean = p.split("*")[0].split("$")[0]
                    if clean and clean != "/":
                        ctx.kb.urls.add(urljoin(base, clean))
                hits = [p for p in disallow if interesting.search(p)]
                ctx.emit("info", self.name, f"robots.txt: {len(disallow)} rutas Disallow ({len(hits)} sugerentes)",
                         {"disallow": disallow[:50]})
        except (HttpError, ScopeViolation):
            pass
        for sm in dict.fromkeys(sitemaps):
            try:
                r = await ctx.fetch(sm, module=self.name, store=False)
            except (HttpError, ScopeViolation):
                continue
            if r.status != 200 or b"<" not in r.content[:200]:
                continue
            try:
                root = safe_xml(r.content[:2_000_000])
            except Exception:  # noqa: BLE001 - defusedxml raises several types on hostile XML
                continue
            locs = [el.text.strip() for el in root.iter() if el.tag.endswith("loc") and el.text][:500]
            added = 0
            for loc in locs:
                if ctx.guard and ctx.guard.host_matches(urlsplit(loc).hostname or ""):
                    ctx.kb.urls.add(loc)
                    added += 1
            ctx.emit("info", self.name, f"sitemap {sm}: {len(locs)} URLs ({added} en alcance)")

    # ------------------------------------------------------------------ admin panels
    async def admin_panels(self, ctx: ScanContext, base: str) -> None:
        hits = await probe_paths(ctx, base, ADMIN_PATHS, self.name)
        for path, r in hits:
            if r.status in (200, 401, 403) or (r.status in (301, 302) and "login" in r.header("location").lower()):
                body = r.text
                sig = ADMIN_SIG.search(body)
                if r.status == 200 and not sig:
                    continue
                if r.status == 403:
                    continue  # exists but blocked: not an exposure
                host = urlsplit(r.url).hostname or ""
                ctx.kb.urls.add(r.url)
                if "type=\"password\"" in body.lower() or "type='password'" in body.lower():
                    ctx.kb.login_urls.add(r.url)
                ctx.add(FindingDraft(
                    title=f"Panel de administración accesible: {path} ({host})", category="exposed_admin",
                    module=self.name, confidence="confirmed", native_evidence=True, asset=host, endpoint=r.url, method="GET",
                    description=f"La ruta {path} responde {r.status} con indicios de un panel de administración "
                                f"({sig.group(0) if sig else 'autenticación HTTP'}).",
                    evidence=evidence_from(r, sig.group(0) if sig else None, 600)))

    async def dev_environment(self, ctx: ScanContext) -> None:
        for base in ctx.kb.base_urls:
            host = urlsplit(base).hostname or ""
            if DEV_HOST.search(host):
                ctx.add(FindingDraft(
                    title=f"Entorno no productivo accesible públicamente: {host}", category="exposed_dev_env",
                    module=self.name, confidence="suspected", native_evidence=True, asset=host, endpoint=base,
                    description="El nombre del host indica un entorno de desarrollo/pruebas. Si es intencionado (staging "
                                "auditado), confirma que no contiene datos reales y está protegido.",
                    evidence={"host": host}))


async def axfr(ctx: ScanContext, ip: str, zone: str, port: int = 53, timeout: float = 10.0) -> list[str]:
    """Read-only AXFR attempt over a raw TCP stream (through the egress when configured). Returns the owner names
    received, or [] if the server refuses the transfer."""
    reader, writer = await ctx.net_open(ip, port, timeout)
    try:
        q = dns.message.make_query(zone, dns.rdatatype.AXFR)
        wire = q.to_wire()
        writer.write(struct.pack("!H", len(wire)) + wire)
        await writer.drain()
        names: list[str] = []
        soa = 0
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 15
        while soa < 2 and loop.time() < deadline:
            try:
                n = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), timeout))[0]
            except asyncio.IncompleteReadError:
                break  # server closed after sending the zone
            # one_rr_per_rrset: the opening and closing SOA of a single-message transfer must not be merged
            msg = dns.message.from_wire(await asyncio.wait_for(reader.readexactly(n), timeout), one_rr_per_rrset=True)
            if msg.id != q.id or msg.rcode() != dns.rcode.NOERROR or not msg.answer:
                return []
            for rrset in msg.answer:
                if rrset.rdtype == dns.rdatatype.SOA:
                    soa += 1
                elif len(names) < 200:
                    names.append(rrset.name.to_text())
            if not soa:
                return []  # a transfer must start with the SOA
        return names if soa >= 1 else []
    finally:
        writer.close()
