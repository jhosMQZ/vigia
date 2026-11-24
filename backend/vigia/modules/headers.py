"""M10 — Configuration and general security: HTTPS/HSTS, CSP, framing, cookies, CORS, cache, disclosure, errors."""
from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import urljoin, urlsplit

from vigia.core.context import ScanContext
from vigia.core.findings import FindingDraft
from vigia.core.module import Module
from vigia.modules.common import ERROR_SIGNATURES, StoredResponse, canary, evidence_from, find_signature, origin, parse_html
from vigia.security.http import HttpError
from vigia.security.scope import ScopeViolation

SESSION_COOKIE = re.compile(r"sess|sid$|^sid|token|auth|jwt|login|remember|connect\.sid|phpsessid|jsessionid|"
                            r"asp\.net_sessionid|laravel_session|_session$|identity", re.I)
CSRF_COOKIE = re.compile(r"csrf|xsrf", re.I)
EVIL = "https://vigia-cors-check.example"


def _cookie_attrs(raw: str) -> tuple[str, dict[str, str]]:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0]
    attrs = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip()
    return name, attrs


def analyse_csp(csp: str) -> list[str]:
    issues = []
    directives: dict[str, list[str]] = {}
    for d in csp.split(";"):
        toks = d.strip().split()
        if toks:
            directives[toks[0].lower()] = [t.lower() for t in toks[1:]]
    script = directives.get("script-src", directives.get("default-src"))
    if script is None:
        issues.append("no define script-src ni default-src")
    else:
        has_nonce = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in script)
        if "'unsafe-inline'" in script and not has_nonce and "'strict-dynamic'" not in script:
            issues.append("script-src permite 'unsafe-inline'")
        if "'unsafe-eval'" in script:
            issues.append("script-src permite 'unsafe-eval'")
        if any(t in ("*", "http:", "https:", "data:") for t in script):
            issues.append("script-src permite orígenes comodín (*, http:, https: o data:)")
    if "object-src" not in directives and "'none'" not in directives.get("default-src", []):
        issues.append("falta object-src 'none'")
    if "base-uri" not in directives:
        issues.append("falta base-uri")
    return issues


class HeadersModule(Module):
    name = "headers"
    title = "Configuración y cabeceras de seguridad"
    phase = "analysis"
    needs_target = True

    async def run(self, ctx: ScanContext) -> None:
        by_origin: dict[str, list[StoredResponse]] = defaultdict(list)
        for sr in ctx.kb.responses.items.values():
            if 200 <= sr.status < 400:
                by_origin[origin(sr.url)].append(sr)
        for base in ctx.kb.base_urls:
            o = origin(base)
            if o not in by_origin:
                try:
                    await ctx.fetch(base, module=self.name)
                    by_origin[o] = [s for s in ctx.kb.responses.items.values() if origin(s.url) == o]
                except (HttpError, ScopeViolation):
                    continue
        for o, responses in by_origin.items():
            ctx.check()
            host = urlsplit(o).hostname or ""
            html = [r for r in responses if "html" in r.content_type] or responses
            main = html[0]
            await self.transport(ctx, o, host, main)
            self.security_headers(ctx, host, main)
            self.cookies(ctx, host, responses)
            self.cache(ctx, host, responses)
            self.mixed_content(ctx, host, html)
            await self.cors(ctx, o, host)
            await self.errors(ctx, o, host)
            await self.methods(ctx, o, host)

    async def transport(self, ctx: ScanContext, o: str, host: str, main: StoredResponse) -> None:
        if o.startswith("https://"):
            sts = main.header("strict-transport-security")
            if not sts:
                ctx.add(FindingDraft(title=f"HSTS ausente en {host}", category="missing_hsts", module=self.name,
                                     confidence="confirmed", native_evidence=True, asset=host, endpoint=main.url,
                                     evidence=evidence_from(main, limit=200)))
            else:
                m = re.search(r"max-age=(\d+)", sts)
                if not m or int(m.group(1)) < 15552000:
                    ctx.add(FindingDraft(title=f"HSTS con max-age insuficiente en {host}", category="missing_hsts",
                                         module=self.name, confidence="confirmed", native_evidence=True, asset=host,
                                         endpoint=main.url, severity="low", cvss_vector=None,
                                         evidence={"strict-transport-security": sts}, fingerprint_extra="weak"))
            plain = "http://" + o[len("https://"):] + "/"
            try:
                r = await ctx.fetch(plain, module=self.name, follow_redirects=False, store=False)
            except (HttpError, ScopeViolation):
                return  # port 80 closed or out of scope: fine
            loc = r.header("location")
            if r.status < 300 or (r.status in (301, 302, 307, 308) and not loc.startswith("https://")):
                ctx.add(FindingDraft(title=f"{host} sirve contenido por HTTP sin redirigir a HTTPS", category="no_https",
                                     module=self.name, confidence="confirmed", native_evidence=True, asset=host,
                                     endpoint=plain, evidence=evidence_from(r, limit=300)))
        else:
            ctx.add(FindingDraft(title=f"{host} se sirve solo por HTTP", category="no_https", module=self.name,
                                 confidence="confirmed", native_evidence=True, asset=host, endpoint=main.url,
                                 evidence={"url": main.url}))

    def security_headers(self, ctx: ScanContext, host: str, r: StoredResponse) -> None:
        csp = r.header("content-security-policy")
        if not csp:
            ro = r.header("content-security-policy-report-only")
            ctx.add(FindingDraft(title=f"Content-Security-Policy ausente en {host}" + (" (solo report-only)" if ro else ""),
                                 category="missing_csp", module=self.name, confidence="confirmed", native_evidence=True,
                                 asset=host, endpoint=r.url, evidence={"csp_report_only": ro or None}))
        else:
            issues = analyse_csp(csp)
            if issues:
                ctx.add(FindingDraft(title=f"CSP débil en {host}: {issues[0]}", category="weak_csp", module=self.name,
                                     confidence="confirmed", native_evidence=True, asset=host, endpoint=r.url,
                                     description="Problemas detectados: " + "; ".join(issues),
                                     evidence={"content-security-policy": csp[:1500], "problemas": issues}))
        if "html" in r.content_type and not r.header("x-frame-options") and "frame-ancestors" not in csp.lower():
            ctx.add(FindingDraft(title=f"Sin protección contra clickjacking en {host}", category="clickjacking",
                                 module=self.name, confidence="confirmed", native_evidence=True, asset=host, endpoint=r.url,
                                 evidence={"x-frame-options": None, "frame-ancestors": None}))
        if r.header("x-content-type-options").lower() != "nosniff":
            ctx.add(FindingDraft(title=f"X-Content-Type-Options ausente en {host}", category="missing_xcto",
                                 module=self.name, severity="info", confidence="confirmed", native_evidence=True,
                                 asset=host, endpoint=r.url))
        if not r.header("referrer-policy"):
            ctx.add(FindingDraft(title=f"Referrer-Policy ausente en {host}", category="missing_referrer_policy",
                                 module=self.name, severity="info", confidence="confirmed", native_evidence=True,
                                 asset=host, endpoint=r.url))
        if not r.header("permissions-policy"):
            ctx.add(FindingDraft(title=f"Permissions-Policy ausente en {host}", category="missing_permissions_policy",
                                 module=self.name, severity="info", confidence="confirmed", native_evidence=True,
                                 asset=host, endpoint=r.url))

    def cookies(self, ctx: ScanContext, host: str, responses: list[StoredResponse]) -> None:
        seen: set[str] = set()
        for r in responses:
            https = r.url.startswith("https://")
            for raw in r.header_list("set-cookie"):
                name, attrs = _cookie_attrs(raw)
                if name in seen or "max-age" in attrs and attrs["max-age"].lstrip("-") == "0":
                    continue
                seen.add(name)
                sensitive = bool(SESSION_COOKIE.search(name)) and not CSRF_COOKIE.search(name)
                if not sensitive:
                    continue
                missing = []
                if https and "secure" not in attrs:
                    missing.append("Secure")
                if "httponly" not in attrs:
                    missing.append("HttpOnly")
                ss = attrs.get("samesite", "").lower()
                if not ss:
                    missing.append("SameSite")
                elif ss == "none" and "secure" not in attrs:
                    missing.append("SameSite=None sin Secure")
                if missing:
                    ctx.add(FindingDraft(title=f"Cookie «{name}» sin {', '.join(missing)} ({host})", category="insecure_cookie",
                                         module=self.name, confidence="confirmed", native_evidence=True, asset=host,
                                         endpoint=r.url, parameter=name, tags=[f"cookie-missing:{m}" for m in missing],
                                         evidence={"set-cookie": f"{name}=****; " + "; ".join(
                                             f"{k}={v}" if v else k for k, v in attrs.items()), "faltan": missing}))

    def cache(self, ctx: ScanContext, host: str, responses: list[StoredResponse]) -> None:
        for r in responses:
            if r.identity == "default" and not r.header_list("set-cookie"):
                continue
            cc = r.header("cache-control").lower()
            if "html" in r.content_type or "json" in r.content_type:
                if "no-store" not in cc and "private" not in cc:
                    ctx.add(FindingDraft(title=f"Respuesta autenticada o con sesión almacenable en caché ({host})",
                                         category="cache_sensitive", module=self.name, confidence="confirmed",
                                         native_evidence=True, asset=host, endpoint=r.url,
                                         evidence={"cache-control": cc or None, "identidad": r.identity}))
                    return

    def mixed_content(self, ctx: ScanContext, host: str, pages: list[StoredResponse]) -> None:
        for r in pages[:50]:
            if not r.url.startswith("https://"):
                continue
            p = parse_html(r.text, r.url)
            if p.http_resources:
                ctx.add(FindingDraft(title=f"Contenido mixto en {urlsplit(r.url).path} ({host})", category="mixed_content",
                                     module=self.name, confidence="confirmed", native_evidence=True, asset=host,
                                     endpoint=r.url, evidence={"recursos_http": p.http_resources[:10]}))
                return

    async def cors(self, ctx: ScanContext, o: str, host: str) -> None:
        targets = [o + "/"] + [e.url for e in ctx.kb.api if origin(e.url) == o and e.method == "GET"][:5]
        for url in dict.fromkeys(targets):
            for test_origin, label in ((EVIL, "origen arbitrario"), ("null", "origen null"),
                                       (f"https://{host}.vigia-cors-check.example", "sufijo del dominio")):
                try:
                    r = await ctx.fetch(url, module=self.name, headers={"Origin": test_origin}, store=False)
                except (HttpError, ScopeViolation):
                    break
                acao = r.header("access-control-allow-origin")
                acac = r.header("access-control-allow-credentials").lower() == "true"
                if acao == test_origin:
                    ctx.add(FindingDraft(
                        title=f"CORS refleja un {label}{' con credenciales' if acac else ''} ({host})",
                        category="cors_misconfig", module=self.name, confidence="confirmed", native_evidence=True,
                        asset=host, endpoint=url, method="GET", parameter="Origin",
                        cvss_vector=None if acac else "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                        description="El servidor devuelve Access-Control-Allow-Origin igual al Origin enviado por el "
                                    "cliente" + (" y permite credenciales: un sitio malicioso puede leer respuestas "
                                                 "autenticadas." if acac else "."),
                        evidence={"request": f"GET {url}", "origin_enviado": test_origin,
                                  "access-control-allow-origin": acao, "access-control-allow-credentials": acac}))
                    return
                if acao == "*" and acac:
                    ctx.add(FindingDraft(title=f"CORS con comodín y credenciales ({host})", category="cors_misconfig",
                                         module=self.name, confidence="confirmed", native_evidence=True, asset=host,
                                         endpoint=url, severity="low", cvss_vector=None,
                                         evidence={"access-control-allow-origin": acao, "allow-credentials": acac}))
                    return

    async def errors(self, ctx: ScanContext, o: str, host: str) -> None:
        mark = canary()
        probes = [urljoin(o, f"/{mark}%ff%2e"), urljoin(o, f"/{mark}?id=%27%22%3E{mark}"), urljoin(o, f"/api/{mark}/%00")]
        for url in probes:  # verbose errors are detected and reported centrally by ScanContext.fetch
            try:
                r = await ctx.fetch(url, module=self.name, store=False)
            except (HttpError, ScopeViolation):
                continue
            if r.status < 400 and find_signature(r.text, ERROR_SIGNATURES):  # trace shown with a 2xx status
                ctx._error_page(r, self.name)

    async def methods(self, ctx: ScanContext, o: str, host: str) -> None:
        try:
            r = await ctx.fetch(o + "/", method="OPTIONS", module=self.name, store=False)
        except (HttpError, ScopeViolation):
            return
        allow = {m.strip().upper() for m in (r.header("allow") or r.header("access-control-allow-methods")).split(",")
                 if m.strip()}
        risky = sorted(allow & {"TRACE", "TRACK", "PUT", "DELETE", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE",
                                "CONNECT"})
        if risky and r.status < 400:
            ctx.add(FindingDraft(title=f"Métodos HTTP potencialmente peligrosos anunciados en {host}: {', '.join(risky)}",
                                 category="dangerous_methods", module=self.name, confidence="suspected",
                                 native_evidence=True, asset=host, endpoint=o + "/", method="OPTIONS",
                                 description="El servidor anuncia estos métodos en la respuesta a OPTIONS. Vigía no los "
                                             "invoca (política no destructiva); verifica si realmente están operativos.",
                                 evidence={"allow": sorted(allow)}))
