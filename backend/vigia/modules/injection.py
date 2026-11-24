"""M03 — Injection analysis with controlled, non-destructive payloads and differential verification.

Every confirmation requires Vigía's own evidence: a signature absent from the baseline, a computed value
only the injected expression can produce, a reproducible true/false difference, or a reproducible delay
compared with a zero-delay control. No data is ever extracted (no UNION, no table reads), delays are ≤ 3 s,
file reads target innocuous files only (/etc/os-release, win.ini).
"""
from __future__ import annotations

import asyncio
import json
import re
import secrets
import statistics
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlsplit

from vigia.core.context import ScanContext
from vigia.core.findings import FindingDraft, endpoint_template
from vigia.core.module import Module
from vigia.modules.common import SQL_ERRORS, canary, find_signature, query_params, similarity, strip_reflections, with_param
from vigia.security.http import HttpError, HttpResponse
from vigia.security.scope import ScopeViolation

UNSAFE_FORM = re.compile(r"delete|remove|destroy|drop|unsubscribe|deactivate|logout|transfer|pay|purchase|checkout|"
                         r"withdraw|reset", re.I)
FILE_PARAM = re.compile(r"file|path|page|template|include|inc|doc|document|folder|dir|download|lang|view|load|read|"
                        r"filename|style|layout|module|conf", re.I)
LOOKS_LIKE_PATH = re.compile(r"[/\\]|\.(txt|html?|pdf|php|jsp|aspx?|log|xml|json|ya?ml|ini|conf|md|csv)$", re.I)
CMD_PARAM = re.compile(r"cmd|exec|command|run|ping|host|ip|addr|domain|query|process|daemon|shell|arg|option", re.I)
NOSQL_ERR = [("MongoDB", re.compile(r"MongoError|MongoServerError|BSONTypeError|\$where|CastError: Cast to|"
                                    r"Unknown operator|unknown top level operator", re.I))]
LDAP_ERR = [("LDAP", re.compile(r"javax\.naming\.|LDAPException|Bad search filter|ldap_search\(|InvalidSearchFilter|"
                                r"Protocol error occurred|com\.sun\.jndi\.ldap", re.I))]
XPATH_ERR = [("XPath", re.compile(r"XPathException|Invalid predicate|SimpleXMLElement::xpath|XPathEvalError|"
                                  r"xmlXPathEval|Expression must evaluate to a node-set|System\.Xml\.XPath", re.I))]
TRAVERSAL = [("os-release", re.compile(r"(?m)^ID=[\w\"]+\s*$.*?^NAME=|^NAME=\".+?\"[\s\S]{0,400}^ID=", re.S | re.M)),
             ("win.ini", re.compile(r"\[fonts\]|; for 16-bit app support|\[extensions\]", re.I))]
LIMITS = {"passive": 0, "light": 15, "standard": 80, "deep": 300}


@dataclass
class Point:
    method: str
    url: str
    param: str
    location: str  # query | form | json
    params: dict[str, Any] = field(default_factory=dict)
    identity: str = "default"
    original: str = "1"
    source: str = ""

    @property
    def key(self) -> tuple[str, str, str]:
        return self.method, endpoint_template(self.url).split("?")[0], self.param


class InjectionModule(Module):
    name = "injection"
    title = "Inyecciones (SQL, NoSQL, comandos, SSTI, XSS, LDAP, XPath, CRLF, traversal)"
    phase = "analysis"
    needs_target = True

    async def run(self, ctx: ScanContext) -> None:
        points = self.collect(ctx)
        limit = LIMITS[ctx.cfg.intensity]
        points = points[:limit]
        ctx.emit("info", self.name, f"{len(points)} puntos de inyección seleccionados (límite {limit} para intensidad "
                 f"{ctx.cfg.intensity})")
        self.found: set[tuple[str, tuple]] = set()
        sem = asyncio.Semaphore(max(1, min(4, ctx.cfg.concurrency)))
        done = 0

        async def one(pt: Point) -> None:
            nonlocal done
            async with sem:
                try:
                    await self.test_point(ctx, pt)
                except (HttpError, ScopeViolation) as e:
                    ctx.emit("debug", self.name, f"Punto {pt.param}@{pt.url} interrumpido: {e}")
            done += 1
            ctx.progress(self.name, "running", int(90 * done / max(1, len(points))), detail=f"{done}/{len(points)} puntos")

        await asyncio.gather(*(one(p) for p in points))
        if ctx.cfg.at_least("standard"):
            await self.stored_xss(ctx)

    # ------------------------------------------------------------------ injection points
    def collect(self, ctx: ScanContext) -> list[Point]:
        pts: dict[tuple, Point] = {}
        for url in sorted(ctx.kb.urls):
            for name, val in query_params(url).items():
                p = Point("GET", url, name, "query", original=val or "1", source="crawl")
                pts.setdefault(p.key, p)
        for f in ctx.kb.forms:
            if f.method == "POST" and not ctx.cfg.at_least("standard"):
                continue
            if UNSAFE_FORM.search(f.action) or any(UNSAFE_FORM.search(k) for k in f.fields):
                continue
            for name, typ in f.field_types.items():
                if typ in ("hidden", "submit", "checkbox", "radio", "file", "password") or "csrf" in name.lower() or \
                        "token" in name.lower():
                    continue
                fields = {k: (v or self._default(f.field_types.get(k, "text"))) for k, v in f.fields.items()}
                p = Point(f.method, f.action, name, "query" if f.method == "GET" else "form", params=fields,
                          original=fields.get(name) or "vigia", source=f"form@{f.page}")
                pts.setdefault(p.key, p)
        for e in ctx.kb.api:
            if "{" in e.url:
                continue
            for prm in e.params:
                if prm.get("in") == "query" and e.method == "GET":
                    p = Point("GET", e.url, prm["name"], "query", original=str(prm.get("example") or "1"), source=e.source)
                    pts.setdefault(p.key, p)
            if e.method in ("POST", "PUT", "PATCH") and e.body_schema and ctx.cfg.at_least("standard") and \
                    (e.method == "POST" or ctx.lab_mode):
                props = e.body_schema.get("properties") or {}
                body = {k: self._schema_example(v) for k, v in props.items()}
                for k, v in props.items():
                    if isinstance(v, dict) and v.get("type", "string") == "string":
                        p = Point(e.method, e.url, k, "json", params=body, original=str(body[k]), source=e.source)
                        pts.setdefault(p.key, p)
        ordered = sorted(pts.values(), key=lambda p: (p.source.startswith("form") is False, p.location != "query"))
        return ordered

    @staticmethod
    def _default(typ: str) -> str:
        return {"email": "vigia@example.com", "number": "1", "tel": "600000000", "url": "https://example.com",
                "date": "2026-01-01"}.get(typ, "vigia")

    @staticmethod
    def _schema_example(s: Any) -> Any:
        if not isinstance(s, dict):
            return "vigia"
        if "example" in s:
            return s["example"]
        return {"integer": 1, "number": 1, "boolean": False, "array": [], "object": {}}.get(s.get("type", "string"),
                                                                                         "vigia")

    # ------------------------------------------------------------------ sending
    async def send(self, ctx: ScanContext, pt: Point, value: Any, raw_query: str | None = None) -> HttpResponse:
        if pt.location == "query":
            if raw_query is not None:
                base = with_param(pt.url, pt.param, "VIGIARAW").replace("VIGIARAW", raw_query)
                url = base
            else:
                url = pt.url
                for k, v in pt.params.items():
                    if k != pt.param:
                        url = with_param(url, k, str(v))
                url = with_param(url, pt.param, str(value))
            return await ctx.fetch(url, method="GET", identity=pt.identity, module=self.name, store=False)
        if pt.location == "form":
            data = dict(pt.params)
            data[pt.param] = value
            return await ctx.fetch(pt.url, method="POST", identity=pt.identity, module=self.name, store=False, data=data)
        body = json.loads(json.dumps(pt.params))
        body[pt.param] = value
        return await ctx.fetch(pt.url, method=pt.method, identity=pt.identity, module=self.name, store=False,
                               json_body=body)

    def report(self, ctx: ScanContext, pt: Point, category: str, title: str, *, confidence: str, desc: str,
               evidence: dict[str, Any], payload: str) -> None:
        key = (category, pt.key)
        if key in self.found:
            return
        self.found.add(key)
        ctx.add(FindingDraft(
            title=f"{title} en «{pt.param}» ({pt.method} {urlsplit(pt.url).path})", category=category, module=self.name,
            confidence=confidence, native_evidence=True, asset=urlsplit(pt.url).hostname or "", endpoint=pt.url,
            method=pt.method, parameter=pt.param, description=desc,
            evidence={"payload": payload, "ubicacion": pt.location, "origen_punto": pt.source, **evidence}))

    # ------------------------------------------------------------------ per-point battery
    async def test_point(self, ctx: ScanContext, pt: Point) -> None:
        ctx.check()
        b1 = await self.send(ctx, pt, pt.original)
        b2 = await self.send(ctx, pt, pt.original)
        stable = similarity(b1.text, b2.text) > 0.97
        base_text = b1.text
        mark = canary()
        refl = await self.send(ctx, pt, mark)
        reflected = mark in refl.text
        await self.sqli(ctx, pt, b1, stable)
        await self.ssti(ctx, pt, base_text)
        if reflected:
            await self.xss(ctx, pt, refl)
        await self.error_based(ctx, pt, base_text, "'\")]}{\\vigia", NOSQL_ERR, "nosqli", "Inyección NoSQL")
        await self.error_based(ctx, pt, base_text, "*)(|(objectClass=*", LDAP_ERR, "ldapi", "Inyección LDAP")
        await self.error_based(ctx, pt, base_text, "'\"]vigia[", XPATH_ERR, "xpathi", "Inyección XPath")
        if pt.location == "query":
            await self.crlf(ctx, pt)
            if ctx.cfg.at_least("standard"):
                await self.nosql_operator(ctx, pt, b1, stable)
        looks_like_path = bool(LOOKS_LIKE_PATH.search(str(pt.original)))
        if FILE_PARAM.search(pt.param) or looks_like_path or ctx.cfg.at_least("deep"):
            await self.traversal(ctx, pt, base_text)
        if ctx.cfg.at_least("standard") and (CMD_PARAM.search(pt.param) or ctx.cfg.at_least("deep")):
            await self.cmdi(ctx, pt, base_text)

    # ------------------------------------------------------------------ SQL injection
    async def sqli(self, ctx: ScanContext, pt: Point, base: HttpResponse, stable: bool) -> None:
        base_sig = find_signature(base.text, SQL_ERRORS)
        for payload in ("'", "\"", "')", "\\", "1'1"):
            r = await self.send(ctx, pt, pt.original + payload)
            sig = find_signature(r.text, SQL_ERRORS)
            if sig and not base_sig:
                # confirm: the error must disappear with a balanced quote (rules out generic error pages)
                ok = await self.send(ctx, pt, pt.original + payload + payload if payload in ("'", '"') else pt.original)
                if not find_signature(ok.text, SQL_ERRORS) or payload not in ("'", '"'):
                    self.report(ctx, pt, "sqli", f"Inyección SQL basada en errores ({sig[0]})", confidence="confirmed",
                                desc=f"Un carácter de cierre provoca un error de base de datos {sig[0]} que no aparece en la "
                                     "respuesta normal; con la comilla equilibrada el error desaparece.",
                                evidence={"error": sig[1][:600], "status": r.status}, payload=payload)
                    return
        if stable:
            numeric = re.fullmatch(r"-?\d+", pt.original or "") is not None
            pairs = [(f"{pt.original}' AND '7'='7", f"{pt.original}' AND '7'='8")]
            if numeric:
                pairs.insert(0, (f"{pt.original} AND 7=7", f"{pt.original} AND 7=8"))
            pairs.append((f"{pt.original}\" AND \"7\"=\"7", f"{pt.original}\" AND \"7\"=\"8"))
            for t, f in pairs:
                rt = await self.send(ctx, pt, t)
                rf = await self.send(ctx, pt, f)
                st = similarity(strip_reflections(rt.text, t), strip_reflections(base.text, pt.original))
                sf = similarity(strip_reflections(rf.text, f), strip_reflections(base.text, pt.original))
                if st > 0.95 and sf < 0.85 and rt.status == base.status:
                    rt2 = await self.send(ctx, pt, t)
                    rf2 = await self.send(ctx, pt, f)
                    if similarity(rt2.text, rt.text) > 0.95 and similarity(rf2.text, rf.text) > 0.95:
                        self.report(ctx, pt, "sqli", "Inyección SQL ciega booleana", confidence="confirmed",
                                    desc="Una condición verdadera reproduce la respuesta original y una falsa la cambia de "
                                         "forma estable (verificado dos veces).",
                                    evidence={"similitud_verdadera": round(st, 3), "similitud_falsa": round(sf, 3),
                                              "condicion_falsa": f, "estados": [rt.status, rf.status]}, payload=t)
                        return
        if ctx.cfg.at_least("deep"):
            await self.sqli_time(ctx, pt)

    async def _timed(self, ctx: ScanContext, pt: Point, value: str) -> float:
        t0 = time.monotonic()
        try:
            await self.send(ctx, pt, value)
        except HttpError:
            return 99.0
        return time.monotonic() - t0

    async def sqli_time(self, ctx: ScanContext, pt: Point) -> None:
        o = pt.original
        variants = [  # nosec B608 vigia:ignore - estos son payloads de prueba, no consultas que Vigía ejecuta
            ("MySQL/MariaDB", f"{o}' AND SLEEP(3)-- -", f"{o}' AND SLEEP(0)-- -"),  # nosec B608 vigia:ignore
            ("MySQL/MariaDB (numérico)", f"{o} AND SLEEP(3)", f"{o} AND SLEEP(0)"),  # nosec B608 vigia:ignore
            ("PostgreSQL", f"{o}' AND 1=(SELECT 1 FROM PG_SLEEP(3))-- -",  # nosec B608 vigia:ignore
             f"{o}' AND 1=(SELECT 1 FROM PG_SLEEP(0))-- -"),  # nosec B608 vigia:ignore
            ("SQL Server", f"{o}'; WAITFOR DELAY '0:0:3'-- -", f"{o}'; WAITFOR DELAY '0:0:0'-- -")]  # nosec B608 vigia:ignore
        base = statistics.median([await self._timed(ctx, pt, o) for _ in range(3)])
        if base > 5:
            return
        for dbms, slow, fast in variants:
            t_slow = await self._timed(ctx, pt, slow)
            if t_slow < base + 2.5 or t_slow > 30:
                continue
            t_fast = await self._timed(ctx, pt, fast)
            t_slow2 = await self._timed(ctx, pt, slow)
            if t_fast < base + 1.0 and t_slow2 >= base + 2.5:
                self.report(ctx, pt, "sqli", f"Inyección SQL ciega por tiempo ({dbms})", confidence="confirmed",
                            desc="La consulta con una espera de 3 s retrasa la respuesta de forma reproducible y la misma "
                                 "consulta con espera 0 no lo hace.",
                            evidence={"tiempo_base_s": round(base, 2), "tiempo_espera3_s": [round(t_slow, 2),
                                                                                           round(t_slow2, 2)],
                                      "tiempo_espera0_s": round(t_fast, 2)}, payload=slow)
                return

    # ------------------------------------------------------------------ SSTI
    async def ssti(self, ctx: ScanContext, pt: Point, base_text: str) -> None:
        a, b = 1000 + secrets.randbelow(9000), 1000 + secrets.randbelow(9000)
        product = str(a * b)
        if product in base_text:
            return
        for engine, payload in (("Jinja2/Twig/Nunjucks", f"{{{{{a}*{b}}}}}"), ("Freemarker/EL/Thymeleaf", f"${{{a}*{b}}}"),
                                ("ERB/EJS", f"<%= {a}*{b} %>"), ("Ruby/Slim", f"#{{{a}*{b}}}"),
                                ("Razor", f"@({a}*{b})"), ("Smarty", f"{{{a}*{b}}}")):
            r = await self.send(ctx, pt, payload)
            if product in r.text and payload not in r.text:
                self.report(ctx, pt, "ssti", f"Inyección de plantillas en servidor ({engine})", confidence="confirmed",
                            desc=f"La expresión {payload} se evaluó en el servidor y la respuesta contiene su resultado "
                                 f"({product}), que no aparece en la respuesta normal.",
                            evidence={"resultado_esperado": product, "status": r.status,
                                      "extracto": r.text[max(0, r.text.find(product) - 120): r.text.find(product) + 120]},
                            payload=payload)
                return

    # ------------------------------------------------------------------ XSS
    async def xss(self, ctx: ScanContext, pt: Point, refl: HttpResponse) -> None:
        if "html" not in refl.content_type:
            return
        m1, m2 = canary(), canary()
        probe = f"{m1}'\"><{m2} x=1>"
        r = await self.send(ctx, pt, probe)
        if f"<{m2} x=1>" in r.text:
            handler = f"\"><{m2} onmouseover={m1}>"
            r2 = await self.send(ctx, pt, handler)
            if f"<{m2} onmouseover={m1}>" in r2.text:
                csp = r2.header("content-security-policy")
                stored = pt.location == "form" and bool(r2.redirects)  # shown on the page we were redirected to
                self.report(ctx, pt, "xss_stored" if stored else "xss_reflected",
                            "Cross-Site Scripting almacenado" if stored else "Cross-Site Scripting reflejado",
                            confidence="confirmed",
                            desc=("El valor enviado se guarda y se muestra sin codificar en la página de destino "
                                  f"({r2.url}), permitiendo inyectar etiquetas con manejadores de eventos." if stored else
                                  "El valor se refleja sin codificar en HTML y permite inyectar etiquetas con manejadores de "
                                  "eventos.") + (" Hay CSP; su eficacia se evalúa por separado." if csp else ""),
                            evidence={"reflejo": r2.text[max(0, r2.text.find(m2) - 150): r2.text.find(m2) + 150],
                                      "status": r2.status, "csp": csp or None}, payload=handler)
            else:
                self.report(ctx, pt, "html_injection", "Inyección de HTML", confidence="confirmed",
                            desc="Se pueden inyectar etiquetas HTML arbitrarias; los manejadores de eventos parecen filtrarse.",
                            evidence={"reflejo": r.text[max(0, r.text.find(m2) - 150): r.text.find(m2) + 150]},
                            payload=probe)
            return
        idx = r.text.find(m1)
        if idx >= 0:
            window = r.text[max(0, idx - 300): idx + 60]
            in_script = window.rfind("<script") > window.rfind("</script")
            if in_script and (f"{m1}'" in r.text or f'{m1}"' in r.text):
                self.report(ctx, pt, "xss_reflected", "XSS reflejado en contexto JavaScript", confidence="likely",
                            desc="El valor se refleja dentro de un bloque <script> sin escapar comillas, lo que permite "
                                 "romper la cadena y ejecutar código.",
                            evidence={"reflejo": window[-200:]}, payload=probe)
            elif re.search(rf"=\s*[\"'][^\"'<>]*{m1}'\"", r.text):
                self.report(ctx, pt, "xss_reflected", "XSS reflejado en atributo HTML", confidence="likely",
                            desc="El valor se refleja dentro de un atributo sin escapar las comillas.",
                            evidence={"reflejo": window[-200:]}, payload=probe)

    async def stored_xss(self, ctx: ScanContext) -> None:
        """Submit inert canaries through POST forms, then look for them unescaped on re-fetched pages."""
        forms = [f for f in ctx.kb.forms if f.method == "POST" and not UNSAFE_FORM.search(f.action)
                 and "password" not in f.field_types.values()][:10]
        planted: dict[str, Any] = {}
        for f in forms:
            text_fields = [k for k, t in f.field_types.items() if t in ("text", "textarea", "search", "email")
                           and "csrf" not in k.lower()]
            if not text_fields:
                continue
            m = canary()
            data = {k: (v or self._default(f.field_types.get(k, "text"))) for k, v in f.fields.items()}
            for k in text_fields:
                data[k] = f"{m}<{m}s>" if f.field_types[k] != "email" else f"{m}@example.com"
            try:
                await ctx.fetch(f.action, method="POST", data=data, module=self.name, store=False)
                planted[m] = f
            except (HttpError, ScopeViolation):
                continue
        if not planted:
            return
        pages = list(dict.fromkeys([f.page for f in planted.values()] + [f.action for f in planted.values()]))[:20]
        for url in pages:
            try:
                r = await ctx.fetch(url, module=self.name, store=False)
            except (HttpError, ScopeViolation):
                continue
            for m, f in planted.items():
                if f"<{m}s>" in r.text:
                    pt = Point("POST", f.action, "/".join(k for k, t in f.field_types.items() if t in ("text", "textarea")),
                               "form", source=f"form@{f.page}")
                    self.report(ctx, pt, "xss_stored", "Cross-Site Scripting almacenado", confidence="confirmed",
                                desc=f"Un canario enviado por el formulario reaparece sin codificar en {url}.",
                                evidence={"pagina": url, "reflejo": r.text[max(0, r.text.find(m) - 150):
                                                                           r.text.find(m) + 150]},
                                payload=f"{m}<{m}s>")

    # ------------------------------------------------------------------ error-based (NoSQL/LDAP/XPath)
    async def error_based(self, ctx: ScanContext, pt: Point, base_text: str, payload: str, sigs, category: str,
                          title: str) -> None:  # noqa: ANN001
        if find_signature(base_text, sigs):
            return
        r = await self.send(ctx, pt, pt.original + payload)
        sig = find_signature(r.text, sigs)
        if sig:
            self.report(ctx, pt, category, f"{title} (error del motor)", confidence="confirmed",
                        desc=f"Caracteres especiales provocan un error de {sig[0]} ausente en la respuesta normal.",
                        evidence={"error": sig[1][:600], "status": r.status}, payload=payload)

    async def nosql_operator(self, ctx: ScanContext, pt: Point, base: HttpResponse, stable: bool) -> None:
        if not stable:
            return
        wrong = await self.send(ctx, pt, canary())
        raw = f"{quote(pt.param)}%5B%24ne%5D={quote(canary())}"
        url = pt.url.split("?")[0] + "?" + raw
        for k, v in query_params(pt.url).items():
            if k != pt.param:
                url += f"&{quote(k)}={quote(v)}"
        try:
            r = await ctx.fetch(url, identity=pt.identity, module=self.name, store=False)
        except (HttpError, ScopeViolation):
            return
        same_as_base = similarity(r.text, base.text) > 0.95
        superset = len(r.content) > len(base.content) * 1.2 and len(r.content) > len(wrong.content) * 1.2
        if (same_as_base or superset) and similarity(r.text, wrong.text) < 0.85 and r.status == base.status:
            self.report(ctx, pt, "nosqli", "Inyección NoSQL por operadores ($ne)", confidence="likely",
                        desc="Con un valor incorrecto la respuesta cambia, pero con el operador $ne y el mismo valor "
                             "incorrecto se obtiene la respuesta original o un superconjunto de resultados: el "
                             "operador se interpreta en la consulta.",
                        evidence={"similitud_operador": round(similarity(r.text, base.text), 3),
                                  "similitud_valor_incorrecto": round(similarity(wrong.text, base.text), 3)},
                        payload=f"{pt.param}[$ne]=…")

    # ------------------------------------------------------------------ CRLF
    async def crlf(self, ctx: ScanContext, pt: Point) -> None:
        m = canary()
        for enc in ("%0d%0a", "%0a", "%E5%98%8A%E5%98%8D"):
            try:
                r = await self.send(ctx, pt, None, raw_query=f"vigia{enc}X-Vigia-Injected:%20{m}")
            except (HttpError, ScopeViolation):
                return
            if r.header("x-vigia-injected") == m:
                self.report(ctx, pt, "crlf_injection", "Inyección CRLF (cabeceras de respuesta)", confidence="confirmed",
                            desc="Los saltos de línea del parámetro se copian a las cabeceras de respuesta y permiten "
                                 "añadir cabeceras arbitrarias.",
                            evidence={"cabecera_inyectada": f"X-Vigia-Injected: {m}", "status": r.status},
                            payload=f"vigia{enc}X-Vigia-Injected: {m}")
                return

    # ------------------------------------------------------------------ path traversal
    async def traversal(self, ctx: ScanContext, pt: Point, base_text: str) -> None:
        if any(rx.search(base_text) for _, rx in TRAVERSAL):
            return
        payloads = ["../" * 8 + "etc/os-release", "..%2f" * 8 + "etc%2fos-release", "....//" * 8 + "etc/os-release",
                    "/etc/os-release", "..\\" * 8 + "windows\\win.ini", "/../" * 6 + "windows/win.ini",
                    "C:\\Windows\\win.ini"]
        for p in payloads:
            if "%2f" in p and pt.location == "query":
                r = await self.send(ctx, pt, None, raw_query=p)  # keep the encoding exactly as written
            else:
                r = await self.send(ctx, pt, p)
            for fname, rx in TRAVERSAL:
                m = rx.search(r.text)
                if m:
                    self.report(ctx, pt, "path_traversal", f"Path traversal (lectura de {fname})", confidence="confirmed",
                                desc=f"El parámetro permite leer ficheros fuera del directorio previsto; se leyó el fichero "
                                     f"inocuo {fname} como prueba y no se accedió a ningún otro.",
                                evidence={"fichero": fname, "extracto": r.text[m.start(): m.start() + 160]}, payload=p)
                    return

    # ------------------------------------------------------------------ OS command injection
    async def cmdi(self, ctx: ScanContext, pt: Point, base_text: str) -> None:
        a, b = 100 + secrets.randbelow(900), 100 + secrets.randbelow(900)
        m = canary()
        expect = f"{m}{a * b}"
        if expect in base_text:
            return
        for sep in (";", "|", "&&", "\n", "`", "$("):
            if sep == "`":
                payload = f"{pt.original}`echo {m}$(({a}*{b}))`"
            elif sep == "$(":
                payload = f"{pt.original}$(echo {m}$(({a}*{b})))"
            else:
                payload = f"{pt.original}{sep}echo {m}$(({a}*{b})){sep if sep != chr(10) else ''}"
            r = await self.send(ctx, pt, payload)
            if expect in r.text:
                self.report(ctx, pt, "cmdi", "Inyección de comandos del sistema operativo", confidence="confirmed",
                            desc=f"El shell del servidor evaluó la aritmética {a}*{b} inyectada y la respuesta contiene el "
                                 "resultado junto al canario.",
                            evidence={"esperado": expect, "status": r.status}, payload=payload)
                return
        if not ctx.cfg.at_least("deep"):
            return
        base = statistics.median([await self._timed(ctx, pt, pt.original) for _ in range(3)])
        if base > 5:
            return
        for slow, fast in ((f"{pt.original};sleep 3;", f"{pt.original};sleep 0;"),
                           (f"{pt.original}|sleep 3", f"{pt.original}|sleep 0"),
                           (f"{pt.original}$(sleep 3)", f"{pt.original}$(sleep 0)"),
                           (f"{pt.original}&ping -n 4 127.0.0.1&", f"{pt.original}&ping -n 1 127.0.0.1&")):
            t1 = await self._timed(ctx, pt, slow)
            if t1 < base + 2.5 or t1 > 30:
                continue
            t0 = await self._timed(ctx, pt, fast)
            t2 = await self._timed(ctx, pt, slow)
            if t0 < base + 1.0 and t2 >= base + 2.5:
                self.report(ctx, pt, "cmdi", "Inyección de comandos ciega por tiempo", confidence="confirmed",
                            desc="Una espera de 3 s inyectada retrasa la respuesta de forma reproducible; la espera 0 no.",
                            evidence={"tiempo_base_s": round(base, 2), "espera3_s": [round(t1, 2), round(t2, 2)],
                                      "espera0_s": round(t0, 2)}, payload=slow)
                return
