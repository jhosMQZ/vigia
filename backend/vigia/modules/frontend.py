# vigia:ignore-file — catálogo de patrones de detección (las expresiones regulares se detectarían a sí mismas)
"""M04 — Frontend and served JavaScript: secrets, DOM sinks, token storage, vulnerable libraries, internal info."""
from __future__ import annotations

import asyncio
import math
import re
from collections import Counter, defaultdict
from urllib.parse import urlsplit

from vigia.config import get_settings
from vigia.core.context import ScanContext
from vigia.core.findings import FindingDraft
from vigia.core.module import Module
from vigia.correlation import intel
from vigia.modules.common import parse_html
from vigia.security.redact import mask

# (name, regex, severity, public_by_design)
SECRET_RULES: list[tuple[str, re.Pattern[str], str, bool]] = [
    ("Clave de acceso AWS", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "high", False),
    ("Clave secreta de Stripe", re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b"), "critical", False),
    ("Clave restringida de Stripe", re.compile(r"\brk_live_[0-9a-zA-Z]{20,}\b"), "high", False),
    ("Token de GitHub", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"), "critical", False),
    ("Token de GitLab", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"), "critical", False),
    ("Token de Slack", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"), "high", False),
    ("Webhook de Slack", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"), "medium", False),
    ("Clave privada", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----\s*[A-Za-z0-9+/=\r\n]{64,}"),
     "critical", False),
    ("Clave de API de OpenAI/Anthropic", re.compile(r"\bsk-(?:proj-|ant-api\d\d-)?[A-Za-z0-9_\-]{32,}\b"), "critical", False),
    ("Clave de SendGrid", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), "high", False),
    ("Clave de Twilio", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "high", False),
    ("Token de Mailgun", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"), "high", False),
    ("Credenciales en URL", re.compile(r"\b[a-z][a-z0-9+.\-]*://[^/\s:@'\"]{2,}:[^/\s:@'\"]{3,}@[\w.\-]+"), "high", False),
    ("Clave de Google API", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "low", True),
    ("Clave publicable de Stripe", re.compile(r"\bpk_live_[0-9a-zA-Z]{20,}\b"), "info", True),
]
GENERIC_SECRET = re.compile(r"""(?i)["']?(api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|auth[_-]?token|"""
                            r"""password|passwd|private[_-]?key)["']?\s*[:=]\s*["']([A-Za-z0-9_\-+/=.]{16,})["']""")
DOM_SOURCES = re.compile(r"location\.(?:hash|search|href)|document\.(?:URL|documentURI|referrer|baseURI)|window\.name|"
                         r"event\.data|e\.data|URLSearchParams|location\b(?!\.(?:reload|replace|assign))")
DOM_SINKS = re.compile(r"\.innerHTML\s*[+]?=|\.outerHTML\s*=|document\.write(?:ln)?\(|\.insertAdjacentHTML\(|"
                       r"\beval\(|new Function\(|setTimeout\(\s*[\"'`]|setInterval\(\s*[\"'`]|\.html\(\s*[^)]|"
                       r"dangerouslySetInnerHTML|v-html|\$sce\.trustAsHtml|bypassSecurityTrust\w+\(")
TOKEN_STORAGE = re.compile(r"(?:local|session)Storage\.setItem\(\s*['\"`]([\w.\-]*(?:token|jwt|auth|session|bearer|"
                           r"access|refresh|credential)[\w.\-]*)['\"`]", re.I)
COOKIE_WRITE = re.compile(r"document\.cookie\s*=\s*[^;]*?(token|jwt|session|auth)", re.I)
INTERNAL = re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b|"
                      r"\b[\w.-]+\.(?:internal|intranet|corp|local|lan)\b|\blocalhost:\d{2,5}\b|"
                      r"https?://[\w.-]*(?:staging|stage|dev|test|qa|uat)[\w.-]*\.[a-z]{2,}", re.I)
CLIENT_AUTH = re.compile(r"(?:role|user\.role|isAdmin|is_admin|userType)\s*(?:===?|!==?)\s*['\"](?:admin|superuser|root)['\"]|"
                         r"(?:local|session)Storage\.getItem\(\s*['\"](?:role|isAdmin|is_admin|permissions)['\"]", re.I)
LIBS: list[tuple[str, re.Pattern[str]]] = [
    ("jquery", re.compile(r"jQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+)|jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js")),
    ("jquery-ui", re.compile(r"jQuery UI - v(\d+\.\d+\.\d+)")),
    ("bootstrap", re.compile(r"Bootstrap v(\d+\.\d+\.\d+)|bootstrap[.-](\d+\.\d+\.\d+)(?:\.min)?\.js")),
    ("angular", re.compile(r"AngularJS v(\d+\.\d+\.\d+)|angular[.-](1\.\d+\.\d+)(?:\.min)?\.js")),
    ("lodash", re.compile(r"lodash(?:\.min)?\.js.{0,240}?(\d+\.\d+\.\d+)|@license\s+Lodash (?:lodash\.com/license )?.{0,240}?(\d+\.\d+\.\d+)|"
                          r"var VERSION\s*=\s*['\"](4\.\d+\.\d+)['\"]")),
    ("moment", re.compile(r"//! moment\.js\s*\n//! version : (\d+\.\d+\.\d+)|moment[.-](\d+\.\d+\.\d+)")),
    ("handlebars", re.compile(r"handlebars v(\d+\.\d+\.\d+)|Handlebars\.VERSION\s*=\s*['\"](\d+\.\d+\.\d+)")),
    ("vue", re.compile(r"Vue\.js v(\d+\.\d+\.\d+)|vue@(\d+\.\d+\.\d+)")),
    ("react-dom", re.compile(r"react-dom\.(?:production|development)\.min\.js.{0,240}?(\d+\.\d+\.\d+)|ReactDOM.*?version:\s*['\"](\d+\.\d+\.\d+)")),
    ("dompurify", re.compile(r"DOMPurify (\d+\.\d+\.\d+)|purify\.js.{0,240}?(\d+\.\d+\.\d+)")),
    ("axios", re.compile(r"axios v(\d+\.\d+\.\d+)|axios/(\d+\.\d+\.\d+)")),
    ("underscore", re.compile(r"Underscore\.js (\d+\.\d+\.\d+)")),
    ("knockout", re.compile(r"Knockout JavaScript library v(\d+\.\d+\.\d+)")),
    ("prototype", re.compile(r"Prototype JavaScript framework, version (\d+\.\d+\.\d+)")),
    ("swiper", re.compile(r"Swiper (\d+\.\d+\.\d+)")),
    ("chart.js", re.compile(r"Chart\.js v(\d+\.\d+\.\d+)")),
]


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


class FrontendModule(Module):
    name = "frontend"
    title = "Seguridad frontend y JavaScript"
    phase = "analysis"
    needs_target = True

    async def run(self, ctx: ScanContext) -> None:
        sources: list[tuple[str, str]] = []
        for url in sorted(ctx.kb.scripts)[:200]:
            sr = ctx.kb.responses.items.get(url)
            if sr is None:
                try:
                    r = await ctx.fetch(url, module=self.name)
                    sr = ctx.kb.responses.items.get(r.url)
                except Exception:  # noqa: BLE001
                    continue
            if sr is not None and sr.body:
                sources.append((url, sr.text))
        for page in ctx.kb.responses.html_pages()[:150]:
            p = parse_html(page.text, page.url)
            for i, js in enumerate(p.inline_scripts):
                if js.strip():
                    sources.append((f"{page.url}#inline-{i}", js))
        ctx.emit("info", self.name, f"Analizando {len(sources)} scripts (externos e inline)")
        libs: dict[tuple[str, str], str] = {}
        dom_by_file: dict[str, list[str]] = defaultdict(list)
        for url, js in sources:
            ctx.check()
            self.secrets(ctx, url, js)
            self.dom(ctx, url, js, dom_by_file)
            self.storage(ctx, url, js)
            self.internal(ctx, url, js)
            for name, rx in LIBS:
                m = rx.search(js[:400_000])
                if m:
                    ver = next((g for g in m.groups() if g), None)
                    if ver:
                        libs.setdefault((name, ver), url)
        for f, sinks in dom_by_file.items():
            ctx.add(FindingDraft(title=f"Sumideros DOM peligrosos en {urlsplit(f).path.rsplit('/', 1)[-1] or f}",
                                 category="js_dom_sink", module=self.name, confidence="suspected", native_evidence=True,
                                 asset=urlsplit(f).hostname or "", endpoint=f.split("#")[0],
                                 description="Se usan APIs que interpretan HTML/JS (" + ", ".join(sorted(set(sinks))[:6]) +
                                             "). Sin una fuente controlable cercana no es explotable por sí mismo.",
                                 evidence={"sumideros": sorted(set(sinks))[:10]}))
        await self.vulnerable_libs(ctx, libs)

    def secrets(self, ctx: ScanContext, url: str, js: str) -> None:
        host = urlsplit(url).hostname or ""
        for name, rx, sev, public in SECRET_RULES:
            for m in list(rx.finditer(js))[:3]:
                val = m.group(0)
                ctx.add(FindingDraft(
                    title=f"{name} en JavaScript servido ({urlsplit(url).path.rsplit('/', 1)[-1] or url})",
                    category="js_secret", module=self.name, confidence="confirmed" if not public else "likely",
                    native_evidence=True, asset=host, endpoint=url.split("#")[0], severity=sev,
                    cvss_vector=None if sev in ("info", "low") else
                    {"critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", "high": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                     "medium": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"}[sev],
                    description=("Clave pública por diseño; verifica que está restringida por dominio/API en el proveedor."
                                 if public else "Credencial utilizable por cualquier visitante."),
                    evidence={"tipo": name, "valor_redactado": mask(val, 6),
                              "contexto": js[max(0, m.start() - 60): m.start()].strip()[-60:]},
                    fingerprint_extra=mask(val, 8)))
        for m in list(GENERIC_SECRET.finditer(js))[:5]:
            val = m.group(2)
            if entropy(val) < 3.5 or re.fullmatch(r"[a-z_]+|[A-Z_]+|\d+", val) or "your" in val.lower():
                continue
            ctx.add(FindingDraft(title=f"Posible secreto «{m.group(1)}» en JavaScript servido", category="js_secret",
                                 module=self.name, confidence="suspected", native_evidence=True, asset=host,
                                 endpoint=url.split("#")[0], severity="medium",
                                 cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                                 evidence={"clave": m.group(1), "valor_redactado": mask(val, 4),
                                           "entropia": round(entropy(val), 2)}, fingerprint_extra=mask(val, 6)))

    def dom(self, ctx: ScanContext, url: str, js: str, by_file: dict[str, list[str]]) -> None:
        for m in DOM_SINKS.finditer(js[:500_000]):
            window = js[max(0, m.start() - 250): m.end() + 250]
            src = DOM_SOURCES.search(window)
            if src:
                ctx.add(FindingDraft(
                    title=f"Posible DOM XSS: {src.group(0)} → {m.group(0).strip()[:30]}", category="xss_dom",
                    module=self.name, confidence="suspected", native_evidence=True, asset=urlsplit(url).hostname or "",
                    endpoint=url.split("#")[0],
                    description="Una fuente controlable por el atacante aparece junto a un sumidero que interpreta HTML/JS. "
                                "El análisis es estático: confirma el flujo en el navegador.",
                    evidence={"fuente": src.group(0), "sumidero": m.group(0).strip()[:40],
                              "fragmento": window.strip()[:400]}, fingerprint_extra=f"{src.group(0)}|{m.group(0)[:20]}"))
                return
            by_file[url].append(m.group(0).strip()[:30])

    def storage(self, ctx: ScanContext, url: str, js: str) -> None:
        m = TOKEN_STORAGE.search(js) or COOKIE_WRITE.search(js)
        if m:
            ctx.add(FindingDraft(title=f"Tokens de sesión en almacenamiento accesible desde JavaScript ({m.group(1)})",
                                 category="js_token_storage", module=self.name, confidence="likely", native_evidence=True,
                                 asset=urlsplit(url).hostname or "", endpoint=url.split("#")[0],
                                 evidence={"fragmento": js[max(0, m.start() - 80): m.end() + 40].strip()[:240]}))
        c = CLIENT_AUTH.search(js)
        if c:
            ctx.add(FindingDraft(title="Comprobación de rol/autorización en el cliente", category="js_client_auth",
                                 module=self.name, confidence="suspected", native_evidence=True,
                                 asset=urlsplit(url).hostname or "", endpoint=url.split("#")[0],
                                 evidence={"fragmento": js[max(0, c.start() - 80): c.end() + 40].strip()[:240]}))

    def internal(self, ctx: ScanContext, url: str, js: str) -> None:
        hits = sorted({m.group(0) for m in INTERNAL.finditer(js[:500_000])})
        hits = [h for h in hits if not h.startswith("10.0.0.0") and "example" not in h][:10]
        if hits:
            ctx.add(FindingDraft(title=f"Información interna en JavaScript ({urlsplit(url).path.rsplit('/', 1)[-1]})",
                                 category="js_internal_info", module=self.name, severity="info", confidence="confirmed",
                                 native_evidence=True, asset=urlsplit(url).hostname or "", endpoint=url.split("#")[0],
                                 evidence={"referencias": hits}))

    async def vulnerable_libs(self, ctx: ScanContext, libs: dict[tuple[str, str], str]) -> None:
        if not libs:
            return
        for (name, ver), url in libs.items():
            ctx.kb.dependencies.append({"ecosystem": "npm", "name": name, "version": ver, "file": url, "source": "served-js"})
        if get_settings().offline:
            ctx.emit("info", self.name, f"Librerías detectadas: {len(libs)} (modo offline: sin consulta de vulnerabilidades)")
            return
        try:
            res = await asyncio.to_thread(intel.osv_query, [{"ecosystem": "npm", "name": n, "version": v}
                                                            for (n, v) in libs])
        except Exception as e:  # noqa: BLE001
            ctx.emit("warn", self.name, f"OSV no disponible: {e}")
            return
        for (name, ver), url in libs.items():
            vulns = res.get(("npm", name, ver), [])
            if not vulns:
                continue
            cves = sorted({a for v in vulns for a in v.get("aliases", []) if a.startswith("CVE-")})
            vector = next((v["cvss_vector"] for v in vulns if v.get("cvss_vector", "") and
                           str(v["cvss_vector"]).startswith("CVSS:3")), None)
            fixed = sorted({f for v in vulns for f in v.get("fixed", [])})
            ctx.add(FindingDraft(
                title=f"{name} {ver} con {len(vulns)} vulnerabilidad(es) conocida(s)", category="js_vulnerable_library",
                module=self.name, confidence="likely", native_evidence=True, asset=urlsplit(url).hostname or "",
                endpoint=url, cve=cves[:20], cvss_vector=vector,
                description="; ".join(f"{v['id']}: {v['summary'][:120]}" for v in vulns[:5]),
                recommendation=f"Actualiza {name} a una versión corregida" + (f" (≥ {fixed[-1]})." if fixed else "."),
                evidence={"libreria": name, "version": ver, "avisos": [v["id"] for v in vulns][:20], "corregido_en": fixed[:5]},
                references=[r for v in vulns[:3] for r in v.get("references", [])[:2]], fingerprint_extra=f"{name}@{ver}"))
