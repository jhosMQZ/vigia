"""M09 (dynamic) — headless-browser crawling and execution-based DOM XSS, in an ephemeral isolated browser.

Runs only when Playwright and Chromium are available and the intensity is at least standard. It renders
in-scope pages with JavaScript (so single-page apps and client-side routes are discovered), feeds the
links, forms, scripts and XHR/fetch endpoints back to the knowledge base, and verifies DOM/reflected XSS
by actually executing a payload in the page (a confirmed finding, with Vigía's own evidence).
"""
from __future__ import annotations

from urllib.parse import urlsplit

from vigia.config import get_settings
from vigia.core.context import ApiEndpoint, Form, ScanContext
from vigia.core.findings import FindingDraft, endpoint_template
from vigia.core.module import Module
from vigia.modules.common import canary, query_params, same_doc
from vigia.tools.browser import BrowserEngine, availability


class BrowserModule(Module):
    name = "browser"
    title = "Rastreo con navegador y DOM XSS (DAST dinámico)"
    phase = "discovery"
    needs_target = True

    def applicable(self, ctx: ScanContext) -> str | None:
        base = super().applicable(ctx)
        if base:
            return base
        if not get_settings().browser_enabled:
            return "navegador desactivado (VIGIA_BROWSER_ENABLED=false)"
        if not ctx.cfg.at_least("standard"):
            return "requiere intensidad ≥ standard"
        ok, reason = availability()
        if not ok:
            return reason
        return None

    async def run(self, ctx: ScanContext) -> None:
        assert ctx.guard is not None
        max_pages = min(max(ctx.cfg.crawl_max_pages, 10), 40)
        seeds = list(dict.fromkeys(ctx.kb.base_urls + sorted(ctx.kb.login_urls)))
        rendered = 0
        candidates: list[tuple[str, str]] = []  # (url, param) that reflect our marker
        workdir = ctx.runner.new_workdir("browser")
        ctx.emit("info", self.name, "Lanzando navegador efímero aislado (sin cookies ni perfil personal)")
        try:
            async with BrowserEngine(ctx.guard, workdir, proxy=ctx.gateway.http_url if ctx.gateway else None,
                                     verify_tls=get_settings().http_verify_tls, netwatch=ctx.netwatch,
                                     isolate=ctx.isolated) as br:
                queue = list(seeds)
                seen: set[str] = set()
                while queue and rendered < max_pages:
                    ctx.check()
                    url = queue.pop(0)
                    if url in seen:
                        continue
                    seen.add(url)
                    data = await br.render(url)
                    rendered += 1
                    ctx.progress(self.name, "running", int(70 * rendered / max_pages), detail=f"{rendered} páginas")
                    if not data:
                        continue
                    ctx.kb.urls.add(data.get("url") or url)
                    for link in data.get("links") or []:
                        if not link:
                            continue
                        link = same_doc(link)
                        host = urlsplit(link).hostname or ""
                        if ctx.guard.host_matches(host) and not ctx.guard.is_excluded(host, urlsplit(link).path or "/", link):
                            if link not in ctx.kb.urls and len(seen) + len(queue) < max_pages * 3:
                                queue.append(link)
                            ctx.kb.urls.add(link)
                            for p in query_params(link):
                                candidates.append((link, p))
                    for s in data.get("scripts") or []:
                        if s and ctx.guard.host_matches(urlsplit(s).hostname or ""):
                            ctx.kb.scripts.add(same_doc(s))
                    for f in data.get("forms") or []:
                        self._add_form(ctx, f)
                    for x in data.get("xhr") or []:
                        self._add_api(ctx, x.get("method", "GET"), x.get("url", ""))
                ctx.emit("info", self.name, f"Navegador: {rendered} páginas renderizadas, {len(ctx.kb.api)} endpoints "
                         f"XHR/fetch, {len(candidates)} parámetros reflejados candidatos")
                if ctx.cfg.at_least("standard"):
                    await self._dom_xss(ctx, br, candidates)
                if br.blocked:
                    ctx.emit("info", self.name, f"El navegador bloqueó {len(br.blocked)} peticiones fuera de alcance",
                             {"muestra": br.blocked[:15]})
        except Exception as e:  # noqa: BLE001 - the browser must never take down the scan
            ctx.emit("warn", self.name, f"El navegador terminó con un error: {type(e).__name__}: {e}")
        finally:
            ctx.runner.cleanup(workdir)

    def _add_form(self, ctx: ScanContext, f: dict) -> None:
        action = f.get("action")
        if not action or not ctx.guard.host_matches(urlsplit(action).hostname or ""):
            return
        fields = {fld["name"]: "" for fld in f.get("fields", []) if fld.get("name")}
        types = {fld["name"]: fld.get("type", "text") for fld in f.get("fields", []) if fld.get("name")}
        form = Form(page=action, action=same_doc(action), method=f.get("method", "GET"), fields=fields, field_types=types)
        key = (form.action, form.method, tuple(sorted(form.fields)))
        if key not in {(x.action, x.method, tuple(sorted(x.fields))) for x in ctx.kb.forms}:
            ctx.kb.forms.append(form)

    @staticmethod
    def _add_api(ctx: ScanContext, method: str, url: str) -> None:
        if not url or not ctx.guard.host_matches(urlsplit(url).hostname or ""):
            return
        tpl = endpoint_template(url)
        if any(e.method == method and endpoint_template(e.url) == tpl for e in ctx.kb.api):
            return
        ctx.kb.api.append(ApiEndpoint(method=method, url=url,
                                      params=[{"name": k, "in": "query"} for k in query_params(url)], source="browser"))
        ctx.kb.urls.add(url)

    async def _dom_xss(self, ctx: ScanContext, br: BrowserEngine, candidates: list[tuple[str, str]]) -> None:
        done: set[tuple[str, str]] = set()
        tested = 0
        limit = 20 if ctx.cfg.at_least("deep") else 8
        for url, param in candidates:
            if tested >= limit:
                break
            key = (endpoint_template(url).split("?")[0], param)
            if key in done:
                continue
            done.add(key)
            ctx.check()
            tested += 1
            res = await br.dom_xss(url, param, canary())
            if res:
                ctx.add(FindingDraft(
                    title=f"Cross-Site Scripting ejecutado en el navegador en «{param}» ({urlsplit(url).path})",
                    category="xss_dom", module=self.name, confidence="confirmed", native_evidence=True,
                    asset=urlsplit(url).hostname or "", endpoint=url, method="GET", parameter=param,
                    description="El navegador headless ejecutó realmente el payload inyectado en este parámetro: es un "
                                "XSS confirmado por ejecución (reflejado o basado en DOM), no una heurística.",
                    evidence={"prueba": res["evidence"], "payload": f'"><img src=x onerror=…(marcador)>',
                              "ubicacion": "navegador (DOM)"}))
        if tested:
            ctx.emit("info", self.name, f"DOM XSS verificado por ejecución en {tested} parámetros")
