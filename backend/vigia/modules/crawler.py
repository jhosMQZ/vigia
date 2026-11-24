"""M09 — Crawler: breadth-first discovery of pages, forms, parameters, scripts and API endpoints.

Every URL is checked against the scope by the HTTP client. Links that look state-changing (logout,
delete, remove…) are never followed (non-destructive policy). When an authenticated identity is
available, the authenticated surface is crawled separately.
"""
from __future__ import annotations

import asyncio
import re
from collections import deque
from urllib.parse import urljoin, urlsplit

from vigia.core.context import ApiEndpoint, Form, ScanContext
from vigia.core.findings import FindingDraft, endpoint_template
from vigia.core.module import Module
from vigia.modules.common import parse_html, query_params, same_doc
from vigia.security.http import HttpError
from vigia.security.scope import ScopeViolation

SKIP_EXT = re.compile(r"\.(?:png|jpe?g|gif|webp|avif|ico|bmp|tiff?|svgz|woff2?|ttf|otf|eot|mp[34]|m4a|webm|ogg|wav|avi|mov|"
                      r"mkv|pdf|docx?|xlsx?|pptx?|zip|gz|tgz|bz2|7z|rar|tar|iso|dmg|exe|msi|apk|bin|wasm)$", re.I)
UNSAFE_LINK = re.compile(r"log-?out|sign-?out|salir|cerrar[-_]?sesi|desconectar|/delete|/remove|/destroy|/drop|"
                         r"[?&](?:action|op|do)=(?:delete|remove|logout|destroy)|/unsubscribe|/deactivate", re.I)
JS_ENDPOINT = re.compile(r"""(?:fetch|axios(?:\.(?:get|post|put|patch|delete))?|\$\.(?:get|post|ajax)|open)\(\s*['"`]"""
                         r"""((?:https?://[^'"`\s]+)?/[A-Za-z0-9_\-./{}:$?=&%]+)['"`]""")
JS_PATH = re.compile(r"""['"`](/(?:api|v\d|graphql|rest|internal|admin|auth|oauth|user|users|account)[A-Za-z0-9_\-./{}:]*)['"`]""")


class CrawlerModule(Module):
    name = "crawler"
    title = "Rastreo (DAST)"
    phase = "discovery"
    needs_target = True

    async def run(self, ctx: ScanContext) -> None:
        if ctx.cfg.crawl_max_pages <= 0:
            return
        seeds = list(dict.fromkeys(ctx.kb.base_urls + sorted(ctx.kb.urls)))
        for base in ctx.kb.base_urls:
            for p in ctx.cfg.include_paths:
                seeds.append(urljoin(base, p))
        identities = ["default"] + ctx.kb.authenticated[:1]
        budget = ctx.cfg.crawl_max_pages
        for ident in identities:
            share = budget if ident == "default" and len(identities) == 1 else budget // len(identities)
            await self.crawl(ctx, seeds + sorted(ctx.kb.login_urls), ident, share)
        ctx.emit("info", self.name, f"Rastreo completado: {len(ctx.kb.urls)} URLs, {len(ctx.kb.forms)} formularios, "
                 f"{len(ctx.kb.scripts)} scripts, {len(ctx.kb.api)} endpoints de API")

    async def crawl(self, ctx: ScanContext, seeds: list[str], identity: str, max_pages: int) -> None:
        assert ctx.guard is not None
        queue: deque[tuple[str, int]] = deque((s, 0) for s in seeds)
        seen: set[str] = set()
        fetched = 0
        sem = asyncio.Semaphore(max(1, ctx.cfg.concurrency))
        lock = asyncio.Lock()

        async def visit(url: str, depth: int) -> None:
            nonlocal fetched
            async with sem:
                try:
                    r = await ctx.fetch(url, identity=identity, module=self.name)
                except (HttpError, ScopeViolation):
                    return
            async with lock:
                fetched += 1
            ctx.kb.urls.add(url)  # the requested URL keeps its parameters even when it redirects
            ctx.kb.urls.add(r.url)
            if r.redirects:
                self._params(ctx, url)
            ctx.kb.pages[r.url] = {"status": r.status, "ctype": r.content_type, "size": len(r.content),
                                   "identity": identity}
            self._params(ctx, r.url)
            if "javascript" in r.content_type or r.url.endswith(".js"):
                self._js(ctx, r.url, r.text)
                return
            if "json" in r.content_type and "/api" in urlsplit(r.url).path:
                self._api(ctx, "GET", r.url, "crawl")
            if "html" not in r.content_type:
                return
            page = parse_html(r.text, r.url)
            if "<title>Index of /" in r.text or "Directory listing for /" in r.text:
                ctx.add(FindingDraft(title=f"Listado de directorio en {urlsplit(r.url).path}", category="directory_listing",
                                     module=self.name, confidence="confirmed", native_evidence=True,
                                     asset=urlsplit(r.url).hostname or "", endpoint=r.url,
                                     evidence={"request": f"GET {r.url}", "status": r.status,
                                               "response_excerpt": r.text[:600]}))
            for f in page.forms:
                form = Form(page=r.url, action=same_doc(f.action), method=f.method, fields=dict(f.inputs),
                            field_types=dict(f.types), enctype=f.enctype)
                key = (form.action, form.method, tuple(sorted(form.fields)))
                if key not in {(x.action, x.method, tuple(sorted(x.fields))) for x in ctx.kb.forms}:
                    ctx.kb.forms.append(form)
                if "password" in f.types.values():
                    ctx.kb.login_urls.add(r.url)
            for s in page.scripts:
                if ctx.guard.host_matches(urlsplit(s).hostname or ""):
                    ctx.kb.scripts.add(same_doc(s))
                    async with lock:
                        if s not in seen:
                            seen.add(s)
                            queue.append((s, depth + 1))
            for js in page.inline_scripts:
                self._js(ctx, r.url, js)
            if depth >= ctx.cfg.crawl_depth:
                return
            async with lock:
                for link in page.links + page.iframes:
                    link = same_doc(link)
                    if link in seen or not link.startswith(("http://", "https://")):
                        continue
                    host = urlsplit(link).hostname or ""
                    if not ctx.guard.host_matches(host) or ctx.guard.is_excluded(host, urlsplit(link).path or "/", link):
                        continue
                    if SKIP_EXT.search(urlsplit(link).path):
                        ctx.kb.urls.add(link)
                        continue
                    if UNSAFE_LINK.search(link):
                        ctx.emit("debug", self.name, f"Enlace con posible efecto de estado no seguido: {link}")
                        continue
                    seen.add(link)
                    queue.append((link, depth + 1))

        while queue and fetched < max_pages:
            ctx.check()
            batch = []
            while queue and len(batch) < max(1, ctx.cfg.concurrency) * 2 and fetched + len(batch) < max_pages:
                url, depth = queue.popleft()
                if url in seen and depth > 0 and url not in seeds:
                    pass
                seen.add(url)
                batch.append(visit(url, depth))
            await asyncio.gather(*batch)
            ctx.progress(self.name, "running", min(95, int(100 * fetched / max(1, max_pages))),
                         detail=f"{fetched} páginas ({identity})")

    def _params(self, ctx: ScanContext, url: str) -> None:
        q = query_params(url)
        if q:
            ctx.kb.params.setdefault(endpoint_template(url).split("?")[0], set()).update(q.keys())

    def _js(self, ctx: ScanContext, base: str, js: str) -> None:
        assert ctx.guard is not None
        for m in list(JS_ENDPOINT.finditer(js))[:200] + list(JS_PATH.finditer(js))[:200]:
            path = m.group(1)
            if "${" in path or len(path) > 300:
                path = re.sub(r"\$\{[^}]*\}", "1", path)
            url = urljoin(base, path)
            host = urlsplit(url).hostname or ""
            if ctx.guard.host_matches(host) and not SKIP_EXT.search(urlsplit(url).path):
                if url not in ctx.kb.urls:
                    ctx.kb.urls.add(url)
                    method = "GET"
                    pre = js[max(0, m.start() - 40):m.start() + 10].lower()
                    for verb in ("post", "put", "patch", "delete"):
                        if verb in pre:
                            method = verb.upper()
                    self._api(ctx, method, url, "js")

    @staticmethod
    def _api(ctx: ScanContext, method: str, url: str, source: str) -> None:
        tpl = endpoint_template(url)
        if any(e.method == method and endpoint_template(e.url) == tpl for e in ctx.kb.api):
            return
        params = [{"name": k, "in": "query"} for k in query_params(url)]
        ctx.kb.api.append(ApiEndpoint(method=method, url=url, params=params, source=source))
        if "graphql" in url.lower():
            ctx.kb.graphql.add(url.split("?")[0])
