"""Code ↔ deployment correlation: routes declared in the source vs what the deployment exposes.

* A route without an authentication guard in the code that answers 2xx anonymously on the deployment
  (and is not a soft-404 / login redirect) → ``route_unprotected`` (confirmed, native evidence).
* An endpoint observed on the deployment that matches no route of the analysed code → ``route_shadow``.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from vigia.core.context import ScanContext
from vigia.core.findings import FindingDraft
from vigia.core.module import Module
from vigia.correlation.engine import _route_regex
from vigia.modules.probe import baseline, looks_like_404
from vigia.security.http import HttpError
from vigia.security.scope import ScopeViolation

SENSITIVE = re.compile(r"admin|manage|internal|debug|config|settings|users?|accounts?|profile|orders?|payments?|export|"
                       r"report|secret|token|keys?|private|dashboard|billing|invoice", re.I)


class RoutesModule(Module):
    name = "routes"
    title = "Correlación código ↔ despliegue"
    phase = "correlation"

    def applicable(self, ctx: ScanContext) -> str | None:
        if ctx.http is None or ctx.source_dir is None:
            return "requiere código fuente y objetivo desplegado"
        if not ctx.kb.code_routes:
            return "no se extrajeron rutas del código"
        return None

    async def run(self, ctx: ScanContext) -> None:
        routes = ctx.kb.code_routes
        ctx.emit("info", self.name, f"{len(routes)} rutas en el código, {len(ctx.kb.api)} endpoints observados")
        by_file_auth: dict[str, bool] = {}
        for r in routes:
            by_file_auth[r["file"]] = by_file_auth.get(r["file"], False) or bool(r.get("auth"))
        for base in ctx.kb.base_urls[:2]:
            bases = await baseline(ctx, base)
            checked = 0
            for r in routes:
                if r.get("auth") or r.get("method", "GET") not in ("GET", "ANY") or checked >= 60:
                    continue
                inconsistent = by_file_auth.get(r["file"], False)
                if not (SENSITIVE.search(r["path"]) or SENSITIVE.search(r.get("handler") or "")):
                    continue
                path = re.sub(r"\{[^}]+\}|<[^>]+>|:[A-Za-z_]\w*|\[[^\]]+\]", "1", r["path"])
                url = urljoin(base, path)
                checked += 1
                try:
                    resp = await ctx.fetch(url, module=self.name, follow_redirects=False, store=False)
                except (HttpError, ScopeViolation):
                    continue
                if not (200 <= resp.status < 300) or looks_like_404(resp, bases, path):
                    continue
                if 'type="password"' in resp.text.lower() or "login" in resp.url.lower():
                    continue
                ctx.add(FindingDraft(
                    title=f"Ruta {r['path']} sin autenticación en el código y accesible en el despliegue",
                    category="route_unprotected", module=self.name, confidence="confirmed", native_evidence=True,
                    asset=urlsplit(url).hostname or "", endpoint=url, method="GET", file=r["file"], line=r.get("line"),
                    function=r.get("handler"),
                    description=f"La ruta está declarada en {r['file']}:{r.get('line')} ({r.get('framework')}) sin "
                                "decorador/middleware de autenticación" + (" mientras otras rutas del mismo fichero sí lo "
                                                                            "tienen" if inconsistent else "") +
                                f", y el despliegue responde {resp.status} sin credenciales.",
                    evidence={"request": f"GET {url}", "status": resp.status, "codigo": f"{r['file']}:{r.get('line')}",
                              "response_excerpt": resp.text[:400]}))
        if len(routes) >= 5:
            regexes = [(_route_regex(r["path"]), r) for r in routes]
            shadow = []
            for e in ctx.kb.api:
                path = urlsplit(e.url).path
                if not any(rx.match(path) for rx, _ in regexes) and not any(rx.match(path.rstrip("/")) for rx, _ in regexes):
                    shadow.append(f"{e.method} {path}")
            if shadow:
                ctx.add(FindingDraft(title=f"{len(shadow)} endpoints expuestos que no aparecen en el código analizado",
                                     category="route_shadow", module=self.name, confidence="suspected", native_evidence=True,
                                     asset=urlsplit(ctx.kb.base_urls[0]).hostname or "" if ctx.kb.base_urls else "",
                                     description="Pueden pertenecer a otro servicio, a un proxy o a código no incluido en el "
                                                 "análisis; si no, son endpoints sin inventariar.",
                                     evidence={"muestra": shadow[:25]}))
