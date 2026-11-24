"""Path probing with soft-404 detection (avoids false positives on catch-all routes / SPAs)."""
from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

from vigia.core.context import ScanContext
from vigia.modules.common import similarity, strip_reflections
from vigia.security.http import HttpError, HttpResponse
from vigia.security.scope import ScopeViolation


@dataclass
class Baseline:
    status: int
    length: int
    body: str
    ctype: str
    location: str


async def baseline(ctx: ScanContext, base: str, suffix: str = "") -> list[Baseline]:
    """Responses for random non-existent paths (two shapes) on an origin."""
    key = f"{base}|{suffix}"
    if key in ctx.kb.soft404:
        return ctx.kb.soft404[key]
    out: list[Baseline] = []
    for path in (f"vigia-{secrets.token_hex(6)}{suffix}", f"{secrets.token_hex(4)}/vigia-{secrets.token_hex(4)}{suffix}"):
        try:
            r = await ctx.fetch(urljoin(base, "/" + path), module="probe", store=False, follow_redirects=False)
            out.append(Baseline(r.status, len(r.content), strip_reflections(r.text, path), r.content_type,
                                r.header("location")))
        except (HttpError, ScopeViolation):
            continue
    ctx.kb.soft404[key] = out
    return out


def looks_like_404(r: HttpResponse, bases: list[Baseline], path: str = "") -> bool:
    if r.status in (404, 410):
        return True
    body = strip_reflections(r.text, path, path.lstrip("/"))
    for b in bases:
        if r.status == b.status:
            if r.status in (301, 302, 303, 307, 308) and r.header("location").split("?")[0] == b.location.split("?")[0]:
                return True
            if b.length and abs(len(r.content) - b.length) <= max(32, b.length * 0.02):
                return True
            if similarity(body, b.body) > 0.92:
                return True
    return False


async def probe_paths(ctx: ScanContext, base: str, paths: list[str], module: str, *, headers: dict[str, str] | None = None,
                      concurrency: int = 4) -> list[tuple[str, HttpResponse]]:
    """GET each path on base; returns (path, response) for responses that are not soft-404."""
    results: list[tuple[str, HttpResponse]] = []
    bases = await baseline(ctx, base)
    exts = {p.rsplit(".", 1)[-1] for p in paths if "." in p.rsplit("/", 1)[-1]}
    ext_bases: dict[str, list[Baseline]] = {}
    for e in list(exts)[:12]:
        ext_bases[e] = await baseline(ctx, base, "." + e)
    sem = asyncio.Semaphore(concurrency)

    async def one(path: str) -> None:
        async with sem:
            url = urljoin(base, path)
            try:
                r = await ctx.fetch(url, module=module, headers=headers, follow_redirects=False, store=False)
            except (HttpError, ScopeViolation):
                return
            ext = path.rsplit(".", 1)[-1] if "." in path.rsplit("/", 1)[-1] else None
            if looks_like_404(r, bases + ext_bases.get(ext or "", []), path):
                return
            results.append((path, r))

    await asyncio.gather(*(one(p) for p in paths))
    return results


def range_headers(n: int = 2047) -> dict[str, Any]:
    """Ask for the first bytes only: minimal evidence, never mass download."""
    return {"Range": f"bytes=0-{n}"}
