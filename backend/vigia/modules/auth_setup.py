"""Authenticated testing: establishes sessions for the test accounts attached to the scan.

Credential payloads (decrypted only in memory, never logged):
  bearer {token} · header {name, value} · basic {username, password} · cookie {cookie}
  form   {login_url, username, password, username_field?, password_field?, extra?, success_text?, verify_url?}
  json   {login_url, body, token_path?, verify_url?}
Optional "role" ("admin"/"user") lets the API module test BFLA.
"""
from __future__ import annotations

import base64
import json
from typing import Any
from urllib.parse import urlsplit

from vigia.core.context import ScanContext
from vigia.modules.common import parse_html
from vigia.security.http import HttpError
from vigia.security.scope import ScopeViolation


def _dig(obj: Any, path: str) -> Any:
    for part in path.split("."):
        if isinstance(obj, dict):
            obj = obj.get(part)
        elif isinstance(obj, list) and part.isdigit() and int(part) < len(obj):
            obj = obj[int(part)]
        else:
            return None
    return obj


async def setup_identities(ctx: ScanContext) -> None:
    if not ctx.identities or ctx.http is None:
        return
    for name, cred in ctx.identities.items():
        ident = ctx.http.identity(name)
        kind = cred.get("kind")
        try:
            if kind == "bearer":
                ident.headers["Authorization"] = f"Bearer {cred['token']}"
            elif kind == "header":
                if cred["name"].lower() in ("host", "content-length", "transfer-encoding"):
                    raise ValueError("cabecera no permitida")
                ident.headers[cred["name"]] = cred["value"]
            elif kind == "basic":
                tok = base64.b64encode(f"{cred['username']}:{cred['password']}".encode()).decode()
                ident.headers["Authorization"] = f"Basic {tok}"
            elif kind == "cookie":
                for host in {urlsplit(b).hostname for b in ctx.kb.base_urls or ctx.guard.seed_urls()} if ctx.guard else []:
                    for pair in str(cred["cookie"]).split(";"):
                        if "=" in pair:
                            ident.store(host, pair.strip() + "; Path=/")
            elif kind == "form":
                await _form_login(ctx, name, cred)
            elif kind == "json":
                await _json_login(ctx, name, cred)
            else:
                raise ValueError(f"tipo de credencial desconocido: {kind}")
        except (KeyError, ValueError, HttpError, ScopeViolation) as e:
            ctx.emit("warn", "auth", f"No se pudo preparar la identidad «{name}»: {type(e).__name__}: {e}")
            continue
        if await _verify(ctx, name, cred):
            ctx.kb.authenticated.append(name)
            ctx.emit("info", "auth", f"Sesión de prueba «{name}» establecida (rol: {cred.get('role', 'user')})")
        else:
            ctx.emit("warn", "auth", f"La sesión «{name}» no pudo verificarse; las pruebas autenticadas la omitirán")


async def _form_login(ctx: ScanContext, name: str, cred: dict[str, Any]) -> None:
    r = await ctx.fetch(cred["login_url"], identity=name, module="auth", store=False)
    page = parse_html(r.text, r.url)
    form = next((f for f in page.forms if "password" in f.types.values()), None)
    if form is None:
        raise ValueError("no se encontró un formulario con campo de contraseña en login_url")
    data = dict(form.inputs)  # keeps hidden CSRF tokens
    ufield = cred.get("username_field") or next((k for k, t in form.types.items() if t in ("text", "email")), None)
    pfield = cred.get("password_field") or next(k for k, t in form.types.items() if t == "password")
    if not ufield:
        raise ValueError("no se pudo identificar el campo de usuario")
    data[ufield], data[pfield] = cred["username"], cred["password"]
    data.update(cred.get("extra") or {})
    resp = await ctx.fetch(form.action, method=form.method if form.method in ("POST", "GET") else "POST", identity=name,
                           module="auth", store=False, data=data)
    if cred.get("success_text") and cred["success_text"] not in resp.text:
        raise ValueError("el texto de éxito no aparece tras el login")
    if 'type="password"' in resp.text.lower() and not cred.get("success_text") and resp.url.rstrip("/") == \
            cred["login_url"].rstrip("/"):
        raise ValueError("el formulario de login sigue apareciendo (¿credenciales incorrectas?)")


async def _json_login(ctx: ScanContext, name: str, cred: dict[str, Any]) -> None:
    body = cred["body"] if isinstance(cred["body"], dict) else json.loads(cred["body"])
    r = await ctx.fetch(cred["login_url"], method="POST", identity=name, module="auth", store=False, json_body=body)
    if r.status >= 400:
        raise ValueError(f"login JSON respondió {r.status}")
    path = cred.get("token_path")
    if path:
        token = _dig(r.json(), path)
        if not isinstance(token, str) or not token:
            raise ValueError(f"no hay token en '{path}'")
        ctx.http.identity(name).headers["Authorization"] = f"Bearer {token}"  # type: ignore[union-attr]


async def _verify(ctx: ScanContext, name: str, cred: dict[str, Any]) -> bool:
    url = cred.get("verify_url")
    if not url:
        ident = ctx.http.identity(name)  # type: ignore[union-attr]
        return bool(ident.headers or ident.cookies)
    try:
        r = await ctx.fetch(url, identity=name, module="auth", follow_redirects=False)
    except (HttpError, ScopeViolation):
        return False
    return 200 <= r.status < 300 and 'type="password"' not in r.text.lower()
