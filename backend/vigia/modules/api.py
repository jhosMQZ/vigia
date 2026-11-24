"""M02 — API analysis (OWASP API Security Top 10 2023).

Discovery: OpenAPI 2/3 and Postman imports, GraphQL detection. Analysis: authentication enforcement,
BOLA/BFLA (requires two test identities), JWT weaknesses, GraphQL introspection, rate limiting, excessive
data exposure, verbose errors, SSRF / open redirect parameters, OAuth/OIDC configuration, inventory.

Only read-only requests are sent outside lab mode; state-changing checks (mass assignment, admin
functions with side effects) are evaluated statically from the specification unless the scope is a lab.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import yaml

from vigia.core.context import ApiEndpoint, ScanContext
from vigia.core.findings import FindingDraft, endpoint_template
from vigia.core.module import Module
from vigia.modules.common import ERROR_SIGNATURES, canary, evidence_from, find_signature, origin, similarity, with_param
from vigia.security.http import HttpError, HttpResponse
from vigia.security.redact import redact
from vigia.security.scope import ScopeViolation

SENSITIVE_KEYS = re.compile(r"^(password|passwd|password_hash|passwordhash|hash|salt|secret|client_secret|api_?key|"
                            r"access_?token|refresh_?token|private_?key|ssn|credit_?card|card_?number|cvv|otp|mfa_secret|"
                            r"reset_?token|session_?id)$", re.I)
SSRF_PARAMS = re.compile(r"^(url|uri|link|src|source|dest|destination|target|proxy|feed|webhook|callback|fetch|image|img|"
                         r"avatar|load|file_url|host|endpoint|site|domain|page_url|download)$", re.I)
REDIRECT_PARAMS = re.compile(r"^(next|redirect|redirect_uri|redirect_url|return|returnto|return_to|returnurl|continue|"
                             r"goto|go|to|r|out|forward|redir|destination|success_url|back)$", re.I)
PRIV_PROPS = re.compile(r"^(role|roles|is_?admin|admin|is_?staff|is_?superuser|permissions?|scopes?|balance|credit|"
                        r"owner_?id|user_?id|account_?id|verified|is_?verified|approved|status|plan|tier|group_?id)$", re.I)
WEAK_JWT_SECRETS = ["secret", "password", "123456", "changeme", "jwt_secret", "jwtsecret", "your-256-bit-secret",
                    "your_jwt_secret", "secretkey", "secret_key", "key", "test", "admin", "dev", "development", "supersecret",
                    "s3cr3t", "mysecret", "default", "token", "qwerty", "letmein", "jwt", "auth", "app", "example",
                    "shhhhh", "keyboard cat", "my_secret_key", "SECRET_KEY", "secret123", "pass", "1234567890"]
INTROSPECTION = {"query": "query VigiaIntrospection { __schema { queryType { name } mutationType { name } "
                          "types { name kind } } }"}


# ------------------------------------------------------------------ spec import
def _resolve_ref(spec: dict[str, Any], node: Any, depth: int = 0) -> Any:
    if depth > 12 or not isinstance(node, dict):
        return node
    if "$ref" in node and isinstance(node["$ref"], str) and node["$ref"].startswith("#/"):
        cur: Any = spec
        for part in node["$ref"][2:].split("/"):
            cur = cur.get(part.replace("~1", "/").replace("~0", "~"), {}) if isinstance(cur, dict) else {}
        return _resolve_ref(spec, cur, depth + 1)
    return node


def parse_openapi(spec: dict[str, Any], spec_url: str) -> list[ApiEndpoint]:
    if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
        raise ValueError("No es una especificación OpenAPI/Swagger (falta 'paths')")
    if "swagger" in spec:
        scheme = (spec.get("schemes") or [urlsplit(spec_url).scheme or "https"])[0]
        host = spec.get("host") or urlsplit(spec_url).netloc
        bases = [f"{scheme}://{host}{spec.get('basePath', '')}"]
    else:
        bases = []
        for srv in spec.get("servers") or []:
            u = str(srv.get("url", ""))
            for var, d in (srv.get("variables") or {}).items():
                u = u.replace("{" + var + "}", str(d.get("default", "")))
            bases.append(urljoin(spec_url, u))
        bases = bases or [origin(spec_url)]
    global_sec = bool(spec.get("security"))
    out: list[ApiEndpoint] = []
    for path, item in list(spec["paths"].items())[:2000]:
        if not isinstance(item, dict):
            continue
        common = item.get("parameters", [])
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options") or not isinstance(op, dict):
                continue
            params = []
            for prm in list(common) + list(op.get("parameters", [])):
                prm = _resolve_ref(spec, prm)
                if isinstance(prm, dict) and prm.get("name"):
                    sch = _resolve_ref(spec, prm.get("schema") or {})
                    params.append({"name": prm["name"], "in": prm.get("in", "query"), "required": prm.get("required", False),
                                   "type": (sch.get("type") if isinstance(sch, dict) else None) or prm.get("type"),
                                   "example": prm.get("example")})
            body = None
            rb = _resolve_ref(spec, op.get("requestBody") or {})
            if isinstance(rb, dict):
                content = rb.get("content", {})
                js = content.get("application/json") or next(iter(content.values()), None) if content else None
                if isinstance(js, dict):
                    body = _resolve_ref(spec, js.get("schema") or {})
            for prm in op.get("parameters", []):
                prm = _resolve_ref(spec, prm)
                if isinstance(prm, dict) and prm.get("in") == "body":
                    body = _resolve_ref(spec, prm.get("schema") or {})
            sec = op.get("security")
            auth = bool(sec) if sec is not None else global_sec
            out.append(ApiEndpoint(method=method.upper(), url=bases[0].rstrip("/") + path, params=params,
                                   body_schema=body if isinstance(body, dict) else None, auth_required=auth,
                                   source="openapi", operation_id=op.get("operationId")))
    return out


def parse_postman(coll: dict[str, Any]) -> list[ApiEndpoint]:
    out: list[ApiEndpoint] = []
    variables = {v.get("key"): v.get("value") for v in coll.get("variable", []) if isinstance(v, dict)}

    def sub(s: str) -> str:
        return re.sub(r"\{\{(\w+)\}\}", lambda m: str(variables.get(m.group(1), m.group(0))), s)

    def walk(items: list[Any], depth: int = 0) -> None:
        if depth > 10:
            return
        for it in items:
            if not isinstance(it, dict):
                continue
            if "item" in it:
                walk(it["item"], depth + 1)
                continue
            req = it.get("request")
            if not isinstance(req, dict):
                continue
            url = req.get("url")
            raw = url.get("raw") if isinstance(url, dict) else url
            if not raw:
                continue
            auth = bool(req.get("auth")) or any(str(h.get("key", "")).lower() == "authorization"
                                                for h in req.get("header", []) if isinstance(h, dict))
            out.append(ApiEndpoint(method=str(req.get("method", "GET")).upper(), url=sub(str(raw)), source="postman",
                                   auth_required=auth or None, operation_id=it.get("name")))
    walk(coll.get("item", []))
    return out


def load_spec_text(text: str) -> dict[str, Any]:
    text = text.strip()
    if len(text) > 15_000_000:
        raise ValueError("Especificación demasiado grande")
    data = json.loads(text) if text.startswith("{") else yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("Formato de especificación no reconocido")
    return data


def add_endpoints(ctx: ScanContext, eps: list[ApiEndpoint]) -> int:
    assert ctx.guard is not None
    known = {(e.method, endpoint_template(e.url)) for e in ctx.kb.api}
    n = 0
    for e in eps:
        host = urlsplit(e.url).hostname or ""
        if not ctx.guard.host_matches(host):
            continue
        key = (e.method, endpoint_template(e.url))
        if key in known:
            for k in ctx.kb.api:  # enrich crawled endpoint with spec metadata
                if (k.method, endpoint_template(k.url)) == key and k.source in ("crawl", "js"):
                    k.params, k.body_schema, k.auth_required, k.source = e.params, e.body_schema, e.auth_required, e.source
            continue
        known.add(key)
        ctx.kb.api.append(e)
        n += 1
    return n


async def import_openapi_from_url(ctx: ScanContext, url: str) -> int:
    r = await ctx.fetch(url, module="api", store=False)
    if r.status != 200:
        raise ValueError(f"HTTP {r.status}")
    return add_endpoints(ctx, parse_openapi(load_spec_text(r.text), url))


# ------------------------------------------------------------------ JWT helpers
def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def decode_jwt(token: str) -> tuple[dict, dict] | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        return json.loads(_b64d(parts[0])), json.loads(_b64d(parts[1]))
    except (ValueError, json.JSONDecodeError):
        return None


def crack_hs(token: str, words: list[str]) -> str | None:
    h, p, sig = token.split(".")
    alg = (decode_jwt(token) or ({}, {}))[0].get("alg", "")
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg)
    if not digest:
        return None
    msg = f"{h}.{p}".encode()
    for w in words:
        if hmac.compare_digest(_b64e(hmac.new(w.encode(), msg, digest).digest()), sig):
            return w
    return None


JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{0,512}")


class ApiModule(Module):
    name = "api"
    title = "Análisis de APIs (OWASP API Top 10)"
    phases = ("discovery", "analysis")
    needs_target = True

    async def run_phase(self, ctx: ScanContext, phase: str) -> None:
        if phase == "discovery":
            await self.discover(ctx)
            return
        eps = [e for e in ctx.kb.api if not ctx.guard or ctx.guard.host_matches(urlsplit(e.url).hostname or "")]
        ctx.emit("info", self.name, f"Inventario de API: {len(eps)} operaciones "
                 f"({sum(1 for e in eps if e.source == 'openapi')} desde OpenAPI)")
        steps = [self.auth_enforcement, self.excessive_data, self.bola_bfla, self.jwt_checks, self.graphql,
                 self.verbose_errors, self.ssrf_redirect, self.mass_assignment_static, self.inventory, self.oauth]
        if ctx.cfg.at_least("standard"):
            steps.append(self.rate_limit)
        for i, step in enumerate(steps):
            ctx.check()
            await step(ctx, eps)
            ctx.progress(self.name + ":analysis", "running", int(100 * (i + 1) / len(steps)))

    # ------------------------------------------------------------------ discovery
    async def discover(self, ctx: ScanContext) -> None:
        if ctx.cfg.openapi_url:
            try:
                n = await import_openapi_from_url(ctx, ctx.cfg.openapi_url)
                ctx.emit("info", self.name, f"OpenAPI importado desde {ctx.cfg.openapi_url}: {n} operaciones nuevas")
            except (HttpError, ScopeViolation, ValueError, yaml.YAMLError) as e:
                ctx.emit("warn", self.name, f"No se pudo importar {ctx.cfg.openapi_url}: {e}")
        for spec_file in getattr(ctx, "spec_files", []):
            try:
                data = load_spec_text(Path(spec_file).read_text(encoding="utf-8", errors="replace"))
                eps = parse_postman(data) if "info" in data and "item" in data else parse_openapi(
                    data, ctx.kb.base_urls[0] if ctx.kb.base_urls else "https://localhost/")
                n = add_endpoints(ctx, eps)
                ctx.emit("info", self.name, f"Especificación importada ({Path(spec_file).name}): {n} operaciones")
            except (ValueError, OSError, yaml.YAMLError) as e:
                ctx.emit("warn", self.name, f"Especificación no válida {Path(spec_file).name}: {e}")
        for base in ctx.kb.base_urls:
            for path in ("/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1", "/query"):
                url = urljoin(origin(base), path)
                try:
                    r = await ctx.fetch(url, method="POST", module=self.name, store=False,
                                        json_body={"query": "query { __typename }"})
                except (HttpError, ScopeViolation):
                    continue
                if r.status < 500 and ('"__typename"' in r.text or '"data"' in r.text and "query" in r.text.lower()
                                       or '"errors"' in r.text and "graphql" in r.text.lower()):
                    ctx.kb.graphql.add(url)
                    ctx.emit("info", self.name, f"Endpoint GraphQL detectado: {url}")
                    break

    # ------------------------------------------------------------------ API2 authentication
    async def auth_enforcement(self, ctx: ScanContext, eps: list[ApiEndpoint]) -> None:
        candidates = [e for e in eps if e.method == "GET" and "{" not in e.url and
                      (e.auth_required or re.search(r"/(admin|users?|accounts?|me|profile|orders?|payments?|internal|"
                                                    r"settings|config)\b", urlsplit(e.url).path, re.I))][:40]
        for e in candidates:
            try:
                r = await ctx.fetch(e.url, module=self.name, store=False)
            except (HttpError, ScopeViolation):
                continue
            if 200 <= r.status < 300 and "json" in r.content_type and len(r.content) > 2 and r.text.strip() not in (
                    "[]", "{}", "null"):
                declared = bool(e.auth_required)
                ctx.add(FindingDraft(
                    title=f"Endpoint {'declarado como protegido ' if declared else 'sensible '}accesible sin autenticación: "
                          f"{e.method} {urlsplit(e.url).path}",
                    category="api_auth_missing", module=self.name, confidence="confirmed" if declared else "suspected",
                    native_evidence=True, asset=urlsplit(e.url).hostname or "", endpoint=e.url, method=e.method,
                    description=("La especificación exige seguridad para esta operación, pero responde con datos sin "
                                 "credenciales." if declared else
                                 "El endpoint parece manejar datos sensibles y responde con datos sin credenciales; "
                                 "confirma si debe ser público."),
                    evidence=evidence_from(r, limit=600)))

    # ------------------------------------------------------------------ API3 excessive data
    async def excessive_data(self, ctx: ScanContext, eps: list[ApiEndpoint]) -> None:
        seen: set[str] = set()
        idents = ["default"] + ctx.kb.authenticated[:1]
        for e in [e for e in eps if e.method == "GET" and "{" not in e.url][:40]:
            for ident in idents:
                if not any(sr.url == e.url and sr.identity == ident for sr in ctx.kb.responses.items.values()):
                    try:
                        await ctx.fetch(e.url, identity=ident, module=self.name)
                    except (HttpError, ScopeViolation):
                        continue
        for sr in list(ctx.kb.responses.items.values()):
            if "json" not in sr.content_type or not sr.body:
                continue
            try:
                data = json.loads(sr.body)
            except ValueError:
                continue
            keys: set[str] = set()
            self._keys(data, keys)
            bad = sorted(k for k in keys if SENSITIVE_KEYS.match(k))
            tpl = endpoint_template(sr.url)
            if bad and tpl not in seen:
                seen.add(tpl)
                ctx.add(FindingDraft(
                    title=f"La API devuelve campos sensibles ({', '.join(bad[:4])}) en {urlsplit(sr.url).path}",
                    category="api_excessive_data", module=self.name, confidence="confirmed", native_evidence=True,
                    asset=urlsplit(sr.url).hostname or "", endpoint=sr.url, method="GET",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:%s/UI:N/S:U/C:H/I:N/A:N" % ("N" if sr.identity == "default" else "L"),
                    evidence={"request": f"GET {sr.url}", "identidad": sr.identity, "campos_sensibles": bad,
                              "response_excerpt": redact(sr.text[:800], 800)}))

    def _keys(self, node: Any, out: set[str], depth: int = 0) -> None:
        if depth > 6 or len(out) > 500:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(k, str) and v not in (None, "", [], {}):
                    out.add(k)
                self._keys(v, out, depth + 1)
        elif isinstance(node, list):
            for v in node[:20]:
                self._keys(v, out, depth + 1)

    # ------------------------------------------------------------------ API1/API5 BOLA / BFLA
    def _own_id(self, ctx: ScanContext, name: str) -> str | None:
        """Identifier of the account itself: JWT 'sub' or the id of a JSON record carrying its username."""
        assert ctx.http is not None
        ident = ctx.http.identity(name)
        for v in list(ident.headers.values()) + [c.value for c in ident.cookies]:
            m = JWT_RE.search(v)
            dec = decode_jwt(m.group(0)) if m else None
            if dec and str(dec[1].get("sub", "")).strip():
                return str(dec[1]["sub"])
        uname = str(ctx.identities.get(name, {}).get("username") or (ctx.identities.get(name, {}).get("body") or {})
                    .get("username", "")).lower()
        for sr in ctx.kb.responses.items.values():
            if sr.identity == name and "json" in sr.content_type:
                try:
                    data = json.loads(sr.body)
                except ValueError:
                    continue
                if isinstance(data, dict) and uname and str(data.get("username", "")).lower() == uname and "id" in data:
                    return str(data["id"])
        return None

    def _object_urls(self, ctx: ScanContext, eps: list[ApiEndpoint], oid: str) -> list[str]:
        out: list[str] = []
        for e in eps:  # spec templates with a single path parameter: /api/users/{id}
            if e.method == "GET" and e.url.count("{") == 1:
                out.append(re.sub(r"\{[^}]+\}", oid, e.url))
        for sr in list(ctx.kb.responses.items.values()):  # collections returning records with ids -> /collection/<id>
            if "json" not in sr.content_type or sr.status != 200:
                continue
            try:
                data = json.loads(sr.body)
            except ValueError:
                continue
            if isinstance(data, list) and data and isinstance(data[0], dict) and "id" in data[0]:
                out.append(sr.url.split("?")[0].rstrip("/") + f"/{oid}")
        for u in ctx.kb.urls:  # observed URLs whose numeric segment is the owner's id
            if re.search(rf"/{re.escape(oid)}(/|$)", urlsplit(u).path):
                out.append(u)
        return list(dict.fromkeys(out))[:30]

    async def bola_bfla(self, ctx: ScanContext, eps: list[ApiEndpoint]) -> None:
        idents = ctx.kb.authenticated
        if len(idents) < 2:
            ctx.emit("info", self.name, "BOLA/BFLA: se necesitan dos cuentas de prueba con sesión válida "
                     f"(disponibles: {len(idents)}). Prueba no evaluada.")
            return
        roles = {name: str(ctx.identities.get(name, {}).get("role", "user")).lower() for name in idents}
        users = [n for n in idents if roles[n] != "admin"]
        admin = next((n for n in idents if roles[n] == "admin"), None)
        owner, other = (users + [n for n in idents if n not in users])[:2]
        oid = self._own_id(ctx, owner)
        if oid is None:
            ctx.emit("info", self.name, f"BOLA: no se pudo determinar el identificador propio de «{owner}»")
        for url in self._object_urls(ctx, eps, oid) if oid else []:
            ctx.check()
            try:
                a = await ctx.fetch(url, identity=owner, module=self.name, store=False)
                if not (200 <= a.status < 300) or "json" not in a.content_type:
                    continue
                b = await ctx.fetch(url, identity=other, module=self.name, store=False)
                anon = await ctx.fetch(url, module=self.name, store=False)
            except (HttpError, ScopeViolation):
                continue
            if 200 <= b.status < 300 and similarity(a.text, b.text) > 0.9 and anon.status in (401, 403):
                ctx.add(FindingDraft(
                    title=f"BOLA: la cuenta «{other}» lee el objeto de «{owner}» en {urlsplit(url).path}",
                    category="api_bola", module=self.name, confidence="confirmed", native_evidence=True,
                    asset=urlsplit(url).hostname or "", endpoint=url, method="GET",
                    description=f"El objeto {oid} pertenece a la cuenta «{owner}» (identificador obtenido de su propia "
                                f"sesión). La cuenta «{other}» lo obtiene igualmente, mientras que sin credenciales se "
                                "deniega: la API autentica pero no comprueba la propiedad del objeto.",
                    evidence={"request": f"GET {url}", "propietario": owner, "id_propietario": oid, "otra_cuenta": other,
                              "estado_otra_cuenta": b.status, "estado_anonimo": anon.status,
                              "similitud": round(similarity(a.text, b.text), 3)}))
                break
        admin_paths = re.compile(r"/(admin|manage|management|internal|roles|staff|superuser|backoffice)(/|$)", re.I)
        cands = [e.url for e in eps if e.method == "GET" and "{" not in e.url and admin_paths.search(urlsplit(e.url).path)]
        cands += [u for u in ctx.kb.urls if admin_paths.search(urlsplit(u).path) and "{" not in u]
        low = owner
        for url in list(dict.fromkeys(cands))[:20]:
            ctx.check()
            try:
                anon = await ctx.fetch(url, module=self.name, store=False, follow_redirects=False)
                if anon.status not in (401, 403):
                    continue  # public or missing: not a function-level authorization question
                r = await ctx.fetch(url, identity=low, module=self.name, store=False, follow_redirects=False)
                ra = await ctx.fetch(url, identity=admin, module=self.name, store=False) if admin else None
            except (HttpError, ScopeViolation):
                continue
            if 200 <= r.status < 300 and 'type="password"' not in r.text.lower():
                same_as_admin = ra is not None and 200 <= ra.status < 300 and similarity(ra.text, r.text) > 0.85
                ctx.add(FindingDraft(
                    title=f"BFLA: función administrativa accesible para «{low}» ({urlsplit(url).path})",
                    category="api_bfla", module=self.name, confidence="confirmed" if same_as_admin else "likely",
                    native_evidence=True, asset=urlsplit(url).hostname or "", endpoint=url, method="GET",
                    description="El endpoint administrativo exige autenticación (anónimo: "
                                f"{anon.status}) pero responde a una cuenta sin rol de administrador" +
                                (", con el mismo contenido que obtiene el administrador." if same_as_admin else
                                 ". Sin cuenta de administrador no se compara el contenido."),
                    evidence={"request": f"GET {url}", "cuenta_sin_privilegios": low, "rol": roles.get(low),
                              "estado": r.status, "estado_anonimo": anon.status,
                              "estado_admin": ra.status if ra is not None else None}))

    # ------------------------------------------------------------------ JWT
    async def jwt_checks(self, ctx: ScanContext, eps: list[ApiEndpoint]) -> None:
        tokens: dict[str, str] = {}
        for name in ctx.kb.authenticated:
            ident = ctx.http.identity(name) if ctx.http else None
            if ident is None:
                continue
            for v in list(ident.headers.values()) + [c.value for c in ident.cookies]:
                for m in JWT_RE.finditer(v):
                    tokens[m.group(0)] = name
        for sr in list(ctx.kb.responses.items.values())[:500]:
            for m in JWT_RE.finditer(sr.text[:50000]):
                tokens.setdefault(m.group(0), sr.identity)
        for tok, ident in list(tokens.items())[:10]:
            dec = decode_jwt(tok)
            if not dec:
                continue
            header, payload = dec
            problems = []
            alg = str(header.get("alg", ""))
            if alg.lower() == "none":
                problems.append("algoritmo 'none' (token sin firma)")
            if "exp" not in payload:
                problems.append("sin caducidad (exp)")
            elif isinstance(payload.get("exp"), (int, float)) and payload["exp"] - payload.get("iat", time.time()) > 7 * 86400:
                problems.append("caducidad superior a 7 días")
            secret = crack_hs(tok, WEAK_JWT_SECRETS + self._context_words(ctx)) if alg.upper().startswith("HS") else None
            if secret:
                problems.append(f"secreto HMAC trivial («{secret[:2]}…», {len(secret)} caracteres)")
            if problems:
                ctx.add(FindingDraft(
                    title=f"JWT inseguro: {problems[0]}", category="api_jwt_weak", module=self.name,
                    confidence="confirmed", native_evidence=True, asset=ctx.kb.base_urls[0] if ctx.kb.base_urls else "",
                    severity="critical" if secret or alg.lower() == "none" else "medium",
                    cvss_vector=("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" if secret or alg.lower() == "none"
                                 else "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"),
                    description="Problemas: " + "; ".join(problems) + ". El análisis del secreto es local (diccionario "
                                "reducido), sin peticiones al objetivo.",
                    evidence={"header": header, "claims": sorted(payload.keys()), "identidad": ident, "problemas": problems},
                    fingerprint_extra=",".join(sorted(problems))))
            sensitive = [k for k in payload if SENSITIVE_KEYS.match(k) or k.lower() in ("email", "phone", "dni", "address")]
            if sensitive:
                ctx.add(FindingDraft(title=f"JWT con datos personales o sensibles en claro ({', '.join(sensitive[:3])})",
                                     category="api_jwt_sensitive", module=self.name, confidence="confirmed",
                                     native_evidence=True, asset=ctx.kb.base_urls[0] if ctx.kb.base_urls else "",
                                     evidence={"claims": sorted(payload.keys())}))
            if ctx.cfg.at_least("standard") and alg.lower() != "none":
                await self._alg_none(ctx, tok, ident, header, payload)

    @staticmethod
    def _context_words(ctx: ScanContext) -> list[str]:
        words = set()
        for b in ctx.kb.base_urls:
            host = urlsplit(b).hostname or ""
            for part in host.split("."):
                if len(part) > 2:
                    words.update({part, part + "123", part + "_secret", part + "-secret", part.upper()})
        return sorted(words)[:60]

    async def _alg_none(self, ctx: ScanContext, tok: str, ident: str, header: dict, payload: dict) -> None:
        """Replay a protected GET with the same claims but alg=none; accepted == signature not verified."""
        assert ctx.http is not None
        probe = next((u for u, sr in ctx.kb.responses.items.items() if sr.identity == ident and sr.status == 200 and
                      "json" in sr.content_type), None)
        if not probe:
            return
        forged = f"{_b64e(json.dumps({**header, 'alg': 'none'}).encode())}.{_b64e(json.dumps(payload).encode())}."
        try:
            anon = await ctx.fetch(probe, module=self.name, store=False)
            if 200 <= anon.status < 300:
                return  # public resource: inconclusive
            r = await ctx.fetch(probe, module=self.name, store=False, headers={"Authorization": f"Bearer {forged}"})
        except (HttpError, ScopeViolation):
            return
        if 200 <= r.status < 300 and similarity(r.text, ctx.kb.responses.items[probe].text) > 0.8:
            ctx.add(FindingDraft(title="El servidor acepta JWT con alg=none (firma no verificada)", category="api_jwt_weak",
                                 module=self.name, confidence="confirmed", native_evidence=True,
                                 asset=urlsplit(probe).hostname or "", endpoint=probe, method="GET",
                                 cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                                 evidence={"request": f"GET {probe} con Authorization: Bearer <token alg=none>",
                                           "estado_anonimo": anon.status, "estado_token_forjado": r.status},
                                 fingerprint_extra="alg-none-accepted"))

    # ------------------------------------------------------------------ GraphQL
    async def graphql(self, ctx: ScanContext, eps: list[ApiEndpoint]) -> None:
        for url in sorted(ctx.kb.graphql):
            try:
                r = await ctx.fetch(url, method="POST", module=self.name, store=False, json_body=INTROSPECTION)
            except (HttpError, ScopeViolation):
                continue
            try:
                data = r.json()
            except ValueError:
                continue
            schema = (data.get("data") or {}).get("__schema") if isinstance(data, dict) else None
            if schema:
                types = [t["name"] for t in schema.get("types", []) if not str(t.get("name", "")).startswith("__")]
                ctx.add(FindingDraft(title=f"Introspección GraphQL habilitada en {urlsplit(url).path}",
                                     category="graphql_introspection", module=self.name, confidence="confirmed",
                                     native_evidence=True, asset=urlsplit(url).hostname or "", endpoint=url, method="POST",
                                     evidence={"tipos": types[:40], "total_tipos": len(types),
                                               "mutaciones": (schema.get("mutationType") or {}).get("name")}))

    # ------------------------------------------------------------------ API8 verbose errors
    async def verbose_errors(self, ctx: ScanContext, eps: list[ApiEndpoint]) -> None:
        tested = 0
        for e in eps:
            if tested >= 15:
                break
            try:
                if e.method in ("POST", "PUT", "PATCH") and ctx.cfg.at_least("standard") and "{" not in e.url:
                    r = await ctx.fetch(e.url, method="POST" if e.method == "POST" else e.method, module=self.name,
                                        store=False, content=b'{"vigia": "\x00", ', headers={"Content-Type": "application/json"})
                elif e.method == "GET" and e.params:
                    r = await ctx.fetch(with_param(e.url, e.params[0]["name"], "%' \"{[vigia"), module=self.name, store=False)
                else:
                    continue
            except (HttpError, ScopeViolation):
                continue
            tested += 1
            sig = find_signature(r.text, ERROR_SIGNATURES)
            if sig:
                ctx.add(FindingDraft(title=f"La API devuelve trazas internas ({sig[0]}) en {urlsplit(e.url).path}",
                                     category="api_verbose_errors", module=self.name, confidence="confirmed",
                                     native_evidence=True, asset=urlsplit(e.url).hostname or "", endpoint=e.url,
                                     method=e.method, evidence={"status": r.status, "response_excerpt": sig[1][:800]}))

    # ------------------------------------------------------------------ SSRF / open redirect parameters
    async def ssrf_redirect(self, ctx: ScanContext, eps: list[ApiEndpoint]) -> None:
        cands: list[tuple[str, str]] = []
        for url in list(ctx.kb.urls):
            from vigia.modules.common import query_params
            for p in query_params(url):
                cands.append((url, p))
        for e in eps:
            for p in e.params:
                if p.get("in") == "query" and e.method == "GET" and "{" not in e.url:
                    cands.append((e.url, p["name"]))
        done: set[tuple[str, str]] = set()
        for url, p in cands:
            key = (endpoint_template(url).split("?")[0], p)
            if key in done:
                continue
            done.add(key)
            if REDIRECT_PARAMS.match(p):
                await self._open_redirect(ctx, url, p)
            elif SSRF_PARAMS.match(p) and ctx.cfg.at_least("standard"):
                await self._ssrf(ctx, url, p)

    async def _open_redirect(self, ctx: ScanContext, url: str, p: str) -> None:
        mark = canary()
        for payload in (f"https://{mark}.vigia-redirect.example/", f"//{mark}.vigia-redirect.example/"):
            try:
                r = await ctx.fetch(with_param(url, p, payload), module=self.name, store=False, follow_redirects=False)
            except (HttpError, ScopeViolation):
                return
            loc = r.header("location")
            if r.status in (301, 302, 303, 307, 308) and urlsplit(urljoin(url, loc)).hostname == f"{mark}.vigia-redirect.example":
                ctx.add(FindingDraft(title=f"Redirección abierta en el parámetro «{p}» ({urlsplit(url).path})",
                                     category="open_redirect", module=self.name, confidence="confirmed", native_evidence=True,
                                     asset=urlsplit(url).hostname or "", endpoint=url, method="GET", parameter=p,
                                     evidence={"request": f"GET {with_param(url, p, payload)}", "status": r.status,
                                               "location": loc}))
                return

    async def _ssrf(self, ctx: ScanContext, url: str, p: str) -> None:
        """Differential, non-destructive: closed loopback port vs unroutable TEST-NET vs harmless value."""
        variants = {"benigno": "vigia", "loopback_cerrado": "http://127.0.0.1:1/", "test_net": "http://192.0.2.1:81/"}
        results: dict[str, tuple[int, float, str]] = {}
        for label, val in variants.items():
            t0 = time.monotonic()
            try:
                r = await ctx.fetch(with_param(url, p, val), module=self.name, store=False)
                results[label] = (r.status, time.monotonic() - t0, r.text[:3000])
            except HttpError:
                results[label] = (0, time.monotonic() - t0, "timeout/error")
            except ScopeViolation:
                return
        b, lo, tn = results["benigno"], results["loopback_cerrado"], results["test_net"]
        conn_errors = re.compile(r"connection refused|ECONNREFUSED|Failed to establish|Errno 111|timed out|"
                                 r"No route to host|getaddrinfo|cURL error|URLError|Connection reset", re.I)
        signs = []
        if conn_errors.search(lo[2]) and not conn_errors.search(b[2]):
            signs.append("error de conexión al usar 127.0.0.1:1")
        if tn[1] - b[1] > 4 and tn[1] - lo[1] > 3:
            signs.append(f"retardo de {tn[1]:.1f}s con una IP no enrutable (el servidor intentó conectar)")
        if signs:
            ctx.add(FindingDraft(title=f"Posible SSRF en el parámetro «{p}» ({urlsplit(url).path})", category="ssrf",
                                 module=self.name, confidence="likely" if len(signs) > 1 else "suspected",
                                 native_evidence=True, asset=urlsplit(url).hostname or "", endpoint=url, method="GET",
                                 parameter=p,
                                 description="El comportamiento del servidor cambia según el destino de red indicado en el "
                                             "parámetro: " + "; ".join(signs) + ". Vigía no intenta acceder a servicios "
                                             "internos ni a metadatos.",
                                 evidence={k: {"status": v[0], "tiempo_s": round(v[1], 2)} for k, v in results.items()}))

    # ------------------------------------------------------------------ API3 mass assignment (static)
    async def mass_assignment_static(self, ctx: ScanContext, eps: list[ApiEndpoint]) -> None:
        for e in eps:
            if e.method not in ("POST", "PUT", "PATCH") or not e.body_schema:
                continue
            props = (e.body_schema.get("properties") or {}) if isinstance(e.body_schema, dict) else {}
            risky = [k for k, v in props.items() if PRIV_PROPS.match(k) and not (isinstance(v, dict) and v.get("readOnly"))]
            if risky:
                ctx.add(FindingDraft(
                    title=f"Posible mass assignment: {e.method} {urlsplit(e.url).path} acepta {', '.join(risky[:4])}",
                    category="api_mass_assignment", module=self.name, confidence="suspected", native_evidence=False,
                    asset=urlsplit(e.url).hostname or "", endpoint=e.url, method=e.method, parameter=risky[0],
                    description="El esquema de entrada documenta propiedades privilegiadas como escribibles. Fuera de modo "
                                "laboratorio no se envían escrituras para comprobarlo (política no destructiva).",
                    evidence={"propiedades_privilegiadas": risky, "fuente": e.source}))

    # ------------------------------------------------------------------ API9 inventory
    async def inventory(self, ctx: ScanContext, eps: list[ApiEndpoint]) -> None:
        versions: dict[str, set[str]] = {}
        for e in eps:
            m = re.search(r"/(v\d+)(/|$)", urlsplit(e.url).path)
            if m:
                versions.setdefault(origin(e.url), set()).add(m.group(1))
        for o, vs in versions.items():
            if len(vs) < 2:
                continue
            old = sorted(vs, key=lambda v: int(v[1:]))[0]
            sample = next((e.url for e in eps if f"/{old}/" in e.url and e.method == "GET" and "{" not in e.url), None)
            if not sample:
                continue
            try:
                r = await ctx.fetch(sample, module=self.name, store=False)
            except (HttpError, ScopeViolation):
                continue
            if r.status < 400:
                ctx.add(FindingDraft(title=f"Versión antigua de la API aún accesible ({old}) en {urlsplit(o).hostname}",
                                     category="api_inventory", module=self.name, confidence="confirmed", native_evidence=True,
                                     asset=urlsplit(o).hostname or "", endpoint=sample, method="GET",
                                     evidence={"versiones": sorted(vs), "status": r.status}))
        internal = [e for e in eps if re.search(r"/(internal|debug|test|dev|private|_)\w*/", urlsplit(e.url).path)]
        if internal:
            ctx.add(FindingDraft(title=f"Endpoints internos o de depuración en el inventario de la API ({len(internal)})",
                                 category="api_inventory", module=self.name, confidence="suspected", native_evidence=True,
                                 asset=urlsplit(internal[0].url).hostname or "", endpoint=internal[0].url,
                                 evidence={"muestra": [f"{e.method} {urlsplit(e.url).path}" for e in internal[:15]]},
                                 fingerprint_extra="internal"))

    # ------------------------------------------------------------------ OAuth / OIDC
    async def oauth(self, ctx: ScanContext, eps: list[ApiEndpoint]) -> None:
        for base in ctx.kb.base_urls[:3]:
            url = urljoin(origin(base), "/.well-known/openid-configuration")
            try:
                r = await ctx.fetch(url, module=self.name, store=False)
                cfg = r.json() if r.status == 200 and "json" in r.content_type else None
            except (HttpError, ScopeViolation, ValueError):
                continue
            if not isinstance(cfg, dict):
                continue
            problems = []
            if "token" in " ".join(cfg.get("response_types_supported", [])).split():
                problems.append("admite el flujo implícito (response_type=token)")
            if "S256" not in (cfg.get("code_challenge_methods_supported") or []):
                problems.append("no anuncia PKCE con S256")
            if problems:
                ctx.add(FindingDraft(title=f"Configuración OIDC mejorable: {problems[0]}", category="oauth_misconfig",
                                     module=self.name, confidence="confirmed", native_evidence=True, severity="low",
                                     cvss_vector=None, asset=urlsplit(base).hostname or "", endpoint=url,
                                     evidence={"problemas": problems, "issuer": cfg.get("issuer")}))
        for u in [u for u in ctx.kb.urls if "client_id=" in u and "redirect_uri=" in u][:3]:
            evil = f"https://{canary()}.vigia-oauth.example/cb"
            try:
                r = await ctx.fetch(with_param(u, "redirect_uri", evil), module=self.name, store=False, follow_redirects=False)
            except (HttpError, ScopeViolation):
                continue
            if r.status in (301, 302, 303, 307, 308) and r.header("location").startswith(evil):
                ctx.add(FindingDraft(title="OAuth acepta un redirect_uri arbitrario", category="oauth_misconfig",
                                     module=self.name, confidence="confirmed", native_evidence=True,
                                     asset=urlsplit(u).hostname or "", endpoint=u, method="GET", parameter="redirect_uri",
                                     cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
                                     evidence={"redirect_uri_enviado": evil, "location": r.header("location")[:200]}))

    # ------------------------------------------------------------------ API4 rate limiting
    async def rate_limit(self, ctx: ScanContext, eps: list[ApiEndpoint]) -> None:
        targets: list[tuple[str, str, dict | None]] = []
        for f in ctx.kb.forms:
            if "password" in f.field_types.values() and f.method == "POST":
                user_field = next((k for k, t in f.field_types.items() if t in ("text", "email")), None)
                pw_field = next(k for k, t in f.field_types.items() if t == "password")
                if user_field:
                    data = dict(f.fields)
                    data[user_field] = f"vigia-ratelimit-{canary()}@invalid.example"
                    data[pw_field] = "Vigia-not-a-password-" + canary()
                    targets.append(("POST", f.action, data))
                    break
        if not targets:
            get_ep = next((e.url for e in eps if e.method == "GET" and "{" not in e.url), None)
            if get_ep:
                targets.append(("GET", get_ep, None))
        for method, url, data in targets:
            statuses: list[int] = []
            limited = False
            for _ in range(25):
                try:
                    r = await ctx.fetch(url, method=method, module=self.name, store=False, data=data,
                                        follow_redirects=False)
                except (HttpError, ScopeViolation):
                    break
                statuses.append(r.status)
                if r.status == 429 or any(h in {k.lower() for k in r.headers} for h in
                                          ("retry-after", "x-ratelimit-remaining", "ratelimit-remaining", "ratelimit",
                                           "ratelimit-policy", "x-ratelimit-limit", "ratelimit-limit")):
                    limited = True
                    break
            if len(statuses) >= 25 and not limited:
                login = method == "POST"
                ctx.add(FindingDraft(
                    title=f"Sin limitación de peticiones en {'el login' if login else 'la API'} ({urlsplit(url).path})",
                    category="api_no_rate_limit", module=self.name, confidence="likely" if login else "suspected",
                    native_evidence=True, asset=urlsplit(url).hostname or "", endpoint=url, method=method,
                    description=f"Se enviaron {len(statuses)} peticiones seguidas (usuario inexistente en el caso del login) "
                                "sin respuesta 429 ni cabeceras de rate limit. El ritmo de prueba está limitado por la "
                                "configuración del escaneo; un límite más alto podría existir.",
                    evidence={"peticiones": len(statuses), "estados": sorted(set(statuses))}))


async def _sleep(s: float) -> None:
    await asyncio.sleep(s)
