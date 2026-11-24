"""M07 — Files, backups and secrets accidentally published.

Each candidate is validated by content (magic bytes / structure), never by status code alone. Only the
first 2 KB are requested (Range) and stored redacted; nothing else is downloaded once exposure is proven.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

from vigia.core.context import ApiEndpoint, ScanContext
from vigia.core.findings import FindingDraft
from vigia.core.module import Module
from vigia.modules.common import origin
from vigia.modules.probe import probe_paths, range_headers
from vigia.security.http import HttpError, HttpResponse
from vigia.security.redact import redact
from vigia.security.scope import ScopeViolation


def _txt(r: HttpResponse) -> str:
    return r.content[:4096].decode("utf-8", errors="replace")


def _not_html(r: HttpResponse) -> bool:
    head = r.content[:512].lstrip().lower()
    return not head.startswith((b"<!doctype", b"<html", b"<head", b"<body")) and b"<html" not in head


def v_env(r: HttpResponse) -> bool:
    lines = [l for l in _txt(r).splitlines() if l.strip() and not l.strip().startswith("#")]
    kv = [l for l in lines if re.match(r"^\s*(export\s+)?[A-Z][A-Z0-9_]{1,60}\s*=", l)]
    return _not_html(r) and len(kv) >= 2 and len(kv) >= len(lines) * 0.6


def v_git_head(r: HttpResponse) -> bool:
    return bool(re.match(r"^(ref: refs/heads/\S+|[0-9a-f]{40})\s*$", _txt(r).strip()))


def v_git_config(r: HttpResponse) -> bool:
    return "[core]" in _txt(r) and _not_html(r)


def v_zip(r: HttpResponse) -> bool:
    return r.content[:4] == b"PK\x03\x04"


def v_gzip(r: HttpResponse) -> bool:
    return r.content[:2] == b"\x1f\x8b"


def v_sql(r: HttpResponse) -> bool:
    t = _txt(r)
    return _not_html(r) and bool(re.search(r"(CREATE TABLE|INSERT INTO|DROP TABLE IF EXISTS|-- MySQL dump|PostgreSQL database "
                                           r"dump|SQLite format 3)", t, re.I))


def v_sqlite(r: HttpResponse) -> bool:
    return r.content[:16] == b"SQLite format 3\x00"


def v_php_source(r: HttpResponse) -> bool:
    return b"<?php" in r.content[:2048] and _not_html(r)


def v_ds_store(r: HttpResponse) -> bool:
    return r.content[:8] == b"\x00\x00\x00\x01Bud1"


def v_private_key(r: HttpResponse) -> bool:
    return b"-----BEGIN" in r.content[:200] and b"PRIVATE KEY" in r.content[:200]


def v_log(r: HttpResponse) -> bool:
    t = _txt(r)
    return _not_html(r) and len(re.findall(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}|\[\w{3} \w{3} \d+|ERROR|WARN|INFO|DEBUG|"
                                           r"Stack trace|Exception)", t)) >= 3


def v_json_config(r: HttpResponse) -> bool:
    t = _txt(r).lstrip()
    return t.startswith("{") and bool(re.search(r"\"(password|secret|connectionstring|apikey|api_key|token|database|"
                                                 r"private_key|client_secret)\"", t, re.I))


def v_yaml_config(r: HttpResponse) -> bool:
    t = _txt(r)
    return _not_html(r) and bool(re.search(r"(?im)^\s*(password|secret|username|host|database|api[_-]?key)\s*:", t))


def v_xml_config(r: HttpResponse) -> bool:
    t = _txt(r)
    return "<configuration" in t or "<connectionStrings" in t or ("<?xml" in t and "password" in t.lower())


def v_properties(r: HttpResponse) -> bool:
    t = _txt(r)
    return _not_html(r) and len(re.findall(r"(?m)^[a-z][\w.\-]+\s*[=:]", t)) >= 3


def v_compose(r: HttpResponse) -> bool:
    t = _txt(r)
    return _not_html(r) and "services:" in t and ("image:" in t or "build:" in t)


def v_dockerfile(r: HttpResponse) -> bool:
    return _not_html(r) and bool(re.search(r"(?m)^FROM\s+\S+", _txt(r)))


def v_htpasswd(r: HttpResponse) -> bool:
    return _not_html(r) and bool(re.search(r"(?m)^[\w.\-]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|[./0-9A-Za-z]{13}$)", _txt(r)))


def v_npmrc(r: HttpResponse) -> bool:
    return _not_html(r) and bool(re.search(r"_authToken|_auth\s*=|//registry", _txt(r)))


def v_phpinfo(r: HttpResponse) -> bool:
    return b"phpinfo()" in r.content or (b"PHP Version" in r.content and b"<title>PHP" in r.content)


def v_actuator(r: HttpResponse) -> bool:
    t = _txt(r)
    return t.lstrip().startswith("{") and ("_links" in t or "propertySources" in t or "activeProfiles" in t)


def v_profiler(r: HttpResponse) -> bool:
    return bool(re.search(rb"Symfony Profiler|sf-toolbar|Laravel Telescope|debugbar|django-debug-toolbar|pprof", r.content[:20000],
                          re.I))


def v_server_status(r: HttpResponse) -> bool:
    return b"Apache Server Status" in r.content or b"Server Version:" in r.content and b"Server uptime" in r.content


def v_elmah(r: HttpResponse) -> bool:
    return b"Error Log for" in r.content or b"ELMAH" in r.content


def v_openapi(r: HttpResponse) -> bool:
    t = _txt(r).lstrip()
    return (t.startswith("{") and ('"openapi"' in t or '"swagger"' in t)) or bool(re.match(r"(openapi|swagger):", t))


def v_swagger_ui(r: HttpResponse) -> bool:
    return b"swagger-ui" in r.content[:20000].lower() or b"redoc" in r.content[:20000].lower()


def v_graphiql(r: HttpResponse) -> bool:
    return bool(re.search(rb"graphiql|altair|graphql-playground", r.content[:20000], re.I))


def v_svn(r: HttpResponse) -> bool:
    return v_sqlite(r) or bool(re.match(rb"^\d+\s*\n", r.content[:10])) or b"svn:" in r.content[:2000]


def v_text_doc(r: HttpResponse) -> bool:
    t = _txt(r)
    return _not_html(r) and bool(re.search(r"(password|contraseña|credencial|internal use|confidencial|confidential|"
                                           r"api key|secret)", t, re.I))


@dataclass(frozen=True)
class Probe:
    path: str
    category: str
    title: str
    validator: Callable[[HttpResponse], bool]
    min_intensity: str = "light"


PROBES: list[Probe] = [
    *[Probe(p, "exposed_env", "Fichero de entorno expuesto", v_env) for p in
      ("/.env", "/.env.local", "/.env.production", "/.env.prod", "/.env.dev", "/.env.backup", "/.env.bak", "/.env.old",
       "/api/.env", "/app/.env", "/backend/.env", "/.env.example")],
    Probe("/.git/HEAD", "exposed_git", "Repositorio git expuesto (.git/HEAD)", v_git_head),
    Probe("/.git/config", "exposed_git", "Repositorio git expuesto (.git/config)", v_git_config),
    Probe("/.svn/entries", "exposed_vcs", "Metadatos SVN expuestos", v_svn),
    Probe("/.svn/wc.db", "exposed_vcs", "Base de datos SVN expuesta", v_sqlite),
    Probe("/.hg/hgrc", "exposed_vcs", "Repositorio Mercurial expuesto", lambda r: "[paths]" in _txt(r) and _not_html(r)),
    Probe("/.DS_Store", "exposed_vcs", "Fichero .DS_Store expuesto", v_ds_store),
    *[Probe(p, "exposed_backup", "Copia de seguridad expuesta", v_zip) for p in
      ("/backup.zip", "/site.zip", "/www.zip", "/web.zip", "/html.zip", "/app.zip", "/source.zip", "/release.zip",
       "/{host}.zip", "/dist.zip", "/public.zip", "/old.zip")],
    *[Probe(p, "exposed_backup", "Copia de seguridad expuesta", v_gzip) for p in
      ("/backup.tar.gz", "/site.tar.gz", "/www.tar.gz", "/{host}.tar.gz", "/backup.tgz")],
    *[Probe(p, "exposed_db_dump", "Volcado de base de datos expuesto", v_sql) for p in
      ("/dump.sql", "/db.sql", "/database.sql", "/backup.sql", "/data.sql", "/{host}.sql", "/mysql.sql", "/users.sql",
       "/db/dump.sql", "/sql/backup.sql")],
    *[Probe(p, "exposed_db_dump", "Base de datos SQLite expuesta", v_sqlite) for p in
      ("/db.sqlite", "/database.sqlite", "/db.sqlite3", "/data.db", "/app.db", "/storage/database.sqlite")],
    *[Probe(p, "exposed_backup", "Código fuente en fichero de respaldo", v_php_source) for p in
      ("/index.php.bak", "/index.php~", "/index.php.old", "/config.php.bak", "/config.php~", "/wp-config.php.bak",
       "/wp-config.php~", "/wp-config.php.save", "/.index.php.swp", "/configuration.php.bak", "/settings.php.bak")],
    Probe("/config.json", "exposed_config", "Configuración JSON con secretos expuesta", v_json_config),
    Probe("/appsettings.json", "exposed_config", "appsettings.json expuesto", v_json_config),
    Probe("/appsettings.Development.json", "exposed_config", "appsettings de desarrollo expuesto", v_json_config),
    Probe("/config/config.json", "exposed_config", "Configuración JSON con secretos expuesta", v_json_config),
    Probe("/firebase.json", "exposed_config", "Configuración Firebase expuesta", v_json_config),
    Probe("/config.yml", "exposed_config", "Configuración YAML expuesta", v_yaml_config),
    Probe("/config.yaml", "exposed_config", "Configuración YAML expuesta", v_yaml_config),
    Probe("/config/database.yml", "exposed_config", "database.yml expuesto", v_yaml_config),
    Probe("/application.yml", "exposed_config", "application.yml expuesto", v_yaml_config),
    Probe("/application.properties", "exposed_config", "application.properties expuesto", v_properties),
    Probe("/web.config", "exposed_config", "web.config expuesto", v_xml_config),
    Probe("/WEB-INF/web.xml", "exposed_config", "WEB-INF/web.xml expuesto", v_xml_config),
    Probe("/docker-compose.yml", "exposed_config", "docker-compose.yml expuesto", v_compose),
    Probe("/docker-compose.yaml", "exposed_config", "docker-compose.yaml expuesto", v_compose),
    Probe("/Dockerfile", "exposed_config", "Dockerfile expuesto", v_dockerfile, "standard"),
    Probe("/.htpasswd", "exposed_config", "Fichero .htpasswd expuesto", v_htpasswd),
    Probe("/.npmrc", "exposed_config", "Fichero .npmrc expuesto", v_npmrc),
    Probe("/.pypirc", "exposed_config", "Fichero .pypirc expuesto", lambda r: "[pypi]" in _txt(r) or "[distutils]" in _txt(r)),
    Probe("/.aws/credentials", "exposed_config", "Credenciales AWS expuestas", lambda r: "aws_access_key_id" in _txt(r).lower()),
    Probe("/.docker/config.json", "exposed_config", "Credenciales de Docker expuestas", lambda r: '"auths"' in _txt(r)),
    Probe("/.travis.yml", "exposed_config", "Configuración CI expuesta", v_yaml_config, "standard"),
    Probe("/.gitlab-ci.yml", "exposed_config", "Configuración CI expuesta", v_yaml_config, "standard"),
    *[Probe(p, "exposed_log", "Fichero de log expuesto", v_log) for p in
      ("/debug.log", "/error.log", "/error_log", "/access.log", "/logs/error.log", "/log/development.log",
       "/log/production.log", "/storage/logs/laravel.log", "/npm-debug.log", "/wp-content/debug.log", "/app.log",
       "/logs/app.log")],
    *[Probe(p, "exposed_private_key", "Clave privada expuesta", v_private_key) for p in
      ("/id_rsa", "/.ssh/id_rsa", "/server.key", "/private.key", "/privatekey.pem", "/key.pem", "/ssl/server.key",
       "/cert/private.key", "/id_ed25519")],
    Probe("/phpinfo.php", "exposed_debug", "phpinfo() expuesto", v_phpinfo),
    Probe("/info.php", "exposed_debug", "phpinfo() expuesto", v_phpinfo),
    Probe("/test.php", "exposed_debug", "phpinfo() expuesto", v_phpinfo),
    Probe("/actuator", "exposed_debug", "Spring Boot Actuator expuesto", v_actuator),
    Probe("/actuator/env", "exposed_debug", "Spring Boot Actuator /env expuesto", v_actuator),
    Probe("/actuator/configprops", "exposed_debug", "Spring Boot Actuator /configprops expuesto", v_actuator),
    Probe("/manage/env", "exposed_debug", "Actuator (/manage) expuesto", v_actuator),
    Probe("/_profiler/", "exposed_debug", "Symfony Profiler expuesto", v_profiler),
    Probe("/_debugbar/open", "exposed_debug", "Laravel Debugbar expuesto", v_profiler),
    Probe("/telescope/requests", "exposed_debug", "Laravel Telescope expuesto", v_profiler),
    Probe("/__debug__/", "exposed_debug", "Django Debug Toolbar expuesto", v_profiler),
    Probe("/debug/pprof/", "exposed_debug", "Go pprof expuesto", v_profiler),
    Probe("/server-status", "exposed_debug", "Apache server-status expuesto", v_server_status),
    Probe("/elmah.axd", "exposed_debug", "ELMAH expuesto", v_elmah),
    Probe("/trace.axd", "exposed_debug", "ASP.NET trace.axd expuesto", lambda r: b"Application Trace" in r.content),
    Probe("/console", "exposed_debug", "Consola de depuración Werkzeug expuesta",
          lambda r: b"Werkzeug" in r.content and b"console" in r.content.lower()),
    *[Probe(p, "exposed_api_docs", "Especificación OpenAPI/Swagger expuesta", v_openapi) for p in
      ("/openapi.json", "/swagger.json", "/swagger/v1/swagger.json", "/v2/api-docs", "/v3/api-docs", "/api-docs",
       "/api/swagger.json", "/api/openapi.json", "/api/v1/openapi.json", "/docs/openapi.json", "/openapi.yaml",
       "/swagger.yaml")],
    *[Probe(p, "exposed_api_docs", "Interfaz Swagger/Redoc expuesta", v_swagger_ui) for p in
      ("/swagger-ui.html", "/swagger-ui/", "/swagger/", "/docs", "/redoc", "/api/docs")],
    *[Probe(p, "graphql_introspection", "Consola GraphQL expuesta", v_graphiql) for p in ("/graphiql", "/playground",
                                                                                        "/altair")],
    *[Probe(p, "exposed_internal_doc", "Documentación interna expuesta", v_text_doc, "standard") for p in
      ("/TODO.txt", "/notes.txt", "/passwords.txt", "/credentials.txt", "/internal.txt", "/INSTALL.txt", "/deploy.txt")],
]
_INTENSITY = {"passive": 0, "light": 1, "standard": 2, "deep": 3}


class ExposureModule(Module):
    name = "exposure"
    title = "Ficheros, backups y secretos expuestos"
    phases = ("discovery", "analysis")
    needs_target = True

    async def run_phase(self, ctx: ScanContext, phase: str) -> None:
        if phase == "discovery":
            await self.probe_known_paths(ctx)
        else:
            await self.source_maps(ctx)
            if ctx.cfg.at_least("deep"):
                await self.backup_variants(ctx)

    async def probe_known_paths(self, ctx: ScanContext) -> None:
        level = _INTENSITY[ctx.cfg.intensity]
        probes = [p for p in PROBES if _INTENSITY[p.min_intensity] <= level]
        bases = list(dict.fromkeys(origin(b) + "/" for b in ctx.kb.base_urls))
        for i, base in enumerate(bases):
            ctx.check()
            host = urlsplit(base).hostname or ""
            paths = {p.path.replace("{host}", host.split(".")[0]): p for p in probes}
            hits = await probe_paths(ctx, base, list(paths), self.name, headers=range_headers())
            confirmed_cats: set[str] = set()
            for path, r in hits:
                pr = paths[path]
                if r.status not in (200, 206) or not pr.validator(r):
                    continue
                if pr.category in ("exposed_env", "exposed_git", "exposed_api_docs") and pr.category in confirmed_cats:
                    continue  # one proof per host is enough: stop collecting
                confirmed_cats.add(pr.category)
                excerpt = redact(r.content[:1200].decode("utf-8", errors="replace"), 1200) if pr.category not in (
                    "exposed_backup", "exposed_db_dump", "exposed_vcs") or not r.content[:4].isascii() else None
                ctx.add(FindingDraft(
                    title=f"{pr.title}: {path} ({host})", category=pr.category, module=self.name, confidence="confirmed",
                    native_evidence=True, asset=host, endpoint=r.url, method="GET",
                    description=f"El recurso {path} es accesible públicamente y su contenido coincide con la firma de "
                                f"{pr.title.lower()}. Se obtuvieron solo los primeros bytes como evidencia y no se "
                                "descargó nada más.",
                    evidence={"request": f"GET {r.url} (Range: bytes=0-2047)", "status": r.status,
                              "content_type": r.content_type, "tamaño_declarado": r.header("content-range") or
                              r.header("content-length"), "primeros_bytes_hex": r.content[:16].hex(),
                              "extracto_redactado": excerpt}))
                if pr.category == "exposed_api_docs" and pr.validator is v_openapi:
                    await self._import_openapi(ctx, r)
            ctx.progress(self.name + ":discovery", "running", int(100 * (i + 1) / max(1, len(bases))))

    async def _import_openapi(self, ctx: ScanContext, r: HttpResponse) -> None:
        from vigia.modules.api import import_openapi_from_url
        try:
            n = await import_openapi_from_url(ctx, r.url)
            ctx.emit("info", self.name, f"Especificación OpenAPI importada desde {r.url}: {n} operaciones")
        except Exception as e:  # noqa: BLE001
            ctx.emit("warn", self.name, f"No se pudo importar la especificación {r.url}: {e}")

    async def source_maps(self, ctx: ScanContext) -> None:
        found = 0
        for js in sorted(ctx.kb.scripts)[:80]:
            ctx.check()
            sr = ctx.kb.responses.items.get(js)
            cands = []
            if sr is not None:
                m = re.search(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)", sr.text[-3000:])
                if m and not m.group(1).startswith("data:"):
                    from urllib.parse import urljoin
                    cands.append(urljoin(js, m.group(1)))
            cands.append(js.split("?")[0] + ".map")
            for url in dict.fromkeys(cands):
                try:
                    r = await ctx.fetch(url, module=self.name, store=False, headers=range_headers(4095))
                except (HttpError, ScopeViolation):
                    continue
                t = r.content[:4096].decode("utf-8", errors="replace")
                if r.status in (200, 206) and '"mappings"' in t and ('"sources"' in t or '"version"' in t):
                    sources = re.findall(r'"(?:webpack://|\.\./|\./|/)?([^"]{3,120}\.(?:ts|tsx|js|jsx|vue|svelte))"', t)[:15]
                    ctx.add(FindingDraft(title=f"Source map público: {urlsplit(url).path}", category="exposed_sourcemap",
                                         module=self.name, confidence="confirmed", native_evidence=True,
                                         asset=urlsplit(url).hostname or "", endpoint=url,
                                         evidence={"request": f"GET {url}", "status": r.status,
                                                   "ficheros_fuente_muestra": sources}))
                    found += 1
                    break
            if found >= 10:
                break

    async def backup_variants(self, ctx: ScanContext) -> None:
        dynamic = [u for u in ctx.kb.urls if re.search(r"\.(php|asp|aspx|jsp|py|rb|config|inc)$", urlsplit(u).path)][:25]
        for url in dynamic:
            ctx.check()
            base = origin(url) + "/"
            path = urlsplit(url).path
            variants = [path + s for s in (".bak", "~", ".old", ".orig", ".save", ".swp")]
            hits = await probe_paths(ctx, base, variants, self.name, headers=range_headers())
            for vpath, r in hits:
                if r.status in (200, 206) and (v_php_source(r) or (b"<%" in r.content[:2000] and _not_html(r))):
                    ctx.add(FindingDraft(title=f"Copia de código fuente accesible: {vpath}", category="exposed_backup",
                                         module=self.name, confidence="confirmed", native_evidence=True,
                                         asset=urlsplit(url).hostname or "", endpoint=r.url,
                                         evidence={"request": f"GET {r.url}", "status": r.status,
                                                   "extracto_redactado": redact(_txt(r)[:600], 600)}))

    @staticmethod
    def as_api(ctx: ScanContext, method: str, url: str) -> None:
        ctx.kb.api.append(ApiEndpoint(method=method, url=url, source="exposure"))
