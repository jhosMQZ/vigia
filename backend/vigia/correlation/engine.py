"""Correlation engine: dedupe → merge → confidence → code↔deploy → attack chains → priority → persist.

Confidence rule (docs/02-arquitectura.md §4): a finding is ``confirmed`` only if a Vigía module produced
its own differential evidence or a direct observation. External tools alone cap at ``likely``; two
independent sources raise one level, never to ``confirmed`` without native evidence.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import delete, select

from vigia.core.findings import CONF_RANK, SEV_RANK, FindingDraft, endpoint_template
from vigia.correlation import intel
from vigia.correlation.catalog import enrich, score
from vigia.db import AttackChain, Finding, SessionLocal

_CONF_BY_RANK = {v: k for k, v in CONF_RANK.items()}
_SEV_BY_RANK = {v: k for k, v in SEV_RANK.items()}
_SEV_BASE = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}


@dataclass
class Merged:
    draft: FindingDraft
    members: list[FindingDraft] = field(default_factory=list)
    kev: bool = False
    epss: float | None = None
    chain_ids: list[int] = field(default_factory=list)
    priority: float = 0.0
    correlated_with: list[str] = field(default_factory=list)

    @property
    def fp(self) -> str:
        return self.draft.fingerprint


def _source_family(src: str) -> str:
    return src.split(":")[0] if src.startswith(("native", "tool")) else src


def merge(drafts: list[FindingDraft]) -> list[Merged]:
    groups: dict[str, list[FindingDraft]] = defaultdict(list)
    for d in drafts:
        if d.confidence == "false_positive":
            continue
        groups[d.fingerprint].append(d)
    out: list[Merged] = []
    for fp, items in groups.items():
        items.sort(key=lambda d: (d.native_evidence, CONF_RANK[d.confidence], SEV_RANK[d.severity]), reverse=True)
        base = items[0]
        m = Merged(draft=FindingDraft(**{k: v for k, v in base.__dict__.items()}), members=items)
        d = m.draft
        d.sources = sorted({s for it in items for s in it.sources})
        d.cve = sorted({c for it in items for c in it.cve})
        d.references = list(dict.fromkeys(r for it in items for r in it.references))
        d.tags = sorted({t for it in items for t in it.tags})
        # keep the worst-case score among members
        best = max(items, key=lambda it: (score(it) or -1, SEV_RANK[it.severity]))
        d.cvss_vector, d.severity = best.cvss_vector, best.severity
        if len(items) > 1:
            d.evidence = {**base.evidence, "otras_fuentes": [{"source": it.sources, "evidence": it.evidence}
                                                             for it in items[1:4]]}
        d.native_evidence = any(it.native_evidence for it in items)
        d.confidence = _confidence(items)
        out.append(m)
    return out


def _confidence(items: list[FindingDraft]) -> str:
    native = [it for it in items if it.native_evidence]
    external = [it for it in items if not it.native_evidence]
    if native:
        level = max(CONF_RANK[it.confidence] for it in native)
    else:
        level = min(CONF_RANK["likely"], max(CONF_RANK[it.confidence] for it in external))
    families = {_source_family(s) for it in items for s in it.sources}
    if len(families) >= 2:
        cap = CONF_RANK["confirmed"] if native and level >= CONF_RANK["likely"] else CONF_RANK["likely"]
        level = min(level + 1, cap)
    if not native:
        level = min(level, CONF_RANK["likely"])
    return _CONF_BY_RANK[level]


# ------------------------------------------------------------------ code <-> deployment
def _route_regex(path: str) -> re.Pattern[str]:
    p = re.sub(r"\{[^}]+\}|<[^>]+>|:[A-Za-z_]\w*|\[[^\]]+\]", "§", path.rstrip("/") or "/")
    p = re.escape(p).replace("§", "[^/]+")
    return re.compile(rf"^{p}/?$")


def code_deploy_links(merged: list[Merged], code_routes: list[dict[str, Any]]) -> list[tuple[Merged, Merged]]:
    """Pairs (code finding, deployed finding) that concern the same route/handler."""
    by_file: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in code_routes:
        by_file[r.get("file", "")].append(r)
    code_f = [m for m in merged if m.draft.file]
    dep_f = [m for m in merged if m.draft.endpoint and not m.draft.file]
    links = []
    for cm in code_f:
        routes = [r for r in by_file.get(cm.draft.file or "", [])
                  if not r.get("end_line") or (r.get("line", 0) <= (cm.draft.line or 0) <= r.get("end_line", 10**9))]
        for r in routes:
            rx = _route_regex(r["path"])
            for dm in dep_f:
                path = urlsplit(dm.draft.endpoint or "").path
                if rx.match(path) and _same_family(cm.draft.category, dm.draft.category):
                    links.append((cm, dm))
    return links


_FAMILIES = [{"sast_sqli", "sqli"}, {"sast_cmdi", "cmdi"}, {"sast_xss", "xss_reflected", "xss_stored", "html_injection"},
             {"sast_path_traversal", "path_traversal"}, {"sast_ssrf", "ssrf"}, {"sast_template_injection", "ssti"},
             {"sast_nosql", "nosqli"}, {"sast_open_redirect", "open_redirect"}, {"sast_ldap", "ldapi"},
             {"sast_missing_auth", "api_auth_missing", "route_unprotected", "api_bola", "api_bfla"},
             {"sast_debug", "exposed_debug", "error_disclosure"}, {"sast_cors_any", "cors_misconfig"}]


def _same_family(a: str, b: str) -> bool:
    return any(a in fam and b in fam for fam in _FAMILIES)


# ------------------------------------------------------------------ attack chains
@dataclass
class ChainRule:
    key: str
    title: str
    groups: list[set[str]]  # one finding from each group, same host (or code+deploy)
    narrative: str
    recommendation: str
    same_host: bool = True


CHAIN_RULES = [
    ChainRule("api_authz_leak", "API expuesta con autorización deficiente y filtración de información",
              [{"exposed_api_docs", "api_inventory", "graphql_introspection", "route_shadow"},
               {"api_bola", "api_bfla", "api_auth_missing", "route_unprotected", "sast_missing_auth"},
               {"api_excessive_data", "error_disclosure", "api_verbose_errors", "api_jwt_sensitive"}],
              "El inventario público de la API ({0}) permite localizar endpoints; el control de autorización deficiente "
              "({1}) permite invocarlos sin los permisos adecuados; y la filtración ({2}) expone datos o detalles internos. "
              "Juntos forman un único problema: acceso no autorizado a datos a través de la API.",
              "Prioriza el control de autorización en el servidor; después reduce la exposición del inventario y filtra las respuestas."),
    ChainRule("leaked_secret_service", "Credenciales filtradas y servicio accesible para usarlas",
              [{"exposed_env", "exposed_config", "exposed_git", "js_secret", "secret_exposed", "sast_hardcoded_secret",
                "iac_secret", "exposed_backup", "exposed_db_dump"},
               {"exposed_database", "db_no_auth", "exposed_admin", "exposed_remote_admin", "exposed_container_api",
                "exposed_debug"}],
              "Se han expuesto credenciales o configuración ({0}) y existe un servicio accesible ({1}) donde podrían "
              "utilizarse para obtener acceso.", "Rota los secretos y cierra el acceso público al servicio.", same_host=False),
    ChainRule("xss_session", "XSS con sesión robable",
              [{"xss_reflected", "xss_stored", "xss_dom", "sast_xss"},
               {"insecure_cookie", "js_token_storage"}, {"missing_csp", "weak_csp"}],
              "Un XSS ({0}) puede leer la sesión porque esta es accesible desde JavaScript ({1}) y no hay CSP efectiva ({2}) "
              "que lo mitigue: secuestro de cuentas.",
              "Corrige el XSS, marca la cookie de sesión como HttpOnly y despliega una CSP con nonces."),
    ChainRule("mitm_session", "Interceptación de sesión por transporte débil",
              [{"no_https", "missing_hsts", "tls_old_protocol", "tls_weak_cipher", "cert_invalid", "mixed_content"},
               {"insecure_cookie"}],
              "El transporte es degradable o débil ({0}) y la cookie de sesión no está protegida ({1}): un atacante en la "
              "red puede capturar sesiones.", "Fuerza HTTPS con HSTS y marca las cookies como Secure."),
    ChainRule("code_to_rce", "Ejecución de código alcanzable desde el despliegue",
              [{"sast_cmdi", "sast_code_injection", "sast_deserialization", "sast_template_injection", "cmdi", "ssti"},
               {"route_unprotected", "api_auth_missing", "exposed_debug"}],
              "Existe un patrón de ejecución de código ({0}) y la superficie que lo alcanza es accesible sin control "
              "suficiente ({1}).", "Elimina el patrón inseguro y protege la ruta.", same_host=False),
    ChainRule("ssrf_cloud", "SSRF con posible acceso a metadatos cloud",
              [{"ssrf", "sast_ssrf"}, {"tech_fingerprint"}],
              "Hay un vector SSRF ({0}) en una aplicación desplegada en infraestructura cloud ({1}); los servicios de "
              "metadatos podrían exponer credenciales temporales.",
              "Corrige el SSRF y exige IMDSv2 / bloquea 169.254.169.254 desde la aplicación.", same_host=False),
    ChainRule("source_and_secrets", "Código fuente público con secretos",
              [{"exposed_git", "exposed_backup", "exposed_sourcemap"}, {"secret_exposed", "sast_hardcoded_secret"}],
              "El código es recuperable públicamente ({0}) y contiene secretos ({1}).",
              "Bloquea el acceso, purga el historial y rota los secretos.", same_host=False),
    ChainRule("admin_bruteforce", "Panel administrativo expuesto sin protección contra fuerza bruta",
              [{"exposed_admin", "exposed_remote_admin"}, {"api_no_rate_limit", "auth_weakness"}],
              "El panel ({0}) es accesible desde Internet y no limita intentos de autenticación ({1}).",
              "Restringe el panel por red, añade MFA y limitación de intentos.", same_host=False),
    ChainRule("vulnerable_exposed", "Componente vulnerable explotable en activo",
              [{"outdated_component", "js_vulnerable_library", "vulnerable_dependency"},
               {"exposed_admin", "exposed_api_docs", "version_disclosure", "service_version_disclosure"}],
              "Se usa un componente con vulnerabilidades conocidas ({0}) y su versión o superficie es visible ({1}), lo "
              "que facilita la explotación automatizada.", "Actualiza el componente y oculta versiones.", same_host=False),
]

_CLOUD_TECH = re.compile(r"aws|amazon|cloudfront|gcp|google cloud|azure|heroku|vercel|netlify|digitalocean", re.I)


def find_chains(merged: list[Merged]) -> list[dict[str, Any]]:
    chains = []
    usable = [m for m in merged if m.draft.confidence in ("confirmed", "likely", "suspected")]
    for rule in CHAIN_RULES:
        hosts: dict[str, list[list[Merged]]] = defaultdict(lambda: [[] for _ in rule.groups])
        for m in usable:
            if rule.key == "ssrf_cloud" and m.draft.category == "tech_fingerprint" and not _CLOUD_TECH.search(m.draft.title):
                continue
            host = (urlsplit(m.draft.endpoint).hostname if m.draft.endpoint else None) or m.draft.asset or "code"
            key = host if rule.same_host else "*"
            for gi, grp in enumerate(rule.groups):
                if m.draft.category in grp:
                    hosts[key][gi].append(m)
        for host, slots in hosts.items():
            if not all(slots):
                continue
            picks = [max(s, key=lambda m: (CONF_RANK[m.draft.confidence], score(m.draft) or 0)) for s in slots]
            worst = max(SEV_RANK[p.draft.severity] for p in picks)
            all_solid = all(p.draft.confidence in ("confirmed", "likely") for p in picks)
            sev = _SEV_BY_RANK[min(4, worst + (1 if all_solid and len(picks) >= 2 else 0))]
            chains.append({"rule": rule.key, "title": rule.title + ("" if host == "*" else f" ({host})"), "severity": sev,
                           "narrative": rule.narrative.format(*[p.draft.title for p in picks]),
                           "recommendation": rule.recommendation, "members": picks})
    return chains


# ------------------------------------------------------------------ priority + intel
def prioritise(merged: list[Merged], in_chain: set[str], offline: bool) -> None:
    cves = sorted({c for m in merged for c in m.draft.cve if c.startswith("CVE-")})
    kev, epss_scores = (set(), {})
    if cves and not offline:
        kev = intel.kev_set()
        epss_scores = intel.epss(cves)
    conf_w = {"confirmed": 1.0, "likely": 0.8, "suspected": 0.5}
    for m in merged:
        d = m.draft
        base = score(d) if d.cvss_vector else _SEV_BASE[d.severity]
        m.kev = any(c in kev for c in d.cve)
        m.epss = max((epss_scores.get(c, 0.0) for c in d.cve), default=None) if d.cve else None
        p = (base or 0.5) * 10 * conf_w.get(d.confidence, 0.4)
        if m.fp in in_chain:
            p *= 1.25
        if m.kev:
            p *= 1.5
        if m.epss:
            p *= 1 + min(m.epss, 1.0) * 0.5
        if d.file and not d.endpoint and not m.correlated_with:
            p *= 0.85  # code-only: exploitability not demonstrated
        m.priority = round(min(p, 100.0), 1)


def correlate_and_store(scan_id: int, project_id: int, drafts: list[FindingDraft], code_routes: list[dict[str, Any]],
                        offline: bool) -> dict[str, Any]:
    for d in drafts:
        enrich(d)
    merged = merge(drafts)
    for cm, dm in code_deploy_links(merged, code_routes):
        cm.correlated_with.append(dm.fp)
        dm.correlated_with.append(cm.fp)
        if not cm.draft.native_evidence or CONF_RANK[cm.draft.confidence] < CONF_RANK["likely"]:
            cm.draft.confidence = "likely"  # the deployed counterpart corroborates the code finding
        cm.draft.evidence["correlacion_despliegue"] = dm.draft.endpoint
        dm.draft.evidence["correlacion_codigo"] = f"{cm.draft.file}:{cm.draft.line}"
    chains = find_chains(merged)
    in_chain = {m.fp for c in chains for m in c["members"]}
    prioritise(merged, in_chain, offline)

    with SessionLocal() as db:
        previous = {f.fingerprint: f for f in db.scalars(
            select(Finding).where(Finding.project_id == project_id, Finding.scan_id != scan_id,
                                  Finding.validation_status != "raw").order_by(Finding.id))}
        db.execute(delete(Finding).where(Finding.scan_id == scan_id))
        db.execute(delete(AttackChain).where(AttackChain.scan_id == scan_id))
        rows: dict[str, Finding] = {}
        for m in sorted(merged, key=lambda m: m.priority, reverse=True):
            d = m.draft
            prev = previous.get(m.fp)
            remediation = prev.remediation_status if prev and prev.remediation_status in ("accepted_risk",
                                                                                          "false_positive") else "open"
            ev = dict(d.evidence)
            if m.kev:
                ev["cisa_kev"] = True
            if m.epss is not None:
                ev["epss"] = round(m.epss, 4)
            if m.correlated_with:
                ev["correlacionado_con"] = m.correlated_with[:5]
            row = Finding(scan_id=scan_id, project_id=project_id, fingerprint=m.fp, title=d.title[:255],
                          category=d.category, module=d.module, severity=d.severity, confidence=d.confidence,
                          cvss_vector=d.cvss_vector, cvss_score=score(d), cwe=d.cwe, cve=d.cve, owasp=d.owasp,
                          asset=d.asset[:512], endpoint=(d.endpoint or None) and d.endpoint[:2048], method=d.method,
                          parameter=d.parameter, file=d.file, line=d.line, function=d.function, snippet=d.snippet,
                          description=d.description, evidence=ev, impact=d.impact, likelihood=d.likelihood or "medium",
                          recommendation=d.recommendation, references=d.references[:15], sources=d.sources,
                          priority=m.priority,
                          validation_status={"confirmed": "validated", "likely": "probable"}.get(d.confidence, "unverified"),
                          remediation_status=remediation, analyst_notes=prev.analyst_notes if prev else "")
            db.add(row)
            rows[m.fp] = row
        db.flush()
        for c in chains:
            steps = [{"finding_id": rows[m.fp].id, "title": m.draft.title, "severity": m.draft.severity,
                      "confidence": m.draft.confidence, "endpoint": m.draft.endpoint, "file": m.draft.file}
                     for m in c["members"] if m.fp in rows]
            ch = AttackChain(scan_id=scan_id, rule=c["rule"], title=c["title"][:255], severity=c["severity"],
                             narrative=c["narrative"], steps=steps, recommendation=c["recommendation"])
            db.add(ch)
            db.flush()
            for m in c["members"]:
                if m.fp in rows:
                    rows[m.fp].chain_ids = sorted(set((rows[m.fp].chain_ids or []) + [ch.id]))
        db.commit()
        counts = defaultdict(int)
        for m in merged:
            counts[m.draft.severity] += 1
        return {"findings": len(merged), "raw": len(drafts), "chains": len(chains),
                "by_severity": {s: counts.get(s, 0) for s in ("critical", "high", "medium", "low", "info")},
                "confirmed": sum(1 for m in merged if m.draft.confidence == "confirmed"),
                "kev": sum(1 for m in merged if m.kev),
                "risk_score": risk_score(merged)}


def risk_score(merged: list[Merged]) -> int:
    """0 (no risk observed) … 100: saturating sum of priorities."""
    total = sum(m.priority for m in merged if m.draft.severity != "info")
    return int(round(100 * (1 - pow(0.985, total))))


def endpoint_key(url: str) -> str:
    return endpoint_template(url)
