"""Adapters for external engines: build a scoped command, run it isolated, normalise the output.

Rules shared by all adapters:
  * the engine must be reported ``available`` by the registry (real binary, real version, not deny-listed);
    otherwise the run is recorded as *skipped* with the real reason — results are never simulated;
  * network engines only receive targets already validated by the ScopeGuard; their traffic is forced through
    Vigía's loopback egress gateway (proxy flag + proxy variables + DNS stub), which enforces the scope again,
    resolves names remotely when an egress is configured and never connects directly if the egress fails;
  * with a dedicated egress, engines that cannot honour the tunnel (``egress = "blocked"``) are not run, and every
    engine runs under the kill switch (killed if it opens a socket outside loopback);
  * options that would contact third parties (OOB/interactsh, secret validation, update checks, telemetry,
    registry rule download) are disabled;
  * findings from engines carry ``native_evidence=False`` (the correlation engine caps them at *likely*).
"""
from __future__ import annotations

import asyncio
import json
import re
import time

import httpx
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlsplit

from vigia.config import get_settings
from vigia.core.context import ScanContext
from vigia.core.findings import FindingDraft
from vigia.core.profiles import INTENSITY_RANK
from vigia.core.toolrunner import ToolResult
from vigia.modules.common import origin
from vigia.tools.registry import TOOLS, get_registry

RULES_DIR = Path(__file__).with_name("rules")
WORDLIST = Path(__file__).resolve().parents[1] / "data" / "wordlists" / "content.txt"

CWE_CATEGORY = {"89": "sqli", "79": "xss_reflected", "80": "html_injection", "78": "cmdi", "77": "cmdi", "22": "path_traversal",
                "23": "path_traversal", "98": "path_traversal", "918": "ssrf", "601": "open_redirect", "1336": "ssti",
                "943": "nosqli", "90": "ldapi", "643": "xpathi", "113": "crlf_injection", "93": "crlf_injection",
                "352": "csrf", "614": "insecure_cookie", "1004": "insecure_cookie", "1275": "insecure_cookie",
                "1021": "clickjacking", "319": "no_https", "209": "error_disclosure", "548": "directory_listing",
                "525": "cache_sensitive", "942": "cors_misconfig", "530": "exposed_backup", "538": "exposed_config",
                "497": "version_disclosure", "295": "cert_invalid", "326": "tls_weak_cipher", "327": "tls_old_protocol",
                "798": "secret_exposed", "306": "api_auth_missing", "639": "api_bola", "285": "api_bfla",
                "915": "api_mass_assignment", "770": "api_no_rate_limit", "347": "api_jwt_weak", "1104": "outdated_component"}


def _cwe_num(v: Any) -> str | None:
    m = re.search(r"(\d+)", str(v or ""))
    return m.group(1) if m else None


class Adapter:
    tool: ClassVar[str] = ""
    phase: ClassVar[str] = "analysis"
    needs_target: ClassVar[bool] = False
    needs_source: ClassVar[bool] = False
    min_intensity: ClassVar[str] = "light"
    family: ClassVar[str | None] = None  # adapters sharing a family run only once (first available wins)
    # How the engine honours the egress: "gateway" (proxy flags to the scope gateway), "public" (third-party
    # traffic only, via the public lane), "offline" (no network expected; proxy variables + kill switch as
    # backstop) or "blocked" (cannot be forced through the tunnel: not run when an egress is configured).
    egress: ClassVar[str] = "offline"
    egress_block_reason: ClassVar[str] = ""
    # Verified to work inside the network-less AppContainer (tests/privacy/test_isolation.py). With preventive
    # isolation in force, an engine that has not been verified there is not run (never run unconfined silently).
    isolation_verified: ClassVar[bool] = False
    isolation_block_reason: ClassVar[str] = "no se ha verificado su funcionamiento dentro del aislamiento preventivo"

    def applicable(self, ctx: ScanContext) -> str | None:
        if self.needs_target and ctx.http is None:
            return "sin objetivo desplegado"
        if self.egress == "blocked" and ctx.egress_active:
            return f"bloqueado con salida dedicada: {self.egress_block_reason}"
        if getattr(ctx, "isolated", False) and not self.isolation_verified:
            return f"bloqueado con aislamiento preventivo obligatorio: {self.isolation_block_reason}"
        if self.needs_source and ctx.source_dir is None:
            return "sin código fuente"
        if INTENSITY_RANK[ctx.cfg.intensity] < INTENSITY_RANK[self.min_intensity]:
            return f"requiere intensidad ≥ {self.min_intensity}"
        spec = TOOLS[self.tool]
        if spec.lab_only and not ctx.lab_mode:
            return "integración restringida a alcances de laboratorio"
        st = get_registry().status(self.tool)
        if st.status != "available":
            return f"{st.status}: {st.reason or ''}".strip()
        if self.family:
            taken = getattr(ctx, "_families", set())
            if self.family in taken:
                return f"otro motor de la familia «{self.family}» ya se ejecuta en este escaneo"
            taken.add(self.family)
            ctx._families = taken  # type: ignore[attr-defined]
        ctx.tool_versions[self.tool] = st.version or ""
        return None

    # ------------------------------------------------------------------ helpers
    def cmd(self) -> list[str]:
        c = get_registry().command(self.tool)
        if not c:
            raise RuntimeError(f"{self.tool} no disponible")
        return c

    async def execute(self, ctx: ScanContext, args: list[str], *, timeout: float | None = None, workdir: Path | None = None,
                      memory_mb: int | None = None, cwd: Path | None = None) -> ToolResult:
        s = get_settings()
        remaining = max(30.0, ctx.deadline - time.monotonic())
        lim = get_registry().limits_for(self.tool, timeout=min(timeout or s.tool_default_timeout, remaining),
                                        **({"max_memory_mb": memory_mb} if memory_mb else {}))
        lim.extra_env.update(ctx.engine_env("scope" if self.egress == "gateway" else "public")
                             if (self.egress == "gateway" or ctx.egress_active) else {})
        lim.netwatch = ctx.netwatch
        lim.isolate = ctx.isolated  # preventive: inside the network-less AppContainer (loopback to the gateway only)
        lim.read_paths = [p for p in (ctx.source_dir, WORDLIST.parent, RULES_DIR) if p is not None]
        ctx.emit("info", f"tool:{self.tool}", f"Ejecutando {self.tool} {ctx.tool_versions.get(self.tool, '')}",
                 {"timeout_s": int(lim.timeout), "memoria_mb": lim.max_memory_mb})
        res = await asyncio.to_thread(ctx.runner.run, self.tool, [*self.cmd(), *args], limits=lim, workdir=workdir, cwd=cwd)
        if res.status not in ("ok", "failed"):
            ctx.emit("warn", f"tool:{self.tool}", f"{self.tool} terminó con estado {res.status}: {res.error}")
        if res.net_violations:
            ctx.emit("error", "egress", f"Kill switch: {self.tool} intentó salir fuera del túnel y se detuvo",
                     {"violaciones": [v.to_dict() for v in res.net_violations[:20]]})
        return res

    @staticmethod
    def dns_stub_file(ctx: ScanContext, wd: Path) -> Path | None:
        """Resolver list pointing an engine's own DNS client at the gateway's loopback stub."""
        if ctx.gateway is None or not ctx.gateway.dns_port:
            return None
        f = wd / "resolvers.txt"
        # "tcp:" (retryabledns syntax): DNS over TCP to the stub, so the engine needs no UDP socket at all and any UDP
        # socket the kill switch sees is genuinely outside the tunnel
        f.write_text(f"tcp:127.0.0.1:{ctx.gateway.dns_port}\n", encoding="utf-8")
        return f

    def finish(self, ctx: ScanContext, res: ToolResult, drafts: list[FindingDraft]) -> None:
        from vigia.modules.source import is_test_path
        for d in drafts:
            d.native_evidence = False
            d.sources = [f"tool:{self.tool}"]
            d.module = f"tool:{self.tool}"
            if d.confidence == "confirmed":
                d.confidence = "likely"
            if d.file and is_test_path(d.file):
                d.tags.append("test-code")
                d.confidence = "suspected"
                if d.category in ("secret_exposed", "sast_hardcoded_secret") and "generic" in str(
                        d.evidence.get("regla") or d.evidence.get("test") or "generic"):
                    d.severity, d.cvss_vector, d.keep_severity = "low", None, True
            ctx.add(d)
        if res.status == "failed" and res.exit_code == 1 and drafts:
            res.status = "ok"  # engines such as bandit exit with 1 when they report issues
        ctx.record_tool(self.tool, res, len(drafts))
        ctx.emit("info", f"tool:{self.tool}", f"{self.tool}: {len(drafts)} resultados normalizados "
                 f"({res.status}, {res.duration:.0f}s, pico {res.max_rss_mb} MB)")

    @staticmethod
    def targets(ctx: ScanContext) -> list[str]:
        assert ctx.guard is not None
        return [u for u in dict.fromkeys(ctx.kb.base_urls or ctx.guard.seed_urls())
                if ctx.guard.host_matches(urlsplit(u).hostname or "")]

    async def run(self, ctx: ScanContext) -> None:  # pragma: no cover - interface
        raise NotImplementedError


# ====================================================================== DAST / recon
class NucleiAdapter(Adapter):
    tool = "nuclei"
    needs_target = True
    # Verified (docs/06-auditoria-red.md): with -proxy (SOCKS5 or HTTP) part of the templates — tcp/network and raw HTTP
    # requests — still connect straight to the target, and nuclei opens UDP sockets of its own. Without a dedicated
    # egress it runs through the gateway as before; with one it is not run.
    egress = "blocked"
    egress_block_reason = ("Nuclei 3.x no respeta el túnel: con -proxy (SOCKS5 o HTTP) sus plantillas tcp y las peticiones "
                           "HTTP raw conectan directamente con el objetivo y abre sockets UDP propios (verificado en la "
                           "auditoría de red). Las comprobaciones equivalentes las hacen los módulos nativos por el túnel")
    EXCLUDE_TAGS = "dos,intrusive,fuzz,default-login,brute-force,bruteforce,headless,osint,file,local,code,javascript"

    async def run(self, ctx: ScanContext) -> None:
        s = get_settings()
        wd = ctx.runner.new_workdir("nuclei")
        targets = self.targets(ctx)
        if not targets:
            return
        validated = []
        for t in targets:
            try:
                await ctx.guard.check_url(t)  # type: ignore[union-attr]
                validated.append(t)
            except Exception:  # noqa: BLE001
                continue
        (wd / "targets.txt").write_text("\n".join(validated), encoding="utf-8")
        tpl = s.tool_bin_dir / "nuclei-templates"
        if not tpl.is_dir():
            ctx.record_tool_skip(self.tool, "faltan las plantillas (vigia tools install nuclei-templates)")
            return
        dirs = [str(tpl / "http")]
        if ctx.cfg.port_set in ("top", "extended") and (tpl / "network").is_dir():
            dirs.append(str(tpl / "network"))
        if (tpl / "ssl").is_dir():
            dirs.append(str(tpl / "ssl"))
        severity = "critical,high,medium,low" + (",info" if ctx.cfg.at_least("deep") else "")
        args = ["-l", str(wd / "targets.txt"), "-jsonl", "-o", str(wd / "out" / "nuclei.jsonl"), "-silent", "-nc",
                "-duc", "-ni", "-disable-redirects", "-rl", str(max(1, int(ctx.cfg.rps))), "-c",
                str(max(1, ctx.cfg.concurrency)), "-bs", "5", "-timeout", "10", "-retries", "1", "-severity", severity,
                "-etags", self.EXCLUDE_TAGS if not ctx.lab_mode else "dos", "-mhe", "10", "-ot"]
        for d in dirs:
            args += ["-t", d]
        if ctx.gateway is not None:  # SOCKS5 to the gateway: HTTP, network and SSL templates all use it
            args += ["-proxy", ctx.gateway.socks_url]
            stub = self.dns_stub_file(ctx, wd)
            if stub:
                args += ["-r", str(stub)]  # nuclei's own resolver → loopback stub (never the system/public resolvers)
        if ctx.guard and ctx.guard.exclusions:
            hosts = [e for e in ctx.guard.exclusions if not e.startswith("/") and "://" not in e]
            if hosts:
                args += ["-eh", ",".join(hosts)]
        res = await self.execute(ctx, args, workdir=wd, timeout=min(1800, ctx.cfg.max_duration_min * 30))
        drafts = []
        out = wd / "out" / "nuclei.jsonl"
        if out.exists():
            for line in out.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    drafts.extend(self.parse(json.loads(line)))
                except (ValueError, KeyError):
                    continue
        self.finish(ctx, res, drafts)

    @staticmethod
    def parse(item: dict[str, Any]) -> list[FindingDraft]:
        info = item.get("info", {})
        tags = set(info.get("tags", []) if isinstance(info.get("tags"), list) else str(info.get("tags", "")).split(","))
        tid = item.get("template-id", "")
        cls = info.get("classification") or {}
        cves = [c.upper() for c in (cls.get("cve-id") or []) if c]
        cwes = [_cwe_num(c) for c in (cls.get("cwe-id") or [])]
        sev = str(info.get("severity", "info")).lower()
        sev = sev if sev in ("critical", "high", "medium", "low", "info") else "info"
        cat = None
        for c in cwes:
            if c and c in CWE_CATEGORY:
                cat = CWE_CATEGORY[c]
                break
        rules = [("panel", "exposed_admin"), ("takeover", "subdomain_dangling"), ("cors", "cors_misconfig"),
                 ("xss", "xss_reflected"), ("sqli", "sqli"), ("lfi", "path_traversal"), ("redirect", "open_redirect"),
                 ("ssrf", "ssrf"), ("ssti", "ssti"), ("crlf", "crlf_injection"), ("tech", "tech_fingerprint"),
                 ("detect", "tech_fingerprint"), ("debug", "exposed_debug"), ("swagger", "exposed_api_docs"),
                 ("graphql", "graphql_introspection"), ("backup", "exposed_backup"), ("logs", "exposed_log"),
                 ("config", "exposed_config"), ("exposure", "exposed_config")]
        if not cat:
            if cves:
                cat = "outdated_component"
            else:
                for tag, c in rules:
                    if tag in tags:
                        cat = c
                        break
        idl = tid.lower()
        if "git-config" in idl or "git-head" in idl:
            cat = "exposed_git"
        elif re.search(r"(^|-)env(-|$)|dotenv", idl):
            cat = "exposed_env"
        elif "phpinfo" in idl:
            cat = "exposed_debug"
        elif "deprecated-tls" in idl or "tls-version" in idl:
            cat = "tls_old_protocol"
        elif "weak-cipher" in idl:
            cat = "tls_weak_cipher"
        elif re.search(r"expired-ssl|self-signed|mismatched-ssl|untrusted-root", idl):
            cat = "cert_invalid"
        cat = cat or "external_finding"
        matched = item.get("matched-at") or item.get("url") or item.get("host", "")
        host = urlsplit(matched).hostname if "://" in str(matched) else str(item.get("host", "")).split(":")[0]
        return [FindingDraft(
            title=f"{info.get('name', tid)}" + (f" ({', '.join(cves[:2])})" if cves else ""), category=cat, module="tool:nuclei",
            severity=sev, confidence="likely" if sev not in ("info",) else "likely", asset=host or "",
            endpoint=matched if "://" in str(matched) else None, cve=cves, cwe=f"CWE-{cwes[0]}" if cwes and cwes[0] else None,
            cvss_vector=cls.get("cvss-metrics") if str(cls.get("cvss-metrics", "")).startswith("CVSS:3") else None,
            description=str(info.get("description", ""))[:1500],
            evidence={"template": tid, "matcher": item.get("matcher-name"), "extraido": (item.get("extracted-results") or [])[:5],
                      "tipo": item.get("type")},
            recommendation=str(info.get("remediation", ""))[:800],
            references=[r for r in (info.get("reference") or []) if isinstance(r, str)][:5],
            fingerprint_extra=tid if cat in ("external_finding", "tech_fingerprint", "outdated_component") else "")]


class ZapAdapter(Adapter):
    tool = "zap"
    needs_target = True
    min_intensity = "standard"
    egress = "gateway"
    isolation_block_reason = ("la JVM de ZAP canonicaliza rutas listando la raíz del disco y el perfil del usuario, algo que un "
                              "AppContainer no puede hacer sin que un administrador se lo conceda (verificado); su salida "
                              "por la pasarela sí está verificada, pero no puede confinarse preventivamente")

    def applicable(self, ctx: ScanContext) -> str | None:
        if ctx.egress_active and get_settings().zap_api_url:
            return ("bloqueado con salida dedicada: el demonio ZAP externo (VIGIA_ZAP_API_URL) no está bajo el control "
                    "de Vigía; su salida no puede forzarse por el túnel. Usa el demonio local (vigia tools install zap jre)")
        return super().applicable(ctx)

    async def run(self, ctx: ScanContext) -> None:
        await asyncio.to_thread(self._run_sync, ctx)

    def _run_sync(self, ctx: ScanContext) -> None:
        from vigia.tools.zap import DISABLED_ASCAN, ZAP_NOISE, ZAP_PLUGIN_CATEGORY, ZapError, ZapSession
        assert ctx.guard is not None
        wd = ctx.runner.new_workdir("zap")
        t0 = time.monotonic()
        targets = self.targets(ctx)
        drafts: list[FindingDraft] = []
        sess = None
        status, error = "ok", None
        try:
            sess = ZapSession(ctx.runner, wd, gateway=ctx.gateway, netwatch=ctx.netwatch, isolate=ctx.isolated)
            with sess as z:
                z.act("core/action/setMode", mode="protect")
                ctx_name = f"vigia-{ctx.scan_id}"
                z.act("context/action/newContext", contextName=ctx_name)
                for t in targets:
                    z.act("context/action/includeInContext", contextName=ctx_name,
                          regex=re.escape(origin(t)) + ".*")
                for ex in ctx.guard.exclusions:
                    rx = re.escape(ex.rstrip("*")) + ".*" if ex.startswith(("/", "http")) else ".*" + re.escape(ex) + ".*"
                    z.act("context/action/excludeFromContext", contextName=ctx_name, regex=rx)
                z.act("context/action/setContextInScope", contextName=ctx_name, booleanInScope=True)
                budget_min = max(2, min(30, int((ctx.deadline - time.monotonic()) / 60 / 3)))
                z.act("spider/action/setOptionMaxDuration", Integer=min(10, budget_min))
                z.act("spider/action/setOptionMaxDepth", Integer=max(1, ctx.cfg.crawl_depth))
                z.act("spider/action/setOptionThreadCount", Integer=max(1, min(4, ctx.cfg.concurrency)))
                for t in targets:
                    sid = z.act("spider/action/scan", url=t, contextName=ctx_name, subtreeOnly=False,
                                maxChildren=50)["scan"]
                    while int(z.get("spider/view/status", scanId=sid)["status"]) < 100:
                        if ctx.stopping:
                            z.act("spider/action/stop", scanId=sid)
                            break
                        time.sleep(3)
                for _ in range(120):
                    if int(z.get("pscan/view/recordsToScan")["recordsToScan"]) == 0 or ctx.stopping:
                        break
                    time.sleep(2)
                if ctx.cfg.at_least("deep") and not ctx.stopping:
                    try:
                        self._active(ctx, z, targets, ctx_name, budget_min, DISABLED_ASCAN)
                    except (ZapError, KeyError, ValueError) as e:
                        error = f"escaneo activo de ZAP incompleto: {e}"
                        ctx.emit("warn", "tool:zap", error)
                for t in targets:
                    start = 0
                    while True:
                        page = z.get("core/view/alerts", baseurl=origin(t), start=start, count=500)["alerts"]
                        for a in page:
                            if a.get("pluginId") in ZAP_NOISE or a.get("confidence") == "False Positive":
                                continue
                            cat = ZAP_PLUGIN_CATEGORY.get(str(a.get("pluginId"))) or CWE_CATEGORY.get(
                                str(a.get("cweid"))) or "external_finding"
                            risk = {"High": "high", "Medium": "medium", "Low": "low"}.get(a.get("risk"), "info")
                            if risk == "info" and cat == "external_finding":
                                continue
                            drafts.append(FindingDraft(
                                title=a.get("alert", "Alerta ZAP"), category=cat, module="tool:zap", severity=risk,
                                confidence={"High": "likely", "Confirmed": "likely"}.get(a.get("confidence"), "suspected"),
                                asset=urlsplit(a.get("url", "")).hostname or "", endpoint=a.get("url"), method=a.get("method"),
                                parameter=a.get("param") or None, cwe=f"CWE-{a['cweid']}" if str(a.get("cweid", "-1")) not in
                                ("-1", "0", "") else None, description=str(a.get("description", ""))[:1500],
                                recommendation=str(a.get("solution", ""))[:800],
                                evidence={"plugin": a.get("pluginId"), "ataque": (a.get("attack") or "")[:300],
                                          "evidencia": (a.get("evidence") or "")[:300], "otra_info": (a.get("other") or "")[:300]},
                                references=[r for r in str(a.get("reference", "")).split() if r.startswith("http")][:4],
                                fingerprint_extra=f"zap:{a.get('pluginId')}" if cat == "external_finding" else ""))
                        if len(page) < 500:
                            break
                        start += 500
        except (ZapError, OSError, KeyError, ValueError, httpx.HTTPError) as e:
            status, error = "failed", f"{type(e).__name__}: {e}"
        violations = list(sess.net_violations) if sess is not None else []
        if violations:
            status, error = "killed", f"Kill switch de salida: ZAP abrió una conexión fuera del túnel ({violations[0]})"
            ctx.emit("error", "egress", "Kill switch: ZAP intentó salir fuera del túnel y se detuvo",
                     {"violaciones": [v.to_dict() for v in violations[:20]]})
        res = ToolResult("zap", ["zap", "daemon-api"], status, duration=round(time.monotonic() - t0, 1), error=error)
        res.net_violations = violations
        self.finish(ctx, res, drafts)

    @staticmethod
    def _active(ctx: ScanContext, z, targets: list[str], ctx_name: str, budget_min: int,  # noqa: ANN001
                disabled: list[str]) -> None:
        """Active scan with Vigía's non-destructive policy (low strength, resource-exhaustion rules off)."""
        from vigia.tools.zap import ZapError
        pol = "vigia-no-destructiva"
        z.act("ascan/action/addScanPolicy", scanPolicyName=pol, alertThreshold="MEDIUM", attackStrength="LOW")
        for sid in disabled:  # rule ids vary across ZAP releases: disable individually, ignore unknown ids
            try:
                z.act("ascan/action/disableScanners", ids=sid, scanPolicyName=pol)
            except ZapError:
                continue
        z.act("ascan/action/setOptionMaxScanDurationInMins", Integer=budget_min)
        z.act("ascan/action/setOptionThreadPerHost", Integer=max(1, min(4, ctx.cfg.concurrency)))
        z.act("ascan/action/setOptionDelayInMs", Integer=int(1000 / max(1.0, ctx.cfg.rps)))
        cid = z.get("context/view/context", contextName=ctx_name)["context"]["id"]
        for t in targets:
            aid = z.act("ascan/action/scan", url=t, recurse=True, inScopeOnly=True, scanPolicyName=pol,
                        contextId=cid)["scan"]
            while int(z.get("ascan/view/status", scanId=aid)["status"]) < 100:
                if ctx.stopping:
                    z.act("ascan/action/stop", scanId=aid)
                    break
                time.sleep(5)


class FfufAdapter(Adapter):
    isolation_verified = True
    tool = "ffuf"
    phase = "discovery"
    needs_target = True
    min_intensity = "deep"
    egress = "gateway"

    async def run(self, ctx: ScanContext) -> None:
        found = 0
        last: ToolResult | None = None
        for base in self.targets(ctx)[:3]:
            wd = ctx.runner.new_workdir("ffuf")
            o = origin(base)
            await ctx.guard.check_url(o + "/")  # type: ignore[union-attr]
            args = ["-u", o + "/FUZZ", "-w", str(WORDLIST), "-mc", "200,204,301,302,307,401,403", "-ac", "-s",
                    "-noninteractive", "-of", "json", "-o", str(wd / "out" / "ffuf.json"), "-rate", str(max(1, int(ctx.cfg.rps))),
                    "-t", str(max(1, min(10, ctx.cfg.concurrency))), "-timeout", "10", "-maxtime", "600",
                    "-H", "User-Agent: Vigia (+authorized-security-testing)"]
            if ctx.gateway is not None:
                args += ["-x", ctx.gateway.http_url]
            last = await self.execute(ctx, args, workdir=wd, timeout=700)
            try:
                data = json.loads((wd / "out" / "ffuf.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            for r in data.get("results", []):
                url = r.get("url")
                if url and ctx.guard and ctx.guard.host_matches(urlsplit(url).hostname or ""):
                    ctx.kb.urls.add(url)
                    found += 1
        if last is not None:
            ctx.record_tool(self.tool, last, 0)
        ctx.emit("info", "tool:ffuf", f"ffuf descubrió {found} rutas (se analizan en los módulos nativos)")


class SubfinderAdapter(Adapter):
    isolation_verified = True
    tool = "subfinder"
    phase = "recon"
    needs_target = True
    min_intensity = "standard"
    egress = "public"  # contacts passive third-party sources only, never the targets

    def applicable(self, ctx: ScanContext) -> str | None:
        if get_settings().offline:
            return "modo offline (subfinder consulta fuentes pasivas externas)"
        if ctx.guard is None or not any(t.kind == "wildcard" for t in ctx.guard.targets):
            return "solo aplica a alcances con comodín (*.dominio)"
        return super().applicable(ctx)

    async def run(self, ctx: ScanContext) -> None:
        assert ctx.guard is not None
        for t in [t for t in ctx.guard.targets if t.kind == "wildcard"][:3]:
            wd = ctx.runner.new_workdir("subfinder")
            args = ["-d", t.host or "", "-silent", "-oJ", "-o", str(wd / "out" / "subs.jsonl"), "-timeout", "20",
                    "-max-time", "5", "-duc"]
            pub = ctx.public_proxy_url()
            if pub:
                args += ["-proxy", pub]
            stub = self.dns_stub_file(ctx, wd)
            if stub:
                args += ["-rL", str(stub)]
            res = await self.execute(ctx, args, workdir=wd, timeout=400)
            subs = set()
            p = wd / "out" / "subs.jsonl"
            if p.exists():
                for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                    try:
                        h = json.loads(line).get("host", "").lower()
                    except ValueError:
                        continue
                    if h and ctx.guard.host_matches(h) and not ctx.guard.is_excluded(h):
                        subs.add(h)
            for h in sorted(subs)[:100]:
                url = f"https://{h}/"
                if url not in ctx.kb.base_urls:
                    ctx.kb.base_urls.append(url)
            ctx.record_tool(self.tool, res, 0)
            ctx.emit("info", "tool:subfinder", f"subfinder: {len(subs)} subdominios en alcance para {t.host}",
                     {"subdominios": sorted(subs)[:100]})


class SslyzeAdapter(Adapter):
    isolation_verified = True
    tool = "sslyze"
    needs_target = True
    family = "tls"
    egress = "gateway"

    async def run(self, ctx: ScanContext) -> None:
        assert ctx.guard is not None
        specs = []
        for b in self.targets(ctx):
            p = urlsplit(b)
            if p.scheme == "https" and p.hostname:
                chk = await ctx.guard.check_url(b)
                # through the gateway the name is resolved (and pinned) by the guard; without it, pin the IP here
                specs.append(f"{p.hostname}:{p.port or 443}" if ctx.gateway is not None
                             else f"{p.hostname}:{p.port or 443}{{{chk.pinned_ip}}}")
        if not specs:
            ctx.record_tool_skip(self.tool, "no hay objetivos HTTPS")
            return
        wd = ctx.runner.new_workdir("sslyze")
        tunnel = ["--https_tunnel", ctx.gateway.http_url] if ctx.gateway is not None else []
        res = await self.execute(ctx, ["--json_out", str(wd / "out" / "sslyze.json"), "--quiet", *tunnel, *specs[:10]],
                                 workdir=wd, timeout=900)
        drafts = []
        try:
            data = json.loads((wd / "out" / "sslyze.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        for srv in data.get("server_scan_results", []):
            loc = srv.get("server_location", {})
            asset = f"{loc.get('hostname')}:{loc.get('port')}"
            r = srv.get("scan_result") or {}
            old = []
            for key, label in (("ssl_2_0_cipher_suites", "SSLv2"), ("ssl_3_0_cipher_suites", "SSLv3"),
                               ("tls_1_0_cipher_suites", "TLSv1.0"), ("tls_1_1_cipher_suites", "TLSv1.1")):
                acc = ((r.get(key) or {}).get("result") or {}).get("accepted_cipher_suites") or []
                if acc:
                    old.append(label)
            if old:
                drafts.append(FindingDraft(title=f"{', '.join(old)} aceptado en {asset}", category="tls_old_protocol",
                                           module="tool:sslyze", confidence="likely", asset=asset,
                                           evidence={"protocolos": old}))
            weak = []
            for key in ("tls_1_2_cipher_suites",):
                for cs in ((r.get(key) or {}).get("result") or {}).get("accepted_cipher_suites") or []:
                    name = (cs.get("cipher_suite") or {}).get("name", "")
                    if re.search(r"RC4|3DES|DES_CBC|NULL|EXPORT|anon|_CBC_SHA$", name) or name.startswith("TLS_RSA_"):
                        weak.append(name)
            if weak:
                drafts.append(FindingDraft(title=f"Suites débiles aceptadas en {asset}", category="tls_weak_cipher",
                                           module="tool:sslyze", confidence="likely", asset=asset,
                                           evidence={"suites": weak[:15]}))
            for vuln_key, label in (("heartbleed", "Heartbleed"), ("openssl_ccs_injection", "OpenSSL CCS injection"),
                                    ("robot", "ROBOT")):
                vr = ((r.get(vuln_key) or {}).get("result") or {})
                vulnerable = vr.get("is_vulnerable_to_heartbleed") or vr.get("is_vulnerable_to_ccs_injection") or \
                    str(vr.get("robot_result", "")).startswith("VULNERABLE")
                if vulnerable:
                    drafts.append(FindingDraft(title=f"{label} en {asset}", category="tls_weak_cipher", module="tool:sslyze",
                                               confidence="likely", severity="high", asset=asset,
                                               cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                               evidence={"prueba": vuln_key}, fingerprint_extra=vuln_key))
        self.finish(ctx, res, drafts)


class TestsslAdapter(Adapter):
    tool = "testssl"
    needs_target = True
    min_intensity = "deep"
    family = "tls"
    egress = "blocked"
    egress_block_reason = ("testssl.sh abre sockets propios (bash /dev/tcp) y consulta DNS con herramientas locales; su "
                           "--proxy solo cubre parte de las pruebas. El análisis TLS sigue cubierto por SSLyze y el "
                           "módulo TLS nativo a través del túnel")

    async def run(self, ctx: ScanContext) -> None:
        assert ctx.guard is not None
        drafts: list[FindingDraft] = []
        last = None
        for b in self.targets(ctx)[:3]:
            p = urlsplit(b)
            if p.scheme != "https" or not p.hostname:
                continue
            chk = await ctx.guard.check_url(b)
            wd = ctx.runner.new_workdir("testssl")
            out = wd / "out" / "testssl.json"
            last = await self.execute(ctx, ["--jsonfile", str(out), "--quiet", "--warnings", "off", "--color", "0",
                                            "--ip", str(chk.pinned_ip), "--sneaky", "--fast",
                                            f"{p.hostname}:{p.port or 443}"], workdir=wd, timeout=1500)
            try:
                items = json.loads(out.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            for it in items if isinstance(items, list) else []:
                sev = str(it.get("severity", "")).upper()
                if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    continue
                iid = str(it.get("id", ""))
                cat = ("tls_old_protocol" if re.match(r"^(SSLv\d|TLS1(_1)?)$", iid) else "cert_invalid" if iid.startswith("cert")
                       else "tls_weak_cipher")
                drafts.append(FindingDraft(title=f"testssl: {iid} — {str(it.get('finding', ''))[:120]}", category=cat,
                                           module="tool:testssl", confidence="likely", severity=sev.lower(),
                                           asset=f"{p.hostname}:{p.port or 443}", cve=[c for c in str(it.get("cve", "")).split()
                                                                                       if c.startswith("CVE-")],
                                           evidence={"id": iid, "finding": it.get("finding")}, fingerprint_extra=iid))
        if last is not None:
            self.finish(ctx, last, drafts)


class NmapAdapter(Adapter):
    tool = "nmap"
    phase = "recon"
    needs_target = True
    min_intensity = "standard"
    egress = "blocked"
    egress_block_reason = ("el motor de escaneo de puertos de Nmap no usa --proxies (solo NSE y -sV), así que sus sondas "
                           "saldrían directamente. Los puertos y servicios se analizan con el escáner TCP nativo a "
                           "través del túnel")

    async def run(self, ctx: ScanContext) -> None:
        from defusedxml.ElementTree import fromstring
        assert ctx.guard is not None
        ips = []
        for h in ctx.guard.hosts()[:32]:
            try:
                chk = await ctx.guard.check_host_port(h, 443)
                ips.append(str(chk.pinned_ip))
            except Exception:  # noqa: BLE001
                continue
        if not ips:
            return
        wd = ctx.runner.new_workdir("nmap")
        ports = "--top-ports=1000" if ctx.cfg.port_set == "extended" else "--top-ports=100"
        res = await self.execute(ctx, ["-sT", "-sV", "--version-light", "-Pn", "-n", "--unprivileged", ports, "-T3",
                                       "--max-rate", str(max(10, int(ctx.cfg.rps * 10))), "-oX", str(wd / "out" / "nmap.xml"),
                                       *ips], workdir=wd, timeout=1800)
        drafts = []
        try:
            root = fromstring((wd / "out" / "nmap.xml").read_bytes())
        except Exception:  # noqa: BLE001
            root = None
        for host in root.iter("host") if root is not None else []:
            addr = host.find("address").get("addr") if host.find("address") is not None else "?"
            for port in host.iter("port"):
                st = port.find("state")
                if st is None or st.get("state") != "open":
                    continue
                svc = port.find("service")
                name = svc.get("name", "") if svc is not None else ""
                product = " ".join(filter(None, [svc.get("product"), svc.get("version")])) if svc is not None else ""
                ctx.kb.open_ports.setdefault(addr, []).append({"port": int(port.get("portid")), "service": name,
                                                              "banner": product, "source": "nmap"})
                if product and re.search(r"\d", product):
                    drafts.append(FindingDraft(title=f"{name} {product} en {addr}:{port.get('portid')}",
                                               category="service_version_disclosure", module="tool:nmap", severity="info",
                                               confidence="likely", asset=f"{addr}:{port.get('portid')}",
                                               evidence={"servicio": name, "producto": product}))
        self.finish(ctx, res, drafts)


# ====================================================================== code
class OpengrepAdapter(Adapter):
    tool = "opengrep"
    isolation_block_reason = ("opengrep aborta dentro del AppContainer al no poder resolver el perfil del usuario "
                              "('{HOME}', verificado); con salida dedicada y objetivos no se ejecuta sin confinar")
    phase = "recon"
    needs_source = True
    family = "semgrep"

    async def run(self, ctx: ScanContext) -> None:
        import os
        wd = ctx.runner.new_workdir(self.tool)
        configs = [str(RULES_DIR / "opengrep")]
        extra = os.environ.get("VIGIA_OPENGREP_RULES")
        if extra and Path(extra).exists():
            configs.append(extra)
        args = ["scan", "--json", "--output", str(wd / "out" / "result.json"), "--disable-version-check", "--quiet",
                "--timeout", "30", "--max-target-bytes", "1500000", "--exclude-minified-files", "--no-git-ignore",
                "--jobs", "2"]
        for c in configs:
            args += ["--config", c]
        for ex in ("node_modules", "vendor", "dist", "build", ".venv", "venv", "tests", "test"):
            args += ["--exclude", ex]
        args.append(str(ctx.source_dir))
        res = await self.execute(ctx, args, workdir=wd, timeout=1500, memory_mb=3072)
        drafts = []
        try:
            data = json.loads((wd / "out" / "result.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        root = str(ctx.source_dir)
        for r in data.get("results", []):
            meta = (r.get("extra") or {}).get("metadata") or {}
            rel = _rel(r.get("path", ""), root)
            cwe = _cwe_num(meta.get("cwe") if not isinstance(meta.get("cwe"), list) else meta["cwe"][0])
            cat = meta.get("vigia_category") or ("sast_generic" if not cwe else {"89": "sast_sqli", "78": "sast_cmdi",
                                                                                 "79": "sast_xss", "22": "sast_path_traversal",
                                                                                 "918": "sast_ssrf", "95": "sast_code_injection",
                                                                                 "502": "sast_deserialization"}.get(cwe, "sast_generic"))
            line = (r.get("start") or {}).get("line")
            drafts.append(FindingDraft(
                title=f"{r.get('check_id', '').split('.')[-1]}: {(r.get('extra') or {}).get('message', '')[:120]} ({rel}:{line})",
                category=cat, module=f"tool:{self.tool}", confidence="likely", asset=rel, file=rel, line=line,
                snippet=((r.get("extra") or {}).get("lines") or "")[:800], cwe=f"CWE-{cwe}" if cwe else None,
                description=(r.get("extra") or {}).get("message", ""),
                evidence={"regla": r.get("check_id"), "flujo": "taint" if "taint" in json.dumps(r.get("extra", {}))[:2000]
                          else "patrón"}, fingerprint_extra=r.get("check_id", "")))
        for err in (data.get("errors") or [])[:5]:
            ctx.emit("warn", f"tool:{self.tool}", f"{self.tool}: {str(err.get('message', err))[:200]}")
        self.finish(ctx, res, drafts)


class SemgrepAdapter(OpengrepAdapter):
    tool = "semgrep"


BANDIT_MAP = {"B404": "sast_generic", "B405": "sast_generic", "B406": "sast_generic", "B102": "sast_code_injection", "B307": "sast_code_injection", "B301": "sast_deserialization",
              "B302": "sast_deserialization", "B403": "sast_deserialization", "B506": "sast_deserialization",
              "B501": "sast_tls_verify", "B502": "sast_tls_verify", "B503": "sast_tls_verify", "B504": "sast_tls_verify",
              "B303": "sast_weak_crypto", "B304": "sast_weak_crypto", "B305": "sast_weak_crypto", "B324": "sast_weak_crypto",
              "B413": "sast_weak_crypto", "B311": "sast_weak_random", "B201": "sast_debug", "B105": "sast_hardcoded_secret",
              "B106": "sast_hardcoded_secret", "B107": "sast_hardcoded_secret", "B108": "sast_insecure_config",
              "B103": "sast_insecure_config", "B104": "sast_insecure_config", "B110": "sast_exception_handling",
              "B112": "sast_exception_handling", "B602": "sast_cmdi", "B603": "sast_cmdi", "B604": "sast_cmdi",
              "B605": "sast_cmdi", "B606": "sast_cmdi", "B607": "sast_cmdi", "B608": "sast_sqli", "B610": "sast_sqli",
              "B611": "sast_sqli", "B701": "sast_xss", "B702": "sast_xss", "B703": "sast_xss", "B308": "sast_xss",
              "B313": "sast_xxe", "B314": "sast_xxe", "B315": "sast_xxe", "B316": "sast_xxe", "B317": "sast_xxe",
              "B318": "sast_xxe", "B319": "sast_xxe", "B320": "sast_xxe", "B410": "sast_xxe", "B310": "sast_ssrf",
              "B113": "sast_insecure_config", "B306": "sast_insecure_config", "B101": "sast_exception_handling"}


class BanditAdapter(Adapter):
    isolation_verified = True
    tool = "bandit"
    phase = "recon"
    needs_source = True

    def applicable(self, ctx: ScanContext) -> str | None:
        why = super().applicable(ctx)
        if why:
            return why
        if ctx.source_dir and not any(ctx.source_dir.rglob("*.py")):
            return "el código no contiene ficheros Python"
        return None

    async def run(self, ctx: ScanContext) -> None:
        wd = ctx.runner.new_workdir(self.tool)
        out = wd / "out" / "bandit.json"
        res = await self.execute(ctx, ["-r", str(ctx.source_dir), "-f", "json", "-o", str(out), "-q", "-x",
                                       ",".join(f"*/{d}/*" for d in ("node_modules", "venv", ".venv", "vendor", "site-packages")),
                                       "--severity-level", "low"], workdir=wd, timeout=900)
        drafts = []
        try:
            data = json.loads(out.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        root = str(ctx.source_dir)
        from vigia.modules.source import is_test_path
        for r in data.get("results", []):
            rel = _rel(r.get("filename", ""), root)
            tid = r.get("test_id", "")
            if tid == "B101" and is_test_path(rel):
                continue  # asserts are how tests work
            conf = {"HIGH": "likely", "MEDIUM": "suspected", "LOW": "suspected"}.get(r.get("issue_confidence"), "suspected")
            bsev = str(r.get("issue_severity", "LOW")).upper()
            own = {"LOW": "low", "MEDIUM": "medium"}.get(bsev)  # HIGH -> category vector applies
            if tid in ("B404", "B405", "B406", "B403"):
                own = "info"
            drafts.append(FindingDraft(
                title=f"{tid} {r.get('test_name', '')}: {r.get('issue_text', '')[:100]} ({rel}:{r.get('line_number')})",
                category=BANDIT_MAP.get(tid, "sast_generic"), module="tool:bandit", confidence=conf, asset=rel, file=rel,
                line=r.get("line_number"), snippet=(r.get("code") or "")[:800],
                cwe=f"CWE-{(r.get('issue_cwe') or {}).get('id')}" if (r.get("issue_cwe") or {}).get("id") else None,
                description=r.get("issue_text", ""), references=[r.get("more_info")] if r.get("more_info") else [],
                severity=own or "high", keep_severity=own is not None,
                evidence={"test": tid, "severidad_bandit": r.get("issue_severity"), "confianza_bandit": r.get("issue_confidence")}))
        self.finish(ctx, res, drafts)


class TrivyAdapter(Adapter):
    isolation_verified = True
    tool = "trivy"
    phase = "recon"
    needs_source = True

    async def run(self, ctx: ScanContext) -> None:
        s = get_settings()
        wd = ctx.runner.new_workdir(self.tool)
        cache = s.tools_dir / "data" / "trivy-cache"
        out = wd / "out" / "trivy.json"
        args = ["fs", "--cache-dir", str(cache), "--format", "json", "--output", str(out), "--quiet",
                "--scanners", "vuln,misconfig,secret", "--skip-dirs", "node_modules", "--skip-dirs", "vendor",
                "--timeout", "15m", "--disable-telemetry"]
        if (cache / "db" / "trivy.db").exists():
            args += ["--skip-db-update", "--skip-java-db-update", "--skip-check-update"]
        if s.offline:
            args += ["--offline-scan"]
        args.append(str(ctx.source_dir))
        res = await self.execute(ctx, args, workdir=wd, timeout=1200, memory_mb=3072)
        if res.status == "failed" and "unknown flag: --disable-telemetry" in res.stderr_tail:
            args.remove("--disable-telemetry")
            res = await self.execute(ctx, args, workdir=wd, timeout=1200, memory_mb=3072)
        drafts = []
        try:
            data = json.loads(out.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        for result in data.get("Results", []) or []:
            target = result.get("Target", "")
            for v in result.get("Vulnerabilities") or []:
                vector = None
                for src in (v.get("CVSS") or {}).values():
                    if str(src.get("V3Vector", "")).startswith("CVSS:3"):
                        vector = src["V3Vector"]
                        break
                vid = v.get("VulnerabilityID", "")
                drafts.append(FindingDraft(
                    title=f"{v.get('PkgName')} {v.get('InstalledVersion')}: {vid}", category="vulnerable_dependency",
                    module="tool:trivy", severity=str(v.get("Severity", "MEDIUM")).lower().replace("unknown", "medium"),
                    confidence="likely", asset=target, file=target, cve=[vid] if vid.startswith("CVE-") else [],
                    cvss_vector=vector, description=(v.get("Title") or v.get("Description") or "")[:800],
                    recommendation=f"Actualiza {v.get('PkgName')} a {v.get('FixedVersion')}." if v.get("FixedVersion") else "",
                    references=[v.get("PrimaryURL")] if v.get("PrimaryURL") else [],
                    evidence={"paquete": v.get("PkgName"), "version": v.get("InstalledVersion"), "corregido": v.get("FixedVersion")},
                    fingerprint_extra=f"{str(v.get('PkgName')).lower()}@{v.get('InstalledVersion')}:{vid}"))
            for m in result.get("Misconfigurations") or []:
                if m.get("Status") == "PASS":
                    continue
                line = (m.get("CauseMetadata") or {}).get("StartLine")
                cat = "iac_privileged" if re.search(r"privileg|host(PID|Network|IPC)|docker\.sock|capabilit", m.get("Title", ""),
                                                    re.I) else "iac_container_root" if "root" in m.get("Title", "").lower() \
                    else "iac_insecure_config"
                drafts.append(FindingDraft(title=f"{m.get('ID')}: {m.get('Title')} ({target}:{line})", category=cat,
                                           module="tool:trivy", severity=str(m.get("Severity", "LOW")).lower(),
                                           confidence="likely", asset=target, file=target, line=line,
                                           description=m.get("Description", "")[:600],
                                           recommendation=m.get("Resolution", "")[:600],
                                           references=[m.get("PrimaryURL")] if m.get("PrimaryURL") else [],
                                           evidence={"check": m.get("ID")}, fingerprint_extra=m.get("ID", "")))
            for sct in result.get("Secrets") or []:
                drafts.append(FindingDraft(title=f"{sct.get('Title')} ({target}:{sct.get('StartLine')})",
                                           category="secret_exposed", module="tool:trivy",
                                           severity=str(sct.get("Severity", "HIGH")).lower(), confidence="likely",
                                           asset=target, file=target, line=sct.get("StartLine"),
                                           evidence={"regla": sct.get("RuleID"), "coincidencia_redactada": sct.get("Match", "")[:120]}))
        self.finish(ctx, res, drafts)


class LeaksAdapter(Adapter):
    isolation_verified = True
    tool = "betterleaks"
    phase = "recon"
    needs_source = True
    family = "leaks"

    async def run(self, ctx: ScanContext) -> None:
        wd = ctx.runner.new_workdir(self.tool)
        out = wd / "out" / "leaks.json"
        # Always "dir" mode: running git inside an untrusted repository lets its .git/config (core.fsmonitor,
        # diff.external, textconv…) execute commands. Never: --validation (sends secrets to live APIs) nor
        # --unsafe-auto-load-config (target-controlled configuration).
        args = ["dir", str(ctx.source_dir), "--report-format", "json", "--report-path", str(out), "--no-banner",
                "--exit-code", "0", "--redact", "--max-target-megabytes", "5", "--log-level", "warn"]
        res = await self.execute(ctx, args, workdir=wd, timeout=900)
        drafts = []
        try:
            items = json.loads(out.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            items = []
        root = str(ctx.source_dir)
        for it in items if isinstance(items, list) else []:
            rel = _rel(it.get("File", ""), root)
            drafts.append(FindingDraft(
                title=f"{it.get('RuleID')}: {it.get('Description', '')[:80]} ({rel}:{it.get('StartLine')})",
                category="secret_exposed", module=f"tool:{self.tool}", severity="high", confidence="likely", asset=rel,
                file=rel, line=it.get("StartLine"), cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                evidence={"regla": it.get("RuleID"), "commit": (it.get("Commit") or "")[:12] or None,
                          "entropia": it.get("Entropy"), "coincidencia_redactada": str(it.get("Match", ""))[:80]},
                description="Detectado en el " + ("historial git" if it.get("Commit") else "árbol de trabajo") + "."))
        self.finish(ctx, res, drafts)


class GitleaksAdapter(LeaksAdapter):
    tool = "gitleaks"


class CheckovAdapter(Adapter):
    isolation_verified = True
    tool = "checkov"
    phase = "recon"
    needs_source = True

    async def run(self, ctx: ScanContext) -> None:
        wd = ctx.runner.new_workdir(self.tool)
        res = await self.execute(ctx, ["-d", str(ctx.source_dir), "-o", "json", "--quiet", "--compact", "--skip-download",
                                       "--framework", "dockerfile", "kubernetes", "terraform", "cloudformation", "helm",
                                       "github_actions", "--skip-path", "node_modules", "--skip-path", "vendor"],
                                 workdir=wd, timeout=1200, memory_mb=3072)
        drafts = []
        try:
            data = json.loads(res.text or "[]")
        except ValueError:
            data = []
        reports = data if isinstance(data, list) else [data]
        root = str(ctx.source_dir)
        for rep in reports:
            for f in ((rep or {}).get("results") or {}).get("failed_checks", []):
                rel = _rel(str(f.get("file_abs_path") or f.get("file_path", "")).lstrip("/"), root)
                rng = f.get("file_line_range") or [None]
                title = f.get("check_name", "")
                cat = "iac_privileged" if re.search(r"privileg|host|capabilit|docker socket", title, re.I) else \
                    "iac_container_root" if "root" in title.lower() else "iac_secret" if "secret" in title.lower() else \
                    "iac_insecure_config"
                drafts.append(FindingDraft(title=f"{f.get('check_id')}: {title} ({rel}:{rng[0]})", category=cat,
                                           module="tool:checkov", confidence="likely",
                                           severity=str(f.get("severity") or "low").lower(), asset=rel, file=rel,
                                           line=rng[0], references=[f["guideline"]] if f.get("guideline") else [],
                                           evidence={"check": f.get("check_id"), "recurso": f.get("resource")},
                                           fingerprint_extra=f.get("check_id", "")))
        self.finish(ctx, res, drafts)


def _rel(path: str, root: str) -> str:
    p = path.replace("\\", "/")
    r = root.replace("\\", "/").rstrip("/") + "/"
    return p[len(r):] if p.startswith(r) else p.lstrip("./")


ADAPTERS: dict[str, type[Adapter]] = {a.tool: a for a in (
    NucleiAdapter, ZapAdapter, FfufAdapter, SubfinderAdapter, SslyzeAdapter, TestsslAdapter, NmapAdapter, OpengrepAdapter,
    SemgrepAdapter, BanditAdapter, TrivyAdapter, LeaksAdapter, GitleaksAdapter, CheckovAdapter)}

