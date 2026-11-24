"""Software composition analysis: dependency manifests → OSV advisories (CVE/GHSA), unpinned dependencies, SBOM data."""
from __future__ import annotations

import asyncio
import json
import re
import tomllib
from pathlib import Path
from typing import Any

import yaml
from defusedxml.ElementTree import fromstring as safe_xml

from vigia.config import get_settings
from vigia.core.context import ScanContext
from vigia.core.findings import FindingDraft
from vigia.core.module import Module
from vigia.correlation import intel
from vigia.modules.source import iter_files, read_text

Dep = dict[str, Any]


def _req_line(line: str) -> tuple[str, str | None, bool] | None:
    line = line.split("#", 1)[0].strip()
    if not line or line.startswith(("-", "git+", "http")):
        return None
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._\-]*)(\[[^\]]*\])?\s*(==|===|>=|<=|~=|!=|>|<)?\s*([\w.*+!\-]+)?", line)
    if not m:
        return None
    return m.group(1).lower(), m.group(4) if m.group(3) in ("==", "===") else None, m.group(3) in ("==", "===")


def parse_manifest(rel: str, text: str) -> tuple[list[Dep], list[str]]:
    """Returns (dependencies with exact versions, names of unpinned dependencies)."""
    name = Path(rel).name.lower()
    deps: list[Dep] = []
    unpinned: list[str] = []

    def add(eco: str, n: str, v: str | None) -> None:
        if n and v and re.match(r"^v?\d", v):
            deps.append({"ecosystem": eco, "name": n, "version": v.lstrip("v=^~ "), "file": rel})

    try:
        if re.match(r"requirements.*\.txt$", name) or name in ("constraints.txt",):
            for line in text.splitlines():
                r = _req_line(line)
                if r:
                    (add("PyPI", r[0], r[1]) if r[2] else unpinned.append(r[0]))
        elif name == "pipfile.lock":
            data = json.loads(text)
            for sec in ("default", "develop"):
                for n, info in (data.get(sec) or {}).items():
                    add("PyPI", n.lower(), str(info.get("version", "")).lstrip("="))
        elif name in ("poetry.lock", "uv.lock"):
            data = tomllib.loads(text)
            for p in data.get("package", []):
                add("PyPI", str(p.get("name", "")).lower(), p.get("version"))
        elif name == "package-lock.json":
            data = json.loads(text)
            for path, info in (data.get("packages") or {}).items():
                if path and "node_modules/" in path:
                    add("npm", path.rsplit("node_modules/", 1)[-1], info.get("version"))
            for n, info in (data.get("dependencies") or {}).items() if not data.get("packages") else []:
                add("npm", n, info.get("version"))
        elif name == "yarn.lock":
            cur = None
            for line in text.splitlines():
                if line and not line.startswith(" ") and line.rstrip().endswith(":"):
                    first = line.split(",")[0].strip().strip('"')
                    cur = first.rsplit("@", 1)[0] if not first.startswith("@") or first.count("@") > 1 else first
                elif cur and line.strip().startswith("version"):
                    add("npm", cur, line.split()[-1].strip('"'))
                    cur = None
        elif name == "pnpm-lock.yaml":
            data = yaml.safe_load(text) or {}
            for key in (data.get("packages") or {}):
                m = re.match(r"^/?(@?[^@]+)@([\d][^(]*)", str(key))
                if m:
                    add("npm", m.group(1), m.group(2))
        elif name == "package.json":
            data = json.loads(text)
            for sec in ("dependencies", "devDependencies"):
                for n, v in (data.get(sec) or {}).items():
                    if not re.match(r"^\d+\.\d+\.\d+$", str(v)):
                        unpinned.append(n)
        elif name == "composer.lock":
            data = json.loads(text)
            for p in (data.get("packages") or []) + (data.get("packages-dev") or []):
                add("Packagist", p.get("name", ""), str(p.get("version", "")).lstrip("v"))
        elif name == "go.mod":
            for m in re.finditer(r"(?m)^\s*(?:require\s+)?([\w.\-/]+\.[a-z]{2,}[\w.\-/]*)\s+(v[\d][\w.\-+]*)", text):
                add("Go", m.group(1), m.group(2))
        elif name == "gemfile.lock":
            for m in re.finditer(r"(?m)^    ([a-zA-Z0-9_\-]+) \(([\d][\w.]*)\)", text):
                add("RubyGems", m.group(1), m.group(2))
        elif name == "cargo.lock":
            data = tomllib.loads(text)
            for p in data.get("package", []):
                add("crates.io", p.get("name", ""), p.get("version"))
        elif name == "pom.xml":
            root = safe_xml(text.encode())
            ns = {"m": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}
            q = (lambda t: f"m:{t}") if ns else (lambda t: t)
            for d in root.iter(("{%s}dependency" % ns["m"]) if ns else "dependency"):
                g, a, v = d.find(q("groupId"), ns), d.find(q("artifactId"), ns), d.find(q("version"), ns)
                if g is not None and a is not None and v is not None and v.text and "${" not in v.text:
                    add("Maven", f"{g.text}:{a.text}", v.text)
        elif name in ("packages.lock.json",):
            data = json.loads(text)
            for fw in (data.get("dependencies") or {}).values():
                for n, info in fw.items():
                    add("NuGet", n, info.get("resolved"))
        elif name.endswith(".csproj"):
            for m in re.finditer(r"<PackageReference\s+Include=\"([^\"]+)\"\s+Version=\"([^\"]+)\"", text):
                add("NuGet", m.group(1), m.group(2))
        elif name == "gradle.lockfile":
            for m in re.finditer(r"(?m)^([\w.\-]+:[\w.\-]+):([\d][\w.\-]*)=", text):
                add("Maven", m.group(1), m.group(2))
    except (ValueError, KeyError, TypeError, yaml.YAMLError, tomllib.TOMLDecodeError, AttributeError):
        pass
    except Exception:  # noqa: BLE001 - defusedxml raises its own types for hostile XML
        pass
    return deps, unpinned


MANIFESTS = re.compile(r"(^|/)(requirements[^/]*\.txt|constraints\.txt|Pipfile\.lock|poetry\.lock|uv\.lock|package-lock\.json|"
                       r"yarn\.lock|pnpm-lock\.yaml|package\.json|composer\.lock|go\.mod|Gemfile\.lock|Cargo\.lock|pom\.xml|"
                       r"packages\.lock\.json|[^/]+\.csproj|gradle\.lockfile)$", re.I)


class ScaModule(Module):
    name = "sca"
    title = "Dependencias vulnerables (SCA)"
    phase = "recon"
    needs_source = True

    async def run(self, ctx: ScanContext) -> None:
        deps, unpinned_by_file = await asyncio.to_thread(self.collect, ctx.source_dir)
        ctx.kb.dependencies.extend(deps)
        files_with_lock = {Path(d["file"]).parent.as_posix() for d in deps if d["file"].endswith(("lock", ".json", ".yaml"))}
        for rel, names in unpinned_by_file.items():
            if Path(rel).name == "package.json" and Path(rel).parent.as_posix() in files_with_lock:
                continue  # a lockfile pins the real versions
            if names:
                ctx.add(FindingDraft(title=f"{len(names)} dependencias sin versión exacta en {rel}",
                                     category="unpinned_dependency", module=self.name, confidence="confirmed",
                                     native_evidence=True, asset=rel, file=rel, line=1,
                                     evidence={"dependencias": names[:30]}, sources=["native:sca"]))
        uniq = {(d["ecosystem"], d["name"], d["version"]): d for d in deps}
        ctx.emit("info", self.name, f"{len(uniq)} dependencias con versión exacta en {len({d['file'] for d in deps})} "
                 "ficheros")
        if not uniq:
            return
        if get_settings().offline:
            ctx.emit("warn", self.name, "Modo offline: no se consultan avisos de vulnerabilidad (OSV)")
            return
        try:
            res = await asyncio.to_thread(intel.osv_query, [{"ecosystem": e, "name": n, "version": v}
                                                            for (e, n, v) in uniq])
        except Exception as e:  # noqa: BLE001
            ctx.emit("error", self.name, f"OSV no disponible: {type(e).__name__}: {e}")
            return
        for key, vulns in res.items():
            d = uniq.get(key)
            if not d or not vulns:
                continue
            for v in vulns[:15]:
                cves = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
                sev = (v.get("severity") or "").lower()
                ctx.add(FindingDraft(
                    title=f"{d['name']} {d['version']}: {v['id']}" + (f" ({cves[0]})" if cves else ""),
                    category="vulnerable_dependency", module=self.name, confidence="likely", native_evidence=False,
                    asset=d["file"], file=d["file"], line=None, cve=cves, cvss_vector=v.get("cvss_vector"),
                    severity={"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium",
                              "low": "low"}.get(sev, "medium"),
                    description=v.get("summary", ""), evidence={"paquete": d["name"], "version": d["version"],
                                                                "ecosistema": d["ecosystem"], "aviso": v["id"],
                                                                "corregido_en": v.get("fixed", [])[:5]},
                    recommendation=(f"Actualiza {d['name']} a {v['fixed'][-1]} o superior." if v.get("fixed")
                                    else f"No hay versión corregida publicada para {d['name']}: evalúa sustituirla o mitigar."),
                    references=[f"https://osv.dev/vulnerability/{v['id']}"] + v.get("references", [])[:3],
                    sources=["native:sca-osv"],
                    fingerprint_extra=f"{d['name'].lower()}@{d['version']}:{(sorted(cves) or [v['id']])[0]}"))

    @staticmethod
    def collect(root: Path) -> tuple[list[Dep], dict[str, list[str]]]:
        deps: list[Dep] = []
        unpinned: dict[str, list[str]] = {}
        for path, rel in iter_files(root, include_minified=True, max_size=30_000_000):
            if not MANIFESTS.search(rel):
                continue
            text = read_text(path)
            if text is None:
                continue
            d, u = parse_manifest(rel, text)
            deps.extend(d)
            if u:
                unpinned[rel] = u
        return deps, unpinned
