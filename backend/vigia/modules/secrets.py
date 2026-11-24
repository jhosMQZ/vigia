# vigia:ignore-file — catálogo de patrones de detección (las expresiones regulares se detectarían a sí mismas)
"""Native secret detector for source trees (works without external binaries).

Provider-specific patterns give ``likely`` findings; generic high-entropy assignments give ``suspected``.
Values are always redacted in evidence; placeholders and obvious examples are ignored.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

from vigia.core.context import ScanContext
from vigia.core.findings import FindingDraft
from vigia.core.module import Module
from vigia.modules.frontend import SECRET_RULES, entropy
from vigia.modules.source import is_test_path, iter_files, read_text
from vigia.security.redact import mask

EXTRA_RULES: list[tuple[str, re.Pattern[str], str]] = [
    ("Clave secreta AWS", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})"), "critical"),
    ("Cadena de conexión con contraseña", re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://"
                                                     r"[^:\s/@'\"]+:([^@\s'\"]{3,})@[\w.\-]+"), "high"),
    ("Clave de cuenta de servicio GCP", re.compile(r"\"type\"\s*:\s*\"service_account\"[\s\S]{0,400}\"private_key\""), "critical"),
    ("Cadena de conexión Azure Storage", re.compile(r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=([A-Za-z0-9+/=]{40,})"),
     "critical"),
    ("Token de npm", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "high"),
    ("Token de PyPI", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b"), "high"),
    ("Clave de Django SECRET_KEY", re.compile(r"(?m)^\s*SECRET_KEY\s*=\s*[\"']([^\"']{20,})[\"']"), "high"),
    ("Secreto JWT/sesión", re.compile(r"(?i)(?:jwt|session|cookie|app)_?secret\s*[=:]\s*[\"']([^\"'\s]{8,})[\"']"), "high"),
]
GENERIC = re.compile(r"""(?ix)(?:^|[\s,{(])["']?([a-z0-9_.\-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|
                     access[_-]?key|private[_-]?key|client[_-]?secret|auth)[a-z0-9_.\-]*)["']?\s*(?:=|:|=>)\s*
                     ["']([^"'\s]{8,200})["']""")
PLACEHOLDER = re.compile(r"(?i)^(x+|\*+|changeme|change_me|your[_-]|example|sample|dummy|test|password|secret|null|none|"
                         r"undefined|todo|<.*>|\$\{.*\}|\{\{.*\}\}|%\(.*\)s|process\.env|os\.environ|getenv|env\(|config\.|"
                         r"settings\.)")
SKIP_FILES = re.compile(r"(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Pipfile\.lock|composer\.lock|"
                        r"Cargo\.lock|go\.sum|\.svg|\.min\.js)$")


class SecretsModule(Module):
    name = "secrets"
    title = "Secretos en el código"
    phase = "recon"
    needs_source = True

    async def run(self, ctx: ScanContext) -> None:
        drafts = await asyncio.to_thread(scan_tree, ctx.source_dir)
        ctx.emit("info", self.name, f"{len(drafts)} posibles secretos en el código")
        for d in drafts:
            ctx.add(d)


def scan_tree(root: Path) -> list[FindingDraft]:
    out: list[FindingDraft] = []
    seen: set[str] = set()
    for path, rel in iter_files(root, include_minified=False):
        if SKIP_FILES.search(rel):
            continue
        text = read_text(path)
        if not text:
            continue
        test = is_test_path(rel)
        env_file = Path(rel).name.startswith(".env") and not rel.endswith((".example", ".sample", ".template", ".dist"))
        rules = [(n, rx, sev) for n, rx, sev, public in SECRET_RULES if not public] + EXTRA_RULES
        for name, rx, sev in rules:
            for m in rx.finditer(text):
                val = m.group(1) if m.groups() and m.group(1) else m.group(0)
                if PLACEHOLDER.match(val) or val in seen or _ignored(text, m.start()):
                    continue
                seen.add(val)
                out.append(_draft(rel, text, m.start(), name, val, sev, "suspected" if test else "likely", test))
        for m in GENERIC.finditer(text):
            key, val = m.group(1), m.group(2)
            if val in seen or PLACEHOLDER.match(val) or entropy(val) < 3.2 or len(set(val)) < 6 or                     _ignored(text, m.start(2)):
                continue
            if re.fullmatch(r"[a-z]+(_[a-z]+)*|[A-Z_]+|\d+|[\w.-]+\.(js|py|html|png)", val):
                continue
            seen.add(val)
            out.append(_draft(rel, text, m.start(2), f"Posible secreto en «{key}»", val,
                              "high" if env_file else "medium", "likely" if env_file and not test else "suspected", test))
    return out


IGNORE_MARK = re.compile(r"vigia:ignore|gitleaks:allow|betterleaks:allow")


def _ignored(text: str, pos: int) -> bool:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    return bool(IGNORE_MARK.search(text[start: end if end >= 0 else len(text)]))


def _draft(rel: str, text: str, pos: int, name: str, val: str, sev: str, conf: str, test: bool) -> FindingDraft:
    line = text.count("\n", 0, pos) + 1
    src_line = text.splitlines()[line - 1] if line - 1 < len(text.splitlines()) else ""
    vector = {"critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", "high": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
              "medium": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N"}.get(sev)
    return FindingDraft(
        title=f"{name} en {rel}:{line}", category="secret_exposed", module="secrets", confidence=conf, native_evidence=False,
        asset=rel, file=rel, line=line, snippet=src_line.replace(val, mask(val, 4))[:400], cvss_vector=vector,
        description="Credencial en el código fuente" + (" (fichero de pruebas: verifica si es real)." if test else ".") +
                    " Rótala aunque se elimine del repositorio: puede seguir en el historial.",
        evidence={"tipo": name, "valor_redactado": mask(val, 4), "longitud": len(val), "entropia": round(entropy(val), 2)},
        sources=["native:secrets"], tags=["test-code"] if test else [])
