"""Report generation: executive report (HTML + PDF, plain language), technical report (HTML + PDF), JSON, CSV and a
CycloneDX SBOM.

Everything is produced from the persisted, correlated results (never from raw tool output) and stored
under data/reports/scan-<id>/. Evidence is already redacted upstream; CSV cells are protected against
formula injection.
"""
from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, select_autoescape
from sqlalchemy import select

from vigia import __version__
from vigia.config import get_settings
from vigia.core.profiles import PROFILES
from vigia.correlation.plain import SEVERITY_PLAIN, plain_count, plain_for
from vigia.db import AttackChain, Finding, Project, Scan, Scope, SessionLocal, ToolRun

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_LABEL = {"critical": "Crítico", "high": "Grave", "medium": "Moderado", "low": "Leve", "info": "Informativo"}  # as in the UI
STATUS_LABEL = {"completed": "completado", "stopped": "detenido antes de terminar", "cancelled": "cancelado",
                "failed": "no se pudo completar", "running": "en curso", "queued": "en espera"}
CONF_LABEL = {"confirmed": "Confirmada", "likely": "Probable", "suspected": "Sospecha", "false_positive": "Falso positivo"}
REPORT_FILES = {"executive": "executive.html", "executive_pdf": "executive.pdf", "json": "report.json",
                "csv": "findings.csv", "html": "report.html", "pdf": "report.pdf", "sbom": "sbom.cdx.json"}
REMEDIATION_LABEL = {"open": "Pendiente", "in_progress": "En curso", "fixed": "Corregido", "accepted_risk": "Riesgo aceptado",
                     "false_positive": "Falso positivo"}


def report_dir(scan_id: int) -> Path:
    d = get_settings().data_dir / "reports" / f"scan-{int(scan_id)}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _f2d(f: Finding) -> dict[str, Any]:
    return {"id": f.id, "fingerprint": f.fingerprint, "title": f.title, "category": f.category, "module": f.module,
            "severity": f.severity, "confidence": f.confidence, "cvss_score": f.cvss_score, "cvss_vector": f.cvss_vector,
            "cwe": f.cwe, "cve": f.cve, "owasp": f.owasp, "asset": f.asset, "endpoint": f.endpoint, "method": f.method,
            "parameter": f.parameter, "file": f.file, "line": f.line, "function": f.function, "snippet": f.snippet,
            "description": f.description, "evidence": f.evidence, "impact": f.impact, "likelihood": f.likelihood,
            "recommendation": f.recommendation, "references": f.references, "sources": f.sources, "priority": f.priority,
            "validation_status": f.validation_status, "remediation_status": f.remediation_status,
            "chain_ids": f.chain_ids, "plain": plain_for(f.category)}


def collect(scan_id: int) -> dict[str, Any]:
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            raise ValueError("escaneo inexistente")
        project = db.get(Project, scan.project_id)
        scope = db.get(Scope, scan.scope_id) if scan.scope_id else None
        findings = sorted(db.scalars(select(Finding).where(Finding.scan_id == scan_id)).all(),
                          key=lambda f: (SEV_ORDER.get(f.severity, 9), -f.priority))
        chains = db.scalars(select(AttackChain).where(AttackChain.scan_id == scan_id)).all()
        tools = db.scalars(select(ToolRun).where(ToolRun.scan_id == scan_id)).all()
        return {
            "generator": {"name": "Vigía", "version": __version__, "generated_at": datetime.now(timezone.utc).isoformat()},
            "project": {"id": project.id, "name": project.name} if project else None,
            "scan": {"id": scan.id, "profile": scan.profile, "profile_name": PROFILES[scan.profile].name, "status": scan.status,
                     "started_at": scan.started_at.isoformat() if scan.started_at else None,
                     "finished_at": scan.finished_at.isoformat() if scan.finished_at else None, "summary": scan.summary,
                     "config": scan.config, "error": scan.error},
            "scope": {"name": scope.name, "targets": scope.targets, "exclusions": scope.exclusions,
                      "authorization": {"attested_at": scope.auth_attested_at.isoformat() if scope.auth_attested_at else None,
                                        "reference": scope.auth_reference, "statement": scope.auth_statement}}
            if scope else None,
            "findings": [_f2d(f) for f in findings],
            "chains": [{"id": c.id, "rule": c.rule, "title": c.title, "severity": c.severity, "narrative": c.narrative,
                        "steps": c.steps, "recommendation": c.recommendation} for c in chains],
            "engines": [{"tool": t.tool, "version": t.version, "status": t.status, "duration_s": t.duration,
                         "findings": t.findings_count, "error": t.error} for t in tools],
        }


def _csv_safe(v: Any) -> str:
    s = "" if v is None else (", ".join(map(str, v)) if isinstance(v, list) else str(v))
    s = s.replace("\r", " ").replace("\n", " ")
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def write_csv(data: dict[str, Any], path: Path) -> None:
    cols = ["id", "severity", "confidence", "cvss_score", "title", "category", "cwe", "cve", "owasp", "asset", "endpoint",
            "method", "parameter", "file", "line", "priority", "validation_status", "remediation_status", "recommendation"]
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_ALL)
    w.writerow(cols)
    for f in data["findings"]:
        w.writerow([_csv_safe(f.get(c)) for c in cols])
    path.write_text("﻿" + buf.getvalue(), encoding="utf-8")


HTML_TEMPLATE = """<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>Informe Vigía — {{ d.project.name if d.project else '' }} #{{ d.scan.id }}</title>
<style>{{ css }}</style></head><body><main>
<p class="eyebrow">Vigía · Informe técnico</p><h1>Informe de seguridad — {{ d.project.name if d.project else '' }}</h1>
<div class="muted">Escaneo #{{ d.scan.id }} · {{ d.scan.profile_name }} · estado {{ d.scan.status }} · generado {{ d.generator.generated_at[:19] }} UTC por Vigía {{ d.generator.version }}</div>
{% if d.scan.error %}<p class="card">⚠ {{ d.scan.error }}</p>{% endif %}
<h2>Resumen</h2>
<div class="grid">
{% for s in ['critical','high','medium','low','info'] %}<div class="card"><div class="n">{{ counts[s] }}</div><span class="sev {{ s }}">{{ sev_label[s] }}</span></div>{% endfor %}
<div class="card"><div class="n">{{ d.scan.summary.get('risk_score', '—') }}</div><span class="muted">Índice de riesgo (0-100)</span></div>
<div class="card"><div class="n">{{ d.chains|length }}</div><span class="muted">Cadenas de ataque</span></div>
</div>
{% if d.scope %}<h2>Alcance y autorización</h2><table><tr><th>Objetivos</th><td>{{ d.scope.targets|join(', ') }}</td></tr>
<tr><th>Exclusiones</th><td>{{ d.scope.exclusions|join(', ') or '—' }}</td></tr>
<tr><th>Autorización</th><td>{{ d.scope.authorization.attested_at or '—' }} · ref. {{ d.scope.authorization.reference or '—' }}</td></tr></table>{% endif %}
{% if d.chains %}<h2>Cadenas de ataque</h2>{% for c in d.chains %}<details open><summary><span class="sev {{ c.severity }}">{{ sev_label[c.severity] }}</span> {{ c.title }}</summary>
<p>{{ c.narrative }}</p><ol>{% for s in c.steps %}<li>{{ s.title }} <span class="muted">({{ conf_label.get(s.confidence, s.confidence) }})</span></li>{% endfor %}</ol>
<p><b>Corrección:</b> {{ c.recommendation }}</p></details>{% endfor %}{% endif %}
<h2>Hallazgos ({{ d.findings|length }})</h2>
<table><tr><th>Sev.</th><th>Título</th><th>Confianza</th><th>CVSS</th><th>Ubicación</th></tr>
{% for f in d.findings %}<tr><td><span class="sev {{ f.severity }}">{{ sev_label[f.severity] }}</span></td><td><a href="#f{{ f.id }}" style="color:inherit">{{ f.title }}</a></td>
<td>{{ conf_label.get(f.confidence, f.confidence) }}</td><td>{{ f.cvss_score or '—' }}</td><td>{{ f.endpoint or ((f.file or '') ~ (':' ~ f.line if f.line else '')) or f.asset }}</td></tr>{% endfor %}</table>
{% for f in d.findings %}<details id="f{{ f.id }}"><summary><span class="sev {{ f.severity }}">{{ sev_label[f.severity] }}</span> {{ f.title }}</summary>
<table>
<tr><th>Categoría</th><td>{{ f.category }} · {{ f.cwe or '' }} · {{ f.owasp|join(', ') }}</td></tr>
{% if f.cve %}<tr><th>CVE</th><td>{{ f.cve|join(', ') }}</td></tr>{% endif %}
<tr><th>CVSS 3.1</th><td>{{ f.cvss_score or '—' }} {{ f.cvss_vector or '' }}</td></tr>
<tr><th>Confianza / validación</th><td>{{ conf_label.get(f.confidence, f.confidence) }} · {{ f.validation_status }} · fuentes: {{ f.sources|join(', ') }}</td></tr>
<tr><th>Activo</th><td>{{ f.asset }}</td></tr>
{% if f.endpoint %}<tr><th>Endpoint</th><td>{{ f.method or '' }} {{ f.endpoint }}{% if f.parameter %} · parámetro «{{ f.parameter }}»{% endif %}</td></tr>{% endif %}
{% if f.file %}<tr><th>Código</th><td>{{ f.file }}{% if f.line %}:{{ f.line }}{% endif %}{% if f.function %} ({{ f.function }}){% endif %}</td></tr>{% endif %}
<tr><th>Descripción</th><td>{{ f.description }}</td></tr><tr><th>Impacto</th><td>{{ f.impact }}</td></tr>
<tr><th>Probabilidad</th><td>{{ f.likelihood }}</td></tr><tr><th>Recomendación</th><td>{{ f.recommendation }}</td></tr>
<tr><th>Estado</th><td>{{ f.remediation_status }}</td></tr>
</table>{% if f.snippet %}<pre>{{ f.snippet }}</pre>{% endif %}<pre>{{ f.evidence | tojson(indent=2) }}</pre>
{% if f.references %}<p class="muted">{% for r in f.references %}{{ r }}<br>{% endfor %}</p>{% endif %}</details>{% endfor %}
<h2>Motores utilizados</h2><table><tr><th>Motor</th><th>Versión</th><th>Estado</th><th>Duración</th><th>Resultados</th><th>Detalle</th></tr>
{% for t in d.engines %}<tr><td>{{ t.tool }}</td><td>{{ t.version or '—' }}</td><td>{{ t.status }}</td><td>{{ t.duration_s }}s</td><td>{{ t.findings }}</td><td>{{ t.error or '' }}</td></tr>{% endfor %}</table>
<p class="muted">Las pruebas fueron no destructivas y limitadas al alcance autorizado. «Confirmada» exige evidencia propia de Vigía; «Probable» y «Sospecha» requieren validación manual. Ningún análisis garantiza la ausencia de vulnerabilidades.</p>
</main></body></html>"""

# Shared print-friendly identity (deep blue / petrol / ivory), WCAG-AA contrast, no external resources.
REPORT_CSS = """
:root{--ink:#172B3A;--petrol:#287C75;--ivory:#F3F4EF;--sage:#DCE5E3;--amber:#D49A55;--muted:#5B6878;--line:#D5DDDB;
--crit:#A8322D;--high:#B85C1E;--med:#8A6A12;--low:#2F6690;--info:#5B6878}
*{box-sizing:border-box}body{font:14px/1.6 "Segoe UI",system-ui,-apple-system,sans-serif;margin:0;background:var(--ivory);color:var(--ink)}
main{max-width:1040px;margin:0 auto;padding:40px 32px 64px;background:#fff;min-height:100vh}
.eyebrow{margin:0;color:var(--petrol);font-weight:600;font-size:12px;letter-spacing:.08em;text-transform:uppercase}
h1{font-size:26px;margin:4px 0 6px;font-weight:650;letter-spacing:-.01em}h2{font-size:18px;margin:36px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line)}
h3{font-size:15px;margin:18px 0 6px}.muted{color:var(--muted)}p{margin:6px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card{border:1px solid var(--line);border-radius:6px;padding:14px 16px;background:#fff}
.n{font-size:28px;font-weight:700;font-variant-numeric:tabular-nums}
.sev{display:inline-block;padding:1px 9px;border-radius:4px;font-size:12px;font-weight:600;color:#fff;white-space:nowrap}
.critical{background:var(--crit)}.high{background:var(--high)}.medium{background:var(--med)}.low{background:var(--low)}.info{background:var(--info)}
.status{font-size:17px;padding:14px 18px;border-left:4px solid var(--petrol);background:var(--sage);border-radius:0 6px 6px 0}
.status.bad{border-left-color:var(--crit)}.status.warn{border-left-color:var(--amber)}
table{width:100%;border-collapse:collapse}td,th{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{font-size:12px;color:var(--muted);font-weight:600}
details{border:1px solid var(--line);border-radius:6px;margin:10px 0;padding:10px 14px}summary{cursor:pointer;font-weight:600}
pre{white-space:pre-wrap;word-break:break-word;background:var(--ivory);padding:10px;border-radius:4px;font-size:12px;border:1px solid var(--line)}
.issue{border:1px solid var(--line);border-radius:6px;padding:14px 18px;margin:12px 0;page-break-inside:avoid}
.issue h3{margin:4px 0 8px}.kv{display:grid;grid-template-columns:140px 1fr;gap:4px 14px}.kv>div:nth-child(odd){color:var(--muted)}
footer{margin-top:40px;font-size:12px;color:var(--muted);border-top:1px solid var(--line);padding-top:12px}
@media print{body{background:#fff}main{padding:0}details{border-color:#ccc}}
"""

EXEC_TEMPLATE = """<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>Resumen ejecutivo — {{ d.project.name if d.project else '' }}</title><style>{{ css }}</style></head><body><main>
<p class="eyebrow">Vigía · Resumen ejecutivo</p>
<h1>{{ d.project.name if d.project else 'Proyecto' }}</h1>
<p class="muted">Análisis del {{ (d.scan.finished_at or d.scan.started_at or '')[:10] }} · {{ d.scan.profile_name }}{% if d.scope %} · {{ d.scope.targets|join(', ') }}{% endif %}</p>
<p class="status {{ status_class }}">{{ headline }}</p>
<h2>Situación</h2>
<div class="grid">{% for s in ['critical','high','medium','low'] %}<div class="card"><div class="n">{{ counts[s] }}</div>
<span class="sev {{ s }}">{{ sev_label[s] }}</span><p class="muted" style="font-size:12px">{{ sev_plain[s] }}</p></div>{% endfor %}</div>
<ul>{% for line in count_lines %}<li>{{ line }}</li>{% endfor %}</ul>
{% if top %}<h2>Qué conviene atender primero</h2>
{% for f in top %}<div class="issue"><span class="sev {{ f.severity }}">{{ sev_label[f.severity] }}</span>
<span class="muted" style="font-size:12px"> · {{ remediation_label.get(f.remediation_status, f.remediation_status) }}</span>
<h3>{{ f.plain.title }}</h3><p>{{ f.plain.summary }}</p>
<div class="kv"><div>Posible consecuencia</div><div>{{ f.plain.impact }}</div><div>Qué hacer</div><div>{{ f.plain.action }}</div>
<div>Dónde</div><div>{{ f.endpoint or f.file or f.asset }}</div></div></div>{% endfor %}{% endif %}
{% if d.chains %}<h2>Riesgos combinados</h2><p>Algunos problemas, juntos, permiten un ataque más grave que cada uno por separado:</p>
<ul>{% for c in d.chains %}<li><b>{{ c.title }}</b>: {{ c.recommendation }}</li>{% endfor %}</ul>{% endif %}
<h2>Alcance y garantías</h2>
<p>El análisis se limitó a los objetivos autorizados{% if d.scope and d.scope.authorization.reference %} (autorización ref. {{ d.scope.authorization.reference }}){% endif %}
y empleó pruebas no destructivas. Los resultados marcados como «confirmados» tienen evidencia directa; el resto requiere revisión técnica.
Ningún análisis automatizado garantiza la ausencia de vulnerabilidades.</p>
<p class="muted">El detalle técnico de cada punto (evidencias, referencias y pasos de corrección) está en el informe técnico.</p>
<footer>Generado por Vigía {{ d.generator.version }} el {{ d.generator.generated_at[:19] }} UTC · Análisis #{{ d.scan.id }}</footer>
</main></body></html>"""

_env = Environment(autoescape=select_autoescape(default=True, default_for_string=True))


def _counts(data: dict[str, Any]) -> dict[str, int]:
    live = [f for f in data["findings"] if f.get("remediation_status") not in ("false_positive",)]
    return {s: sum(1 for f in live if f["severity"] == s) for s in SEV_ORDER}


def executive_summary(data: dict[str, Any]) -> dict[str, Any]:
    counts = _counts(data)
    pending = [f for f in data["findings"] if f.get("remediation_status") in ("open", "in_progress", None)]
    if counts["critical"]:
        headline, cls = f"{plain_count('critical', counts['critical'])}.", "bad"
    elif counts["high"]:
        headline, cls = f"{plain_count('high', counts['high'])}.", "bad"
    elif counts["medium"]:
        headline, cls = f"No hay problemas críticos ni graves. {plain_count('medium', counts['medium'])}.", "warn"
    else:
        headline, cls = "No se encontraron problemas críticos, graves ni de gravedad media en el alcance analizado.", ""
    status = data["scan"].get("status")
    if status not in ("completed",):
        headline += (f" El análisis quedó {STATUS_LABEL.get(status, status)}: los resultados pueden estar incompletos.")
    top = [f for f in pending if f["severity"] in ("critical", "high", "medium")][:12]
    lines = [plain_count(s, counts[s]) for s in ("critical", "high", "medium", "low") if counts[s]]
    return {"headline": headline, "status_class": cls, "counts": counts, "top": top, "count_lines": lines}


def write_html(data: dict[str, Any], path: Path) -> None:
    counts = {s: sum(1 for f in data["findings"] if f["severity"] == s) for s in SEV_ORDER}
    html = _env.from_string(HTML_TEMPLATE).render(d=data, counts=counts, sev_label=SEV_LABEL, conf_label=CONF_LABEL,
                                                  css=REPORT_CSS)
    path.write_text(html, encoding="utf-8")


def write_executive_html(data: dict[str, Any], path: Path) -> None:
    ex = executive_summary(data)
    html = _env.from_string(EXEC_TEMPLATE).render(d=data, css=REPORT_CSS, sev_label=SEV_LABEL, sev_plain=SEVERITY_PLAIN,
                                                  remediation_label=REMEDIATION_LABEL, **ex)
    path.write_text(html, encoding="utf-8")


def write_executive_pdf(data: dict[str, Any], path: Path) -> None:
    from xml.sax.saxutils import escape

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    ex = executive_summary(data)
    ink, petrol = colors.HexColor("#172B3A"), colors.HexColor("#287C75")
    ss = getSampleStyleSheet()
    title = ParagraphStyle("t", parent=ss["Title"], textColor=ink, alignment=0, fontSize=20, leading=24)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], textColor=ink, fontSize=13, spaceBefore=12)
    body = ParagraphStyle("b", parent=ss["BodyText"], textColor=ink, fontSize=10, leading=14)
    small = ParagraphStyle("s", parent=body, fontSize=8.5, leading=11, textColor=colors.HexColor("#5B6878"))
    eyebrow = ParagraphStyle("e", parent=small, textColor=petrol, fontSize=9)

    def p(txt: Any, st=body) -> Paragraph:  # noqa: ANN001
        return Paragraph(escape(str(txt or "")[:3000]), st)  # cut before escaping: never split an entity
    doc = SimpleDocTemplate(str(path), pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=18 * mm,
                            bottomMargin=18 * mm, title=f"Resumen ejecutivo Vigía #{data['scan']['id']}")
    el = [p("VIGÍA · RESUMEN EJECUTIVO", eyebrow), p(data["project"]["name"] if data["project"] else "Proyecto", title),
          p(f"Análisis #{data['scan']['id']} · {data['scan']['profile_name']}", small), Spacer(1, 8),
          p(ex["headline"], ParagraphStyle("hl", parent=body, fontSize=12, leading=16, backColor=colors.HexColor("#DCE5E3"),
                                           borderPadding=8)), Spacer(1, 10)]
    rows = [["Gravedad", "Problemas", "Qué significa"]] + [[SEV_LABEL[s], str(ex["counts"][s]), SEVERITY_PLAIN[s]]
                                                          for s in ("critical", "high", "medium", "low")]
    t = Table(rows, colWidths=[30 * mm, 24 * mm, 110 * mm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), ink), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                           ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#D5DDDB")), ("FONTSIZE", (0, 0), (-1, -1), 9)]))
    el += [t]
    if ex["top"]:
        el.append(p("Qué conviene atender primero", h2))
        for f in ex["top"]:
            el += [p(f"[{SEV_LABEL[f['severity']]}] {f['plain']['title']}", ParagraphStyle("it", parent=body, fontName="Helvetica-Bold")),
                   p(f["plain"]["summary"]), p("Posible consecuencia: " + f["plain"]["impact"], small),
                   p("Qué hacer: " + f["plain"]["action"], small), Spacer(1, 6)]
    el += [p("Alcance y garantías", h2),
           p("El análisis se limitó a los objetivos autorizados y empleó pruebas no destructivas. Los resultados "
             "«confirmados» tienen evidencia directa; el resto requiere revisión técnica. Ningún análisis automatizado "
             "garantiza la ausencia de vulnerabilidades. El detalle técnico está en el informe técnico.")]
    doc.build(el)


def write_pdf(data: dict[str, Any], path: Path) -> None:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    from xml.sax.saxutils import escape

    styles = getSampleStyleSheet()
    small = ParagraphStyle("small", parent=styles["BodyText"], fontSize=8, leading=10)
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=9, leading=12)
    sev_col = {"critical": colors.HexColor("#c62828"), "high": colors.HexColor("#ef6c00"), "medium": colors.HexColor("#f9a825"),
               "low": colors.HexColor("#0277bd"), "info": colors.HexColor("#757575")}

    def p(txt: Any, st=body) -> Paragraph:  # noqa: ANN001
        return Paragraph(escape(str(txt if txt is not None else "")[:4000]).replace("\n", "<br/>"), st)

    doc = SimpleDocTemplate(str(path), pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=16 * mm,
                            bottomMargin=16 * mm, title=f"Informe Vigía #{data['scan']['id']}")
    el = [Paragraph(f"Informe de seguridad — {escape(data['project']['name'] if data['project'] else '')}", styles["Title"]),
          p(f"Escaneo #{data['scan']['id']} · {data['scan']['profile_name']} · estado {data['scan']['status']} · "
            f"generado {data['generator']['generated_at'][:19]} UTC"), Spacer(1, 8)]
    counts = [[SEV_LABEL[s], str(sum(1 for f in data["findings"] if f["severity"] == s))] for s in SEV_ORDER]
    t = Table([["Severidad", "Hallazgos"]] + counts, colWidths=[60 * mm, 30 * mm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263238")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                           ("GRID", (0, 0), (-1, -1), 0.3, colors.grey)]))
    el += [t, Spacer(1, 6), p(f"Índice de riesgo: {data['scan']['summary'].get('risk_score', '—')} / 100 · "
                              f"cadenas de ataque: {len(data['chains'])}")]
    if data["scope"]:
        el += [Spacer(1, 6), Paragraph("Alcance y autorización", styles["Heading2"]),
               p("Objetivos: " + ", ".join(data["scope"]["targets"])),
               p(f"Autorización registrada: {data['scope']['authorization']['attested_at']} · "
                 f"referencia: {data['scope']['authorization']['reference'] or '—'}")]
    if data["chains"]:
        el.append(Paragraph("Cadenas de ataque", styles["Heading2"]))
        for c in data["chains"]:
            el += [p(f"[{SEV_LABEL[c['severity']]}] {c['title']}", styles["Heading4"]), p(c["narrative"]),
                   p("Corrección: " + c["recommendation"]), Spacer(1, 4)]
    el += [PageBreak(), Paragraph("Hallazgos", styles["Heading2"])]
    rows = [["Sev.", "Título", "Conf.", "CVSS"]]
    for f in data["findings"]:
        rows.append([p(SEV_LABEL[f["severity"]], small), p(f["title"], small), p(CONF_LABEL.get(f["confidence"], ""), small),
                     p(f["cvss_score"] or "—", small)])
    t = Table(rows, colWidths=[18 * mm, 120 * mm, 22 * mm, 14 * mm], repeatRows=1)
    st = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263238")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
          ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey), ("VALIGN", (0, 0), (-1, -1), "TOP")]
    for i, f in enumerate(data["findings"], start=1):
        st.append(("BACKGROUND", (0, i), (0, i), sev_col.get(f["severity"], colors.grey)))
    t.setStyle(TableStyle(st))
    el += [t, PageBreak()]
    for f in data["findings"][:300]:
        loc = f["endpoint"] or (f"{f['file']}:{f['line']}" if f["file"] else f["asset"])
        el += [p(f"[{SEV_LABEL[f['severity']]}] {f['title']}", styles["Heading4"]),
               p(f"{f['category']} · {f['cwe'] or ''} · {', '.join(f['owasp'])} · CVSS {f['cvss_score'] or '—'} "
                 f"{f['cvss_vector'] or ''}", small),
               p(f"Ubicación: {loc} · confianza {CONF_LABEL.get(f['confidence'], '')} · fuentes {', '.join(f['sources'])}", small),
               p(f["description"]), p("Impacto: " + (f["impact"] or "")), p("Recomendación: " + (f["recommendation"] or "")),
               p("Evidencia: " + json.dumps(f["evidence"], ensure_ascii=False)[:1500], small), Spacer(1, 6)]
    if len(data["findings"]) > 300:
        el.append(p(f"… {len(data['findings']) - 300} hallazgos más en los formatos JSON/CSV/HTML."))
    el += [Paragraph("Motores utilizados", styles["Heading2"])]
    for e in data["engines"]:
        el.append(p(f"{e['tool']} {e['version'] or ''}: {e['status']} ({e['duration_s']} s, {e['findings']} resultados) "
                    f"{e['error'] or ''}", small))
    doc.build(el)


def write_sbom(scan_id: int, dependencies: list[dict[str, Any]], path: Path) -> None:
    purl_type = {"PyPI": "pypi", "npm": "npm", "Packagist": "composer", "Go": "golang", "RubyGems": "gem",
                 "crates.io": "cargo", "Maven": "maven", "NuGet": "nuget"}
    comps, seen = [], set()
    for d in dependencies:
        key = (d["ecosystem"], d["name"], d["version"])
        if key in seen:
            continue
        seen.add(key)
        t = purl_type.get(d["ecosystem"], "generic")
        name = d["name"]
        if t == "maven" and ":" in name:
            g, a = name.split(":", 1)
            purl = f"pkg:maven/{g}/{a}@{d['version']}"
        else:
            purl = f"pkg:{t}/{name}@{d['version']}"
        comps.append({"type": "library", "name": name, "version": d["version"], "purl": purl,
                      "properties": [{"name": "vigia:source", "value": d.get("file", "")}]})
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
           "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(),
                        "tools": {"components": [{"type": "application", "name": "Vigía", "version": __version__}]},
                        "properties": [{"name": "vigia:scan_id", "value": str(scan_id)}]},
           "components": comps}
    path.write_text(json.dumps(bom, indent=2, ensure_ascii=False), encoding="utf-8")


def generate_all(scan_id: int, dependencies: list[dict[str, Any]] | None = None,
                 final_status: str | None = None) -> dict[str, str]:
    """``final_status``: the reports are written just before the scan's final status is stored, so the caller that
    knows it passes it (otherwise every report would say the scan was still running)."""
    data = collect(scan_id)
    if final_status:
        data["scan"]["status"] = final_status
    d = report_dir(scan_id)
    (d / REPORT_FILES["json"]).write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    write_executive_html(data, d / REPORT_FILES["executive"])
    write_executive_pdf(data, d / REPORT_FILES["executive_pdf"])
    write_csv(data, d / REPORT_FILES["csv"])
    write_html(data, d / REPORT_FILES["html"])
    write_pdf(data, d / REPORT_FILES["pdf"])
    if dependencies:
        write_sbom(scan_id, dependencies, d / REPORT_FILES["sbom"])
    return {k: str(d / v) for k, v in REPORT_FILES.items() if (d / v).exists()}
