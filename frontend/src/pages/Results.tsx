import { useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../api'
import { useAuth } from '../auth'
import {
  Disclosure, Empty, ErrorNotice, Loading, Notice, PageHead, Pill, ReportMenu, Sev, SevBar, Tabs, TrendChart, fmtDate, useAsync, useToast,
} from '../components/ui'
import { CONFIDENCE, REMEDIATION, SEVERITIES, SEV_MEANING, SEV_NAME, profileName } from '../copy'
import type { Dashboard, Finding, Project, Scan } from '../types'

type View = 'problemas' | 'comparar'
const DONE = ['completed', 'stopped', 'cancelled', 'failed']

export default function Results() {
  const [params, setParams] = useSearchParams()
  const scanParam = Number(params.get('analisis')) || 0
  const view: View = params.get('vista') === 'comparar' ? 'comparar' : 'problemas'
  const projects = useAsync(() => api.get<Project[]>('/api/projects'), [])
  const dash = useAsync(() => (scanParam ? Promise.resolve(null) : api.get<Dashboard>('/api/dashboard')), [scanParam])
  const [pid, setPid] = useState(0)

  // where to start: the analysis in the address, or the latest analysed project
  useEffect(() => {
    if (scanParam) { api.get<Scan>(`/api/scans/${scanParam}`).then((s) => setPid(s.project_id)).catch(() => {}); return }
    const first = dash.data?.per_project[0]
    if (first) setParams((p) => { const q = new URLSearchParams(p); q.set('analisis', String(first.last_scan)); return q }, { replace: true })
  }, [scanParam, dash.data, setParams])

  const scans = useAsync(() => (pid ? api.get<Scan[]>(`/api/projects/${pid}/scans`) : Promise.resolve([])), [pid])
  const done = useMemo(() => (scans.data ?? []).filter((s) => DONE.includes(s.status) && (s.status === 'completed' || (s.summary?.findings ?? 0) > 0)), [scans.data])
  const scan = scans.data?.find((s) => s.id === scanParam)
  const project = projects.data?.find((p) => p.id === pid)

  const setQuery = (patch: Record<string, string | null>) => setParams((p) => {
    const q = new URLSearchParams(p)
    Object.entries(patch).forEach(([k, v]) => (v ? q.set(k, v) : q.delete(k)))
    return q
  }, { replace: true })

  function chooseProject(id: number) {
    setPid(id)
    api.get<Scan[]>(`/api/projects/${id}/scans`).then((list) => {
      const last = list.find((s) => DONE.includes(s.status) && (s.status === 'completed' || (s.summary?.findings ?? 0) > 0))
      setQuery({ analisis: last ? String(last.id) : null, problema: null })
    }).catch(() => setQuery({ analisis: null, problema: null }))
  }

  const nothing = !scanParam && dash.data && dash.data.per_project.length === 0
  return (
    <div className="page" style={{ maxWidth: 1360 }}>
      <PageHead title="Resultados" intro="Los problemas encontrados, explicados en lenguaje claro, con lo que conviene hacer en cada caso."
        actions={scan && <ReportMenu scanId={scan.id} />} />
      <ErrorNotice error={projects.error ?? dash.error} />
      {nothing ? (
        <div className="panel"><Empty title="Aún no hay resultados" action={<Link className="btn primary" to="/analisis/nuevo">Nuevo análisis</Link>}>
          Cuando termine un análisis, sus problemas aparecerán aquí.</Empty></div>
      ) : (
        <>
          <div className="row" style={{ marginBottom: 18, alignItems: 'flex-end' }}>
            <label className="field" style={{ minWidth: 220 }}>Proyecto
              <select value={pid || ''} onChange={(e) => chooseProject(Number(e.target.value))}>
                <option value="" disabled>Elige un proyecto</option>
                {projects.data?.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}</select></label>
            <label className="field" style={{ minWidth: 300 }}>Análisis
              <select value={scanParam || ''} onChange={(e) => setQuery({ analisis: e.target.value, problema: null })} disabled={!done.length}>
                {!done.length && <option value="">Sin análisis terminados</option>}
                {done.map((s) => <option key={s.id} value={s.id}>{profileName(s.profile, s.profile_name)}, {fmtDate(s.finished_at ?? s.created_at)} ({s.summary?.findings ?? 0} resultados)</option>)}</select></label>
          </div>
          {scanParam > 0 && (
            <Tabs label="Vista" tabs={[['problemas', 'Problemas'], ['comparar', 'Comparar con otro análisis']]} value={view}
              onChange={(v) => setQuery({ vista: v === 'comparar' ? 'comparar' : null })} />
          )}
          {scanParam > 0 && view === 'problemas' && <Problems scanId={scanParam} scan={scan} canEdit={project?.role !== 'viewer'} focus={Number(params.get('problema')) || 0}
            onFocus={(fid) => setQuery({ problema: fid ? String(fid) : null })} />}
          {scanParam > 0 && view === 'comparar' && <Compare scan={scan} done={done} onOpen={(sid, fid) => setQuery({ analisis: String(sid), problema: String(fid), vista: null })} />}
        </>
      )}
    </div>
  )
}

// ------------------------------------------------------------------ problems of one analysis
function Problems({ scanId, scan, canEdit, focus, onFocus }: { scanId: number; scan?: Scan; canEdit: boolean; focus: number; onFocus: (id: number) => void }) {
  const { user } = useAuth()
  const [filters, setFilters] = useState({ severity: '', status: '', confidence: '', q: '' })
  const [q, setQ] = useState('')
  useEffect(() => { const t = window.setTimeout(() => setFilters((f) => ({ ...f, q })), 300); return () => clearTimeout(t) }, [q])
  const qs = new URLSearchParams(Object.entries(filters).filter(([, v]) => v)).toString()
  const list = useAsync(() => api.get<{ total: number; items: Finding[] }>(`/api/scans/${scanId}/findings?${qs}&limit=1000`), [scanId, qs])
  const [sel, setSel] = useState<Finding | null>(null)
  const [loadingSel, setLoadingSel] = useState(false)

  useEffect(() => {
    if (!focus) { setSel(null); return }
    let alive = true
    setLoadingSel(true)
    api.get<Finding>(`/api/findings/${focus}`).then((f) => { if (alive) setSel(f) }).catch(() => { if (alive) setSel(null) }).finally(() => { if (alive) setLoadingSel(false) })
    return () => { alive = false }
  }, [focus])
  // open the first problem when nothing is selected (wide screens show list and detail side by side)
  useEffect(() => {
    if (!focus && list.data?.items.length && window.matchMedia('(min-width: 1101px)').matches) onFocus(list.data.items[0].id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [list.data])

  const filtered = Object.values(filters).some(Boolean)
  const bySev = scan?.summary?.by_severity ?? {}
  return (
    <div className="stack" style={{ gap: 18 }}>
      {scan && (scan.summary?.findings ?? 0) > 0 && <div className="panel panel-pad sev-summary"><SevBar counts={bySev} /></div>}
      <div className="row" role="search" aria-label="Filtrar problemas">
        <select aria-label="Gravedad" value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })} style={{ width: 'auto' }}>
          <option value="">Todas las gravedades</option>{SEVERITIES.map((s) => <option key={s} value={s}>{SEV_NAME[s]}</option>)}</select>
        <select aria-label="Estado" value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })} style={{ width: 'auto' }}>
          <option value="">Todos los estados</option>{Object.entries(REMEDIATION).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
        <select aria-label="Fiabilidad" value={filters.confidence} onChange={(e) => setFilters({ ...filters, confidence: e.target.value })} style={{ width: 'auto' }}>
          <option value="">Cualquier fiabilidad</option>{['confirmed', 'likely', 'suspected'].map((c) => <option key={c} value={c}>{CONFIDENCE[c]}</option>)}</select>
        <input type="search" aria-label="Buscar" placeholder="Buscar por título, dirección, archivo o CWE" value={q} onChange={(e) => setQ(e.target.value)} style={{ flex: 1, minWidth: 220 }} />
        {filtered && <button className="btn quiet" onClick={() => { setFilters({ severity: '', status: '', confidence: '', q: '' }); setQ('') }}>Quitar filtros</button>}
      </div>
      <ErrorNotice error={list.error} />
      <div className="split">
        <section className="panel" aria-label="Lista de problemas">
          <div className="panel-head"><h2>{list.data ? `${list.data.total} ${list.data.total === 1 ? 'problema' : 'problemas'}${filtered ? ' con estos filtros' : ''}` : 'Problemas'}</h2></div>
          {list.loading && !list.data ? <Loading /> : list.data?.items.length === 0 ? (
            <Empty title={filtered ? 'Ningún problema coincide' : 'Este análisis no encontró problemas'}>{filtered ? 'Prueba a quitar algún filtro.' : 'Revisa también la cobertura en el informe técnico.'}</Empty>
          ) : (
            <ul className="issue-list" style={{ maxHeight: 'calc(100vh - 300px)', overflow: 'auto' }}>
              {list.data?.items.map((f) => (
                <li key={f.id}>
                  <button onClick={() => onFocus(f.id)} aria-current={sel?.id === f.id ? 'true' : undefined}>
                    <Sev s={f.severity} />
                    <span className="t">{f.plain?.title ?? f.title}{f.remediation_status !== 'open' && <span className="muted small"> ({REMEDIATION[f.remediation_status].toLowerCase()})</span>}</span>
                    <span className="w ellipsis">{where(f)}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>
        <section className="panel panel-pad detail" aria-live="polite" aria-label="Detalle del problema">
          {loadingSel && !sel ? <Loading /> : sel ? <Detail key={sel.id} f={sel} canEdit={canEdit && user?.role !== 'viewer'} onChange={(nf) => {
            setSel(nf)
            list.setData((d) => d && { ...d, items: d.items.map((x) => (x.id === nf.id ? { ...x, ...nf } : x)) })
          }} /> : <Empty title="Elige un problema">Verás qué ocurre, por qué importa y cómo corregirlo.</Empty>}
        </section>
      </div>
    </div>
  )
}

function where(f: Finding): string {
  if (f.endpoint) return `${f.method && f.method !== 'GET' ? f.method + ' ' : ''}${f.endpoint}${f.parameter ? ` (campo «${f.parameter}»)` : ''}`
  if (f.file) return `${f.file}${f.line ? `, línea ${f.line}` : ''}`
  return f.asset
}

function Detail({ f, canEdit, onChange }: { f: Finding; canEdit: boolean; onChange: (f: Finding) => void }) {
  const [notes, setNotes] = useState(f.analyst_notes ?? '')
  const [err, setErr] = useState<unknown>(null)
  const toast = useToast()
  async function save(patch: Record<string, unknown>, msg: string) {
    setErr(null)
    try { onChange(await api.patch<Finding>(`/api/findings/${f.id}`, patch)); toast(msg) } catch (e) { setErr(e) }
  }
  const p = f.plain
  return (
    <article className="stack" style={{ gap: 18 }}>
      <header className="stack-sm">
        <div className="row"><Sev s={f.severity} /><Pill tone={f.confidence === 'confirmed' ? 'ok' : ''}>{CONFIDENCE[f.confidence] ?? f.confidence}</Pill>
          <Pill tone={f.remediation_status === 'fixed' ? 'ok' : f.remediation_status === 'in_progress' ? 'live' : ''}>{REMEDIATION[f.remediation_status]}</Pill></div>
        <h2>{p?.title ?? f.title}</h2>
        <p className="small muted">{SEV_MEANING[f.severity]}.</p>
      </header>
      <Block title="Dónde"><span className="mono break">{where(f)}</span>{f.function && <span className="muted small"> en {f.function}</span>}</Block>
      {p?.summary && <Block title="Qué ocurre">{p.summary}</Block>}
      {p?.impact && <Block title="Por qué importa">{p.impact}</Block>}
      {p?.action && <Block title="Qué hacer">{p.action}</Block>}
      {f.recommendation && <Block title="Cómo corregirlo">{f.recommendation}</Block>}
      {f.chain_ids.length > 0 && <Notice tone="attn"><span>Este problema se combina con otros para permitir un ataque mayor. <Link to={`/analisis/${f.scan_id}`}>Ver la combinación</Link></span></Notice>}

      <section className="stack-sm" aria-labelledby={`st-${f.id}`}>
        <h3 id={`st-${f.id}`}>Seguimiento</h3>
        <label className="field">Estado de la corrección
          <select disabled={!canEdit} value={f.remediation_status} onChange={(e) => save({ remediation_status: e.target.value }, `Marcado como «${REMEDIATION[e.target.value]}»`)}>
            {Object.entries(REMEDIATION).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
        <label className="field">Notas <span className="hint">Visibles para los miembros del proyecto.</span>
          <textarea value={notes} disabled={!canEdit} onChange={(e) => setNotes(e.target.value)} maxLength={8000} rows={3} /></label>
        {canEdit && <div><button className="btn sm" disabled={notes === (f.analyst_notes ?? '')} onClick={() => save({ analyst_notes: notes }, 'Notas guardadas')}>Guardar notas</button></div>}
        <ErrorNotice error={err} />
      </section>

      <Disclosure summary="Detalles técnicos">
        <div className="stack">
          <dl className="kv">
            <dt>Nombre técnico</dt><dd>{f.title}</dd>
            <dt>Gravedad CVSS 3.1</dt><dd className="mono">{f.cvss_score ?? '—'}{f.cvss_vector ? ` ${f.cvss_vector}` : ''}</dd>
            <dt>CWE</dt><dd>{f.cwe ? <a href={`https://cwe.mitre.org/data/definitions/${f.cwe.replace(/\D/g, '')}.html`} target="_blank" rel="noopener noreferrer">{f.cwe}</a> : '—'}</dd>
            <dt>OWASP</dt><dd>{f.owasp.join(', ') || '—'}</dd>
            {f.cve.length > 0 && <><dt>CVE</dt><dd>{f.cve.map((c) => <a key={c} className="chip mono" href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c)}`} target="_blank" rel="noopener noreferrer">{c}</a>)}</dd></>}
            <dt>Activo</dt><dd className="mono">{f.asset}</dd>
            <dt>Probabilidad</dt><dd>{f.likelihood ?? '—'}</dd>
            <dt>Prioridad</dt><dd className="mono">{f.priority}</dd>
            <dt>Detectado por</dt><dd>{f.sources.join(', ')}</dd>
            <dt>Categoría</dt><dd className="mono">{f.category}</dd>
          </dl>
          {f.description && <Block title="Descripción técnica">{f.description}</Block>}
          {f.impact && <Block title="Impacto técnico">{f.impact}</Block>}
          {f.snippet && <Block title="Fragmento de código"><pre>{f.snippet}</pre></Block>}
          {f.evidence && Object.keys(f.evidence).length > 0 && <Block title="Evidencia (datos sensibles ocultos)"><pre>{JSON.stringify(f.evidence, null, 2)}</pre></Block>}
          {f.references && f.references.length > 0 && (
            <Block title="Referencias">
              <ul style={{ margin: 0, paddingLeft: 18 }}>{f.references.map((r) => <li key={r} className="small break">{/^https?:\/\//i.test(r) ? <a href={r} target="_blank" rel="noopener noreferrer">{r}</a> : r}</li>)}</ul>
            </Block>
          )}
        </div>
      </Disclosure>
    </article>
  )
}

function compareHeadline(added: number, fixed: number): string {
  const n = (x: number, one: string, many: string) => (x === 1 ? `1 ${one}` : `${x} ${many}`)
  if (!added && !fixed) return 'Sin cambios: los mismos problemas que en el análisis anterior.'
  if (!added) return `${n(fixed, 'problema corregido', 'problemas corregidos')} y ninguno nuevo.`
  if (!fixed) return `${n(added, 'problema nuevo', 'problemas nuevos')} y ninguno corregido.`
  return `${n(added, 'problema nuevo', 'problemas nuevos')} y ${n(fixed, 'corregido', 'corregidos')}.`
}

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return <section className="stack-sm" style={{ gap: 4 }}><h3 style={{ fontSize: 14, color: 'var(--muted)', fontWeight: 500 }}>{title}</h3><div>{children}</div></section>
}

// ------------------------------------------------------------------ compare two analyses
interface Diff { scan: number; baseline: number; risk: { scan: number | null; baseline: number | null }; new: Finding[]; fixed: Finding[]; persistent: Finding[] }

function Compare({ scan, done, onOpen }: { scan?: Scan; done: Scan[]; onOpen: (scanId: number, findingId: number) => void }) {
  const older = done.filter((s) => scan && s.id !== scan.id && s.id < scan.id)
  const [base, setBase] = useState(0)
  useEffect(() => { setBase(older[0]?.id ?? 0) }, [scan?.id]) // eslint-disable-line react-hooks/exhaustive-deps
  const diff = useAsync(() => (scan && base ? api.get<Diff>(`/api/scans/${scan.id}/compare/${base}`) : Promise.resolve(null)), [scan?.id, base])
  if (!scan) return <Loading />
  const trend = [...done].reverse().filter((s) => s.summary?.risk_score != null)
  if (older.length === 0) return (
    <div className="panel"><Empty title="No hay análisis anteriores para comparar">Cuando vuelvas a analizar este proyecto, aquí verás qué problemas son nuevos, cuáles se han corregido y cuáles siguen pendientes.</Empty></div>
  )
  const baseScan = done.find((s) => s.id === base)
  return (
    <div className="stack" style={{ gap: 20 }}>
      <label className="field" style={{ maxWidth: 420 }}>Comparar con
        <select value={base} onChange={(e) => setBase(Number(e.target.value))}>
          {older.map((s) => <option key={s.id} value={s.id}>{profileName(s.profile, s.profile_name)}, {fmtDate(s.finished_at ?? s.created_at)}</option>)}</select></label>
      <ErrorNotice error={diff.error} />
      {diff.loading && <Loading />}
      {diff.data && (
        <>
          <section className="panel statement">
            <h2 style={{ fontSize: 24 }}>{compareHeadline(diff.data.new.length, diff.data.fixed.length)}</h2>
            <p>Desde el análisis del {fmtDate(baseScan?.finished_at ?? baseScan?.created_at, false)}. {diff.data.persistent.length} {diff.data.persistent.length === 1 ? 'sigue' : 'siguen'} presentes.
              {diff.data.risk.scan != null && diff.data.risk.baseline != null && ` El índice de riesgo pasó de ${diff.data.risk.baseline} a ${diff.data.risk.scan}.`}</p>
          </section>
          {([['new', 'Nuevos'], ['fixed', 'Ya no aparecen'], ['persistent', 'Siguen presentes']] as const).map(([k, title]) => (
            <section key={k} className="panel" aria-label={title}>
              <div className="panel-head"><h2>{title}</h2><span className="small muted">{diff.data![k].length}</span></div>
              {diff.data![k].length === 0 ? <p className="panel-pad muted small">Ninguno.</p> : k === 'persistent' ? (
                <div className="panel-pad"><Disclosure summary={`Ver los ${diff.data![k].length} que siguen presentes`}>
                  <ul className="issue-list">
                    {diff.data![k].slice(0, 200).map((f) => (
                      <li key={f.id}><button onClick={() => onOpen(f.scan_id, f.id)}>
                        <Sev s={f.severity} /><span className="t">{f.plain?.title ?? f.title}</span><span className="w ellipsis">{where(f)}</span>
                      </button></li>
                    ))}
                  </ul>
                </Disclosure></div>
              ) : (
                <ul className="issue-list">
                  {diff.data![k].slice(0, 200).map((f) => (
                    <li key={f.id}><button onClick={() => onOpen(f.scan_id, f.id)}>
                      <Sev s={f.severity} /><span className="t">{f.plain?.title ?? f.title}</span><span className="w ellipsis">{where(f)}</span>
                    </button></li>
                  ))}
                </ul>
              )}
            </section>
          ))}
        </>
      )}
      {trend.length >= 2 && (
        <section className="panel panel-pad">
          <h2>Evolución del riesgo en este proyecto</h2>
          <p className="muted small" style={{ margin: '4px 0 12px' }}>Índice de 0 a 100 en cada análisis terminado; más bajo es mejor.</p>
          <TrendChart label="Índice de riesgo" points={trend.map((s) => ({ x: fmtDate(s.finished_at ?? s.created_at, false), y: s.summary?.risk_score ?? null }))} />
        </section>
      )}
    </div>
  )
}
