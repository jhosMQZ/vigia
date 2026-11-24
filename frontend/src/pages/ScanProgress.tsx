import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, scanSocket } from '../api'
import { useAuth } from '../auth'
import { IArrowLeft, ICheck, IStop } from '../components/Icons'
import {
  Confirm, Disclosure, ErrorNotice, Loading, Notice, PageHead, Pill, ReportMenu, ScanStatus, Sev, SevBar, errorText, fmtDate, fmtDur,
  useAsync, useToast,
} from '../components/ui'
import { STEP_STATUS, TOOL_STATUS, moduleName, plainCount, profileName } from '../copy'
import type { Chain, ModuleProgress, Profile, Project, Scan, ScanEvent, Severity, ToolRun } from '../types'

const FINISHED = ['done', 'skipped', 'failed', 'stopped']

export default function ScanProgress() {
  const id = Number(useParams().id)
  const { user } = useAuth()
  const toast = useToast()
  const [scan, setScan] = useState<Scan | null>(null)
  const [events, setEvents] = useState<ScanEvent[]>([])
  const [error, setError] = useState<unknown>(null)
  const [confirmStop, setConfirmStop] = useState(false)
  const [tick, setTick] = useState(0)
  const lastId = useRef(0)
  const running = scan ? ['queued', 'running'].includes(scan.status) : false
  const project = useAsync(() => (scan ? api.get<Project>(`/api/projects/${scan.project_id}`) : Promise.resolve(null)), [scan?.project_id])
  const profiles = useAsync(() => api.get<Profile[]>('/api/profiles'), [])
  const tools = useAsync(() => api.get<ToolRun[]>(`/api/scans/${id}/tools`), [id, scan?.status, tick])
  const chains = useAsync(() => (scan && !running ? api.get<Chain[]>(`/api/scans/${id}/chains`) : Promise.resolve([])), [id, scan?.status])

  useEffect(() => {
    let ws: WebSocket | null = null
    let stopped = false
    let pollTimer: number | undefined
    lastId.current = 0
    setEvents([])
    api.get<Scan>(`/api/scans/${id}`).then(setScan).catch(setError)
    const poll = async () => { // fallback when the live connection is unavailable
      try {
        const evs = await api.get<ScanEvent[]>(`/api/scans/${id}/events?after=${lastId.current}`)
        if (evs.length) { lastId.current = evs[evs.length - 1].id; setEvents((p) => [...p, ...evs].slice(-4000)) }
        const s = await api.get<Scan>(`/api/scans/${id}`)
        setScan(s)
        if (!stopped && ['queued', 'running'].includes(s.status)) pollTimer = window.setTimeout(poll, 2000)
      } catch (e) { setError(e) }
    }
    ws = scanSocket(id, 0, (msg) => {
      const m = msg as { type: string; scan: Scan; events: ScanEvent[] }
      if (m.type !== 'state') return
      setScan(m.scan)
      if (m.events.length) { lastId.current = m.events[m.events.length - 1].id; setEvents((p) => [...p, ...m.events].slice(-4000)) }
    }, () => { if (!stopped) poll() })
    return () => { stopped = true; ws?.close(); if (pollTimer) clearTimeout(pollTimer) }
  }, [id])

  // engines list refresh while running (their rows appear as each engine finishes)
  useEffect(() => {
    if (!running) return
    const t = window.setInterval(() => setTick((x) => x + 1), 10_000)
    return () => clearInterval(t)
  }, [running])

  const prof = profiles.data?.find((p) => p.key === scan?.profile)
  // the profile's planned phases; sub-steps such as "exposure:discovery" are folded into their module
  const phases = useMemo(() => {
    if (!scan) return [] as [string, ModuleProgress | undefined][]
    const prog = scan.progress ?? {}
    const keys = Object.keys(prog)
    const disabled = (scan.config?.modules_disabled as string[] | undefined) ?? []
    const mods = (prof?.modules ?? []).filter((m) => !disabled.includes(m))
    const fixed = ['correlation', 'reports']
    const extra = [...new Set(keys.map((k) => k.split(':')[0]))].filter((b) => b !== 'tool' && !mods.includes(b) && !fixed.includes(b))
    const order = [...extra.filter((m) => m === 'auth'), ...mods, ...extra.filter((m) => m !== 'auth'), ...keys.filter((k) => k.startsWith('tool:')), ...fixed]
    return order.map((m) => [m, m.startsWith('tool:') ? prog[m] : foldPhase(m, prog)] as [string, ModuleProgress | undefined])
  }, [scan, prof])
  const finished = phases.filter(([, p]) => p && FINISHED.includes(p.status)).length
  const partial = phases.reduce((a, [, p]) => a + (p?.status === 'running' && p.pct ? p.pct / 100 : 0), 0)
  const current = phases.filter(([, p]) => p?.status === 'running').map(([k]) => moduleName(k))
  const live = useMemo(() => events.filter((e) => e.level === 'finding').slice(-12).reverse(), [events])

  if (!scan) return <div className="page">{error ? <ErrorNotice error={error} /> : <Loading />}</div>
  const canWrite = user?.role !== 'viewer' && project.data?.role !== 'viewer'
  const bySev = scan.summary?.by_severity ?? {}
  const total = scan.summary?.findings ?? 0
  const worst = (['critical', 'high', 'medium', 'low'] as Severity[]).find((s) => (bySev[s] ?? 0) > 0)
  const hasResults = !running && (scan.status === 'completed' || total > 0)

  async function stop() {
    try { setScan(await api.post<Scan>(`/api/scans/${id}/cancel`)); toast('Deteniendo el análisis…') } catch (e) { toast(errorText(e), 'bad') } finally { setConfirmStop(false) }
  }

  return (
    <div className="page">
      <PageHead title={project.data ? `Análisis de ${project.data.name}` : `Análisis ${scan.id}`}
        back={project.data ? <Link to={`/proyectos/${scan.project_id}`}><IArrowLeft size={16} />{project.data.name}</Link> : undefined}
        intro={<span className="row" style={{ gap: 14 }}><ScanStatus s={scan.status} />
          <span>Profundidad: {profileName(scan.profile, scan.profile_name)}</span>
          <span>{scan.started_at ? `Empezó ${fmtDate(scan.started_at)}` : `Creado ${fmtDate(scan.created_at)}`}</span>
          {scan.started_at && <Elapsed from={scan.started_at} to={scan.finished_at} running={running} />}</span>}
        actions={<>
          {running && canWrite && (
            <button className="btn danger" onClick={() => setConfirmStop(true)} disabled={scan.cancel_requested}>
              <IStop size={18} />{scan.cancel_requested ? 'Deteniendo…' : 'Detener'}</button>
          )}
          {hasResults && <ReportMenu scanId={id} />}
          {hasResults && <Link className="btn primary" to={`/resultados?analisis=${id}`}>Ver resultados</Link>}
        </>} />

      {scan.error && (
        <div style={{ marginBottom: 20 }}>
          <Notice tone={scan.status === 'failed' ? 'bad' : 'attn'} title={scan.status === 'failed' ? 'El análisis no pudo completarse' : 'El análisis se detuvo antes de terminar'}>
            {scan.error}{scan.status !== 'failed' && ' Los resultados obtenidos hasta ese momento se han conservado.'}
          </Notice>
        </div>
      )}

      {!running && (
        <section className="panel statement" aria-labelledby="sum" style={{ marginBottom: 24 }}>
          <h2 id="sum" style={{ fontSize: 24 }}>
            {total === 0 ? (scan.status === 'completed' ? 'No se encontraron problemas.' : 'No hay resultados.') : worst ? plainCount(worst, bySev[worst] ?? 0) + '.' : `${total} observaciones informativas.`}
          </h2>
          {total > 0 && <p>{total} {total === 1 ? 'resultado' : 'resultados'} en total{scan.summary?.confirmed ? `, ${scan.summary.confirmed} confirmados con evidencia` : ''}{scan.summary?.chains ? `. ${scan.summary.chains} combinaciones de problemas permiten un ataque mayor` : ''}.</p>}
          {total > 0 && <SevBar counts={bySev} />}
        </section>
      )}

      <div className="cols">
        <div className="stack" style={{ gap: 24 }}>
          <section className="panel" aria-labelledby="phases">
            <div className="panel-head">
              <h2 id="phases">Fases</h2>
              <span className="small muted">{finished} de {phases.length} terminadas</span>
            </div>
            <div className="panel-pad" style={{ paddingBottom: 6 }}>
              {running && (
                <div style={{ marginBottom: 14 }}>
                  <div className={`progress ${finished === 0 && partial === 0 ? 'indeterminate' : ''}`} role="progressbar" aria-label="Fases terminadas"
                    aria-valuemin={0} aria-valuemax={phases.length} aria-valuenow={finished}>
                    <div style={finished || partial ? { width: `${(100 * (finished + partial)) / Math.max(1, phases.length)}%` } : undefined} />
                  </div>
                  <p className="small" style={{ marginTop: 8 }} aria-live="polite">
                    {scan.status === 'queued' ? 'En espera de un hueco para empezar.' : current.length ? `Ahora: ${current.join(', ')}.` : 'Preparando la siguiente fase…'}
                  </p>
                </div>
              )}
              <ul className="phases">
                {phases.map(([k, p0]) => {
                  // an engine phase reports "done" even when the engine was not used: the engine run says what happened
                  const run = k.startsWith('tool:') ? tools.data?.find((t) => t.tool === k.slice(5)) : undefined
                  const p = run?.status === 'skipped' && p0 ? { ...p0, status: 'skipped', detail: run.error ?? p0.detail } : p0
                  return (
                    <li key={k}>
                      <PhaseMark status={p?.status} />
                      <span title={k}>{moduleName(k)}{p?.detail && <span className="sub small muted" style={{ display: 'block' }}>{p.detail}</span>}</span>
                      <span className="small muted">{p ? (p.status === 'running' && p.pct ? `${p.pct} %` : run?.status === 'skipped' ? 'No se usó' : STEP_STATUS[p.status] ?? p.status) : 'Pendiente'}</span>
                    </li>
                  )
                })}
              </ul>
            </div>
          </section>

          <section aria-labelledby="log">
            <Disclosure summary="Registro técnico">
              <LiveLog events={events} running={running} />
            </Disclosure>
          </section>
        </div>

        <div className="stack" style={{ gap: 24 }}>
          {running && (
            <section className="panel" aria-labelledby="live">
              <div className="panel-head"><h2 id="live">Encontrado hasta ahora</h2><span className="small muted">{events.filter((e) => e.level === 'finding').length}</span></div>
              {live.length === 0 ? <p className="panel-pad muted small">Todavía nada. Los resultados aparecen aquí en cuanto se detectan.</p> : (
                <ul className="issue-list" aria-live="polite">
                  {live.map((e) => {
                    const m = /^\[(\w+)\]\s*(.*)$/.exec(e.message)
                    const sev = (m?.[1].toLowerCase() ?? 'info') as Severity
                    const d = e.data as { endpoint?: string; file?: string } | null
                    return <li key={e.id}><div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '4px 12px', padding: '12px 20px' }}>
                      <Sev s={sev} /><span className="t">{m?.[2] ?? e.message}</span>
                      {(d?.endpoint || d?.file) && <span className="w ellipsis small muted" style={{ gridColumn: 2 }}>{d.endpoint ?? d.file}</span>}
                    </div></li>
                  })}
                </ul>
              )}
              <p className="small muted panel-pad" style={{ borderTop: '1px solid var(--line)', paddingTop: 12, paddingBottom: 14 }}>Provisional: al terminar se eliminan duplicados y se confirma cada resultado.</p>
            </section>
          )}

          <section className="panel" aria-labelledby="engines">
            <div className="panel-head"><h2 id="engines">Motores</h2></div>
            {!tools.data || tools.data.length === 0 ? <p className="panel-pad muted small">{running ? 'Los motores aparecen aquí a medida que terminan su trabajo.' : 'Este análisis no usó motores externos.'}</p> : (
              <ul className="phases" style={{ padding: '0 20px' }}>
                {tools.data.map((t) => {
                  const st = TOOL_STATUS[t.status] ?? { label: t.status, tone: '' as const }
                  return (
                    <li key={t.id} style={{ gridTemplateColumns: '1fr auto' }}>
                      <span><b style={{ fontWeight: 500 }}>{t.tool}</b>{t.version && <span className="muted small"> {t.version}</span>}
                        {t.error && <span className="small muted" style={{ display: 'block' }}>{t.error}</span>}
                        {t.status === 'ok' && <span className="small muted" style={{ display: 'block' }}>{t.findings} {t.findings === 1 ? 'resultado' : 'resultados'}{t.duration ? ` en ${fmtDur(t.duration)}` : ''}</span>}</span>
                      <Pill tone={st.tone}>{st.label}</Pill>
                    </li>
                  )
                })}
              </ul>
            )}
          </section>

          {chains.data && chains.data.length > 0 && (
            <section className="panel" aria-labelledby="chains">
              <div className="panel-head"><h2 id="chains">Problemas que se combinan</h2></div>
              <div className="panel-pad stack">
                <p className="small muted">Por separado pueden parecer menores, pero juntos permiten un ataque más serio.</p>
                {chains.data.map((c) => (
                  <div key={c.id} className="stack-sm">
                    <div className="row"><Sev s={c.severity} /><b>{c.title}</b></div>
                    <p className="small">{c.narrative}</p>
                    {c.recommendation && <p className="small muted">{c.recommendation}</p>}
                  </div>
                ))}
              </div>
            </section>
          )}
        </div>
      </div>

      {confirmStop && (
        <Confirm title="¿Detener el análisis?" confirmLabel="Detener" danger onCancel={() => setConfirmStop(false)} onConfirm={stop}>
          <p>Los motores terminan el paso que están haciendo y no se envían más peticiones al objetivo.</p>
          <p className="muted small">Los resultados obtenidos hasta ahora se conservan y se generan sus informes.</p>
        </Confirm>
      )}
    </div>
  )
}

const SUBSTEP: Record<string, string> = { discovery: 'búsqueda', analysis: 'análisis' }

/** Merge a module's own progress with its sub-steps ("exposure:discovery", "exposure:analysis"). */
function foldPhase(m: string, prog: Record<string, ModuleProgress>): ModuleProgress | undefined {
  const parts = Object.entries(prog).filter(([k]) => k === m || k.startsWith(`${m}:`))
  if (!parts.length) return undefined
  if (parts.length === 1) return parts[0][1]
  const st = parts.map(([, p]) => p.status)
  const status = st.includes('running') ? 'running' : st.includes('failed') ? 'failed' : st.every((x) => FINISHED.includes(x)) ? (st.includes('stopped') ? 'stopped' : 'done') : 'running'
  const detail = parts.filter(([k]) => k !== m).map(([k, p]) => `${SUBSTEP[k.split(':')[1]] ?? k.split(':')[1]}: ${(STEP_STATUS[p.status] ?? p.status).toLowerCase()}${p.detail ? ` (${p.detail})` : ''}`).join('; ')
  return { status, detail }
}

/** Elapsed time computed from the real start/end timestamps (ticks every second while running). */
function Elapsed({ from, to, running }: { from: string; to: string | null; running: boolean }) {
  const [now, setNow] = useState(Date.now())
  useEffect(() => {
    if (!running) return
    const t = window.setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(t)
  }, [running])
  const parse = (s: string) => new Date(s.endsWith('Z') || s.includes('+') ? s : s + 'Z').getTime()
  const end = running || !to ? now : parse(to)
  const secs = Math.max(0, (end - parse(from)) / 1000)
  return <span>{running ? 'Lleva' : 'Duró'} {fmtDur(secs)}</span>
}

function PhaseMark({ status }: { status?: string }) {
  if (status === 'done') return <span style={{ color: 'var(--ok)' }} aria-label="Terminada"><ICheck size={18} /></span>
  if (status === 'running') return <span className="pill live" style={{ padding: 0, border: 0, background: 'none' }} aria-label="En curso" />
  if (status === 'failed') return <span style={{ color: 'var(--bad)', fontWeight: 600 }} aria-label="Con errores">!</span>
  if (status === 'skipped' || status === 'stopped') return <span className="muted" aria-label={status === 'skipped' ? 'Omitida' : 'Detenida'}>–</span>
  return <span className="muted" aria-label="Pendiente">·</span>
}

function LiveLog({ events, running }: { events: ScanEvent[]; running: boolean }) {
  const [level, setLevel] = useState('all')
  const [follow, setFollow] = useState(true)
  const box = useRef<HTMLDivElement>(null)
  const shown = useMemo(() => events.filter((e) => level === 'all' || e.level === level), [events, level])
  useEffect(() => { if (follow && box.current) box.current.scrollTop = box.current.scrollHeight }, [shown, follow])
  const LV: Record<string, string> = { info: 'info', warn: 'aviso', error: 'error', finding: 'resultado', debug: 'detalle' }
  return (
    <div className="stack-sm">
      <div className="row between">
        <span className="small muted">{events.length} eventos{running ? ', en directo' : ''}</span>
        <div className="row">
          <label className="row small" style={{ gap: 6 }}>Mostrar
            <select value={level} onChange={(e) => setLevel(e.target.value)} style={{ width: 'auto', minHeight: 32, padding: '4px 8px' }}>
              <option value="all">Todo</option><option value="finding">Resultados</option><option value="warn">Avisos</option><option value="error">Errores</option><option value="info">Información</option>
            </select></label>
          <label className="check small"><input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} />Seguir el final</label>
        </div>
      </div>
      <div className="log" ref={box} tabIndex={0} aria-label="Registro técnico del análisis">
        {shown.map((e) => (
          <div key={e.id}><span className="t">{e.ts.slice(11, 19)}</span><span className={`l-${e.level}`}>{LV[e.level] ?? e.level}</span>
            <span className="ellipsis" title={e.module}>{e.module}</span><span className="break">{e.message}</span></div>
        ))}
        {shown.length === 0 && <div><span /><span /><span /><span className="muted">Sin eventos todavía.</span></div>}
      </div>
    </div>
  )
}
