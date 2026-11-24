import { createContext, useCallback, useContext, useEffect, useId, useRef, useState, type ReactNode } from 'react'
import { ApiError } from '../api'
import { SCAN_STATUS, SEVERITIES, SEV_NAME, sevCount } from '../copy'
import type { Severity } from '../types'
import { IAlert, ICheck, IClose, IDownload, IInfo } from './Icons'

// ------------------------------------------------------------------ data helpers
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [loading, setLoading] = useState(true)
  const [tick, setTick] = useState(0)
  useEffect(() => {
    let alive = true
    setLoading(true)
    fn().then((d) => { if (alive) { setData(d); setError(null) } })
      .catch((e) => { if (alive) setError(e) })
      .finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick])
  return { data, error, loading, reload: () => setTick((t) => t + 1), setData }
}

export function fmtDate(s?: string | null, withTime = true): string {
  if (!s) return '—'
  const d = new Date(s.endsWith('Z') || s.includes('+') ? s : s + 'Z')
  return d.toLocaleString('es-ES', withTime ? { dateStyle: 'medium', timeStyle: 'short' } : { dateStyle: 'medium' })
}
/** Real duration of an analysis from its timestamps (until now while it is running). */
export function scanDuration(s: { started_at: string | null; finished_at: string | null }): number | null {
  if (!s.started_at) return null
  const t = (x: string) => new Date(x.endsWith('Z') || x.includes('+') ? x : x + 'Z').getTime()
  return Math.max(0, ((s.finished_at ? t(s.finished_at) : Date.now()) - t(s.started_at)) / 1000)
}
export function fmtDur(sec?: number | null): string {
  if (sec == null) return '—'
  const m = Math.floor(sec / 60)
  if (m >= 60) return `${Math.floor(m / 60)} h ${m % 60} min`
  return m ? `${m} min ${Math.round(sec % 60)} s` : `${Math.round(sec)} s`
}

/** Turn an API error into a sentence that says what happened and what to do. */
export function errorText(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 401) return 'Tu sesión ha caducado. Vuelve a iniciar sesión.'
    if (e.status === 403) return e.message && e.message !== 'Error 403' ? e.message : 'No tienes permiso para hacer esto.'
    if (e.status === 404) return 'No se encontró el elemento o no tienes acceso a él.'
    if (e.status === 429) return 'Demasiadas peticiones seguidas. Espera un momento y vuelve a intentarlo.'
    if (e.status >= 500) return 'El servidor no pudo completar la operación. Revisa los registros y vuelve a intentarlo.'
    return e.message
  }
  if (e instanceof TypeError) return 'No se pudo contactar con el servidor de Vigía. Comprueba que está en marcha.'
  return e instanceof Error ? e.message : String(e)
}

// ------------------------------------------------------------------ status & severity
export function Sev({ s }: { s: Severity }) {
  return <span className={`sev sev-${s}`}>{SEV_NAME[s] ?? s}</span>
}
export function ScanStatus({ s }: { s: string }) {
  const st = SCAN_STATUS[s] ?? { label: s, tone: '' }
  return <span className={`pill ${st.tone}`}>{st.label}</span>
}
export function Pill({ tone = '', children }: { tone?: '' | 'ok' | 'warn' | 'bad' | 'live'; children: ReactNode }) {
  return <span className={`pill ${tone}`}>{children}</span>
}

const SEV_VAR: Record<Severity, string> = { critical: 'var(--sev-critical)', high: 'var(--sev-high)', medium: 'var(--sev-medium)',
  low: 'var(--sev-low)', info: 'var(--sev-info)' }

export function SevBar({ counts, legend = true }: { counts: Partial<Record<Severity, number>>; legend?: boolean }) {
  const total = SEVERITIES.reduce((a, s) => a + (counts[s] ?? 0), 0)
  return (
    <div>
      <div className="sevbar" role="img" aria-label={`Distribución: ${SEVERITIES.map((s) => `${counts[s] ?? 0} ${SEV_NAME[s].toLowerCase()}`).join(', ')}`}>
        {total > 0 && SEVERITIES.map((s) => (counts[s] ? <span key={s} style={{ width: `${(100 * (counts[s] ?? 0)) / total}%`, background: SEV_VAR[s] }} /> : null))}
      </div>
      {legend && (
        <div className="legend">
          {SEVERITIES.map((s) => <span key={s}><i style={{ background: SEV_VAR[s] }} />{sevCount(s, counts[s] ?? 0)}</span>)}
        </div>
      )}
    </div>
  )
}

// ------------------------------------------------------------------ notices, empty, loading
export function Notice({ tone = '', children, title }: { tone?: '' | 'attn' | 'bad' | 'ok'; children: ReactNode; title?: string }) {
  const Icon = tone === 'ok' ? ICheck : tone === '' ? IInfo : IAlert
  return (
    <div className={`notice ${tone}`} role={tone === 'bad' ? 'alert' : undefined}>
      <Icon size={18} />
      <div>{title && <b style={{ display: 'block', marginBottom: 2 }}>{title}</b>}{children}</div>
    </div>
  )
}
export function ErrorNotice({ error }: { error: unknown }) {
  if (!error) return null
  return <Notice tone="bad">{errorText(error)}</Notice>
}
export function Empty({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return <div className="empty"><h3>{title}</h3>{children && <p>{children}</p>}{action}</div>
}
export function Loading({ label = 'Cargando…' }: { label?: string }) {
  return <div className="loading" role="status" aria-live="polite"><span className="progress indeterminate" style={{ width: 120 }}><div /></span>{label}</div>
}
export function useTitle(title: string) {
  useEffect(() => { document.title = title ? `${title} · Vigía` : 'Vigía' }, [title])
}
export function PageHead({ title, intro, actions, back }: { title: string; intro?: ReactNode; actions?: ReactNode; back?: ReactNode }) {
  useTitle(title)
  return (
    <header className="page-head">
      <div>{back && <div className="back">{back}</div>}<h1>{title}</h1>{intro && <div className="intro">{intro}</div>}</div>
      {actions && <div className="row">{actions}</div>}
    </header>
  )
}

// ------------------------------------------------------------------ tabs (keyboard: arrows, Home, End)
export function Tabs<K extends string>({ tabs, value, onChange, label }: { tabs: [K, string][]; value: K; onChange: (k: K) => void; label: string }) {
  const refs = useRef<(HTMLButtonElement | null)[]>([])
  const key = (e: React.KeyboardEvent, i: number) => {
    let n = -1
    if (e.key === 'ArrowRight') n = (i + 1) % tabs.length
    else if (e.key === 'ArrowLeft') n = (i - 1 + tabs.length) % tabs.length
    else if (e.key === 'Home') n = 0
    else if (e.key === 'End') n = tabs.length - 1
    if (n >= 0) { e.preventDefault(); onChange(tabs[n][0]); refs.current[n]?.focus() }
  }
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {tabs.map(([k, l], i) => (
        <button key={k} ref={(el) => { refs.current[i] = el }} role="tab" aria-selected={value === k} tabIndex={value === k ? 0 : -1}
          onClick={() => onChange(k)} onKeyDown={(e) => key(e, i)}>{l}</button>
      ))}
    </div>
  )
}

/** Radio group rendered as large choices (arrow keys move and select, like native radios). */
export function ChoiceGroup<K extends string | number>({ label, options, value, onChange, columns = 1 }: {
  label: string; value: K | null; onChange: (k: K) => void; columns?: 1 | 2
  options: { key: K; title: string; text?: ReactNode; icon?: ReactNode; disabled?: boolean; extra?: ReactNode }[]
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([])
  const enabled = options.map((o, i) => (o.disabled ? -1 : i)).filter((i) => i >= 0)
  const current = options.findIndex((o) => o.key === value)
  const key = (e: React.KeyboardEvent, i: number) => {
    const pos = enabled.indexOf(i)
    let n = -1
    if (e.key === 'ArrowDown' || e.key === 'ArrowRight') n = enabled[(pos + 1) % enabled.length]
    else if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') n = enabled[(pos - 1 + enabled.length) % enabled.length]
    if (n >= 0) { e.preventDefault(); onChange(options[n].key); refs.current[n]?.focus() }
  }
  return (
    <div role="radiogroup" aria-label={label} className={columns === 2 ? 'cols-2' : 'stack-sm'} style={columns === 2 ? { gap: 10 } : undefined}>
      {options.map((o, i) => (
        <button key={String(o.key)} type="button" role="radio" className="choice" aria-checked={o.key === value} disabled={o.disabled}
          ref={(el) => { refs.current[i] = el }} tabIndex={o.key === value || (current < 0 && i === enabled[0]) ? 0 : -1}
          onClick={() => onChange(o.key)} onKeyDown={(e) => key(e, i)}>
          {o.icon}
          <span style={{ minWidth: 0, flex: 1 }}><h3>{o.title}</h3>{o.text && <p>{o.text}</p>}{o.extra}</span>
        </button>
      ))}
    </div>
  )
}

export function Disclosure({ summary, children, open }: { summary: string; children: ReactNode; open?: boolean }) {
  return <details className="disclosure" open={open}><summary>{summary}</summary><div>{children}</div></details>
}

// ------------------------------------------------------------------ dialogs (focus trapped, Escape closes, focus restored)
export function Dialog({ title, onClose, children, footer }: { title: string; onClose: () => void; children: ReactNode; footer?: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null)
  const titleId = useId()
  // the latest onClose without re-running the effect: re-running would steal focus back to the first field on every
  // parent render
  const close = useRef(onClose)
  close.current = onClose
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null
    const first = ref.current?.querySelector<HTMLElement>('input, select, textarea, button:not([data-close]), a[href]')
    ;(first ?? ref.current)?.focus()
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { e.preventDefault(); close.current() }
      if (e.key !== 'Tab' || !ref.current) return
      const items = [...ref.current.querySelectorAll<HTMLElement>('a[href], button:not(:disabled), input:not(:disabled), select, textarea, [tabindex="0"]')]
      if (!items.length) return
      const [a, z] = [items[0], items[items.length - 1]]
      if (e.shiftKey && document.activeElement === a) { e.preventDefault(); z.focus() }
      else if (!e.shiftKey && document.activeElement === z) { e.preventDefault(); a.focus() }
    }
    document.addEventListener('keydown', onKey)
    return () => { document.removeEventListener('keydown', onKey); prev?.focus?.() }
  }, [])
  return (
    <div className="dialog-bg" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}>
      <div className="dialog" role="dialog" aria-modal="true" aria-labelledby={titleId} ref={ref} tabIndex={-1}>
        <header><h2 id={titleId}>{title}</h2><button className="icon-btn" data-close onClick={onClose} aria-label="Cerrar"><IClose /></button></header>
        <div className="body">{children}</div>
        {footer && <footer>{footer}</footer>}
      </div>
    </div>
  )
}

export function Confirm({ title, children, confirmLabel, danger, onConfirm, onCancel }: {
  title: string; children: ReactNode; confirmLabel: string; danger?: boolean; onConfirm: () => void | Promise<void>; onCancel: () => void
}) {
  const [busy, setBusy] = useState(false)
  return (
    <Dialog title={title} onClose={onCancel} footer={<>
      <button className="btn" onClick={onCancel}>Volver</button>
      <button className={`btn ${danger ? 'danger' : 'primary'}`} disabled={busy}
        onClick={async () => { setBusy(true); try { await onConfirm() } finally { setBusy(false) } }}>{busy ? 'Un momento…' : confirmLabel}</button>
    </>}>
      <div className="stack">{children}</div>
    </Dialog>
  )
}

// ------------------------------------------------------------------ toasts
interface Toast { id: number; text: string; tone: '' | 'bad' }
const ToastCtx = createContext<(text: string, tone?: '' | 'bad') => void>(() => {})
export const useToast = () => useContext(ToastCtx)
export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([])
  const push = useCallback((text: string, tone: '' | 'bad' = '') => {
    const id = Date.now() + Math.random()
    setItems((t) => [...t, { id, text, tone }])
    window.setTimeout(() => setItems((t) => t.filter((x) => x.id !== id)), tone === 'bad' ? 7000 : 4000)
  }, [])
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {items.map((t) => <div key={t.id} className={`toast ${t.tone}`}>{t.tone === 'bad' ? <IAlert size={18} /> : <ICheck size={18} />}<span>{t.text}</span></div>)}
      </div>
    </ToastCtx.Provider>
  )
}

// ------------------------------------------------------------------ chart (single series, only where a trend matters)
export function TrendChart({ points, label, max = 100 }: { points: { x: string; y: number | null }[]; label: string; max?: number }) {
  const valid = points.filter((p) => p.y != null) as { x: string; y: number }[]
  if (valid.length < 2) return <p className="muted small">Hacen falta al menos dos análisis completados para ver la evolución.</p>
  const w = 640, h = 160, pad = 30
  const step = (w - pad * 2) / (valid.length - 1)
  const yv = (v: number) => h - pad - (v / max) * (h - pad * 1.7)
  const d = valid.map((p, i) => `${i ? 'L' : 'M'}${pad + i * step},${yv(p.y)}`).join(' ')
  return (
    <svg className="chart" viewBox={`0 0 ${w} ${h}`} width="100%" role="img" aria-label={`${label}: ${valid.map((p) => `${p.x} ${p.y}`).join(', ')}`}>
      {[0, 50, 100].map((g) => <g key={g}><line className="grid" x1={pad} x2={w - pad} y1={yv(g)} y2={yv(g)} /><text x={2} y={yv(g) + 4}>{g}</text></g>)}
      <path className="line" d={d} fill="none" strokeWidth={2} />
      {valid.map((p, i) => <circle key={i} className="pt" cx={pad + i * step} cy={yv(p.y)} r={3.5} strokeWidth={2}><title>{`${p.x}: ${p.y}`}</title></circle>)}
    </svg>
  )
}

// ------------------------------------------------------------------ report downloads
const REPORTS: [string, string, string][] = [
  ['executive', 'Informe ejecutivo', 'Para dirección, en lenguaje claro (HTML)'], ['executive_pdf', 'Informe ejecutivo en PDF', 'Para imprimir o enviar'],
  ['html', 'Informe técnico', 'Para el equipo que corrige (HTML)'], ['pdf', 'Informe técnico en PDF', 'Con todos los detalles'],
  ['csv', 'Lista de problemas (CSV)', 'Para hojas de cálculo'], ['json', 'Datos completos (JSON)', 'Para integraciones'],
  ['sbom', 'Inventario de componentes (SBOM)', 'Formato CycloneDX'],
]
export function ReportMenu({ scanId }: { scanId: number }) {
  const ref = useRef<HTMLDetailsElement>(null)
  useEffect(() => {
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (!ref.current?.open) return
      if (e instanceof KeyboardEvent ? e.key === 'Escape' : !ref.current.contains(e.target as Node)) ref.current.open = false
    }
    document.addEventListener('mousedown', close); document.addEventListener('keydown', close)
    return () => { document.removeEventListener('mousedown', close); document.removeEventListener('keydown', close) }
  }, [])
  return (
    <details className="menu" ref={ref}>
      <summary className="btn"><IDownload size={18} />Descargar informe</summary>
      <div className="menu-list" role="list">
        {REPORTS.map(([fmt, title, text]) => (
          <a key={fmt} role="listitem" href={`/api/scans/${scanId}/reports/${fmt}`} target="_blank" rel="noopener noreferrer"
            onClick={() => { if (ref.current) ref.current.open = false }}>
            <b>{title}</b><span>{text}</span>
          </a>
        ))}
      </div>
    </details>
  )
}
