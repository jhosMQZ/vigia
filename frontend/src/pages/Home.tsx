import { Link, useNavigate } from 'react-router-dom'
import { api } from '../api'
import { protectionTone, useAuth, useProtection } from '../auth'
import { ICheck } from '../components/Icons'
import { ErrorNotice, Loading, Notice, ScanStatus, Sev, SevBar, TrendChart, fmtDate, useAsync, useTitle } from '../components/ui'
import { SEVERITIES, actionable, plainCount, profileName, sevCount } from '../copy'
import type { Dashboard, Severity } from '../types'

export default function Home() {
  const { user } = useAuth()
  const { status } = useProtection()
  const { data, error, loading } = useAsync(() => api.get<Dashboard>('/api/dashboard'), [])
  const nav = useNavigate()
  useTitle('Inicio')
  if (error) return <div className="page"><ErrorNotice error={error} /></div>
  if (loading || !data) return <div className="page"><Loading /></div>

  const canWrite = user?.role !== 'viewer'
  const open = data.open_by_severity
  const analysed = data.per_project.length > 0
  const running = data.recent.filter((s) => s.status === 'running' || s.status === 'queued')
  const firstRun = data.scans === 0

  return (
    <div className="page">
      {firstRun ? <Welcome projects={data.projects} canWrite={canWrite} protectionLevel={status?.protection.level} isAdmin={user?.role === 'admin'} /> : (
        <section className="panel statement" aria-labelledby="state">
          <h1 id="state">{headline(open, analysed)}</h1>
          <p>{subline(open, analysed, data.per_project.length, data.fixed)}</p>
          {analysed && <SevBar counts={open} />}
          <div className="row" style={{ marginTop: 22 }}>
            {analysed && <Link className="btn primary" to="/resultados">Revisar los problemas</Link>}
            {canWrite && <Link className="btn" to="/analisis/nuevo">Nuevo análisis</Link>}
          </div>
        </section>
      )}

      {running.length > 0 && (
        <div style={{ marginTop: 20 }}>
          <Notice>
            {running.length === 1 ? 'Hay un análisis en marcha' : `Hay ${running.length} análisis en marcha`}:{' '}
            {running.map((s, i) => <span key={s.id}>{i > 0 && ', '}<Link to={`/analisis/${s.id}`}>{s.project} ({profileName(s.profile)})</Link></span>)}.
          </Notice>
        </div>
      )}

      {!firstRun && analysed && (
        <div className="cols section">
          <section className="panel" aria-labelledby="first">
            <div className="panel-head"><h2 id="first">Qué corregir primero</h2>{data.top_open.length > 0 && <Link className="small" to="/resultados">Ver todos</Link>}</div>
            {data.top_open.length === 0 ? (
              <div className="empty"><h3>Nada urgente</h3><p>No hay problemas críticos, graves ni moderados pendientes en los últimos análisis.</p></div>
            ) : (
              <ul className="issue-list">
                {data.top_open.map((f) => (
                  <li key={f.id}>
                    <button onClick={() => nav(`/resultados?analisis=${f.scan_id}&problema=${f.id}`)}>
                      <Sev s={f.severity} /><span className="t">{f.title}</span>
                      <span className="w ellipsis">{f.project}: {f.where}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <div className="stack">
            <ProtectionSummary />
            <section className="panel" aria-labelledby="projs">
              <div className="panel-head"><h2 id="projs">Proyectos</h2><Link className="small" to="/proyectos">Ver todos</Link></div>
              {data.per_project.length === 0 ? <div className="empty"><p>Ningún proyecto tiene todavía un análisis terminado.</p></div> : (
                <div className="table-wrap"><table>
                  <thead><tr><th>Proyecto</th><th>Pendientes</th></tr></thead>
                  <tbody>{data.per_project.map((p) => {
                    const urgent = (p.open.critical ?? 0) + (p.open.high ?? 0)
                    const total = actionable(p.open)
                    return (
                      <tr key={p.project_id}>
                        <td><Link to={`/proyectos/${p.project_id}`}>{p.name}</Link></td>
                        <td className="num">{total === 0 ? <span className="muted">Ninguno</span> : <>{total}{urgent > 0 && <span className="sub">{urgent} críticos o graves</span>}</>}</td>
                      </tr>
                    )
                  })}</tbody>
                </table></div>
              )}
            </section>
          </div>
        </div>
      )}

      {data.recent.length > 0 && (
        <section className="section" aria-labelledby="recent">
          <h2 id="recent">Análisis recientes</h2>
          <div className="panel table-wrap">
            <table>
              <thead><tr><th>Proyecto</th><th>Tipo</th><th>Estado</th><th>Problemas</th><th>Fecha</th></tr></thead>
              <tbody>{data.recent.map((s) => (
                <tr key={s.id} className="rowlink" onClick={() => nav(`/analisis/${s.id}`)}>
                  <td><Link to={`/analisis/${s.id}`} onClick={(e) => e.stopPropagation()}>{s.project}</Link></td>
                  <td>{profileName(s.profile)}</td>
                  <td><ScanStatus s={s.status} /></td>
                  <td className="num">{s.findings ?? '—'}</td>
                  <td className="muted small">{fmtDate(s.created_at)}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </section>
      )}

      {data.trend.filter((t) => t.risk != null).length >= 2 && (
        <section className="section panel panel-pad" aria-labelledby="trend">
          <h2 id="trend">Evolución del riesgo</h2>
          <p className="muted small" style={{ margin: '4px 0 12px' }}>Índice de 0 a 100 calculado en cada análisis terminado; más bajo es mejor.</p>
          <TrendChart label="Índice de riesgo por análisis" points={data.trend.map((t) => ({ x: fmtDate(t.date, false), y: t.risk }))} />
        </section>
      )}
    </div>
  )
}

function headline(open: Record<Severity, number>, analysed: boolean): string {
  if (!analysed) return 'Todavía no hay análisis terminados.'
  for (const s of ['critical', 'high'] as Severity[]) if (open[s] > 0) return plainCount(s, open[s]) + '.'
  if (open.medium > 0) return 'No hay problemas críticos ni graves pendientes.'
  return 'No hay problemas pendientes en los últimos análisis.'
}

function subline(open: Record<Severity, number>, analysed: boolean, projects: number, fixed: number): string {
  if (!analysed) return 'Cuando termine el primer análisis verás aquí qué conviene corregir primero.'
  const lead = open.critical > 0 ? 'critical' : open.high > 0 ? 'high' : null
  const rest = SEVERITIES.filter((s) => s !== lead && s !== 'info' && open[s] > 0)
    .map((s) => sevCount(s, open[s]))
  const scope = projects === 1 ? 'el último análisis de tu proyecto' : `los últimos análisis de ${projects} proyectos`
  const parts = [rest.length ? `${lead ? 'Además quedan' : 'Quedan'} ${joinEs(rest)} en ${scope}.` : `Datos de ${scope}.`]
  if (fixed > 0) parts.push(`${fixed} ${fixed === 1 ? 'problema ya está marcado' : 'problemas ya están marcados'} como corregidos.`)
  return parts.join(' ')
}
const joinEs = (xs: string[]) => (xs.length <= 1 ? xs.join('') : `${xs.slice(0, -1).join(', ')} y ${xs[xs.length - 1]}`)

function ProtectionSummary() {
  const { status, error } = useProtection()
  const level = status?.protection.level
  const tone = protectionTone(level)
  return (
    <section className="panel panel-pad" aria-labelledby="prot">
      <h2 id="prot" className="row" style={{ gap: 10 }}><span className={`dot ${tone}`} style={{ width: 10, height: 10 }} />Protección de la conexión</h2>
      <p className="muted small" style={{ marginTop: 8 }}>
        {!status && (error ? 'No se pudo consultar el estado.' : 'Comprobando…')}
        {status && (level === 'none' ? 'Sin salida protegida: los sitios analizados verían tu dirección IP.' : status.protection.label)}
      </p>
      {status && level !== 'none' && status.protection.limitations.length > 0 && (
        <p className="small" style={{ marginTop: 8 }}>{status.protection.limitations[0]}{status.protection.limitations.length > 1 && ` Y ${status.protection.limitations.length - 1} más.`}</p>
      )}
      <Link className="small" to="/privacidad" style={{ display: 'inline-block', marginTop: 10 }}>Ver el estado completo</Link>
    </section>
  )
}

function Welcome({ projects, canWrite, protectionLevel, isAdmin }: { projects: number; canWrite: boolean; protectionLevel?: string; isAdmin: boolean }) {
  const steps = [
    { done: !!protectionLevel && protectionLevel !== 'none', title: 'Protege tu conexión',
      text: 'Haz que el tráfico de los análisis salga por un servidor intermedio para que los sitios analizados no vean tu dirección IP.',
      action: isAdmin ? <Link className="btn sm" to="/configuracion?tab=conexion">Configurar</Link> : <Link className="btn sm" to="/privacidad">Ver estado</Link> },
    { done: projects > 0, title: 'Crea un proyecto',
      text: 'Un proyecto reúne lo que estás autorizado a analizar, el código, las cuentas de prueba y los resultados.',
      action: canWrite ? <Link className="btn sm" to="/proyectos?crear=1">Crear proyecto</Link> : null },
    { done: false, title: 'Registra la autorización y lanza el primer análisis',
      text: 'Indica qué direcciones puedes analizar y la referencia del permiso del titular. Después elige qué analizar y con qué profundidad.',
      action: canWrite && projects > 0 ? <Link className="btn sm primary" to="/analisis/nuevo">Nuevo análisis</Link> : null },
  ]
  return (
    <section className="panel statement" aria-labelledby="welcome">
      <h1 id="welcome">Empecemos por lo básico.</h1>
      <p>Tres pasos para tu primer análisis. Cada paso se marca solo cuando está hecho.</p>
      <ol className="checklist" style={{ marginTop: 18 }}>
        {steps.map((s, i) => (
          <li key={s.title} className={s.done ? 'done' : ''}>
            <span className="mark" aria-hidden>{s.done ? <ICheck size={16} /> : i + 1}</span>
            <div className="grow">
              <h3>{s.title}{s.done && <span className="sr-only"> (hecho)</span>}</h3>
              <p className="muted small" style={{ marginTop: 3 }}>{s.text}</p>
            </div>
            {!s.done && s.action && <div style={{ alignSelf: 'center' }}>{s.action}</div>}
          </li>
        ))}
      </ol>
    </section>
  )
}
