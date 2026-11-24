import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import { protectionTone, useAuth, useProtection } from '../auth'
import { Disclosure, ErrorNotice, Loading, Notice, PageHead, Pill, errorText, useAsync, useToast } from '../components/ui'
import { ISOLATION_ACTIVE, ISOLATION_MODE } from '../copy'
import type { PrivacyCheck, PrivacyStatus } from '../types'

const LEVEL_TITLE: Record<string, string> = {
  complete: 'Tu conexión está protegida y verificada.', partial: 'Tu conexión está protegida, con limitaciones.',
  weak: 'La protección de tu conexión es débil.', none: 'Tu conexión no está protegida.',
}
const PROBE: Record<string, string> = {
  tcp_testnet: 'Conexión TCP directa a Internet', tcp_ipv6: 'Conexión IPv6 directa', udp_dns_server: 'Consulta DNS por UDP al servidor del sistema',
  os_dns: 'Resolución DNS del sistema', loopback: 'Acceso a la pasarela local de Vigía',
}
function probeState(k: string, v: string): { label: string; tone: 'ok' | 'warn' | 'bad'; note?: string } {
  if (k === 'loopback') return v === 'connected' ? { label: 'Permitido', tone: 'ok', note: 'Necesario: es la única salida que se deja abierta.' } : { label: 'Falla', tone: 'bad' }
  if (v.startsWith('blocked:timed out')) return { label: 'Sin respuesta', tone: 'warn', note: 'Se interpreta como bloqueado; sin captura de red no puede confirmarse.' }
  if (v.startsWith('blocked')) return { label: 'Bloqueado', tone: 'ok' }
  if (v === 'untested') return { label: 'Sin comprobar', tone: 'warn' }
  return { label: 'Abierto', tone: 'bad' }
}

export default function Privacy() {
  const { user } = useAuth()
  const { reload: reloadShell } = useProtection()
  const { data, error, reload, loading } = useAsync(() => api.get<PrivacyStatus>('/api/privacy'), [])
  const history = useAsync(() => api.get<PrivacyCheck[]>('/api/privacy/checks'), [])
  const [checking, setChecking] = useState(false)
  const [result, setResult] = useState<PrivacyCheck | null>(null)
  const toast = useToast()
  const isAdmin = user?.role === 'admin'

  async function verify() {
    setChecking(true); setResult(null)
    try {
      const r = await api.post<PrivacyCheck>('/api/privacy/check')
      setResult(r)
      toast(r.ok ? 'Verificación superada' : 'La verificación encontró problemas', r.ok ? '' : 'bad')
      reload(); history.reload(); reloadShell()
    } catch (e) { toast(errorText(e), 'bad') } finally { setChecking(false) }
  }

  if (error) return <div className="page"><ErrorNotice error={error} /></div>
  if (loading && !data) return <div className="page"><Loading label="Comprobando la protección…" /></div>
  if (!data) return null
  const d = data
  const level = d.protection.level
  const tone = protectionTone(level)
  const e = d.egress
  const iso = d.isolation
  const lastProbe = iso.last_check?.results ?? {}

  return (
    <div className="page">
      <PageHead title="Privacidad" intro="Qué protege tu conexión durante los análisis y qué puede ver cada parte. Solo se muestra como verificado lo que se ha comprobado."
        actions={<>
          {isAdmin && <Link className="btn" to="/configuracion?tab=conexion">Configurar</Link>}
          {isAdmin && <button className="btn primary" onClick={verify} disabled={checking}>{checking ? 'Verificando…' : 'Verificar ahora'}</button>}
        </>} />

      <section className="panel statement" aria-labelledby="lvl">
        <h2 id="lvl" className="row" style={{ fontSize: 24, gap: 12 }}><span className={`dot ${tone}`} style={{ width: 12, height: 12 }} />{LEVEL_TITLE[level]}</h2>
        <p>{d.protection.label}</p>
        {d.protection.limitations.length > 0 && (
          <div style={{ marginTop: 16 }}>
            <h3 style={{ fontSize: 15 }}>Limitaciones conocidas</h3>
            <ul style={{ margin: '8px 0 0', paddingLeft: 20 }}>{d.protection.limitations.map((l) => <li key={l} style={{ marginBottom: 4 }}>{l}</li>)}</ul>
          </div>
        )}
        {checking && <div className="loading" role="status" style={{ paddingBottom: 0 }}><span className="progress indeterminate" style={{ width: 120 }}><div /></span>Comprobando aislamiento, salida y DNS. Puede tardar hasta un minuto.</div>}
        {result && <CheckResult r={result} />}
      </section>

      <div className="cols-2 section">
        <section className="panel panel-pad stack" aria-labelledby="out">
          <h2 id="out">Cómo sale el tráfico</h2>
          <dl className="kv">
            <dt>Salida</dt>
            <dd>{d.tunnel.configured ? <>Túnel SSH con <span className="mono">{d.tunnel.destination ?? '—'}</span></>
              : e.configured ? <>Proxy <span className="mono">{e.proxy}</span></> : 'Directa, sin servidor intermedio'}</dd>
            {d.tunnel.configured && <><dt>Identidad del servidor</dt>
              <dd>{d.tunnel.ok === false ? <span style={{ color: 'var(--bad)' }}>{d.tunnel.detail}</span>
                : d.tunnel.host_key_registered ? 'Registrada en known_hosts; se exige en cada conexión' : 'No registrada: el túnel no se abrirá'}</dd></>}
            {!d.tunnel.configured && e.configured && <><dt>Cifrado hasta el proxy</dt>
              <dd>{({ loopback: 'Extremo local de un túnel', tls: 'Sí (HTTPS)', plaintext: 'No: tu proveedor de Internet ve los destinos' } as Record<string, string>)[e.transport] ?? e.transport}</dd></>}
            <dt>Nombres de los objetivos</dt><dd>{d.dns.remote ? 'Se resuelven a través de la salida' : 'Se resuelven con el DNS de tu red'}</dd>
            <dt>Sin salida protegida</dt><dd>{e.require_proxy ? 'Los análisis de webs públicas no se inician' : 'Los análisis se inician igualmente'}</dd>
            {e.observed_ip && <><dt>IP que ven los objetivos</dt><dd className="mono">{e.observed_ip}</dd></>}
          </dl>
          <p className="small muted">{e.detail}</p>
        </section>

        <section className="panel panel-pad stack" aria-labelledby="who">
          <h2 id="who">Quién ve qué</h2>
          <dl className="kv">
            <dt>Tu proveedor de Internet</dt><dd>{d.visibility.isp}</dd>
            <dt>Servidor de salida</dt><dd>{d.visibility.egress_provider}</dd>
            <dt>Resolución DNS</dt><dd>{d.visibility.dns_resolver}</dd>
            <dt>Sitio analizado</dt><dd>{d.visibility.target}</dd>
          </dl>
          <p className="small muted">{d.identity_note}</p>
        </section>

        <section className="panel panel-pad stack" aria-labelledby="iso">
          <h2 id="iso">Aislamiento de los análisis</h2>
          <dl className="kv">
            <dt>Modo</dt><dd>{ISOLATION_ACTIVE[iso.mode] ?? ISOLATION_MODE[iso.mode] ?? iso.mode}</dd>
            <dt>Bloqueo preventivo</dt><dd>{iso.preventive ? (iso.verified ? 'Activo y verificado' : 'Activo, pendiente de verificar') : 'No: solo se detectan las fugas'}</dd>
            <dt>Proceso del análisis</dt><dd>{iso.worker_confined ? 'Cada análisis corre en su propio contenedor, con base de datos y carpetas temporales propias' : 'Corre dentro del proceso principal de Vigía'}</dd>
            <dt>Vigilancia de fugas</dt><dd>{d.kill_switch.enabled ? 'Activa: corta el motor que intente salir directamente' : 'Desactivada'}</dd>
            <dt>Fugas registradas</dt><dd>{d.leaks.count === 0 ? 'Ninguna' : `${d.leaks.count}. Última: ${d.leaks.recent[0]?.message ?? ''}`}</dd>
          </dl>
          {iso.last_check && (
            <div className="stack-sm">
              <h3 style={{ fontSize: 15 }}>Última comprobación del aislamiento: {iso.last_check.ok ? 'superada' : 'no superada'}, {new Date(iso.last_check.ts * 1000).toLocaleString('es-ES')}</h3>
              {Object.keys(lastProbe).length > 0 && (
                <ul className="phases">
                  {Object.entries(lastProbe).map(([k, v]) => {
                    const st = probeState(k, String(v))
                    return (
                      <li key={k} style={{ gridTemplateColumns: '1fr auto' }}>
                        <span>{PROBE[k] ?? k}<span className="small muted" style={{ display: 'block' }}>{st.note ?? <span className="mono">{String(v)}</span>}</span></span>
                        <Pill tone={st.tone}>{st.label}</Pill>
                      </li>
                    )
                  })}
                </ul>
              )}
            </div>
          )}
          <p className="small muted">{iso.detail}</p>
        </section>

        <section className="panel panel-pad stack" aria-labelledby="data">
          <h2 id="data">Datos y credenciales</h2>
          <dl className="kv">
            <dt>Antes de guardar</dt><dd>Se ocultan {d.data_protection.redacted.join(', ')}.</dd>
            <dt>Cuentas de prueba</dt><dd>{d.data_protection.credentials_at_rest}</dd>
            <dt>Navegador aislado</dt><dd>{d.browser.available ? 'Disponible' : 'No disponible'}. {d.browser.detail}</dd>
          </dl>
          <p className="small muted">{d.data_protection.identity_to_model}</p>
        </section>
      </div>

      <section className="section" aria-labelledby="eng">
        <h2 id="eng">Motores y su salida</h2>
        <p className="muted small" style={{ margin: '4px 0 12px', maxWidth: '78ch' }}>Cada motor externo solo se usa si puede salir por la vía protegida. Los que no pueden garantizarlo se bloquean cuando la salida protegida es obligatoria.</p>
        <div className="panel table-wrap">
          <table>
            <thead><tr><th>Motor</th><th>Estado</th><th>Cómo sale</th><th>Aislamiento</th></tr></thead>
            <tbody>{d.engines_egress.map((m) => (
              <tr key={m.engine}>
                <td><b style={{ fontWeight: 500 }}>{m.engine}</b></td>
                <td>{m.state_labels.map((l, i) => <Pill key={l} tone={m.states[i] === 1 ? 'ok' : m.states[i] === 3 ? 'bad' : m.states[i] === 2 ? 'warn' : ''}>{l}</Pill>)}</td>
                <td className="small">{m.detail}<span className="sub">{m.evidence}</span></td>
                <td className="small">{m.isolation}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      </section>

      <section className="section" aria-labelledby="hist">
        <h2 id="hist">Verificaciones anteriores</h2>
        <div className="panel table-wrap" style={{ marginTop: 12 }}>
          {history.data?.length === 0 ? <p className="panel-pad muted small">Aún no se ha hecho ninguna verificación.{isAdmin && ' Usa «Verificar ahora».'}</p> : (
            <table>
              <thead><tr><th>Fecha</th><th>Resultado</th><th>Aislamiento</th><th>Salida</th><th>DNS remoto</th><th>IP observada</th></tr></thead>
              <tbody>{history.data?.map((h) => (
                <tr key={h.ts}>
                  <td className="small">{new Date(h.ts * 1000).toLocaleString('es-ES')}</td>
                  <td><Pill tone={h.ok ? 'ok' : 'bad'}>{h.ok ? 'Superada' : 'No superada'}</Pill></td>
                  <td>{okText(typeof h.isolation === 'object' ? h.isolation?.ok : h.isolation)}</td>
                  <td className="small">{h.egress ? <>{okText(h.egress.ok)}<span className="sub">{h.egress.detail}</span></> : '—'}</td>
                  <td className="small">{h.dns ? okText(h.dns.ok) : '—'}</td>
                  <td className="mono small">{h.observed_ip ?? '—'}</td>
                </tr>
              ))}</tbody>
            </table>
          )}
        </div>
      </section>

      <section className="section">
        <Disclosure summary="Detalles técnicos del aislamiento y del alcance">
          <dl className="kv">
            <dt>Procesos</dt><dd>{d.worker_isolation.process}</dd>
            <dt>Archivos</dt><dd>{d.worker_isolation.filesystem}</dd>
            <dt>Entorno</dt><dd>{d.worker_isolation.environment}</dd>
            <dt>Limpieza</dt><dd>{d.worker_isolation.cleanup}</dd>
            <dt>Siempre bloqueado</dt><dd>{d.network_scope.always_blocked.join('; ')}</dd>
            <dt>Direcciones internas</dt><dd>{d.network_scope.private_targets}</dd>
            {d.network_scope.egress_gateway && <><dt>Pasarela</dt><dd>{d.network_scope.egress_gateway}</dd></>}
            <dt>Trazabilidad</dt><dd>{d.network_scope.connection_trace}</dd>
            <dt>Vigilancia de fugas</dt><dd>{d.kill_switch.detail}</dd>
            <dt>DNS</dt><dd>{d.dns.detail}</dd>
            <dt>Auditoría de red</dt>
            <dd>{d.last_audit ? `${d.last_audit.target_connections} conexiones al objetivo; ${d.last_audit.home_ip_seen_by_target} con tu IP; ${d.last_audit.local_lookups_of_target_names} consultas DNS locales de nombres de objetivos.`
              : 'No registrada en este equipo.'}</dd>
          </dl>
        </Disclosure>
      </section>
      {!isAdmin && <div className="section"><Notice>Solo una persona con permisos de administración puede cambiar esta configuración o lanzar una verificación.</Notice></div>}
    </div>
  )
}

const okText = (ok?: boolean | null) => (ok == null ? '—' : ok ? 'Correcto' : 'Falla')

function CheckResult({ r }: { r: PrivacyCheck }) {
  const isoOk = typeof r.isolation === 'object' ? r.isolation?.ok : r.isolation
  return (
    <div style={{ marginTop: 18 }}>
      <Notice tone={r.ok ? 'ok' : 'bad'} title={r.ok ? 'Verificación superada' : 'La verificación no se superó'}>
        <ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>
          <li>Aislamiento: {okText(isoOk)}</li>
          <li>Salida: {r.egress ? `${okText(r.egress.ok)}. ${r.egress.detail}` : 'sin comprobar'}</li>
          <li>DNS a través de la salida: {r.dns ? `${okText(r.dns.ok)}. ${r.dns.detail}` : 'sin comprobar'}</li>
          {r.observed_ip && <li>IP que verán los objetivos: <span className="mono">{r.observed_ip}</span></li>}
        </ul>
      </Notice>
    </div>
  )
}
