import { useEffect, useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../api'
import { useAuth, useProtection } from '../auth'
import { ChoiceGroup, Confirm, Dialog, Disclosure, ErrorNotice, Loading, Notice, PageHead, Pill, Tabs, errorText, fmtDate, useAsync, useToast } from '../components/ui'
import { ENGINE_STATUS, INTENSITY, ISOLATION_MODE, PROFILE_PLAIN, ROLE } from '../copy'
import { getThemePref, setThemePref, type ThemePref } from '../theme'
import type { Engine, PrivacyCheck, Profile, SettingRow, User } from '../types'

type Tab = 'apariencia' | 'conexion' | 'motores' | 'perfiles' | 'usuarios' | 'actividad' | 'cuenta'

export default function Settings() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const tabs: [Tab, string][] = [
    ['apariencia', 'Apariencia'], ...(isAdmin ? [['conexion', 'Conexión protegida']] as [Tab, string][] : []),
    ['motores', 'Motores'], ['perfiles', 'Perfiles de análisis'],
    ...(isAdmin ? [['usuarios', 'Usuarios'], ['actividad', 'Registro de actividad']] as [Tab, string][] : []), ['cuenta', 'Tu cuenta'],
  ]
  const [params, setParams] = useSearchParams()
  const tab = (tabs.find(([k]) => k === params.get('tab'))?.[0] ?? 'apariencia') as Tab
  return (
    <div className="page">
      <PageHead title="Configuración" />
      <Tabs label="Secciones de configuración" tabs={tabs} value={tab} onChange={(k) => setParams(k === 'apariencia' ? {} : { tab: k }, { replace: true })} />
      <div role="tabpanel">
        {tab === 'apariencia' && <Appearance />}
        {tab === 'conexion' && isAdmin && <Connection />}
        {tab === 'motores' && <Engines isAdmin={isAdmin} />}
        {tab === 'perfiles' && <Profiles />}
        {tab === 'usuarios' && isAdmin && <Users />}
        {tab === 'actividad' && isAdmin && <Activity />}
        {tab === 'cuenta' && <Account />}
      </div>
    </div>
  )
}

// ------------------------------------------------------------------ appearance
function Appearance() {
  const [pref, setPref] = useState<ThemePref>(getThemePref())
  return (
    <section className="stack" style={{ maxWidth: 640 }}>
      <h2>Tema</h2>
      <ChoiceGroup label="Tema" value={pref} onChange={(p) => { setPref(p); setThemePref(p) }}
        options={[
          { key: 'system', title: 'Según el sistema', text: 'Cambia entre claro y oscuro con la preferencia de tu equipo.' },
          { key: 'light', title: 'Claro', text: 'Fondo marfil y texto azul oscuro.' },
          { key: 'dark', title: 'Oscuro', text: 'Fondo azul profundo, pensado para poca luz.' },
        ]} />
      <p className="small muted">Se guarda en este navegador.</p>
    </section>
  )
}

// ------------------------------------------------------------------ guided connection-protection setup (admin)
type Way = 'ssh' | 'proxy' | 'none'
function Connection() {
  const { reload: reloadShell } = useProtection()
  const toast = useToast()
  const st = useAsync(() => api.get<{ settings: SettingRow[]; ssh_client: string }>('/api/settings/privacy'), [])
  const [form, setForm] = useState<Record<string, string | boolean>>({})
  const [way, setWay] = useState<Way>('none')
  const [err, setErr] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)
  const [check, setCheck] = useState<PrivacyCheck | null>(null)
  const [checking, setChecking] = useState(false)
  const rows = Object.fromEntries((st.data?.settings ?? []).map((r) => [r.key, r]))
  useEffect(() => {
    if (!st.data) return
    const f: Record<string, string | boolean> = {}
    st.data.settings.forEach((r) => { f[r.key] = typeof r.value === 'boolean' ? r.value : (r.value ?? '') as string })
    setForm(f)
    setWay(f.ssh_tunnel ? 'ssh' : f.http_proxy ? 'proxy' : 'none')
  }, [st.data])
  if (st.error) return <ErrorNotice error={st.error} />
  if (!st.data) return <Loading />

  const locked = (k: string) => rows[k] && !rows[k].editable
  const val = (k: string) => (form[k] ?? '') as string
  const field = (k: string, label: string, hint?: string, placeholder?: string) => (
    <label className="field">{label}{hint && <span className="hint">{hint}</span>}
      <input value={val(k)} onChange={(e) => setForm({ ...form, [k]: e.target.value })} disabled={locked(k)} placeholder={placeholder} spellCheck={false} />
      {locked(k) && <span className="hint">Fijado por la variable de entorno VIGIA_{k.toUpperCase()}.</span>}
    </label>
  )
  const toggle = (k: string, label: string, hint: string) => (
    <label className="check"><input type="checkbox" checked={!!form[k]} disabled={locked(k)} onChange={(e) => setForm({ ...form, [k]: e.target.checked })} />
      <span>{label}<span className="small muted" style={{ display: 'block' }}>{hint}{locked(k) && ` Fijado por VIGIA_${k.toUpperCase()}.`}</span></span></label>
  )

  async function save() {
    setErr(null); setBusy(true); setCheck(null)
    const body: Record<string, unknown> = {}
    const edit = (k: string, v: unknown) => { if (!locked(k)) body[k] = v }
    edit('ssh_tunnel', way === 'ssh' ? val('ssh_tunnel').trim() : '')
    edit('ssh_known_hosts', way === 'ssh' ? val('ssh_known_hosts').trim() : '')
    edit('ssh_identity', way === 'ssh' ? val('ssh_identity').trim() : '')
    edit('http_proxy', way === 'proxy' ? val('http_proxy').trim() : '')
    for (const k of ['dns_resolver', 'egress_isolation', 'egress_check_url']) edit(k, val(k).trim())
    for (const k of ['require_proxy', 'confine_worker', 'egress_kill_switch']) edit(k, !!form[k])
    try {
      await api.patch('/api/settings/privacy', body)
      toast('Configuración guardada'); st.reload(); reloadShell()
    } catch (e) { setErr(e) } finally { setBusy(false) }
  }
  async function verify() {
    setChecking(true); setCheck(null)
    try { const r = await api.post<PrivacyCheck>('/api/privacy/check'); setCheck(r); reloadShell() } catch (e) { toast(errorText(e), 'bad') } finally { setChecking(false) }
  }
  const dest = val('ssh_tunnel').trim()
  const m = /^([^@\s]+)@([^:\s]+)(?::(\d+))?$/.exec(dest)
  const host = m?.[2] ?? 'servidor'
  const port = m?.[3] ?? '22'
  return (
    <div className="stack" style={{ gap: 26, maxWidth: 860 }}>
      <p className="muted" style={{ maxWidth: '72ch' }}>Haz que el tráfico de los análisis salga por un servidor intermedio de tu confianza. Así los sitios analizados ven la dirección de ese servidor y no la tuya. Vigía no usa servidores de terceros por su cuenta: tú decides cuál.</p>

      <section className="stack">
        <h2>1. Elige cómo saldrá el tráfico</h2>
        <ChoiceGroup label="Vía de salida" value={way} onChange={setWay}
          options={[
            { key: 'ssh', title: 'Túnel SSH a un servidor propio (recomendado)', text: 'Vigía abre y cierra el túnel en cada análisis y comprueba la identidad del servidor antes de enviar nada.', disabled: locked('ssh_tunnel') },
            { key: 'proxy', title: 'Un proxy que ya tienes', text: 'SOCKS5 o HTTPS. Si el proxy no cifra la conexión, tu proveedor de Internet verá los destinos.', disabled: locked('http_proxy') },
            { key: 'none', title: 'Sin servidor intermedio', text: 'Los sitios analizados verán tu dirección IP. Válido para laboratorio o sistemas propios.' },
          ]} />
      </section>

      {way === 'ssh' && (
        <section className="stack">
          <h2>2. Datos del servidor</h2>
          {!st.data.ssh_client && <Notice tone="bad">No se encontró el cliente OpenSSH en este equipo. Instálalo (en Windows: Configuración, Aplicaciones, Características opcionales, Cliente OpenSSH).</Notice>}
          <div className="form-grid">
            {field('ssh_tunnel', 'Usuario y servidor', 'Forma usuario@servidor o usuario@servidor:puerto.', 'vigia@203.0.113.10')}
            {field('ssh_identity', 'Clave privada', 'Ruta del archivo de clave sin contraseña creado para Vigía.', 'C:\\Users\\tu-usuario\\.ssh\\vigia_ed25519')}
          </div>
          {field('ssh_known_hosts', 'Identidad registrada del servidor (known_hosts)', 'Obligatorio. Vigía rechaza el túnel si el servidor no coincide con esta huella.', 'C:\\Users\\tu-usuario\\.ssh\\vigia_known_hosts')}
          <Disclosure summary="Cómo preparar la clave y la identidad del servidor">
            <ol className="stack-sm" style={{ paddingLeft: 20, margin: 0 }}>
              <li>Crea una clave solo para Vigía: <pre>ssh-keygen -t ed25519 -N "" -f %USERPROFILE%\.ssh\vigia_ed25519</pre></li>
              <li>Añade el contenido de <span className="mono">vigia_ed25519.pub</span> a <span className="mono">~/.ssh/authorized_keys</span> del usuario en el servidor. Recomendado: limitarlo a reenvío de puertos con <span className="mono">restrict,port-forwarding</span>.</li>
              <li>Guarda la identidad del servidor: <pre>{`ssh-keyscan -p ${port} ${host} > %USERPROFILE%\\.ssh\\vigia_known_hosts`}</pre></li>
              <li>Compruébala antes de confiar en ella. Muestra la huella con <pre>ssh-keygen -lf %USERPROFILE%\.ssh\vigia_known_hosts</pre> y compárala con la que te dé quien administra el servidor (en el servidor: <span className="mono">ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</span>). Si no coinciden, no sigas.</li>
            </ol>
          </Disclosure>
        </section>
      )}

      {way === 'proxy' && (
        <section className="stack">
          <h2>2. Dirección del proxy</h2>
          {field('http_proxy', 'Proxy', 'socks5h://, socks5://, https:// o http://. Las credenciales pueden ir en la dirección y nunca se muestran después.', 'socks5h://127.0.0.1:1080')}
        </section>
      )}

      <section className="stack">
        <h2>{way === 'none' ? '2' : '3'}. Protecciones</h2>
        {toggle('require_proxy', 'Exigir salida protegida', 'Si no hay túnel o proxy disponible, los análisis de sitios públicos no se inician (nunca se usa tu conexión directa como alternativa).')}
        {toggle('confine_worker', 'Aislar cada análisis en su propio contenedor', 'Proceso, base de datos temporal y carpetas propias para cada análisis; sin acceso a otros proyectos ni a las claves.')}
        {toggle('egress_kill_switch', 'Vigilar fugas', 'Corta cualquier motor que intente conectarse directamente en lugar de usar la salida protegida.')}
        <Disclosure summary="Opciones avanzadas">
          <div className="stack">
            <label className="field">Aislamiento de red
              <select value={val('egress_isolation') || 'auto'} disabled={locked('egress_isolation')} onChange={(e) => setForm({ ...form, egress_isolation: e.target.value })}>
                {Object.entries(ISOLATION_MODE).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
            {field('dns_resolver', 'Resolución de nombres de los objetivos', 'auto (a través de la salida), system (DNS de tu red; no recomendado), una dirección https:// de DoH o tcp://IP.', 'auto')}
            {field('egress_check_url', 'Comprobación de la IP de salida', 'Opcional. Dirección que devuelve la IP pública; solo se consulta al verificar.', 'https://…')}
          </div>
        </Disclosure>
      </section>

      <ErrorNotice error={err} />
      <div className="row" style={{ borderTop: '1px solid var(--line)', paddingTop: 18 }}>
        <button className="btn primary" onClick={save} disabled={busy}>{busy ? 'Guardando…' : 'Guardar'}</button>
        <button className="btn" onClick={verify} disabled={checking}>{checking ? 'Verificando…' : 'Verificar la conexión'}</button>
        <Link to="/privacidad" className="small">Ver el estado de la privacidad</Link>
      </div>
      {checking && <div className="loading" role="status" style={{ padding: 0 }}><span className="progress indeterminate" style={{ width: 120 }}><div /></span>Abriendo la salida y comprobando el DNS remoto…</div>}
      {check && (
        <Notice tone={check.ok ? 'ok' : 'bad'} title={check.ok ? 'Todo correcto' : 'La verificación no se superó'}>
          <ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>
            <li>Aislamiento: {(typeof check.isolation === 'object' ? check.isolation?.ok : check.isolation) ? 'correcto' : 'falla'}</li>
            <li>Salida: {check.egress ? check.egress.detail : 'sin comprobar'}</li>
            <li>DNS a través de la salida: {check.dns ? `${check.dns.ok ? 'correcto' : 'falla'}. ${check.dns.detail}` : 'sin comprobar'}</li>
            {check.observed_ip && <li>IP que verán los objetivos: <span className="mono">{check.observed_ip}</span></li>}
          </ul>
        </Notice>
      )}
    </div>
  )
}

// ------------------------------------------------------------------ engines
function Engines({ isAdmin }: { isAdmin: boolean }) {
  const { data, error, loading, setData } = useAsync(() => api.get<Engine[]>('/api/engines'), [])
  const [busy, setBusy] = useState(false)
  const toast = useToast()
  async function refresh() {
    setBusy(true)
    try { setData(await api.get<Engine[]>('/api/engines?refresh=true')); toast('Motores comprobados') } catch (e) { toast(errorText(e), 'bad') } finally { setBusy(false) }
  }
  return (
    <div className="stack">
      <div className="row between">
        <p className="muted" style={{ maxWidth: '72ch' }}>Vigía tiene revisiones propias y funciona aunque no haya motores externos. Un motor que falta se muestra como «No se usó» en cada análisis; nunca se simula su resultado.</p>
        {isAdmin && <button className="btn" onClick={refresh} disabled={busy}>{busy ? 'Comprobando…' : 'Volver a comprobar'}</button>}
      </div>
      <ErrorNotice error={error} />
      {loading && !data ? <Loading /> : (
        <div className="panel table-wrap">
          <table>
            <thead><tr><th>Motor</th><th>Estado</th><th>Versión</th><th>Detalle</th></tr></thead>
            <tbody>{data?.map((e) => {
              const st = ENGINE_STATUS[e.status] ?? { label: e.status, tone: '' as const }
              return (
                <tr key={e.name}>
                  <td><b style={{ fontWeight: 500 }}>{e.title}</b><span className="sub">{e.category}{e.lab_only ? ', solo laboratorio' : ''}. Licencia {e.license}.</span></td>
                  <td><Pill tone={st.tone}>{st.label}</Pill></td>
                  <td className="mono small">{e.version ?? '—'}</td>
                  <td className="small muted">{[e.reason, e.notes].filter(Boolean).join(' ')}</td>
                </tr>
              )
            })}</tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ------------------------------------------------------------------ profiles
function Profiles() {
  const { data, error } = useAsync(() => api.get<Profile[]>('/api/profiles'), [])
  return (
    <div className="stack">
      <p className="muted" style={{ maxWidth: '72ch' }}>Cada perfil fija qué se revisa y los límites máximos. En «Nuevo análisis» se pueden reducir, nunca superar.</p>
      <ErrorNotice error={error} />
      {!data ? <Loading /> : (
        <div className="panel table-wrap">
          <table>
            <thead><tr><th>Perfil</th><th>Necesita</th><th>Límites</th><th>Motores externos</th></tr></thead>
            <tbody>{data.map((p) => (
              <tr key={p.key}>
                <td><b style={{ fontWeight: 500 }}>{PROFILE_PLAIN[p.key]?.name ?? p.name}</b><span className="sub">{PROFILE_PLAIN[p.key]?.text ?? p.description}</span><span className="sub mono">{p.name}</span></td>
                <td className="small">{[p.needs_target && 'Direcciones autorizadas', p.needs_source && 'Código'].filter(Boolean).join(' y ') || '—'}</td>
                <td className="small">{p.max_duration_min} min; {p.rps} peticiones/s; intensidad {(INTENSITY[p.intensity] ?? p.intensity).toLowerCase()}{p.max_requests ? `; ${p.max_requests.toLocaleString('es-ES')} peticiones` : ''}</td>
                <td className="small">{p.tools.length ? p.tools.join(', ') : 'Ninguno'}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ------------------------------------------------------------------ users (admin)
function Users() {
  const { user: me } = useAuth()
  const users = useAsync(() => api.get<User[]>('/api/users'), [])
  const [adding, setAdding] = useState(false)
  const [toggle, setToggle] = useState<User | null>(null)
  const toast = useToast()
  async function patch(u: User, body: Record<string, unknown>, msg: string) {
    try { await api.patch(`/api/users/${u.id}`, body); users.reload(); toast(msg) } catch (x) { toast(errorText(x), 'bad') }
  }
  return (
    <div className="stack">
      <div className="row between">
        <p className="muted">Administración gestiona todo; analistas lanzan análisis en sus proyectos; solo lectura consulta resultados.</p>
        <button className="btn" onClick={() => setAdding(true)}>Crear usuario</button>
      </div>
      <ErrorNotice error={users.error} />
      <div className="panel table-wrap">
        <table>
          <thead><tr><th>Usuario</th><th>Papel</th><th>Estado</th><th><span className="sr-only">Acciones</span></th></tr></thead>
          <tbody>{users.data?.map((u) => (
            <tr key={u.id}>
              <td>{u.username}{u.id === me?.id && <span className="sub">Tú</span>}</td>
              <td><select aria-label={`Papel de ${u.username}`} value={u.role} disabled={u.id === me?.id} style={{ width: 'auto' }}
                onChange={(e) => patch(u, { role: e.target.value }, `${u.username}: ${ROLE[e.target.value]}`)}>
                <option value="admin">{ROLE.admin}</option><option value="analyst">{ROLE.analyst}</option><option value="viewer">{ROLE.viewer}</option></select></td>
              <td><Pill tone={u.is_active ? 'ok' : ''}>{u.is_active ? 'Activo' : 'Desactivado'}</Pill></td>
              <td>{u.id !== me?.id && <button className="btn sm quiet" onClick={() => setToggle(u)}>{u.is_active ? 'Desactivar' : 'Activar'}</button>}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
      {adding && <CreateUser onClose={() => setAdding(false)} onCreated={(n) => { setAdding(false); users.reload(); toast(`Usuario ${n} creado`) }} />}
      {toggle && (
        <Confirm title={toggle.is_active ? `¿Desactivar a ${toggle.username}?` : `¿Activar a ${toggle.username}?`} danger={toggle.is_active}
          confirmLabel={toggle.is_active ? 'Desactivar' : 'Activar'} onCancel={() => setToggle(null)}
          onConfirm={async () => { await patch(toggle, { is_active: !toggle.is_active }, toggle.is_active ? 'Usuario desactivado' : 'Usuario activado'); setToggle(null) }}>
          <p>{toggle.is_active ? 'No podrá iniciar sesión y sus sesiones abiertas dejarán de funcionar. Sus análisis y datos se conservan.' : 'Podrá volver a iniciar sesión con su contraseña.'}</p>
        </Confirm>
      )}
    </div>
  )
}

function CreateUser({ onClose, onCreated }: { onClose: () => void; onCreated: (name: string) => void }) {
  const [form, setForm] = useState({ username: '', password: '', role: 'analyst' })
  const [err, setErr] = useState<unknown>(null)
  async function submit(e: FormEvent) {
    e.preventDefault(); setErr(null)
    try { await api.post('/api/users', form); onCreated(form.username) } catch (x) { setErr(x) }
  }
  return (
    <Dialog title="Crear usuario" onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        <label className="field">Nombre de usuario <span className="hint">Minúsculas, números, punto, guion o guion bajo; de 3 a 64 caracteres.</span>
          <input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required pattern="[a-z0-9][a-z0-9._\-]{2,63}" autoComplete="off" /></label>
        <label className="field">Contraseña inicial <span className="hint">Al menos 12 caracteres y tres tipos (mayúsculas, minúsculas, números o símbolos).</span>
          <input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required minLength={12} autoComplete="new-password" /></label>
        <label className="field">Papel
          <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
            <option value="analyst">{ROLE.analyst}</option><option value="viewer">{ROLE.viewer}</option><option value="admin">{ROLE.admin}</option></select></label>
        <ErrorNotice error={err} />
        <div className="row end"><button type="button" className="btn" onClick={onClose}>Cancelar</button><button className="btn primary">Crear usuario</button></div>
      </form>
    </Dialog>
  )
}

// ------------------------------------------------------------------ activity log (admin)
interface AuditRow { id: number; ts: string; username: string; action: string; target: string; details: Record<string, unknown>; ip: string; severity: string }
function Activity() {
  const audit = useAsync(() => api.get<AuditRow[]>('/api/audit?limit=300'), [])
  const [verify, setVerify] = useState<{ ok: boolean; entries: number; broken_at: number | null; reason: string | null } | null>(null)
  const [busy, setBusy] = useState(false)
  const toast = useToast()
  return (
    <div className="stack">
      <div className="row between">
        <p className="muted" style={{ maxWidth: '70ch' }}>Cada acción importante queda registrada. Las entradas están encadenadas: si alguien modifica o borra una, la verificación lo detecta.</p>
        <button className="btn" disabled={busy} onClick={async () => {
          setBusy(true)
          try { setVerify(await api.get('/api/audit/verify')) } catch (e) { toast(errorText(e), 'bad') } finally { setBusy(false) }
        }}>{busy ? 'Verificando…' : 'Verificar integridad'}</button>
      </div>
      {verify && (verify.ok
        ? <Notice tone="ok">Registro íntegro: {verify.entries} entradas sin alteraciones.</Notice>
        : <Notice tone="bad" title="El registro ha sido alterado">Primera entrada afectada: {verify.broken_at}. {verify.reason}</Notice>)}
      <ErrorNotice error={audit.error} />
      <div className="panel table-wrap" style={{ maxHeight: 620, overflow: 'auto' }}>
        <table>
          <thead><tr><th>Fecha</th><th>Usuario</th><th>Acción</th><th>Sobre</th><th>IP</th></tr></thead>
          <tbody>{audit.data?.map((a) => (
            <tr key={a.id}>
              <td className="small" style={{ whiteSpace: 'nowrap' }}>{fmtDate(a.ts)}</td><td>{a.username || '—'}</td>
              <td><span className="mono small" style={{ color: a.severity === 'alert' ? 'var(--bad)' : a.severity === 'warn' ? 'var(--attn)' : undefined }}>{a.action}</span>
                {a.details && Object.keys(a.details).length > 0 && <span className="sub mono ellipsis" style={{ maxWidth: 420 }} title={JSON.stringify(a.details)}>{JSON.stringify(a.details)}</span>}</td>
              <td className="mono small">{a.target}</td><td className="mono small">{a.ip}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
    </div>
  )
}

// ------------------------------------------------------------------ own account
function Account() {
  const { user, setUser } = useAuth()
  const [form, setForm] = useState({ current: '', next: '', repeat: '' })
  const [err, setErr] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)
  const toast = useToast()
  async function submit(e: FormEvent) {
    e.preventDefault(); setErr(null)
    if (form.next !== form.repeat) { setErr(new Error('Las dos contraseñas nuevas no coinciden.')); return }
    setBusy(true)
    try {
      await api.post('/api/auth/password', { current_password: form.current, new_password: form.next })
      toast('Contraseña cambiada. Inicia sesión de nuevo.')
      setUser(null)
    } catch (x) { setErr(x) } finally { setBusy(false) }
  }
  return (
    <div className="cols-2" style={{ alignItems: 'start' }}>
      <section className="panel panel-pad stack">
        <h2>Datos</h2>
        <dl className="kv"><dt>Usuario</dt><dd>{user?.username}</dd><dt>Papel</dt><dd>{ROLE[user?.role ?? ''] ?? user?.role}</dd></dl>
      </section>
      <form className="panel panel-pad stack" onSubmit={submit}>
        <h2>Cambiar contraseña</h2>
        <label className="field">Contraseña actual<input type="password" value={form.current} onChange={(e) => setForm({ ...form, current: e.target.value })} required autoComplete="current-password" /></label>
        <label className="field">Contraseña nueva <span className="hint">Al menos 12 caracteres y tres tipos de carácter.</span>
          <input type="password" value={form.next} onChange={(e) => setForm({ ...form, next: e.target.value })} required minLength={12} autoComplete="new-password" /></label>
        <label className="field">Repite la contraseña nueva<input type="password" value={form.repeat} onChange={(e) => setForm({ ...form, repeat: e.target.value })} required minLength={12} autoComplete="new-password" /></label>
        <p className="small muted">Al cambiarla se cierran todas tus sesiones abiertas.</p>
        <ErrorNotice error={err} />
        <div><button className="btn primary" disabled={busy}>{busy ? 'Cambiando…' : 'Cambiar contraseña'}</button></div>
      </form>
    </div>
  )
}
