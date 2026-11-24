import { useState, type FormEvent } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { api } from '../api'
import { useAuth } from '../auth'
import { IArrowLeft, ICheck, IPlus } from '../components/Icons'
import {
  Confirm, Dialog, Disclosure, Empty, ErrorNotice, Loading, Notice, PageHead, Pill, ScanStatus, Tabs, errorText, fmtDate, fmtDur,
  scanDuration, useAsync, useToast,
} from '../components/ui'
import { CRED_KIND, MEMBER_ROLE, SOURCE_KIND, profileName } from '../copy'
import type { Credential, Project, Scan, Scope, Source } from '../types'

type Tab = 'analisis' | 'alcance' | 'codigo' | 'cuentas' | 'miembros'
const TABS: [Tab, string][] = [['analisis', 'Análisis'], ['alcance', 'Qué se puede analizar'], ['codigo', 'Código y especificaciones'],
  ['cuentas', 'Cuentas de prueba'], ['miembros', 'Miembros']]

export default function ProjectDetail() {
  const id = Number(useParams().id)
  const { user } = useAuth()
  const proj = useAsync(() => api.get<Project>(`/api/projects/${id}`), [id])
  const [params, setParams] = useSearchParams()
  const tab = (TABS.find(([k]) => k === params.get('tab'))?.[0] ?? 'analisis') as Tab
  const [editing, setEditing] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const nav = useNavigate()
  const toast = useToast()
  if (proj.error) return <div className="page"><ErrorNotice error={proj.error} /></div>
  if (!proj.data) return <div className="page"><Loading /></div>
  const p = proj.data
  const owner = p.role === 'owner' || user?.role === 'admin'
  const canWrite = owner || p.role === 'analyst'
  return (
    <div className="page">
      <PageHead title={p.name} back={<Link to="/proyectos"><IArrowLeft size={16} />Proyectos</Link>}
        intro={<>{p.description || 'Sin descripción.'}</>}
        actions={<>
          {owner && <button className="btn" onClick={() => setEditing(true)}>Editar</button>}
          {canWrite && <Link className="btn primary" to={`/analisis/nuevo?proyecto=${id}`}>Nuevo análisis</Link>}
        </>} />
      <Tabs label="Secciones del proyecto" tabs={TABS} value={tab} onChange={(k) => setParams(k === 'analisis' ? {} : { tab: k }, { replace: true })} />
      <div role="tabpanel">
        {tab === 'analisis' && <Scans id={id} canWrite={canWrite} />}
        {tab === 'alcance' && <Scopes id={id} canWrite={canWrite} />}
        {tab === 'codigo' && <Sources id={id} canWrite={canWrite} />}
        {tab === 'cuentas' && <Credentials id={id} canWrite={canWrite} />}
        {tab === 'miembros' && <Members id={id} owner={owner} />}
      </div>
      {owner && (
        <section className="section">
          <Disclosure summary="Eliminar el proyecto">
            <div className="stack" style={{ maxWidth: '70ch' }}>
              <p className="small muted">Se borran sus análisis, resultados, informes, código importado y cuentas de prueba. La acción queda registrada y no se puede deshacer.</p>
              <div><button className="btn danger" onClick={() => setDeleting(true)}>Eliminar «{p.name}»</button></div>
            </div>
          </Disclosure>
        </section>
      )}
      {editing && <EditProject project={p} onClose={() => setEditing(false)} onSaved={(np) => { proj.setData(np); setEditing(false); toast('Cambios guardados') }} />}
      {deleting && (
        <Confirm title="¿Eliminar el proyecto?" danger confirmLabel="Eliminar definitivamente" onCancel={() => setDeleting(false)}
          onConfirm={async () => {
            try { await api.del(`/api/projects/${id}`); toast(`Proyecto «${p.name}» eliminado`); nav('/proyectos') } catch (e) { toast(errorText(e), 'bad'); setDeleting(false) }
          }}>
          <p>Se eliminarán todos los análisis, resultados, informes, código importado y cuentas de prueba de <b>{p.name}</b>.</p>
          <p className="muted small">Si hay un análisis en marcha, detenlo antes.</p>
        </Confirm>
      )}
    </div>
  )
}

function EditProject({ project, onClose, onSaved }: { project: Project; onClose: () => void; onSaved: (p: Project) => void }) {
  const [name, setName] = useState(project.name)
  const [description, setDesc] = useState(project.description)
  const [err, setErr] = useState<unknown>(null)
  async function submit(e: FormEvent) {
    e.preventDefault()
    try { onSaved(await api.patch<Project>(`/api/projects/${project.id}`, { name: name.trim(), description })) } catch (x) { setErr(x) }
  }
  return (
    <Dialog title="Editar proyecto" onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        <label className="field">Nombre<input value={name} onChange={(e) => setName(e.target.value)} required maxLength={120} /></label>
        <label className="field">Descripción<textarea value={description} onChange={(e) => setDesc(e.target.value)} maxLength={4000} rows={3} /></label>
        <ErrorNotice error={err} />
        <div className="row end"><button type="button" className="btn" onClick={onClose}>Cancelar</button><button className="btn primary">Guardar cambios</button></div>
      </form>
    </Dialog>
  )
}

// ------------------------------------------------------------------ analyses
function Scans({ id, canWrite }: { id: number; canWrite: boolean }) {
  const { data, error, reload } = useAsync(() => api.get<Scan[]>(`/api/projects/${id}/scans`), [id])
  const [del, setDel] = useState<Scan | null>(null)
  const nav = useNavigate()
  const toast = useToast()
  if (error) return <ErrorNotice error={error} />
  if (!data) return <Loading />
  if (!data.length) return (
    <div className="panel"><Empty title="Este proyecto aún no tiene análisis"
      action={canWrite ? <Link className="btn primary" to={`/analisis/nuevo?proyecto=${id}`}>Nuevo análisis</Link> : undefined}>
      Antes de analizar una web, registra en «Qué se puede analizar» las direcciones y la autorización del titular.</Empty></div>
  )
  return (
    <>
      <div className="panel table-wrap">
        <table>
          <thead><tr><th>Análisis</th><th>Estado</th><th>Problemas</th><th>Inicio</th><th>Duración</th><th><span className="sr-only">Acciones</span></th></tr></thead>
          <tbody>{data.map((s) => (
            <tr key={s.id} className="rowlink" onClick={() => nav(`/analisis/${s.id}`)}>
              <td><Link to={`/analisis/${s.id}`} onClick={(e) => e.stopPropagation()}>{profileName(s.profile, s.profile_name)}</Link><span className="sub">Nº {s.id}</span></td>
              <td><ScanStatus s={s.status} /></td>
              <td className="num">{s.summary?.findings ?? '—'}</td>
              <td className="small">{fmtDate(s.started_at ?? s.created_at)}</td>
              <td className="small">{fmtDur(scanDuration(s))}</td>
              <td onClick={(e) => e.stopPropagation()}>
                <div className="row end" style={{ flexWrap: 'nowrap' }}>
                  {['completed', 'stopped'].includes(s.status) && <Link className="btn sm" to={`/resultados?analisis=${s.id}`}>Resultados</Link>}
                  {canWrite && !['queued', 'running'].includes(s.status) && <button className="btn sm quiet" onClick={() => setDel(s)} aria-label={`Eliminar el análisis ${s.id}`}>Eliminar</button>}
                </div>
              </td>
            </tr>
          ))}</tbody>
        </table>
      </div>
      {del && (
        <Confirm title="¿Eliminar este análisis?" danger confirmLabel="Eliminar análisis" onCancel={() => setDel(null)}
          onConfirm={async () => {
            try { await api.del(`/api/scans/${del.id}`); toast('Análisis eliminado'); reload() } catch (e) { toast(errorText(e), 'bad') } finally { setDel(null) }
          }}>
          <p>Se borran sus resultados, evidencias e informes ({profileName(del.profile, del.profile_name)}, {fmtDate(del.created_at)}).</p>
        </Confirm>
      )}
    </>
  )
}

// ------------------------------------------------------------------ scopes & authorization
const lines = (s: string) => s.split(/[\n,]/).map((x) => x.trim()).filter(Boolean)

function Scopes({ id, canWrite }: { id: number; canWrite: boolean }) {
  const list = useAsync(() => api.get<Scope[]>(`/api/projects/${id}/scopes`), [id])
  const stmt = useAsync(() => api.get<{ statement: string }>('/api/authorization-statement'), [])
  const [adding, setAdding] = useState(false)
  const [authFor, setAuthFor] = useState<Scope | null>(null)
  const [del, setDel] = useState<Scope | null>(null)
  const toast = useToast()
  return (
    <div className="stack">
      <div className="row between">
        <p className="muted" style={{ maxWidth: '70ch' }}>Solo se analizan las direcciones registradas aquí, y solo cuando consta la autorización del titular. Cada petición se comprueba contra esta lista.</p>
        {canWrite && <button className="btn" onClick={() => setAdding(true)}><IPlus size={18} />Añadir direcciones</button>}
      </div>
      <ErrorNotice error={list.error} />
      {list.data?.length === 0 && (
        <div className="panel"><Empty title="No hay direcciones registradas"
          action={canWrite ? <button className="btn primary" onClick={() => setAdding(true)}>Añadir direcciones</button> : undefined}>
          Añade las webs, APIs o servidores que tienes permiso para analizar.</Empty></div>
      )}
      {list.data && list.data.length > 0 && (
        <div className="panel">
          {list.data.map((s, i) => (
            <div key={s.id} className="panel-pad" style={{ borderTop: i ? '1px solid var(--line)' : undefined }}>
              <div className="row between" style={{ alignItems: 'flex-start' }}>
                <div className="stack-sm" style={{ minWidth: 0 }}>
                  <h3>{s.name}</h3>
                  <div>{s.targets.map((t) => <span key={t} className="chip mono">{t}</span>)}</div>
                  {s.exclusions.length > 0 && <div className="small muted">Excluido: {s.exclusions.join(', ')}</div>}
                  <div className="small muted">Hasta {s.max_rps} peticiones por segundo{s.allowed_ports ? `; puertos ${s.allowed_ports.join(', ')}` : ''}{s.allow_private ? '; permite direcciones internas' : ''}{s.lab_mode ? '; laboratorio' : ''}.</div>
                </div>
                <div className="stack-sm" style={{ alignItems: 'flex-end' }}>
                  {s.authorization.valid
                    ? <Pill tone="ok"><ICheck size={14} />Autorizado</Pill>
                    : <Pill tone="warn">Falta la autorización</Pill>}
                  {s.authorization.valid && <span className="small muted" style={{ textAlign: 'right' }}>Ref. {s.authorization.reference}<br />{s.authorization.valid_until ? `Válida hasta ${fmtDate(s.authorization.valid_until, false)}` : `Registrada ${fmtDate(s.authorization.attested_at, false)}`}</span>}
                  <div className="row">
                    {canWrite && !s.authorization.valid && <button className="btn sm primary" onClick={() => setAuthFor(s)}>Registrar autorización</button>}
                    {canWrite && <button className="btn sm quiet" onClick={() => setDel(s)}>Eliminar</button>}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
      {adding && <AddScope projectId={id} onClose={() => setAdding(false)} onCreated={() => { setAdding(false); list.reload(); toast('Direcciones añadidas. Registra ahora la autorización.') }} />}
      {authFor && stmt.data && <AuthorizeDialog scope={authFor} statement={stmt.data.statement} onClose={() => setAuthFor(null)} onDone={() => { setAuthFor(null); list.reload(); toast('Autorización registrada') }} />}
      {del && (
        <Confirm title="¿Eliminar estas direcciones?" danger confirmLabel="Eliminar" onCancel={() => setDel(null)}
          onConfirm={async () => {
            try { await api.del(`/api/scopes/${del.id}`); toast('Direcciones eliminadas'); list.reload() } catch (e) { toast(errorText(e), 'bad') } finally { setDel(null) }
          }}>
          <p>«{del.name}» dejará de estar disponible para nuevos análisis.</p>
          <p className="small muted">Si ya se usó en algún análisis se conserva para mantener la trazabilidad y no se podrá eliminar.</p>
        </Confirm>
      )}
    </div>
  )
}

function AddScope({ projectId, onClose, onCreated }: { projectId: number; onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState({ name: '', targets: '', exclusions: '', allow_private: false, max_rps: 10, ports: '' })
  const [err, setErr] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)
  const [validation, setValidation] = useState<{ target: string; ok: boolean; error?: string; kind?: string }[] | null>(null)
  async function validate() {
    setErr(null)
    try { setValidation((await api.post<{ results: NonNullable<typeof validation> }>('/api/scopes/validate', { targets: lines(form.targets) })).results) } catch (x) { setErr(x) }
  }
  async function submit(e: FormEvent) {
    e.preventDefault()
    setErr(null); setBusy(true)
    try {
      await api.post(`/api/projects/${projectId}/scopes`, {
        name: form.name.trim(), targets: lines(form.targets), exclusions: lines(form.exclusions), allow_private: form.allow_private,
        max_rps: Number(form.max_rps), allowed_ports: form.ports ? lines(form.ports).map(Number) : null,
      })
      onCreated()
    } catch (x) { setErr(x) } finally { setBusy(false) }
  }
  const KIND: Record<string, string> = { host: 'servidor o dirección web', wildcard: 'dominio y subdominios', ip: 'IP', cidr: 'rango de IP' }
  return (
    <Dialog title="Añadir direcciones autorizadas" onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        <label className="field">Nombre<input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required maxLength={120} placeholder="Entorno de pruebas" /></label>
        <label className="field">Direcciones <span className="hint">Una por línea: dominio, *.dominio, URL, IP o rango CIDR.</span>
          <textarea className="code" value={form.targets} onChange={(e) => { setForm({ ...form, targets: e.target.value }); setValidation(null) }} required rows={4} placeholder={'staging.ejemplo.com\nhttps://api.ejemplo.com/v1'} /></label>
        {validation && (
          <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
            {validation.map((v) => <li key={v.target} style={{ color: v.ok ? 'var(--ok)' : 'var(--bad)' }}><span className="mono">{v.target}</span>: {v.ok ? `válida (${KIND[v.kind ?? ''] ?? v.kind})` : v.error}</li>)}
          </ul>
        )}
        <label className="field">Excluir <span className="hint">Opcional. Servidores o rutas (empiezan por /) que no deben tocarse.</span>
          <textarea className="code" value={form.exclusions} onChange={(e) => setForm({ ...form, exclusions: e.target.value })} rows={2} placeholder="/logout" /></label>
        <Disclosure summary="Más opciones">
          <div className="form-grid">
            <label className="field">Ritmo máximo <span className="hint">Peticiones por segundo.</span>
              <input type="number" min={0.5} max={100} step={0.5} value={form.max_rps} onChange={(e) => setForm({ ...form, max_rps: Number(e.target.value) })} /></label>
            <label className="field">Puertos permitidos <span className="hint">Opcional, separados por comas.</span>
              <input value={form.ports} onChange={(e) => setForm({ ...form, ports: e.target.value })} placeholder="443, 8443" /></label>
          </div>
          <label className="check" style={{ marginTop: 14 }}><input type="checkbox" checked={form.allow_private} onChange={(e) => setForm({ ...form, allow_private: e.target.checked })} />
            <span>Permitir direcciones internas de la red<span className="sub muted small" style={{ display: 'block' }}>Además debe estar habilitado en el servidor (VIGIA_ALLOW_PRIVATE_TARGETS).</span></span></label>
        </Disclosure>
        <Notice>Los servicios de terceros, los metadatos de la nube y los rangos reservados se rechazan siempre. Si cambias las direcciones después, habrá que registrar de nuevo la autorización.</Notice>
        <ErrorNotice error={err} />
        <div className="row end">
          <button type="button" className="btn" onClick={validate} disabled={!form.targets.trim()}>Comprobar direcciones</button>
          <button className="btn primary" disabled={busy}>{busy ? 'Guardando…' : 'Añadir'}</button>
        </div>
      </form>
    </Dialog>
  )
}

function AuthorizeDialog({ scope, statement, onClose, onDone }: { scope: Scope; statement: string; onClose: () => void; onDone: () => void }) {
  const [accept, setAccept] = useState(false)
  const [reference, setRef] = useState('')
  const [until, setUntil] = useState('')
  const [contact, setContact] = useState('')
  const [err, setErr] = useState<unknown>(null)
  async function submit(e: FormEvent) {
    e.preventDefault()
    try {
      await api.post(`/api/scopes/${scope.id}/authorize`, { accept: true, statement, reference, owner_contact: contact,
        valid_until: until ? new Date(until).toISOString() : null })
      onDone()
    } catch (x) { setErr(x) }
  }
  return (
    <Dialog title={`Autorización para «${scope.name}»`} onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        <div>{scope.targets.map((t) => <span key={t} className="chip mono">{t}</span>)}</div>
        <div className="notice" style={{ whiteSpace: 'pre-wrap' }}>{statement}</div>
        <label className="field">Referencia del permiso <span className="hint">Contrato, ticket, correo o documento donde el titular lo autoriza.</span>
          <input value={reference} onChange={(e) => setRef(e.target.value)} required minLength={3} maxLength={255} /></label>
        <div className="form-grid">
          <label className="field">Válida hasta <span className="hint">Opcional.</span><input type="datetime-local" value={until} onChange={(e) => setUntil(e.target.value)} /></label>
          <label className="field">Contacto del titular <span className="hint">Opcional.</span><input value={contact} onChange={(e) => setContact(e.target.value)} maxLength={255} /></label>
        </div>
        <label className="check"><input type="checkbox" checked={accept} onChange={(e) => setAccept(e.target.checked)} />
          <span>Acepto la declaración. Quedará registrada con mi usuario, la fecha y mi dirección IP.</span></label>
        <ErrorNotice error={err} />
        <div className="row end">
          <button type="button" className="btn" onClick={onClose}>Cancelar</button>
          <button className="btn primary" disabled={!accept || reference.trim().length < 3}>Registrar autorización</button>
        </div>
      </form>
    </Dialog>
  )
}

// ------------------------------------------------------------------ source code & API specifications
function Sources({ id, canWrite }: { id: number; canWrite: boolean }) {
  const list = useAsync(() => api.get<Source[]>(`/api/projects/${id}/sources`), [id])
  const [git, setGit] = useState('')
  const [ref, setRef] = useState('')
  const [err, setErr] = useState<unknown>(null)
  const [busy, setBusy] = useState('')
  const [del, setDel] = useState<Source | null>(null)
  const toast = useToast()
  async function upload(input: HTMLInputElement, kind: 'upload' | 'spec') {
    const file = input.files?.[0]
    if (!file) return
    setBusy(kind); setErr(null)
    const fd = new FormData()
    fd.append('file', file)
    try { await api.post(`/api/projects/${id}/sources/${kind}`, fd); list.reload(); toast(kind === 'spec' ? 'Especificación importada' : 'Código importado') }
    catch (x) { setErr(x) } finally { setBusy(''); input.value = '' }
  }
  async function clone(e: FormEvent) {
    e.preventDefault(); setBusy('git'); setErr(null)
    try { await api.post(`/api/projects/${id}/sources/git`, { url: git.trim(), ref: ref.trim() || null }); setGit(''); setRef(''); list.reload(); toast('Repositorio importado') }
    catch (x) { setErr(x) } finally { setBusy('') }
  }
  return (
    <div className="stack">
      <p className="muted" style={{ maxWidth: '72ch' }}>El código se lee sin ejecutarlo. Los archivos se comprueban antes de guardarse (rutas peligrosas, archivos comprimidos maliciosos y enlaces simbólicos).</p>
      {canWrite && (
        <div className="panel cols-3" style={{ gap: 0 }}>
          <div className="panel-pad stack-sm">
            <h3>Subir un ZIP</h3>
            <p className="small muted">Una copia del código del proyecto.</p>
            <input type="file" accept=".zip" aria-label="Archivo ZIP con el código" disabled={!!busy} onChange={(e) => upload(e.target, 'upload')} />
          </div>
          <form className="panel-pad stack-sm" onSubmit={clone} style={{ borderLeft: '1px solid var(--line)' }}>
            <h3>Clonar un repositorio</h3>
            <input placeholder="https://github.com/organizacion/repositorio" aria-label="Dirección HTTPS del repositorio" value={git} onChange={(e) => setGit(e.target.value)} required />
            <div className="row" style={{ flexWrap: 'nowrap' }}>
              <input placeholder="Rama o etiqueta (opcional)" aria-label="Rama o etiqueta" value={ref} onChange={(e) => setRef(e.target.value)} />
              <button className="btn" disabled={!!busy}>{busy === 'git' ? 'Clonando…' : 'Clonar'}</button>
            </div>
          </form>
          <div className="panel-pad stack-sm" style={{ borderLeft: '1px solid var(--line)' }}>
            <h3>Especificación de API</h3>
            <p className="small muted">OpenAPI o colección Postman, para descubrir todas las rutas.</p>
            <input type="file" accept=".json,.yaml,.yml" aria-label="Especificación OpenAPI o Postman" disabled={!!busy} onChange={(e) => upload(e.target, 'spec')} />
          </div>
        </div>
      )}
      {busy && busy !== 'git' && <div className="loading" role="status" style={{ padding: 0 }}><span className="progress indeterminate" style={{ width: 120 }}><div /></span>Comprobando e importando…</div>}
      <ErrorNotice error={err} />
      {list.data?.length === 0 ? <div className="panel"><Empty title="No hay código importado">Importa el código para revisar fallos, contraseñas escritas en el código y dependencias con problemas conocidos.</Empty></div> : list.data && (
        <div className="panel table-wrap">
          <table>
            <thead><tr><th>Origen</th><th>Tipo</th><th>Archivos</th><th>Tamaño</th><th>Importado</th><th><span className="sr-only">Acciones</span></th></tr></thead>
            <tbody>{list.data.map((s) => (
              <tr key={s.id}>
                <td className="break"><span className="mono">{s.origin}</span><span className="sub mono" title="Huella SHA-256">{s.sha256.slice(0, 16)}</span></td>
                <td>{SOURCE_KIND[s.kind] ?? s.kind}</td><td className="num">{s.files}</td>
                <td className="num">{s.size_bytes >= 1048576 ? `${(s.size_bytes / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(s.size_bytes / 1024))} KB`}</td>
                <td className="small">{fmtDate(s.created_at)}</td>
                <td>{canWrite && <button className="btn sm quiet" onClick={() => setDel(s)}>Eliminar</button>}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}
      {del && (
        <Confirm title="¿Eliminar el código importado?" danger confirmLabel="Eliminar" onCancel={() => setDel(null)}
          onConfirm={async () => {
            try { await api.del(`/api/sources/${del.id}`); toast('Código eliminado'); list.reload() } catch (e) { toast(errorText(e), 'bad') } finally { setDel(null) }
          }}>
          <p>Se borrará la copia de <span className="mono">{del.origin}</span>. Los resultados de análisis anteriores se conservan.</p>
        </Confirm>
      )}
    </div>
  )
}

// ------------------------------------------------------------------ test accounts
const CRED_TEMPLATES: Record<string, string> = {
  form: '{\n  "login_url": "https://app.ejemplo.com/login",\n  "username": "usuario-prueba",\n  "password": "…",\n  "verify_url": "https://app.ejemplo.com/cuenta"\n}',
  json: '{\n  "login_url": "https://api.ejemplo.com/auth/login",\n  "body": {"email": "qa@ejemplo.com", "password": "…"},\n  "token_path": "access_token",\n  "verify_url": "https://api.ejemplo.com/me"\n}',
  bearer: '{\n  "token": "…"\n}', header: '{\n  "name": "X-API-Key",\n  "value": "…"\n}',
  basic: '{\n  "username": "…",\n  "password": "…"\n}', cookie: '{\n  "cookie": "session=…"\n}',
}

function Credentials({ id, canWrite }: { id: number; canWrite: boolean }) {
  const list = useAsync(() => api.get<Credential[]>(`/api/projects/${id}/credentials`), [id])
  const [adding, setAdding] = useState(false)
  const [del, setDel] = useState<Credential | null>(null)
  const toast = useToast()
  return (
    <div className="stack">
      <div className="row between">
        <p className="muted" style={{ maxWidth: '70ch' }}>Con una cuenta de prueba se analizan también las zonas privadas. Con dos cuentas se comprueba si un usuario puede ver o modificar datos de otro. Se guardan cifradas.</p>
        {canWrite && <button className="btn" onClick={() => setAdding(true)}><IPlus size={18} />Añadir cuenta</button>}
      </div>
      <ErrorNotice error={list.error} />
      {list.data?.length === 0 ? <div className="panel"><Empty title="No hay cuentas de prueba">Usa solo cuentas creadas para la auditoría, nunca cuentas reales de usuarios.</Empty></div> : list.data && (
        <div className="panel table-wrap">
          <table>
            <thead><tr><th>Nombre</th><th>Tipo</th><th>Añadida</th><th><span className="sr-only">Acciones</span></th></tr></thead>
            <tbody>{list.data.map((c) => (
              <tr key={c.id}><td>{c.name}</td><td>{CRED_KIND[c.kind] ?? c.kind}</td><td className="small">{fmtDate(c.created_at)}</td>
                <td>{canWrite && <button className="btn sm quiet" onClick={() => setDel(c)}>Eliminar</button>}</td></tr>
            ))}</tbody>
          </table>
        </div>
      )}
      {adding && <AddCredential projectId={id} onClose={() => setAdding(false)} onCreated={() => { setAdding(false); list.reload(); toast('Cuenta de prueba guardada') }} />}
      {del && (
        <Confirm title="¿Eliminar la cuenta de prueba?" danger confirmLabel="Eliminar" onCancel={() => setDel(null)}
          onConfirm={async () => {
            try { await api.del(`/api/credentials/${del.id}`); toast('Cuenta eliminada'); list.reload() } catch (e) { toast(errorText(e), 'bad') } finally { setDel(null) }
          }}>
          <p>Se borran los datos cifrados de «{del.name}». Los análisis futuros no podrán usarla.</p>
        </Confirm>
      )}
    </div>
  )
}

function AddCredential({ projectId, onClose, onCreated }: { projectId: number; onClose: () => void; onCreated: () => void }) {
  const [name, setName] = useState('')
  const [kind, setKind] = useState('json')
  const [role, setRole] = useState('user')
  const [data, setData] = useState(CRED_TEMPLATES.json)
  const [err, setErr] = useState<unknown>(null)
  async function submit(e: FormEvent) {
    e.preventDefault(); setErr(null)
    let parsed: unknown
    try { parsed = JSON.parse(data) } catch { setErr(new Error('Los datos no son un JSON válido. Revisa comillas y comas.')); return }
    try { await api.post(`/api/projects/${projectId}/credentials`, { name, kind, role, data: parsed }); onCreated() } catch (x) { setErr(x) }
  }
  return (
    <Dialog title="Añadir cuenta de prueba" onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        <div className="form-grid">
          <label className="field">Nombre <span className="hint">Letras, números, punto o guion.</span>
            <input value={name} onChange={(e) => setName(e.target.value)} required pattern="[\w.\-]+" maxLength={64} placeholder="usuario-a" /></label>
          <label className="field">Permisos de la cuenta
            <select value={role} onChange={(e) => setRole(e.target.value)}><option value="user">Usuario normal</option><option value="admin">Administrador</option></select></label>
        </div>
        <label className="field">Cómo inicia sesión
          <select value={kind} onChange={(e) => { setKind(e.target.value); setData(CRED_TEMPLATES[e.target.value]) }}>
            {Object.keys(CRED_TEMPLATES).map((k) => <option key={k} value={k}>{CRED_KIND[k]}</option>)}</select></label>
        <label className="field">Datos <span className="hint">Completa la plantilla. Se cifran al guardarse y no vuelven a mostrarse.</span>
          <textarea className="code" rows={7} value={data} onChange={(e) => setData(e.target.value)} spellCheck={false} /></label>
        <ErrorNotice error={err} />
        <div className="row end"><button type="button" className="btn" onClick={onClose}>Cancelar</button><button className="btn primary">Guardar cuenta</button></div>
      </form>
    </Dialog>
  )
}

// ------------------------------------------------------------------ members
function Members({ id, owner }: { id: number; owner: boolean }) {
  const list = useAsync(() => api.get<{ user_id: number; username: string; role: string }[]>(`/api/projects/${id}/members`), [id])
  const [username, setU] = useState('')
  const [role, setRole] = useState('viewer')
  const [err, setErr] = useState<unknown>(null)
  const toast = useToast()
  async function add(e: FormEvent) {
    e.preventDefault(); setErr(null)
    try { await api.post(`/api/projects/${id}/members`, { username: username.trim(), role }); setU(''); list.reload(); toast('Miembro añadido') } catch (x) { setErr(x) }
  }
  async function remove(uid: number, name: string) {
    try { await api.del(`/api/projects/${id}/members/${uid}`); list.reload(); toast(`${name} ya no es miembro`) } catch (x) { toast(errorText(x), 'bad') }
  }
  return (
    <div className="cols">
      <div className="panel table-wrap">
        {list.error ? <div className="panel-pad"><ErrorNotice error={list.error} /></div> : (
          <table>
            <thead><tr><th>Usuario</th><th>Papel</th><th><span className="sr-only">Acciones</span></th></tr></thead>
            <tbody>{list.data?.map((m) => (
              <tr key={m.user_id}><td>{m.username}</td><td>{MEMBER_ROLE[m.role] ?? m.role}</td>
                <td>{owner && <button className="btn sm quiet" onClick={() => remove(m.user_id, m.username)}>Quitar</button>}</td></tr>
            ))}</tbody>
          </table>
        )}
      </div>
      {owner && (
        <form className="panel panel-pad stack" onSubmit={add}>
          <h3>Añadir miembro</h3>
          <label className="field">Usuario<input value={username} onChange={(e) => setU(e.target.value)} required /></label>
          <label className="field">Papel
            <select value={role} onChange={(e) => setRole(e.target.value)}>
              <option value="viewer">Lector: consulta resultados</option><option value="analyst">Analista: lanza análisis y gestiona datos</option>
              <option value="owner">Propietario: además gestiona miembros</option></select></label>
          <ErrorNotice error={err} />
          <div><button className="btn primary">Añadir</button></div>
        </form>
      )}
    </div>
  )
}
