import { useState, type FormEvent } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { api } from '../api'
import { useAuth } from '../auth'
import { IPlus } from '../components/Icons'
import { Dialog, Empty, ErrorNotice, Loading, PageHead, fmtDate, useAsync, useToast } from '../components/ui'
import { MEMBER_ROLE, actionable } from '../copy'
import type { Dashboard, Project } from '../types'

export default function Projects() {
  const { user } = useAuth()
  const [params, setParams] = useSearchParams()
  const list = useAsync(() => api.get<Project[]>('/api/projects'), [])
  const dash = useAsync(() => api.get<Dashboard>('/api/dashboard'), [])
  const creating = params.get('crear') === '1'
  const setCreating = (v: boolean) => setParams(v ? { crear: '1' } : {}, { replace: true })
  const nav = useNavigate()
  const canCreate = user?.role !== 'viewer'
  const stats = new Map(dash.data?.per_project.map((p) => [p.project_id, p]) ?? [])

  return (
    <div className="page">
      <PageHead title="Proyectos" intro="Cada proyecto reúne lo que estás autorizado a analizar, el código, las cuentas de prueba y los resultados."
        actions={canCreate && <button className="btn primary" onClick={() => setCreating(true)}><IPlus size={18} />Crear proyecto</button>} />
      <ErrorNotice error={list.error} />
      {list.loading && !list.data && <Loading />}
      {list.data && list.data.length === 0 && (
        <div className="panel">
          <Empty title="Todavía no hay proyectos"
            action={canCreate ? <button className="btn primary" onClick={() => setCreating(true)}>Crear el primer proyecto</button> : undefined}>
            {canCreate ? 'Crea uno para registrar qué sitios o qué código vas a analizar.' : 'Cuando alguien te añada a un proyecto aparecerá aquí.'}
          </Empty>
        </div>
      )}
      {list.data && list.data.length > 0 && (
        <div className="panel table-wrap">
          <table>
            <thead><tr><th>Proyecto</th><th>Problemas pendientes</th><th>Tu papel</th><th>Creado</th></tr></thead>
            <tbody>{list.data.map((p) => {
              const st = stats.get(p.id)
              const total = st ? actionable(st.open) : null
              const urgent = st ? (st.open.critical ?? 0) + (st.open.high ?? 0) : 0
              return (
                <tr key={p.id} className="rowlink" onClick={() => nav(`/proyectos/${p.id}`)}>
                  <td><Link to={`/proyectos/${p.id}`} onClick={(e) => e.stopPropagation()}><b>{p.name}</b></Link>
                    <span className="sub">{p.description || 'Sin descripción'}</span></td>
                  <td className="num">{total == null ? <span className="muted">Sin análisis terminados</span>
                    : total === 0 ? 'Ninguno' : <>{total}{urgent > 0 && <span className="sub">{urgent} críticos o graves</span>}</>}</td>
                  <td>{MEMBER_ROLE[p.role ?? ''] ?? (user?.role === 'admin' ? 'Administración' : '—')}</td>
                  <td className="muted small">{fmtDate(p.created_at, false)}</td>
                </tr>
              )
            })}</tbody>
          </table>
        </div>
      )}
      {creating && <CreateProject onClose={() => setCreating(false)} onCreated={(p) => nav(`/proyectos/${p.id}`)} />}
    </div>
  )
}

function CreateProject({ onClose, onCreated }: { onClose: () => void; onCreated: (p: Project) => void }) {
  const [name, setName] = useState('')
  const [description, setDesc] = useState('')
  const [err, setErr] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)
  const toast = useToast()
  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true); setErr(null)
    try {
      const p = await api.post<Project>('/api/projects', { name: name.trim(), description: description.trim() })
      toast(`Proyecto «${p.name}» creado`)
      onCreated(p)
    } catch (x) { setErr(x) } finally { setBusy(false) }
  }
  return (
    <Dialog title="Crear proyecto" onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        <label className="field">Nombre<input value={name} onChange={(e) => setName(e.target.value)} required maxLength={120} placeholder="Tienda online" /></label>
        <label className="field">Descripción <span className="hint">Opcional. Para qué sirve el sistema o quién es el responsable.</span>
          <textarea value={description} onChange={(e) => setDesc(e.target.value)} maxLength={4000} rows={3} /></label>
        <p className="small muted">Después podrás añadir las direcciones que estás autorizado a analizar, el código fuente y las cuentas de prueba.</p>
        <ErrorNotice error={err} />
        <div className="row end">
          <button type="button" className="btn" onClick={onClose}>Cancelar</button>
          <button className="btn primary" disabled={busy || !name.trim()}>{busy ? 'Creando…' : 'Crear proyecto'}</button>
        </div>
      </form>
    </Dialog>
  )
}
