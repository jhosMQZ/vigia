import { useState, type FormEvent } from 'react'
import { ApiError, api } from '../api'
import { useAuth } from '../auth'
import { Logo } from '../components/Icons'
import { Notice, errorText, useTitle } from '../components/ui'
import type { User } from '../types'

export default function Login() {
  const { setUser } = useAuth()
  const [username, setU] = useState('')
  const [password, setP] = useState('')
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)
  useTitle('Iniciar sesión')

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const r = await api.post<{ user: User }>('/api/auth/login', { username, password })
      setUser(r.user)
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
      setP('')
    }
  }

  return (
    <div className="login">
      <section className="login-aside">
        <div className="brand" style={{ padding: 0 }}><Logo size={32} /><div>Vigía<span>Seguridad de aplicaciones</span></div></div>
        <div>
          <h1>Encuentra los problemas de seguridad antes que otros.</h1>
          <p>Analiza tus webs, APIs y código con autorización registrada, sin exponer tu conexión y con resultados explicados en lenguaje claro.</p>
        </div>
        <p className="small">Uso exclusivo sobre sistemas propios o con autorización expresa del titular. Todas las acciones quedan registradas.</p>
      </section>
      <form className="login-form" onSubmit={submit} autoComplete="on" aria-labelledby="login-title">
        <div>
          <h2 id="login-title">Iniciar sesión</h2>
          <p className="muted" style={{ marginTop: 6 }}>Usa la cuenta que te ha dado la persona que administra Vigía.</p>
        </div>
        <label className="field">Usuario
          <input value={username} onChange={(e) => setU(e.target.value)} autoComplete="username" required maxLength={64} autoFocus />
        </label>
        <label className="field">Contraseña
          <input type="password" value={password} onChange={(e) => setP(e.target.value)} autoComplete="current-password" required maxLength={256} />
        </label>
        {!!error && <Notice tone="bad">{error instanceof ApiError && error.status === 401 ? (error.message.endsWith('.') ? error.message : error.message + '.') : errorText(error)}</Notice>}
        <button className="btn primary" disabled={busy} style={{ height: 42 }}>{busy ? 'Entrando…' : 'Entrar'}</button>
      </form>
    </div>
  )
}
