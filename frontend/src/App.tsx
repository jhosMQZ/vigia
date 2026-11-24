import { useCallback, useEffect, useRef, useState } from 'react'
import { NavLink, Navigate, Route, Routes, useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { api } from './api'
import { AuthContext, ProtectionContext, protectionTone, useAuth, useProtection } from './auth'
import { IClose, IFolder, IHome, ILogout, IMenu, IMoon, IPlus, IResults, ISettings, IShield, ISun, Logo } from './components/Icons'
import { ROLE } from './copy'
import { getThemePref, setThemePref } from './theme'
import type { PrivacyStatus, User } from './types'
import Login from './pages/Login'
import Home from './pages/Home'
import Projects from './pages/Projects'
import ProjectDetail from './pages/ProjectDetail'
import NewScan from './pages/NewScan'
import ScanProgress from './pages/ScanProgress'
import Results from './pages/Results'
import Privacy from './pages/Privacy'
import Settings from './pages/Settings'

export default function App() {
  const [user, setUser] = useState<User | null>(null)
  const [ready, setReady] = useState(false)
  const nav = useNavigate()

  useEffect(() => {
    api.get<{ user: User }>('/api/auth/me').then((r) => setUser(r.user)).catch(() => setUser(null)).finally(() => setReady(true))
    const onUnauth = () => setUser(null)
    window.addEventListener('vigia:unauthorized', onUnauth)
    return () => window.removeEventListener('vigia:unauthorized', onUnauth)
  }, [])

  const logout = useCallback(async () => {
    try { await api.post('/api/auth/logout') } catch { /* the session is dropped locally anyway */ } finally { setUser(null); nav('/') }
  }, [nav])

  if (!ready) return null
  return (
    <AuthContext.Provider value={{ user, setUser, logout }}>
      {user ? <Shell /> : <Login />}
    </AuthContext.Provider>
  )
}

function Shell() {
  const { user } = useAuth()
  const [status, setStatus] = useState<PrivacyStatus | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [tick, setTick] = useState(0)
  const reload = useCallback(() => setTick((t) => t + 1), [])
  useEffect(() => {
    let alive = true
    api.get<PrivacyStatus>('/api/privacy').then((d) => { if (alive) { setStatus(d); setError(null) } }).catch((e) => { if (alive) setError(e) })
    const t = window.setTimeout(reload, 5 * 60_000)
    return () => { alive = false; clearTimeout(t) }
  }, [tick, reload])

  const [open, setOpen] = useState(false)
  const loc = useLocation()
  const main = useRef<HTMLElement>(null)
  const first = useRef(true)
  // a new page: close the mobile menu and move focus to the content so screen readers announce it
  useEffect(() => {
    setOpen(false)
    if (first.current) { first.current = false; return }
    main.current?.focus({ preventScroll: true })
    window.scrollTo(0, 0)
  }, [loc.pathname])

  const canWrite = user?.role !== 'viewer'
  return (
    <ProtectionContext.Provider value={{ status, error, reload }}>
      <a className="skip" href="#main">Saltar al contenido</a>
      <header className="topbar">
        <button className="icon-btn" onClick={() => setOpen(true)} aria-label="Abrir menú" aria-expanded={open} aria-controls="rail"><IMenu /></button>
        <span className="row" style={{ gap: 8, fontWeight: 600 }}><Logo size={24} />Vigía</span>
        <ProtectionDot />
      </header>
      <div className="shell">
        <aside id="rail" className={`rail ${open ? 'open' : ''}`} aria-label="Navegación principal">
          <div className="row between" style={{ alignItems: 'flex-start', flexWrap: 'nowrap' }}>
            <div className="brand"><Logo /><div>Vigía<span>Seguridad de aplicaciones</span></div></div>
            {open && <button className="icon-btn" onClick={() => setOpen(false)} aria-label="Cerrar menú"><IClose /></button>}
          </div>
          <nav className="nav">
            <NavLink to="/" end><IHome />Inicio</NavLink>
            <NavLink to="/proyectos"><IFolder />Proyectos</NavLink>
            {canWrite && <NavLink to="/analisis/nuevo"><IPlus />Nuevo análisis</NavLink>}
            <NavLink to="/resultados"><IResults />Resultados</NavLink>
            <NavLink to="/privacidad"><IShield />Privacidad</NavLink>
            <NavLink to="/configuracion"><ISettings />Configuración</NavLink>
          </nav>
          <div className="rail-foot">
            <ProtectionCard />
            <UserBox />
          </div>
        </aside>
        {open && <div className="scrim" onClick={() => setOpen(false)} aria-hidden />}
        <main id="main" className="content" ref={main} tabIndex={-1}>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/proyectos" element={<Projects />} />
            <Route path="/proyectos/:id" element={<ProjectDetail />} />
            <Route path="/analisis/nuevo" element={canWrite ? <NewScan /> : <Navigate to="/" replace />} />
            <Route path="/analisis/:id" element={<ScanProgress />} />
            <Route path="/resultados" element={<Results />} />
            <Route path="/privacidad" element={<Privacy />} />
            <Route path="/configuracion" element={<Settings />} />
            {/* addresses of the previous interface keep working */}
            <Route path="/projects" element={<Navigate to="/proyectos" replace />} />
            <Route path="/projects/:id" element={<Legacy to={(p) => `/proyectos/${p.id}`} />} />
            <Route path="/scan/new" element={<LegacyQuery to="/analisis/nuevo" map={{ project: 'proyecto' }} />} />
            <Route path="/scans/:id" element={<Legacy to={(p) => `/analisis/${p.id}`} />} />
            <Route path="/findings" element={<LegacyQuery to="/resultados" map={{ scan: 'analisis' }} />} />
            <Route path="/history" element={<Navigate to="/resultados?vista=comparar" replace />} />
            <Route path="/engines" element={<Navigate to="/configuracion?tab=motores" replace />} />
            <Route path="/privacy" element={<Navigate to="/privacidad" replace />} />
            <Route path="/admin" element={<Navigate to="/configuracion?tab=usuarios" replace />} />
            <Route path="/login" element={<Navigate to="/" replace />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </main>
      </div>
    </ProtectionContext.Provider>
  )
}

function Legacy({ to }: { to: (p: Record<string, string | undefined>) => string }) {
  return <Navigate to={to(useParams())} replace />
}
function LegacyQuery({ to, map }: { to: string; map: Record<string, string> }) {
  const [params] = useSearchParams()
  const q = new URLSearchParams()
  Object.entries(map).forEach(([a, b]) => { const v = params.get(a); if (v) q.set(b, v) })
  return <Navigate to={q.toString() ? `${to}?${q}` : to} replace />
}

function NotFound() {
  useEffect(() => { document.title = 'Página no encontrada · Vigía' }, [])
  return (
    <div className="page">
      <div className="panel empty">
        <h3>Esta página no existe</h3>
        <p>Puede que la dirección esté mal escrita o que el elemento se haya eliminado.</p>
        <NavLink className="btn" to="/">Ir al inicio</NavLink>
      </div>
    </div>
  )
}

const SHORT: Record<string, string> = {
  complete: 'Conexión protegida y verificada', partial: 'Protección parcial', weak: 'Protección débil', none: 'Sin protección de conexión',
}

function ProtectionDot() {
  const { status } = useProtection()
  const level = status?.protection.level
  return (
    <NavLink to="/privacidad" className="icon-btn" aria-label={`Privacidad: ${level ? SHORT[level] : 'comprobando'}`}>
      <span className={`dot ${protectionTone(level)}`} />
    </NavLink>
  )
}

function ProtectionCard() {
  const { status, error } = useProtection()
  const level = status?.protection.level
  const lim = status?.protection.limitations.length ?? 0
  return (
    <NavLink to="/privacidad" className="protect">
      <b><span className={`dot ${protectionTone(level)}`} />{level ? SHORT[level] : error ? 'Estado no disponible' : 'Comprobando…'}</b>
      {level === 'none' && 'Los sitios analizados verían tu dirección IP.'}
      {level && level !== 'none' && (lim ? `${lim} ${lim === 1 ? 'limitación conocida' : 'limitaciones conocidas'}. Ver detalles.` : 'Sin limitaciones conocidas.')}
    </NavLink>
  )
}

function UserBox() {
  const { user, logout } = useAuth()
  const [dark, setDark] = useState(document.documentElement.dataset.theme === 'dark')
  useEffect(() => {
    const obs = new MutationObserver(() => setDark(document.documentElement.dataset.theme === 'dark'))
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
    return () => obs.disconnect()
  }, [])
  const toggle = () => {
    const next = dark ? 'light' : 'dark'
    // a manual toggle that lands on the system preference goes back to following the system
    const sys = window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
    setThemePref(next === sys && getThemePref() !== 'system' ? 'system' : next)
  }
  if (!user) return null
  return (
    <div className="who">
      <div style={{ minWidth: 0 }}><b className="ellipsis">{user.username}</b>{ROLE[user.role] ?? user.role}</div>
      <div className="row" style={{ gap: 2, flexWrap: 'nowrap' }}>
        <button className="icon-btn" onClick={toggle} aria-label={dark ? 'Usar tema claro' : 'Usar tema oscuro'} title={dark ? 'Tema claro' : 'Tema oscuro'}>{dark ? <ISun size={18} /> : <IMoon size={18} />}</button>
        <button className="icon-btn" onClick={logout} aria-label="Cerrar sesión" title="Cerrar sesión"><ILogout size={18} /></button>
      </div>
    </div>
  )
}
