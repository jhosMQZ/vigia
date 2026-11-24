import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { api } from '../api'
import { protectionTone, useProtection } from '../auth'
import { IApi, ICode, IGlobe, IServer } from '../components/Icons'
import { ChoiceGroup, Disclosure, Empty, ErrorNotice, Loading, Notice, PageHead, useAsync, useTitle, useToast } from '../components/ui'
import { ANALYSIS_KIND, CRED_KIND, INTENSITY, PROFILE_PLAIN, SOURCE_KIND, profileName } from '../copy'
import type { Credential, Profile, Project, Scan, Scope, Source } from '../types'

type Kind = keyof typeof ANALYSIS_KIND
const KIND_ICON: Record<Kind, ReactNode> = { web: <IGlobe size={22} />, code: <ICode size={22} />, api: <IApi size={22} />, infra: <IServer size={22} /> }
const KIND_PROFILES: Record<Kind, string[]> = { web: ['quick', 'standard', 'deep', 'full'], code: ['code'], api: ['api'], infra: ['infra'] }
const STEPS = ['Proyecto', 'Qué analizar', 'Objetivo', 'Profundidad', 'Revisar']

const EMPTY_CFG = { max_duration_min: '', rps: '', concurrency: '', crawl_depth: '', crawl_max_pages: '', port_set: '',
  extra_exclusions: '', include_paths: '', openapi_url: '', stop_on_first_critical: false, max_error_ratio: '0.3',
  window_on: false, start_hour: 22, end_hour: 6 }
const lines = (s: string) => s.split(/[\n,]/).map((x) => x.trim()).filter(Boolean)

export default function NewScan() {
  const [params] = useSearchParams()
  const nav = useNavigate()
  const toast = useToast()
  const { status: protection } = useProtection()
  const projects = useAsync(() => api.get<Project[]>('/api/projects'), [])
  const profiles = useAsync(() => api.get<Profile[]>('/api/profiles'), [])
  const [step, setStep] = useState(0)
  const [pid, setPid] = useState<number | null>(Number(params.get('proyecto')) || null)
  const [kind, setKind] = useState<Kind | null>(null)
  const [scopeId, setScopeId] = useState<number | null>(null)
  const [sourceId, setSourceId] = useState<number | null>(null)
  const [profile, setProfile] = useState('standard')
  const [creds, setCreds] = useState<number[]>([])
  const [specs, setSpecs] = useState<number[]>([])
  const [cfg, setCfg] = useState(EMPTY_CFG)
  const [err, setErr] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)

  const writable = useMemo(() => projects.data?.filter((p) => p.role !== 'viewer') ?? [], [projects.data])
  useEffect(() => { if (pid && params.get('proyecto') && step === 0 && writable.some((p) => p.id === pid)) setStep(1) },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [writable])
  const scopes = useAsync(() => (pid ? api.get<Scope[]>(`/api/projects/${pid}/scopes`) : Promise.resolve([])), [pid])
  const sources = useAsync(() => (pid ? api.get<Source[]>(`/api/projects/${pid}/sources`) : Promise.resolve([])), [pid])
  const credentials = useAsync(() => (pid ? api.get<Credential[]>(`/api/projects/${pid}/credentials`) : Promise.resolve([])), [pid])
  const code = sources.data?.filter((s) => ['zip', 'git', 'path'].includes(s.kind)) ?? []
  const apiSpecs = sources.data?.filter((s) => ['openapi', 'postman'].includes(s.kind)) ?? []
  const project = writable.find((p) => p.id === pid)
  const scope = scopes.data?.find((s) => s.id === scopeId)
  const source = code.find((s) => s.id === sourceId)
  const prof = profiles.data?.find((p) => p.key === profile)
  useTitle('Nuevo análisis')

  function chooseProject(id: number) { setPid(id); setScopeId(null); setSourceId(null); setCreds([]); setSpecs([]) }
  function chooseKind(k: Kind) { setKind(k); setProfile(k === 'web' ? 'standard' : KIND_PROFILES[k][0]); if (k === 'code') setScopeId(null); else if (k !== 'web') setSourceId(null) }

  const ready = [
    !!pid,
    !!kind,
    kind === 'code' ? !!sourceId : !!scopeId,
    !!profile && (profile !== 'full' || !!scopeId || !!sourceId),
    true,
  ]
  const next = () => { setErr(null); if (ready[step]) setStep((s) => Math.min(s + 1, STEPS.length - 1)) }
  const back = () => { setErr(null); setStep((s) => Math.max(s - 1, 0)) }

  async function start() {
    setErr(null)
    const badSeeds = lines(cfg.include_paths).filter((p) => !p.startsWith('/'))
    if (badSeeds.length) { setErr(new Error(`Las rutas adicionales deben empezar por / (por ejemplo /admin). Revisa: ${badSeeds.join(', ')}`)); return }
    const num = (v: string) => (v === '' ? undefined : Number(v))
    const config: Record<string, unknown> = {
      max_duration_min: num(cfg.max_duration_min), rps: num(cfg.rps), concurrency: num(cfg.concurrency), crawl_depth: num(cfg.crawl_depth),
      crawl_max_pages: num(cfg.crawl_max_pages), port_set: cfg.port_set || undefined, extra_exclusions: lines(cfg.extra_exclusions),
      include_paths: lines(cfg.include_paths), openapi_url: cfg.openapi_url.trim() || undefined, credential_ids: kind === 'code' ? [] : creds,
      spec_source_ids: kind === 'code' ? [] : specs,
      stop: { stop_on_first_critical: cfg.stop_on_first_critical, max_error_ratio: Number(cfg.max_error_ratio) },
      window: cfg.window_on ? { start_hour: Number(cfg.start_hour), end_hour: Number(cfg.end_hour) } : undefined,
    }
    Object.keys(config).forEach((k) => config[k] === undefined && delete config[k])
    setBusy(true)
    try {
      const s = await api.post<Scan>(`/api/projects/${pid}/scans`, { profile, scope_id: kind === 'code' ? null : scopeId,
        source_id: kind === 'code' || profile === 'full' ? sourceId : null, config })
      toast('Análisis iniciado')
      nav(`/analisis/${s.id}`)
    } catch (x) { setErr(x) } finally { setBusy(false) }
  }

  if (projects.error) return <div className="page"><ErrorNotice error={projects.error} /></div>
  if (!projects.data || !profiles.data) return <div className="page"><Loading /></div>
  if (writable.length === 0) return (
    <div className="page">
      <PageHead title="Nuevo análisis" />
      <div className="panel"><Empty title="Primero necesitas un proyecto" action={<Link className="btn primary" to="/proyectos?crear=1">Crear proyecto</Link>}>
        Los análisis se guardan dentro de un proyecto, junto con las direcciones autorizadas y el código.</Empty></div>
    </div>
  )

  const set = (k: keyof typeof cfg) => (e: { target: { value: string } }) => setCfg({ ...cfg, [k]: e.target.value })
  const changed = Object.entries(cfg).filter(([k, v]) => v !== (EMPTY_CFG as Record<string, unknown>)[k]).length
  return (
    <div className="page" style={{ maxWidth: 920 }}>
      <PageHead title="Nuevo análisis" intro="Elige qué revisar y con qué profundidad. Nada se inicia hasta que confirmes en el último paso." />
      <ol className="steps" aria-label="Pasos">
        {STEPS.map((s, i) => (
          <li key={s} className={i < step ? 'done' : i === step ? 'current' : ''} aria-current={i === step ? 'step' : undefined}>
            <b>{i + 1}</b><span className="lbl">{s}</span>
          </li>
        ))}
      </ol>

      <section className="panel panel-pad stack" aria-labelledby="step-title" style={{ gap: 18 }}>
        {step === 0 && <>
          <h2 id="step-title">¿En qué proyecto?</h2>
          <ChoiceGroup label="Proyecto" value={pid} onChange={chooseProject} columns={writable.length > 3 ? 2 : 1}
            options={writable.map((p) => ({ key: p.id, title: p.name, text: p.description || undefined }))} />
        </>}

        {step === 1 && <>
          <h2 id="step-title">¿Qué quieres analizar?</h2>
          <ChoiceGroup label="Tipo de análisis" value={kind} onChange={chooseKind} columns={2}
            options={(Object.keys(ANALYSIS_KIND) as Kind[]).map((k) => ({ key: k, title: ANALYSIS_KIND[k].title, text: ANALYSIS_KIND[k].text, icon: KIND_ICON[k] }))} />
        </>}

        {step === 2 && kind === 'code' && <>
          <h2 id="step-title">¿Qué código?</h2>
          {sources.loading ? <Loading /> : code.length === 0 ? (
            <Empty title="Este proyecto no tiene código importado" action={<Link className="btn" to={`/proyectos/${pid}?tab=codigo`}>Importar código</Link>}>
              Sube un ZIP o clona un repositorio desde el proyecto.</Empty>
          ) : (
            <ChoiceGroup label="Código fuente" value={sourceId} onChange={setSourceId}
              options={code.map((s) => ({ key: s.id, title: s.origin, text: `${SOURCE_KIND[s.kind] ?? s.kind}, ${s.files} archivos` }))} />
          )}
        </>}

        {step === 2 && kind !== 'code' && <>
          <h2 id="step-title">¿Sobre qué direcciones?</h2>
          <p className="muted">Solo puedes elegir direcciones con la autorización del titular registrada.</p>
          {scopes.loading ? <Loading /> : (scopes.data?.length ?? 0) === 0 ? (
            <Empty title="Este proyecto no tiene direcciones registradas" action={<Link className="btn" to={`/proyectos/${pid}?tab=alcance`}>Añadir direcciones</Link>}>
              Registra las webs, APIs o servidores que tienes permiso para analizar.</Empty>
          ) : (
            <ChoiceGroup label="Direcciones autorizadas" value={scopeId} onChange={setScopeId}
              options={scopes.data!.map((s) => ({ key: s.id, title: s.name, disabled: !s.authorization.valid,
                text: s.authorization.valid ? s.targets.join(', ') : <>Falta la autorización. <Link to={`/proyectos/${pid}?tab=alcance`}>Registrarla</Link></> }))} />
          )}
          {kind === 'api' && apiSpecs.length > 0 && (
            <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }}>
              <legend className="field" style={{ marginBottom: 8 }}>Especificaciones de la API <span className="hint">Ayudan a encontrar todas las rutas.</span></legend>
              {apiSpecs.map((s) => (
                <label key={s.id} className="check"><input type="checkbox" checked={specs.includes(s.id)} onChange={(e) => setSpecs(e.target.checked ? [...specs, s.id] : specs.filter((x) => x !== s.id))} />
                  <span><span className="mono">{s.origin}</span> <span className="muted small">({SOURCE_KIND[s.kind] ?? s.kind})</span></span></label>
              ))}
            </fieldset>
          )}
          {(credentials.data?.length ?? 0) > 0 && (
            <fieldset className="stack-sm" style={{ border: 0, padding: 0, margin: 0 }}>
              <legend className="field" style={{ marginBottom: 8 }}>Cuentas de prueba <span className="hint">Opcional, hasta cuatro. Con dos se comprueba si un usuario accede a datos de otro.</span></legend>
              {credentials.data!.map((c) => (
                <label key={c.id} className="check"><input type="checkbox" checked={creds.includes(c.id)} disabled={!creds.includes(c.id) && creds.length >= 4}
                  onChange={(e) => setCreds(e.target.checked ? [...creds, c.id] : creds.filter((x) => x !== c.id))} />
                  <span>{c.name} <span className="muted small">({CRED_KIND[c.kind] ?? c.kind})</span></span></label>
              ))}
            </fieldset>
          )}
        </>}

        {step === 3 && kind && <>
          <h2 id="step-title">¿Con qué profundidad?</h2>
          <ChoiceGroup label="Profundidad" value={profile} onChange={setProfile}
            options={KIND_PROFILES[kind].map((k) => {
              const p = profiles.data!.find((x) => x.key === k)
              return { key: k, title: PROFILE_PLAIN[k]?.name ?? p?.name ?? k, text: PROFILE_PLAIN[k]?.text ?? p?.description,
                extra: p && <span className="small muted" style={{ display: 'block', marginTop: 6 }}>Hasta {p.max_duration_min} min. Intensidad {(INTENSITY[p.intensity] ?? p.intensity).toLowerCase()}. Perfil técnico: {p.name}.</span> }
            })} />
          {profile === 'full' && (
            <label className="field">Código fuente para relacionar con la web <span className="hint">Opcional.</span>
              <select value={sourceId ?? ''} onChange={(e) => setSourceId(e.target.value ? Number(e.target.value) : null)}>
                <option value="">Sin código</option>{code.map((s) => <option key={s.id} value={s.id}>{s.origin}</option>)}</select></label>
          )}
          <Disclosure summary={`Ajustes avanzados${changed ? ` (${changed} cambiados)` : ''}`}>
            <div className="stack">
              <p className="small muted">Por defecto se usan los valores del perfil. Los valores que superen el máximo del perfil se reducen automáticamente.</p>
              <div className="form-grid">
                <label className="field">Duración máxima (minutos)<input type="number" min={1} max={720} placeholder={String(prof?.max_duration_min ?? '')} value={cfg.max_duration_min} onChange={set('max_duration_min')} /></label>
                {kind !== 'code' && <>
                  <label className="field">Peticiones por segundo<input type="number" min={0.5} max={100} step={0.5} placeholder={String(prof?.rps ?? '')} value={cfg.rps} onChange={set('rps')} /></label>
                  <label className="field">Peticiones simultáneas<input type="number" min={1} max={32} placeholder={String(prof?.concurrency ?? '')} value={cfg.concurrency} onChange={set('concurrency')} /></label>
                  <label className="field">Niveles de enlaces a seguir<input type="number" min={0} max={10} placeholder={String(prof?.crawl_depth ?? '')} value={cfg.crawl_depth} onChange={set('crawl_depth')} /></label>
                  <label className="field">Páginas máximas<input type="number" min={0} max={10000} placeholder={String(prof?.crawl_max_pages ?? '')} value={cfg.crawl_max_pages} onChange={set('crawl_max_pages')} /></label>
                  <label className="field">Puertos a revisar
                    <select value={cfg.port_set} onChange={set('port_set')}>
                      <option value="">Los del perfil</option><option value="none">Ninguno</option><option value="web">Solo web</option>
                      <option value="top">Los más habituales</option><option value="extended">Ampliado</option></select></label>
                  <label className="field">Detener si fallan más del… <span className="hint">Proporción de respuestas de error del servidor (0,05 a 1).</span>
                    <input type="number" min={0.05} max={1} step={0.05} value={cfg.max_error_ratio} onChange={set('max_error_ratio')} /></label>
                  <label className="field">Dirección de la especificación OpenAPI <span className="hint">Debe estar dentro de las direcciones autorizadas.</span>
                    <input value={cfg.openapi_url} onChange={set('openapi_url')} placeholder="https://api.ejemplo.com/openapi.json" /></label>
                  <label className="field">Excluir además <span className="hint">Servidores o rutas, uno por línea.</span>
                    <textarea className="code" rows={2} value={cfg.extra_exclusions} onChange={set('extra_exclusions')} /></label>
                  <label className="field">Rutas adicionales a visitar <span className="hint">Empiezan por /, una por línea.</span>
                    <textarea className="code" rows={2} placeholder={'/admin\n/api/v1/estado'} value={cfg.include_paths} onChange={set('include_paths')} /></label>
                </>}
              </div>
              {kind !== 'code' && <>
                <label className="check"><input type="checkbox" checked={cfg.stop_on_first_critical} onChange={(e) => setCfg({ ...cfg, stop_on_first_critical: e.target.checked })} />Detener al confirmar el primer problema crítico</label>
                <label className="check"><input type="checkbox" checked={cfg.window_on} onChange={(e) => setCfg({ ...cfg, window_on: e.target.checked })} />Analizar solo dentro de un horario</label>
                {cfg.window_on && (
                  <div className="row small">De las
                    <input type="number" min={0} max={23} aria-label="Hora de inicio" value={cfg.start_hour} onChange={(e) => setCfg({ ...cfg, start_hour: Number(e.target.value) })} style={{ width: 76 }} />
                    a las<input type="number" min={0} max={23} aria-label="Hora de fin" value={cfg.end_hour} onChange={(e) => setCfg({ ...cfg, end_hour: Number(e.target.value) })} style={{ width: 76 }} />h
                  </div>
                )}
              </>}
            </div>
          </Disclosure>
        </>}

        {step === 4 && kind && <>
          <h2 id="step-title">Revisa y empieza</h2>
          <dl className="kv">
            <dt>Proyecto</dt><dd>{project?.name}</dd>
            <dt>Qué se analiza</dt><dd>{ANALYSIS_KIND[kind].title}</dd>
            {scope && kind !== 'code' && <><dt>Direcciones</dt><dd>{scope.targets.map((t) => <span key={t} className="chip mono">{t}</span>)}</dd>
              <dt>Autorización</dt><dd>Ref. {scope.authorization.reference}</dd></>}
            {source && (kind === 'code' || profile === 'full') && <><dt>Código</dt><dd className="mono">{source.origin}</dd></>}
            <dt>Profundidad</dt><dd>{profileName(profile)}{prof && <span className="muted">, hasta {cfg.max_duration_min || prof.max_duration_min} min</span>}</dd>
            {creds.length > 0 && kind !== 'code' && <><dt>Cuentas de prueba</dt><dd>{credentials.data?.filter((c) => creds.includes(c.id)).map((c) => c.name).join(', ')}</dd></>}
            {changed > 0 && <><dt>Ajustes avanzados</dt><dd>{changed} {changed === 1 ? 'cambio' : 'cambios'} sobre el perfil</dd></>}
          </dl>
          {kind !== 'code' && <Notice>Las pruebas no son destructivas: no borran datos, no extraen información y no usan exploits. Aun así generan tráfico; usa preferiblemente un entorno de pruebas.</Notice>}
          {kind !== 'code' && protection && protection.protection.level === 'none' && (
            <Notice tone={protection.egress.require_proxy ? 'bad' : 'attn'} title="Tu conexión no está protegida">
              {protection.egress.require_proxy
                ? 'La configuración exige una salida protegida y no hay ninguna activa, así que el análisis no podrá empezar. '
                : 'El sitio analizado verá tu dirección IP. '}
              <Link to="/privacidad">Ver la protección de la conexión</Link>
            </Notice>
          )}
          {kind !== 'code' && protection && protectionTone(protection.protection.level) === 'warn' && (
            <Notice tone="attn">Protección parcial de la conexión: {protection.protection.limitations[0] ?? protection.protection.label} <Link to="/privacidad">Detalles</Link></Notice>
          )}
        </>}

        <ErrorNotice error={err} />
        <div className="row between" style={{ borderTop: '1px solid var(--line)', paddingTop: 16 }}>
          <button className="btn" onClick={back} disabled={step === 0}>Atrás</button>
          {step < STEPS.length - 1
            ? <button className="btn primary" onClick={next} disabled={!ready[step]}>Continuar</button>
            : <button className="btn primary" onClick={start} disabled={busy}>{busy ? 'Iniciando…' : 'Iniciar análisis'}</button>}
        </div>
      </section>
    </div>
  )
}

