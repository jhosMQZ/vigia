// Plain-language vocabulary for the interface. Technical names stay available in "Detalles técnicos".
import type { Severity } from './types'

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export const SEV_NAME: Record<Severity, string> = {
  critical: 'Crítico', high: 'Grave', medium: 'Moderado', low: 'Leve', info: 'Informativo',
}

export const SEV_PLURAL: Record<Severity, string> = {
  critical: 'críticos', high: 'graves', medium: 'moderados', low: 'leves', info: 'informativos',
}
export const sevCount = (s: Severity, n: number) => `${n} ${n === 1 ? SEV_NAME[s].toLowerCase() : SEV_PLURAL[s]}`
/** Problems that need action (informative observations excluded). */
export const actionable = (c: Partial<Record<Severity, number>>) => (['critical', 'high', 'medium', 'low'] as Severity[]).reduce((a, s) => a + (c[s] ?? 0), 0)

export const SEV_MEANING: Record<Severity, string> = {
  critical: 'Requiere atención inmediata', high: 'Debe corregirse pronto',
  medium: 'Conviene corregirlo en la próxima planificación', low: 'Mejora recomendable', info: 'Informativo',
}

const SEV_ADJ: Record<Severity, [string, string]> = {
  critical: ['crítico', 'críticos'], high: ['grave', 'graves'], medium: ['moderado', 'moderados'],
  low: ['leve', 'leves'], info: ['informativo', 'informativos'],
}

/** "4 problemas críticos requieren atención inmediata", "1 problema grave debe corregirse pronto"… */
export function plainCount(sev: Severity, n: number): string {
  const [one, many] = SEV_ADJ[sev]
  if (n <= 0) return `Sin problemas ${many}`
  const verbs: Record<Severity, [string, string]> = {
    critical: ['requiere atención inmediata', 'requieren atención inmediata'],
    high: ['debe corregirse pronto', 'deben corregirse pronto'],
    medium: ['conviene corregirlo en la próxima planificación', 'conviene corregirlos en la próxima planificación'],
    low: ['es una mejora recomendable', 'son mejoras recomendables'],
    info: ['es informativo', 'son informativos'],
  }
  return n === 1 ? `1 problema ${one} ${verbs[sev][0]}` : `${n} problemas ${many} ${verbs[sev][1]}`
}

export const CONFIDENCE: Record<string, string> = {
  confirmed: 'Confirmado con evidencia', likely: 'Probable, conviene revisarlo', suspected: 'Indicio, requiere revisión',
  false_positive: 'Descartado',
}

export const REMEDIATION: Record<string, string> = {
  open: 'Pendiente', in_progress: 'En corrección', fixed: 'Corregido', accepted_risk: 'Riesgo aceptado',
  false_positive: 'Falso positivo',
}

export const SCAN_STATUS: Record<string, { label: string; tone: 'ok' | 'warn' | 'bad' | 'live' | '' }> = {
  queued: { label: 'En espera', tone: 'live' }, running: { label: 'En curso', tone: 'live' },
  completed: { label: 'Completado', tone: 'ok' }, failed: { label: 'No se pudo completar', tone: 'bad' },
  cancelled: { label: 'Cancelado', tone: '' }, stopped: { label: 'Detenido', tone: 'warn' },
}

export const STEP_STATUS: Record<string, string> = {
  running: 'En curso', done: 'Terminado', skipped: 'Omitido', failed: 'Con errores', stopped: 'Detenido',
}

// Scan phases/modules in plain words (technical module name kept as a tooltip).
export const MODULE_NAME: Record<string, string> = {
  auth: 'Inicio de sesión con las cuentas de prueba', recon: 'Reconocimiento del objetivo', crawler: 'Exploración del sitio',
  browser: 'Revisión en un navegador aislado', headers: 'Configuración de seguridad del sitio', exposure: 'Archivos expuestos',
  injection: 'Pruebas de manipulación de datos', api: 'Revisión de la interfaz de programación', infra: 'Servicios y puertos',
  frontend: 'Código que se ejecuta en el navegador', source: 'Lectura del código fuente', sast: 'Revisión del código fuente',
  secrets: 'Búsqueda de contraseñas en el código', sca: 'Dependencias con fallos conocidos', iac: 'Configuración de infraestructura',
  routes: 'Rutas del código', correlation: 'Correlación de resultados', reports: 'Preparación de informes',
}

export function moduleName(key: string): string {
  const base = key.replace(/^tool:/, '').split(':')[0]
  if (key.startsWith('tool:')) return `Motor ${base}`
  return MODULE_NAME[base] ?? base
}

export const ROLE: Record<string, string> = { admin: 'Administración', analyst: 'Analista', viewer: 'Solo lectura',
  owner: 'Propietario' }

export const ANALYSIS_KIND = {
  web: { title: 'Una web o aplicación', text: 'Revisa una dirección web autorizada: configuración, archivos expuestos y fallos habituales.' },
  code: { title: 'Código fuente', text: 'Lee el código importado sin ejecutarlo: fallos, contraseñas escritas en el código y dependencias.' },
  api: { title: 'Una interfaz de programación (API)', text: 'Comprueba autenticación, permisos entre usuarios y datos expuestos.' },
  infra: { title: 'Infraestructura autorizada', text: 'Servicios accesibles, puertos, certificados y bases de datos expuestas.' },
} as const

// Engine run inside one analysis
export const TOOL_STATUS: Record<string, { label: string; tone: 'ok' | 'warn' | 'bad' | '' }> = {
  ok: { label: 'Terminado', tone: 'ok' }, failed: { label: 'Con errores', tone: 'bad' }, timeout: { label: 'Superó el tiempo', tone: 'warn' },
  killed: { label: 'Detenido por límites', tone: 'warn' }, cancelled: { label: 'Cancelado', tone: '' }, error: { label: 'No se pudo ejecutar', tone: 'bad' },
  skipped: { label: 'No se usó', tone: '' },
}
// Engine installation state
export const ENGINE_STATUS: Record<string, { label: string; tone: 'ok' | 'warn' | 'bad' | '' }> = {
  available: { label: 'Disponible', tone: 'ok' }, missing: { label: 'No instalado', tone: '' }, blocked: { label: 'Bloqueado', tone: 'bad' },
  unconfigured: { label: 'Sin configurar', tone: 'warn' }, error: { label: 'Con errores', tone: 'bad' },
}

// Analysis depth in plain words; the technical profile name stays visible as secondary text.
export const PROFILE_PLAIN: Record<string, { name: string; text: string }> = {
  quick: { name: 'Rápido', text: 'Revisión ligera, sin pruebas intrusivas: configuración, archivos expuestos y código servido al navegador.' },
  standard: { name: 'Estándar', text: 'Explora el sitio y prueba las entradas de datos con valores inofensivos. Adecuado para la mayoría de casos.' },
  deep: { name: 'Profundo', text: 'La cobertura más amplia sin pruebas destructivas. Tarda más y genera más tráfico.' },
  full: { name: 'Completo: web y código', text: 'Análisis profundo de la web junto con el código fuente, relacionando ambos resultados.' },
  code: { name: 'Revisión de código', text: 'Lee el código sin ejecutarlo: fallos, contraseñas en el código, dependencias e infraestructura.' },
  api: { name: 'Revisión de API', text: 'Autenticación, permisos entre usuarios, datos expuestos y límites de uso.' },
  infra: { name: 'Revisión de infraestructura', text: 'Servicios accesibles, certificados, bases de datos y paneles expuestos.' },
}
export const profileName = (key: string, fallback?: string) => PROFILE_PLAIN[key]?.name ?? fallback ?? key

export const INTENSITY: Record<string, string> = { passive: 'Solo observación', light: 'Ligera', standard: 'Normal', deep: 'Exhaustiva' }

export const CRED_KIND: Record<string, string> = {
  form: 'Formulario de inicio de sesión', json: 'Inicio de sesión por API (JSON)', bearer: 'Token de acceso', header: 'Cabecera con clave',
  basic: 'Usuario y contraseña HTTP', cookie: 'Cookie de sesión',
}
export const MEMBER_ROLE: Record<string, string> = { viewer: 'Lector', analyst: 'Analista', owner: 'Propietario' }
export const SOURCE_KIND: Record<string, string> = { zip: 'Archivo ZIP', git: 'Repositorio git', path: 'Carpeta local', openapi: 'OpenAPI', postman: 'Colección Postman' }

// what is actually in force (resolved mode shown on the privacy page)
export const ISOLATION_ACTIVE: Record<string, string> = {
  appcontainer: 'Aislamiento de Windows (AppContainer)', external: 'Externo: contenedor o máquina virtual propia', detect: 'Solo detección (no bloquea)',
}
// the setting
export const ISOLATION_MODE: Record<string, string> = {
  auto: 'Automático: aislamiento del sistema si está disponible', appcontainer: 'Aislamiento del sistema obligatorio (AppContainer)',
  external: 'Aislamiento externo (contenedor o máquina virtual propia)', detect: 'Solo detección (no bloquea)',
}
