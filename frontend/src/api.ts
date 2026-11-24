// API client: same-origin cookies (HttpOnly session) + double-submit CSRF header on state-changing requests.
export class ApiError extends Error {
  status: number
  details: unknown
  constructor(status: number, message: string, details?: unknown) {
    super(message)
    this.status = status
    this.details = details
  }
}

function csrfToken(): string {
  const m = document.cookie.split('; ').find((c) => c.startsWith('vigia_csrf='))
  return m ? decodeURIComponent(m.split('=')[1]) : ''
}

type Json = Record<string, unknown> | unknown[]

async function request<T>(method: string, path: string, body?: Json | FormData): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (method !== 'GET') headers['X-CSRF-Token'] = csrfToken()
  let payload: BodyInit | undefined
  if (body instanceof FormData) payload = body
  else if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
    payload = JSON.stringify(body)
  }
  const res = await fetch(path, { method, headers, body: payload, credentials: 'same-origin', redirect: 'error' })
  if (res.status === 401 && !path.startsWith('/api/auth/login')) {
    window.dispatchEvent(new Event('vigia:unauthorized'))
  }
  const ctype = res.headers.get('content-type') || ''
  const data = ctype.includes('application/json') ? await res.json() : await res.text()
  if (!res.ok) {
    const detail = typeof data === 'object' && data && 'detail' in data ? (data as { detail: unknown }).detail : data
    let msg = typeof detail === 'string' ? detail : Array.isArray((detail as { errors?: unknown[] })?.errors)
      ? ((detail as { errors: string[] }).errors).join(' · ') : `Error ${res.status}`
    // 422 from the validation handler: {detail, errors: [{field, msg}]} -> say which field and why
    const fieldErrors = typeof data === 'object' && data && Array.isArray((data as { errors?: unknown[] }).errors)
      ? (data as { errors: { field?: string; msg?: string }[] }).errors : []
    if (fieldErrors.length && typeof fieldErrors[0] === 'object') {
      msg += ': ' + fieldErrors.map((e) => `${(e.field || 'petición').replace(/^config\.?/, '') || 'configuración'} — ${(e.msg || '').replace(/^Value error, /, '')}`).join(' · ')
    }
    throw new ApiError(res.status, msg, data)
  }
  return data as T
}

export const api = {
  get: <T>(p: string) => request<T>('GET', p),
  post: <T>(p: string, b?: Json | FormData) => request<T>('POST', p, b ?? {}),
  patch: <T>(p: string, b: Json) => request<T>('PATCH', p, b),
  del: <T>(p: string) => request<T>('DELETE', p),
}

export function scanSocket(scanId: number, after: number, onMessage: (msg: unknown) => void, onClose: () => void): WebSocket {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  const ws = new WebSocket(`${proto}://${location.host}/api/ws/scans/${scanId}?after=${after}`)
  ws.onmessage = (ev) => {
    try { onMessage(JSON.parse(ev.data)) } catch { /* ignore malformed frames */ }
  }
  ws.onclose = onClose
  return ws
}

