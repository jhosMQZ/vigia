// Appearance preference: follow the system, or force light/dark. Stored locally (no server round trip).
export type ThemePref = 'system' | 'light' | 'dark'
const KEY = 'vigia.theme'

export function getThemePref(): ThemePref {
  const v = localStorage.getItem(KEY)
  return v === 'light' || v === 'dark' ? v : 'system'
}

export function applyTheme(pref: ThemePref = getThemePref()): 'light' | 'dark' {
  const dark = pref === 'dark' || (pref === 'system' && window.matchMedia?.('(prefers-color-scheme: dark)').matches)
  const mode = dark ? 'dark' : 'light'
  document.documentElement.dataset.theme = mode
  return mode
}

export function setThemePref(pref: ThemePref): void {
  if (pref === 'system') localStorage.removeItem(KEY)
  else localStorage.setItem(KEY, pref)
  applyTheme(pref)
}

export function watchSystemTheme(): () => void {
  const mq = window.matchMedia?.('(prefers-color-scheme: dark)')
  if (!mq) return () => {}
  const on = () => { if (getThemePref() === 'system') applyTheme('system') }
  mq.addEventListener('change', on)
  return () => mq.removeEventListener('change', on)
}
