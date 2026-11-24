import { createContext, useContext } from 'react'
import type { PrivacyStatus, User } from './types'

export interface AuthCtx { user: User | null; setUser: (u: User | null) => void; logout: () => Promise<void> }
export const AuthContext = createContext<AuthCtx>({ user: null, setUser: () => {}, logout: async () => {} })
export const useAuth = () => useContext(AuthContext)

/** Connection-protection status shared by the navigation rail and the home page (refreshed by the shell). */
export interface ProtectionCtx { status: PrivacyStatus | null; error: unknown; reload: () => void }
export const ProtectionContext = createContext<ProtectionCtx>({ status: null, error: null, reload: () => {} })
export const useProtection = () => useContext(ProtectionContext)

export function protectionTone(level?: string): 'ok' | 'warn' | 'bad' | '' {
  return level === 'complete' ? 'ok' : level === 'partial' || level === 'weak' ? 'warn' : level === 'none' ? 'bad' : ''
}
