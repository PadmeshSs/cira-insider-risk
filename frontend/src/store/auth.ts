import { create } from 'zustand'
import { createJSONStorage, persist } from 'zustand/middleware'
import type { Analyst } from '@/types/api'

/**
 * The signed-in analyst. Only the bearer token, its expiry and the account
 * returned by /users/me are kept; the password never leaves the login form
 * (N65). sessionStorage, so closing the tab signs out.
 */
interface AuthState {
  token: string | null
  expiresAt: string | null
  analyst: Analyst | null
  /** Why the last session ended, shown once on the login screen. */
  endReason: string | null
  signIn: (token: string, expiresAt: string) => void
  setAnalyst: (a: Analyst) => void
  signOut: (reason?: string | null) => void
  isValid: () => boolean
}

/** True while the token's expiry is in the future. */
export function sessionValid(token: string | null, expiresAt: string | null): boolean {
  return Boolean(token && expiresAt && Date.parse(expiresAt) > Date.now())
}

export const useAuth = create<AuthState>()(
  persist(
    (set, get) => ({
      token: null,
      expiresAt: null,
      analyst: null,
      endReason: null,
      signIn: (token, expiresAt) => set({ token, expiresAt, endReason: null }),
      setAnalyst: (analyst) => set({ analyst }),
      signOut: (reason = null) => set({ token: null, expiresAt: null, analyst: null, endReason: reason }),
      isValid: () => sessionValid(get().token, get().expiresAt),
    }),
    {
      name: 'cira-session',
      storage: createJSONStorage(() => sessionStorage),
      partialize: (s) => ({ token: s.token, expiresAt: s.expiresAt, analyst: s.analyst }),
    },
  ),
)
