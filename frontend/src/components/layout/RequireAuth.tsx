import { useEffect } from 'react'
import { Navigate, Outlet, useLocation } from 'react-router'
import { sessionValid, useAuth } from '@/store/auth'

/** Every view but Login needs a valid bearer token; the timer ends the session at `expires_at`. */
export function RequireAuth() {
  const token = useAuth((s) => s.token)
  const expiresAt = useAuth((s) => s.expiresAt)
  const signOut = useAuth((s) => s.signOut)
  const location = useLocation()
  const valid = sessionValid(token, expiresAt)

  useEffect(() => {
    if (!token || !expiresAt) return
    const ms = Date.parse(expiresAt) - Date.now()
    if (ms <= 0) {
      signOut('Your session expired. Sign in again to continue.')
      return
    }
    const t = window.setTimeout(() => signOut('Your session expired. Sign in again to continue.'), Math.min(ms, 2 ** 31 - 1))
    return () => window.clearTimeout(t)
  }, [token, expiresAt, signOut])

  if (!valid) return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />
  return <Outlet />
}
