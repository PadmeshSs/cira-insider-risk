import axios from 'axios'
import { useAuth } from '@/store/auth'
import { toApiError } from '@/utils/errors'

export const API_BASE_URL: string = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/$/, '') ||
  'http://localhost:8000/api/v1'

/** One Axios instance for every route group. Bearer token on every request (N65). */
export const http = axios.create({ baseURL: API_BASE_URL, timeout: 30_000 })

http.interceptors.request.use((config) => {
  const { token } = useAuth.getState()
  if (token) config.headers.set('Authorization', `Bearer ${token}`)
  return config
})

http.interceptors.response.use(
  (r) => r,
  (err) => {
    const e = toApiError(err)
    // A missing, expired, forged or deactivated token answers 401 (Chapter 13). The
    // login route itself also answers 401 for a wrong password; that one is not a session end.
    const url = String(err?.config?.url ?? '')
    if (e.status === 401 && !url.includes('/auth/token') && useAuth.getState().token) {
      useAuth.getState().signOut('Your session ended. Sign in again to continue.')
    }
    return Promise.reject(e)
  },
)

/** Reject anything that would ask the API for more than its cap (N66). */
export const MAX_LIMIT = 200

export async function get<T>(url: string, params?: Record<string, unknown>, signal?: AbortSignal): Promise<T> {
  const clean = params
    ? Object.fromEntries(Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== ''))
    : undefined
  const r = await http.get<T>(url, { params: clean, signal })
  return r.data
}

export async function post<T>(url: string, body: unknown, signal?: AbortSignal): Promise<T> {
  const r = await http.post<T>(url, body, { signal })
  return r.data
}
