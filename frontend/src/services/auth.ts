import type { Analyst, Token } from '@/types/api'
import { get, http } from './client'

/** POST /auth/token — OAuth2 password flow (form-encoded), then GET /users/me. */
export async function login(username: string, password: string): Promise<Token> {
  const body = new URLSearchParams({ username, password })
  const r = await http.post<Token>('/auth/token', body, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  return r.data
}

export const me = (signal?: AbortSignal) => get<Analyst>('/users/me', undefined, signal)
