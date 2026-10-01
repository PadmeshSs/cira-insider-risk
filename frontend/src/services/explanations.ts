import type { AlertExplanations, MemberExplanation } from '@/types/api'
import { get } from './client'

/** GET /explanations/alerts/{id} — stored explanation of every member day, sections apart (N50). */
export const alertExplanations = (id: number | string, signal?: AbortSignal) =>
  get<AlertExplanations>(`/explanations/alerts/${id}`, undefined, signal)

/** GET /explanations/users/{user}/days/{day} */
export const dayExplanation = (user: string, day: string, signal?: AbortSignal) =>
  get<MemberExplanation>(`/explanations/users/${encodeURIComponent(user)}/days/${day}`, undefined, signal)
