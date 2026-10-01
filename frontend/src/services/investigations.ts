import type { Investigation, SubjectPage } from '@/types/api'
import { get } from './client'

/** GET /investigations?scope=all|alerting|demo — monitored users with persisted rows, paginated. */
export const listSubjects = (
  p: { scope?: 'all' | 'alerting' | 'demo'; limit?: number; offset?: number },
  signal?: AbortSignal,
) => get<SubjectPage>('/investigations', { ...p }, signal)

/** GET /investigations/{user} — one user's alerts and persisted coverage. */
export const investigation = (user: string, signal?: AbortSignal) =>
  get<Investigation>(`/investigations/${encodeURIComponent(user)}`, undefined, signal)
