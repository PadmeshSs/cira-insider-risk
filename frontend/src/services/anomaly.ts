import type { StoredAnomalyScore } from '@/types/api'
import { get } from './client'

/** GET /anomaly/users/{user}/days/{day} — the stored served score of one user-day. */
export const storedAnomaly = (user: string, day: string, signal?: AbortSignal) =>
  get<StoredAnomalyScore>(`/anomaly/users/${encodeURIComponent(user)}/days/${day}`, undefined, signal)
