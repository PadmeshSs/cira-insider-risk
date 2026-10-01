import type { Overview, RiskHistory, RiskRow, RiskScoreOut, RiskScoreRequest } from '@/types/api'
import { get, post } from './client'

/** GET /risk/overview — counts, bands, top factors, weekly new alerts, ranked users (server-aggregated). */
export const overview = (signal?: AbortSignal) => get<Overview>('/risk/overview', undefined, signal)

/** GET /risk/users/{user}/history?bucket=day|week */
export const history = (user: string, bucket: 'day' | 'week', signal?: AbortSignal) =>
  get<RiskHistory>(`/risk/users/${encodeURIComponent(user)}/history`, { bucket }, signal)

/** GET /risk/users/{user}/days/{day} — one stored risk row with the anomaly score beside it. */
export const riskDay = (user: string, day: string, signal?: AbortSignal) =>
  get<RiskRow>(`/risk/users/${encodeURIComponent(user)}/days/${day}`, undefined, signal)

/** POST /risk/score — re-score one user-day on demand. Never stored (N64). */
export const scoreDay = (body: RiskScoreRequest, signal?: AbortSignal) => post<RiskScoreOut>('/risk/score', body, signal)
