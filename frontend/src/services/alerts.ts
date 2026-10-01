import type { AlertDetail, AlertQueue, Severity } from '@/types/api'
import { get } from './client'

export interface AlertQueueParams {
  status?: 'open' | 'suppressed' | 'all'
  severity?: Severity | null
  user_id?: string | null
  /** queue = the policy's order (anomaly score, N55); recent = first day, newest first */
  sort?: 'queue' | 'recent'
  limit?: number
  offset?: number
}

/** GET /alerts — the analyst queue of the served run, paginated (cap 200). */
export const listAlerts = (p: AlertQueueParams, signal?: AbortSignal) =>
  get<AlertQueue>('/alerts', { ...p }, signal)

/** GET /alerts/{id} — members with both scores, suppressed repeats or the alert it repeats. */
export const getAlert = (id: number | string, signal?: AbortSignal) => get<AlertDetail>(`/alerts/${id}`, undefined, signal)
