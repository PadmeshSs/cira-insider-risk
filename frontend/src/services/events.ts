import type { EventPage, SourceType } from '@/types/api'
import { get } from './client'

export interface EventParams {
  user_id: string
  date_from?: string
  date_to?: string
  source_type?: SourceType
  limit?: number
  offset?: number
}

/** GET /events — persisted CERT events of one user, oldest first, paginated (cap 200, N66). */
export const listEvents = (p: EventParams, signal?: AbortSignal) => get<EventPage>('/events', { ...p }, signal)
