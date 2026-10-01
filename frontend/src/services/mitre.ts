import type { AlertMitre, Technique } from '@/types/api'
import { get } from './client'

/** GET /mitre/alerts/{id} — ATT&CK rows of the member days: mapped, unmapped or not evaluated. */
export const alertMitre = (id: number | string, signal?: AbortSignal) =>
  get<AlertMitre>(`/mitre/alerts/${id}`, undefined, signal)

/** GET /mitre/techniques/{id} — one technique of the pinned table and the rules that can map to it. */
export const technique = (id: string, signal?: AbortSignal) =>
  get<Technique>(`/mitre/techniques/${encodeURIComponent(id)}`, undefined, signal)
