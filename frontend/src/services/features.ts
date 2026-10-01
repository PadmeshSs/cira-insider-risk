import type { FeatureVector } from '@/types/api'
import { get } from './client'

/** GET /features/users/{user}/days/{day} — the stored Chapter 5 vector, each value described. */
export const featureVector = (user: string, day: string, signal?: AbortSignal) =>
  get<FeatureVector>(`/features/users/${encodeURIComponent(user)}/days/${day}`, undefined, signal)
