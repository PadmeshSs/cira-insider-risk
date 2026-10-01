import type { Health } from '@/types/api'
import { get } from './client'

/** GET /health (also at /api/v1/health) — no token needed; `routes` is the readiness signal (N68). */
export const health = (signal?: AbortSignal) => get<Health>('/health', undefined, signal)
