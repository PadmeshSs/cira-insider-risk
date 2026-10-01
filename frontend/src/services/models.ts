import type { ModelsOut } from '@/types/api'
import { get } from './client'

/** GET /models — served and shadow models, and the versions behind stored scores. */
export const models = (signal?: AbortSignal) => get<ModelsOut>('/models', undefined, signal)
