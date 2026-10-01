import { create } from 'zustand'
import { health as fetchHealth } from '@/services/health'
import type { Health } from '@/types/api'
import { type ApiError, toApiError } from '@/utils/errors'

/** /health, polled for the status bar and the login screen (N68). */
interface HealthState {
  health: Health | null
  error: ApiError | null
  checkedAt: number | null
  refresh: () => Promise<void>
}

export const useHealth = create<HealthState>()((set) => ({
  health: null,
  error: null,
  checkedAt: null,
  refresh: async () => {
    try {
      const h = await fetchHealth()
      set({ health: h, error: null, checkedAt: Date.now() })
    } catch (e) {
      set({ error: toApiError(e), checkedAt: Date.now() })
    }
  },
}))
