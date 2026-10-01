import { bandsFrom, DEFAULT_MAXIMA, type Band } from '@/constants/severity'
import { useHealth } from '@/store/health'
import type { Severity } from '@/types/api'

/** CRI band boundaries from the served CRI config in /health, so the scale follows any CRI_SEVERITY_* override. */
export function useBands(): { bands: Band[]; fromServer: boolean } {
  const maxima = useHealth(
    (s) => (s.health?.cri as { config?: { severity_maxima?: Partial<Record<Severity, number>> } } | undefined)?.config?.severity_maxima,
  )
  return { bands: bandsFrom(maxima ?? DEFAULT_MAXIMA), fromServer: Boolean(maxima) }
}
