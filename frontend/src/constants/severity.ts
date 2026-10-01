import type { Severity } from '@/types/api'

export const SEVERITIES: Severity[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

/**
 * Chapter 9 default upper bound of each band (app/cri/config.py DEFAULT_BANDS).
 * Used only until /health answers: the scale is drawn from the served CRI
 * config (`cri.config.severity_maxima`), and the band of every row is the
 * backend's own `severity` field, never recomputed here.
 */
export const DEFAULT_MAXIMA: Record<Severity, number> = { LOW: 24, MEDIUM: 49, HIGH: 74, CRITICAL: 100 }

export interface Band {
  severity: Severity
  from: number
  to: number
}

/** Bands on the 0-100 drawing scale from the per-band maxima, e.g. LOW 0-25, MEDIUM 25-50. */
export function bandsFrom(maxima: Partial<Record<Severity, number>>): Band[] {
  let from = 0
  return SEVERITIES.map((s) => {
    const max = s === 'CRITICAL' ? 100 : (maxima[s] ?? DEFAULT_MAXIMA[s]) + 1
    const b = { severity: s, from, to: Math.min(100, max) }
    from = b.to
    return b
  })
}

export const SEV_STYLE: Record<Severity, { base: string; tint: string; text: string; bg15: string }> = {
  LOW: { base: '#14B8A6', tint: '#0F2E2C', text: '#5EEAD4', bg15: 'rgba(20, 184, 166, 0.15)' },
  MEDIUM: { base: '#F59E0B', tint: '#332408', text: '#FCD34D', bg15: 'rgba(245, 158, 11, 0.15)' },
  HIGH: { base: '#F97316', tint: '#3A1A0B', text: '#FDBA74', bg15: 'rgba(249, 115, 22, 0.15)' },
  CRITICAL: { base: '#EF4444', tint: '#3F1414', text: '#FCA5A5', bg15: 'rgba(239, 68, 68, 0.15)' },
}
