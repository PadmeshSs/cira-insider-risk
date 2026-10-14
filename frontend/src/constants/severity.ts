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

/** Neon per band, kept in step with the --color-sev-* tokens in index.css. `glow` is the halo around a badge. */
export const SEV_STYLE: Record<Severity, { base: string; tint: string; text: string; bg15: string; glow: string }> = {
  LOW: { base: '#00E5FF', tint: '#001F24', text: '#7AF3FF', bg15: 'rgba(0, 229, 255, 0.10)', glow: 'rgba(0, 229, 255, 0.35)' },
  MEDIUM: { base: '#FFE600', tint: '#1F1C00', text: '#FFF27A', bg15: 'rgba(255, 230, 0, 0.10)', glow: 'rgba(255, 230, 0, 0.35)' },
  HIGH: { base: '#FF8A00', tint: '#241300', text: '#FFB766', bg15: 'rgba(255, 138, 0, 0.12)', glow: 'rgba(255, 138, 0, 0.40)' },
  CRITICAL: { base: '#FF2E5B', tint: '#26040C', text: '#FF8AA3', bg15: 'rgba(255, 46, 91, 0.14)', glow: 'rgba(255, 46, 91, 0.50)' },
}
