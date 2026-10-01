import { SEV_STYLE } from '@/constants/severity'
import type { Severity } from '@/types/api'

/**
 * Severity badge (DESIGN.md): 20px, mono 11px/600, 1px tinted border, 15% fill.
 * Shows the explicit CRI value, `HIGH [68]`, so colour never carries meaning alone.
 */
export function SeverityBadge({ severity, value, title }: { severity: Severity | null | undefined; value?: number | null; title?: string }) {
  if (!severity) return <span className="t-code-sm text-ink-faint">no band</span>
  const s = SEV_STYLE[severity]
  return (
    <span
      title={title ?? (value !== undefined && value !== null ? `CRI ${value.toFixed(1)} of 100: ${severity}` : `CRI band ${severity}`)}
      className="inline-flex h-6 items-center rounded-md border px-2 font-mono text-[12px] font-semibold uppercase leading-none tracking-wide"
      style={{ background: s.bg15, borderColor: s.base, color: s.text }}
    >
      {severity}
      {value !== undefined && value !== null && <span className="ml-1.5 opacity-80">{Math.round(value)}</span>}
    </span>
  )
}
