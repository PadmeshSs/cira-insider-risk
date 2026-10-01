import type { SuppressedSummary } from '@/types/api'
import { fmtDayRange, fmtSpan } from '@/utils/format'

/**
 * Suppressed repeats folded into an open alert (N57, N60). Suppressed means a
 * kept repeat of the same pattern inside the cooldown: not resolved, not benign.
 * "One alert" can stand for weeks of continuing activity, so the span is shown.
 */
export function SuppressedCell({ s }: { s: SuppressedSummary | null | undefined }) {
  if (!s || s.count === 0) return <span className="text-[14px] text-ink-ghost">None</span>
  return (
    <span className="inline-flex items-center gap-1.5" title={`${s.count} suppressed repeat${s.count === 1 ? '' : 's'} point at this alert, ${fmtSpan(s.first_date, s.last_date)}. Suppressed is not resolved.`}>
      <span className="text-[14px] font-medium text-sev-medium-text">+{s.count}</span>
      <span className="text-[13px] text-ink-faint">{fmtDayRange(s.first_date, s.last_date)}</span>
    </span>
  )
}
