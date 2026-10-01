import { Icon } from '@/components/ui/Icon'
import type { Coverage } from '@/types/api'

/**
 * The API reads PostgreSQL only: alert member days and the demo sample (D-6).
 * Shown next to every history chart and timeline, so a gap between persisted
 * days is never read as "no risk" (N63).
 */
export function CoverageNote({ coverage, note }: { coverage?: Coverage | null; note?: string }) {
  const text = note ?? coverage?.note
  return (
    <div className="flex items-start gap-2 rounded-sm border border-line bg-ground px-2.5 py-2">
      <Icon name="info" size={14} className="mt-0.5 shrink-0 text-ink-faint" />
      <p className="t-body-sm text-ink-muted">
        {coverage && (
          <span className="t-code-sm mr-1.5 text-ink">
            {coverage.persisted_days} persisted day{coverage.persisted_days === 1 ? '' : 's'}
            {coverage.first_date ? `, ${coverage.first_date} to ${coverage.last_date}` : ''}.
          </span>
        )}
        {text} A gap between persisted days is not a low-risk period.
      </p>
    </div>
  )
}
