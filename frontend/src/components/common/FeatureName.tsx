import { columnLabel } from '@/utils/format'

/**
 * A Chapter 5 column. When the API sends a described label (explanations,
 * /features) that label is shown; otherwise the column name, unaltered, so it
 * can be looked up.
 */
export function FeatureName({ column, label }: { column: string | null | undefined; label?: string | null }) {
  if (!column) return <span className="t-code-sm text-ink-ghost">—</span>
  return (
    <span className="inline-flex min-w-0 flex-col leading-tight" title={column}>
      <span className="truncate text-[13px] text-ink">{label ?? columnLabel(column)}</span>
      {label && <span className="t-code-sm truncate text-ink-faint">{column}</span>}
    </span>
  )
}
