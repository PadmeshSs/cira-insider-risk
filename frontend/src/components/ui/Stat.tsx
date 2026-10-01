import type { ReactNode } from 'react'

/** A KPI card: the number first, then one plain sentence about what it means. */
export function Stat({ label, value, sub, accent, children }: { label: ReactNode; value: ReactNode; sub?: ReactNode; accent?: string; children?: ReactNode }) {
  return (
    <div className="panel flex min-w-0 flex-col gap-2 p-5">
      <span className="text-[13px] font-medium text-ink-muted">{label}</span>
      <span className="t-metric text-ink-strong" style={accent ? { color: accent } : undefined}>{value}</span>
      {sub && <span className="text-[13px] leading-5 text-ink-faint">{sub}</span>}
      {children}
    </div>
  )
}
