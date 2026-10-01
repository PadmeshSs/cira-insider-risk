import { SEV_STYLE } from '@/constants/severity'
import type { AlertMember } from '@/types/api'
import { weekday } from '@/utils/format'

/** Compact member-day selector for the Explainability and ATT&CK tabs. */
export function DayTabs({ members, selected, onSelect, mark }: {
  members: AlertMember[]
  selected?: string
  onSelect: (d: string) => void
  mark?: (m: AlertMember) => string | null
}) {
  const days = [...members].sort((a, b) => a.activity_date.localeCompare(b.activity_date))
  return (
    <div className="flex gap-1 overflow-x-auto p-2" role="tablist" aria-label="Member day">
      {days.map((m) => {
        const sel = m.activity_date === selected
        const note = mark?.(m)
        return (
          <button
            key={m.id}
            role="tab"
            aria-selected={sel}
            onClick={() => onSelect(m.activity_date)}
            className={`flex shrink-0 flex-col items-start gap-0.5 rounded-sm border px-2 py-1 ${sel ? 'border-cyan bg-cyan/[0.08]' : 'border-line hover:bg-l2'}`}
          >
            <span className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5" style={{ background: SEV_STYLE[m.severity].base }} />
              <span className={`t-code-sm ${sel ? 'text-ink-strong' : 'text-ink-muted'}`}>{m.activity_date.slice(5)}</span>
              <span className="text-[10px] text-ink-faint">{weekday(m.activity_date)}</span>
              {m.is_peak && <span className="font-mono text-[10px] text-cyan">peak</span>}
            </span>
            {note && <span className="text-[10px] text-ink-faint">{note}</span>}
          </button>
        )
      })}
    </div>
  )
}
