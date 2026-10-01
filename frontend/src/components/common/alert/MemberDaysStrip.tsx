import { Fragment } from 'react'
import { SEV_STYLE } from '@/constants/severity'
import { useBands } from '@/hooks/useBands'
import type { AlertMember } from '@/types/api'
import { dayDiff, fmtAnomaly, fmtCri, fmtDay, weekday } from '@/utils/format'

/**
 * The member days of one alert, oldest first. Each day carries its two
 * scores as two separate bars on their own scales (anomaly 0-1, CRI 0-100),
 * the triggers that admitted it, and the peak marker. Gaps between member
 * days are labelled with their length rather than closed up.
 */
export function MemberDaysStrip({ members, selected, onSelect }: {
  members: AlertMember[]
  selected?: string
  onSelect: (day: string) => void
}) {
  const days = [...members].sort((a, b) => a.activity_date.localeCompare(b.activity_date))
  const H = 88
  const ticks = useBands().bands.slice(1).map((b) => b.from)
  return (
    <div className="overflow-x-auto">
      <div className="flex min-w-max items-end gap-2 px-5 pb-4 pt-4" role="listbox" aria-label="Member days">
        {days.map((m, i) => {
          const gap = i > 0 ? dayDiff(days[i - 1].activity_date, m.activity_date) - 1 : 0
          const sel = m.activity_date === selected
          const sev = SEV_STYLE[m.severity]
          return (
            <Fragment key={m.id}>
              {gap > 0 && (
                <div className="flex w-10 shrink-0 flex-col items-center justify-end self-stretch pb-9" title={`${gap} day${gap === 1 ? '' : 's'} between member days: not part of this alert`}>
                  <span className="t-code-sm text-ink-ghost">···</span>
                  <span className="t-code-sm text-ink-ghost">{gap}d</span>
                </div>
              )}
              <button
                role="option"
                aria-selected={sel}
                onClick={() => onSelect(m.activity_date)}
                className={`flex w-[92px] shrink-0 flex-col items-center gap-2 rounded-lg border px-2 pb-2.5 pt-3 transition-colors ${
                  sel ? 'border-cyan bg-cyan/[0.08]' : 'border-transparent hover:border-line-strong hover:bg-l2'
                }`}
                title={`${m.activity_date}: anomaly ${fmtAnomaly(m.anomaly_score)}, CRI ${fmtCri(m.cri_score)} ${m.severity}`}
              >
                <div className="flex items-end gap-1.5" style={{ height: H }}>
                  <span className="relative w-3.5 rounded-sm bg-l2" style={{ height: H }} aria-hidden="true">
                    <span className="absolute inset-x-0 bottom-0 bg-prov-model" style={{ height: Math.max(1, m.anomaly_score * H) }} />
                  </span>
                  <span className="relative w-3.5 rounded-sm bg-l2" style={{ height: H }} aria-hidden="true">
                    <span className="absolute inset-x-0 bottom-0" style={{ height: Math.max(1, (m.cri_score / 100) * H), background: sev.base }} />
                    {ticks.map((b) => (
                      <span key={b} className="absolute inset-x-0 h-px bg-canvas/70" style={{ bottom: (b / 100) * H }} />
                    ))}
                  </span>
                </div>
                <span className={`text-[13px] font-medium ${sel ? 'text-ink-strong' : 'text-ink-muted'}`}>{fmtDay(m.activity_date, false)}</span>
                <span className="flex h-4 items-center gap-1">
                  <span className="text-[12px] text-ink-faint">{weekday(m.activity_date)}</span>
                  {m.is_peak && <span className="text-[12px] font-medium text-cyan">peak</span>}
                </span>
                <span className="flex gap-0.5">
                  <span className={`h-1 w-3 ${m.by_top_k ? 'bg-prov-model' : 'bg-l2'}`} title={m.by_top_k ? 'admitted by the daily top-k' : 'not in the daily top-k'} />
                  <span className={`h-1 w-3 ${m.by_band ? 'bg-prov-context' : 'bg-l2'}`} title={m.by_band ? 'admitted by the CRI band' : 'CRI band below HIGH'} />
                </span>
              </button>
            </Fragment>
          )
        })}
      </div>
      <div className="flex flex-wrap items-center gap-x-5 gap-y-1 border-t border-line px-5 py-3 text-[12px] text-ink-faint">
        <span className="flex items-center gap-1.5"><span className="h-2 w-2.5 bg-prov-model" /> anomaly score, 0 to 1</span>
        <span className="flex items-center gap-1.5"><span className="h-2 w-2.5 bg-sev-high" /> CRI, 0 to 100, band colour, ticks at the band limits</span>
        <span className="flex items-center gap-1.5"><span className="h-1 w-3 bg-prov-model" /> top-k trigger</span>
        <span className="flex items-center gap-1.5"><span className="h-1 w-3 bg-prov-context" /> band trigger</span>
      </div>
    </div>
  )
}
