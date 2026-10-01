import { SOURCE_META, SOURCE_TYPES, WORK_END_H, WORK_START_H } from '@/constants/events'
import type { CertEvent } from '@/types/api'
import { clockOf } from '@/utils/format'
import { eventSummary, isSecondary } from './eventText'

/**
 * A user-day on a 24-hour axis, one lane per CERT domain. Off-hours
 * (before 07:00 and from 19:00, the Chapter 5 definition) are hatched, so an
 * after-hours logon or USB connect stands out against the working day.
 * Clock times are read from the recorded timestamp, never shifted by the
 * browser's time zone.
 */
export function DayTimeline({ events, onPick, picked }: { events: CertEvent[]; onPick?: (id: number) => void; picked?: number | null }) {
  const lanes = SOURCE_TYPES.map((s) => ({ s, items: events.filter((e) => e.source_type === s) }))
  const hours = [0, 3, 6, 9, 12, 15, 18, 21, 24]
  return (
    <div className="flex flex-col">
      <div className="grid grid-cols-[120px_1fr] gap-x-3 px-5 pt-3">
        <span />
        <div className="relative h-4">
          {hours.map((h) => (
            <span key={h} className="t-code-sm absolute -translate-x-1/2 text-ink-faint" style={{ left: `${(h / 24) * 100}%` }}>
              {String(h).padStart(2, '0')}
            </span>
          ))}
        </div>
      </div>
      {lanes.map(({ s, items }) => {
        const meta = SOURCE_META[s]
        return (
          <div key={s} className="grid grid-cols-[120px_1fr] items-center gap-x-3 px-5 py-0.5">
            <span className="flex items-center justify-between gap-2" title={meta.what}>
              <span className="flex items-center gap-1.5 text-[12px] text-ink">
                <span className="h-2 w-2" style={{ background: meta.color }} />
                {meta.label}
              </span>
              <span className="t-code-sm text-ink-faint">{items.length}</span>
            </span>
            <div className="relative h-7 border-y border-row-line bg-ground">
              <div className="off-hours absolute inset-y-0 left-0" style={{ width: `${(WORK_START_H / 24) * 100}%` }} />
              <div className="off-hours absolute inset-y-0 right-0" style={{ width: `${((24 - WORK_END_H) / 24) * 100}%` }} />
              {[6, 12, 18].map((h) => (
                <span key={h} className="absolute inset-y-0 w-px bg-row-line" style={{ left: `${(h / 24) * 100}%` }} />
              ))}
              {items.map((e) => {
                const c = clockOf(e.event_time)
                const x = ((c.hh * 3600 + c.mm * 60 + c.ss) / 86400) * 100
                const sec = isSecondary(e)
                const sel = picked === e.id
                return (
                  <button
                    key={e.id}
                    type="button"
                    onClick={() => onPick?.(e.id)}
                    className="absolute top-1/2 -translate-x-1/2 -translate-y-1/2 focus:outline-none"
                    style={{ left: `${x}%` }}
                    title={`${c.text} ${eventSummary(e)}${e.device_id ? ` on ${e.device_id.toUpperCase()}` : ''}`}
                    aria-label={`${c.text} ${eventSummary(e)}`}
                  >
                    <span
                      className="block"
                      style={{
                        width: s === 'http' ? 2 : 6,
                        height: s === 'http' ? 14 : 14,
                        background: sec ? 'transparent' : meta.color,
                        border: sec ? `1px solid ${meta.color}` : undefined,
                        opacity: s === 'http' ? 0.55 : 1,
                        outline: sel ? '1px solid #F1F5F9' : undefined,
                        outlineOffset: 1,
                      }}
                    />
                  </button>
                )
              })}
            </div>
          </div>
        )
      })}
      <div className="flex flex-wrap gap-x-4 gap-y-1 px-5 pb-3 pt-2 text-[11px] text-ink-faint">
        <span className="flex items-center gap-1.5"><span className="off-hours inline-block h-3 w-5 border border-line" /> off-hours, outside 07:00 to 19:00</span>
        <span className="flex items-center gap-1.5"><span className="inline-block h-3 w-1.5 bg-ink-muted" /> logon, device connect</span>
        <span className="flex items-center gap-1.5"><span className="inline-block h-3 w-1.5 border border-ink-muted" /> logoff, device disconnect</span>
      </div>
    </div>
  )
}
