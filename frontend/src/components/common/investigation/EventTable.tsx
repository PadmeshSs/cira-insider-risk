import { useEffect, useRef } from 'react'
import { DeviceChip } from '@/components/common/EntityChip'
import { SOURCE_META } from '@/constants/events'
import type { CertEvent } from '@/types/api'
import { clockOf } from '@/utils/format'
import { WORK_END_H, WORK_START_H } from '@/constants/events'
import { eventSummary } from './eventText'

export function EventTable({ events, picked, onPick }: { events: CertEvent[]; picked?: number | null; onPick?: (id: number) => void }) {
  const ref = useRef<HTMLTableRowElement | null>(null)
  useEffect(() => {
    ref.current?.scrollIntoView({ block: 'nearest' })
  }, [picked])
  return (
    <div className="max-h-[380px] overflow-auto">
      <table className="grid-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Domain</th>
            <th>What CERT recorded</th>
            <th>PC</th>
            <th>CERT id</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e) => {
            const c = clockOf(e.event_time)
            const off = c.hh < WORK_START_H || c.hh >= WORK_END_H
            return (
              <tr key={e.id} ref={picked === e.id ? ref : undefined} className={`is-link ${picked === e.id ? 'is-selected' : ''}`} onClick={() => onPick?.(e.id)}>
                <td className={`t-code ${off ? 'text-sev-medium-text' : 'text-ink'}`} title={off ? 'Outside 07:00-19:00' : undefined}>{c.text}</td>
                <td>
                  <span className="flex items-center gap-1.5 text-[12px] text-ink-muted">
                    <span className="h-2 w-2" style={{ background: SOURCE_META[e.source_type].color }} />
                    {SOURCE_META[e.source_type].label}
                  </span>
                </td>
                <td className="max-w-[460px] truncate text-[13px] text-ink">
                  {eventSummary(e)}
                </td>
                <td><DeviceChip deviceId={e.device_id} /></td>
                <td className="t-code-sm text-ink-faint">{e.event_id}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
