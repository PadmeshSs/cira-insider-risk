import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { Overview } from '@/types/api'
import { AXIS, GRID, TOOLTIP_STYLE } from './chartTheme'

/**
 * New open alerts per week, by an alert's first day (server-aggregated). Answers
 * "when did the queue fill": weeks with no new open alert are drawn as zero
 * only between the first and last week the run covers.
 */
export function WeeklyAlertsChart({ weeks }: { weeks: Overview['new_open_alerts'] }) {
  const data = fillWeeks(weeks)
  return (
    <div className="h-[200px] w-full">
      <ResponsiveContainer>
        <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -18 }}>
          <CartesianGrid {...GRID} />
          <XAxis dataKey="start" {...AXIS} tickFormatter={(d: string) => d.slice(5)} minTickGap={18} />
          <YAxis {...AXIS} allowDecimals={false} width={44} />
          <Tooltip
            {...TOOLTIP_STYLE}
            formatter={(v) => [String(v), 'new open alerts']}
            labelFormatter={(d) => `week of ${String(d)}`}
          />
          <Bar dataKey="count" fill="#38BDF8" fillOpacity={0.75} maxBarSize={18} isAnimationActive={false} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

function fillWeeks(weeks: Overview['new_open_alerts']) {
  if (weeks.length < 2) return weeks
  const byStart = new Map(weeks.map((w) => [w.start, w]))
  const out: Overview['new_open_alerts'] = []
  const cur = new Date(`${weeks[0].start}T00:00:00Z`)
  const last = new Date(`${weeks[weeks.length - 1].start}T00:00:00Z`)
  while (cur <= last) {
    const k = cur.toISOString().slice(0, 10)
    const end = new Date(cur)
    end.setUTCDate(end.getUTCDate() + 6)
    out.push(byStart.get(k) ?? { start: k, end: end.toISOString().slice(0, 10), count: 0 })
    cur.setUTCDate(cur.getUTCDate() + 7)
  }
  return out
}
