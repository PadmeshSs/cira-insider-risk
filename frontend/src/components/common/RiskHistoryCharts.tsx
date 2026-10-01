import { CartesianGrid, ComposedChart, Line, ReferenceArea, ResponsiveContainer, Scatter, Tooltip, XAxis, YAxis } from 'recharts'
import { SEV_STYLE } from '@/constants/severity'
import { useBands } from '@/hooks/useBands'
import type { HistoryBucket, Severity } from '@/types/api'
import { dayDiff, fmtAnomaly, fmtCri } from '@/utils/format'
import { AXIS, GRID, TOOLTIP_STYLE } from './chartTheme'

interface Pt {
  t: number
  start: string
  end: string
  days: number
  maxCri: number | null
  meanCri: number | null
  maxAn: number | null
  meanAn: number | null
  sev: Severity | null
  alertDays: number
  alertMark: number | null
}

const ms = (d: string) => Date.parse(`${d}T00:00:00Z`)

/**
 * Persisted buckets on a true time axis. Where two persisted buckets are not
 * adjacent, a break is inserted so the line stops: the database holds alert
 * member days and the demo sample only, and the gap is unknown, not low (N63).
 */
function toPoints(buckets: HistoryBucket[], bucket: 'day' | 'week'): Pt[] {
  const step = bucket === 'day' ? 1 : 7
  const out: Pt[] = []
  buckets.forEach((b, i) => {
    if (i > 0 && dayDiff(buckets[i - 1].start, b.start) > step) {
      out.push({ t: (ms(buckets[i - 1].start) + ms(b.start)) / 2, start: '', end: '', days: 0, maxCri: null, meanCri: null, maxAn: null, meanAn: null, sev: null, alertDays: 0, alertMark: null })
    }
    out.push({
      t: ms(b.start), start: b.start, end: b.end, days: b.days,
      maxCri: b.max_cri_score, meanCri: b.mean_cri_score, maxAn: b.max_anomaly_score, meanAn: b.mean_anomaly_score,
      sev: b.max_severity, alertDays: b.alert_member_days, alertMark: b.alert_member_days > 0 ? 104 : null,
    })
  })
  return out
}

const fmtTick = (t: number) => new Date(t).toISOString().slice(0, 10)

function SevDot(props: { cx?: number; cy?: number; payload?: Pt }) {
  const { cx, cy, payload } = props
  if (cx === undefined || cy === undefined || !payload?.sev) return null
  return <rect x={cx - 3} y={cy - 3} width={6} height={6} fill={SEV_STYLE[payload.sev].base} stroke="#0B0F17" strokeWidth={1} />
}

function AlertMark(props: { cx?: number; cy?: number; payload?: Pt }) {
  const { cx, cy, payload } = props
  if (cx === undefined || cy === undefined || payload?.alertMark === null || payload?.alertMark === undefined) return null
  return <path d={`M${cx - 4},${cy - 3} L${cx + 4},${cy - 3} L${cx},${cy + 3} Z`} fill="#F1F5F9" />
}

function TipBody({ active, payload, which }: { active?: boolean; payload?: { payload: Pt }[]; which: 'cri' | 'an' }) {
  const p = payload?.[0]?.payload
  if (!active || !p || !p.start) return null
  return (
    <div style={TOOLTIP_STYLE.contentStyle}>
      <div className="t-code-sm mb-1 text-ink-strong">{p.start === p.end ? p.start : `${p.start} → ${p.end}`}</div>
      {which === 'cri' ? (
        <>
          <div className="t-code-sm text-ink">max CRI {fmtCri(p.maxCri)} {p.sev}</div>
          <div className="t-code-sm text-ink-muted">mean CRI {fmtCri(p.meanCri)}</div>
        </>
      ) : (
        <>
          <div className="t-code-sm text-ink">max anomaly {fmtAnomaly(p.maxAn)}</div>
          <div className="t-code-sm text-ink-muted">mean anomaly {fmtAnomaly(p.meanAn)}</div>
        </>
      )}
      <div className="t-code-sm text-ink-faint">{p.days} persisted day{p.days === 1 ? '' : 's'}{p.alertDays ? `, ${p.alertDays} in an alert` : ''}</div>
    </div>
  )
}

export function CriHistoryChart({ buckets, bucket, height = 240, onPick }: { buckets: HistoryBucket[]; bucket: 'day' | 'week'; height?: number; onPick?: (start: string) => void }) {
  const { bands: BANDS } = useBands()
  const data = toPoints(buckets, bucket)
  const pad = bucket === 'day' ? 86_400_000 : 7 * 86_400_000
  const domain: [number, number] = data.length ? [data[0].t - pad, data[data.length - 1].t + pad] : [0, 1]
  return (
    <div style={{ height }} className="w-full">
      <ResponsiveContainer>
        <ComposedChart data={data} margin={{ top: 10, right: 12, bottom: 0, left: -14 }}
          onClick={(s) => { const p = (s as { activePayload?: { payload: Pt }[] } | null)?.activePayload?.[0]?.payload; if (p?.start) onPick?.(p.start) }}>
          {BANDS.map((b) => (
            <ReferenceArea key={b.severity} y1={b.from} y2={b.to} fill={SEV_STYLE[b.severity].base} fillOpacity={0.06} stroke="none" ifOverflow="hidden" />
          ))}
          <CartesianGrid {...GRID} />
          <XAxis dataKey="t" type="number" scale="time" domain={domain} tickFormatter={fmtTick} {...AXIS} minTickGap={40} />
          <YAxis domain={[0, 108]} ticks={[0, ...BANDS.slice(1).map((b) => b.from), 100]} {...AXIS} width={44} />
          <Tooltip content={<TipBody which="cri" />} cursor={{ stroke: '#3B475D' }} />
          <Line dataKey="meanCri" stroke="#94A3B8" strokeDasharray="3 3" strokeWidth={1} dot={false} connectNulls={false} isAnimationActive={false} />
          <Line dataKey="maxCri" stroke="#E2E8F0" strokeWidth={1.25} dot={<SevDot />} activeDot={false} connectNulls={false} isAnimationActive={false} />
          <Scatter dataKey="alertMark" shape={<AlertMark />} isAnimationActive={false} />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  )
}

export function AnomalyHistoryChart({ buckets, bucket, height = 160 }: { buckets: HistoryBucket[]; bucket: 'day' | 'week'; height?: number }) {
  const data = toPoints(buckets, bucket)
  const pad = bucket === 'day' ? 86_400_000 : 7 * 86_400_000
  const domain: [number, number] = data.length ? [data[0].t - pad, data[data.length - 1].t + pad] : [0, 1]
  return (
    <div style={{ height }} className="w-full">
      <ResponsiveContainer>
        <ComposedChart data={data} margin={{ top: 10, right: 12, bottom: 0, left: -14 }}>
          <CartesianGrid {...GRID} />
          <XAxis dataKey="t" type="number" scale="time" domain={domain} tickFormatter={fmtTick} {...AXIS} minTickGap={40} />
          <YAxis domain={[0, 1]} ticks={[0, 0.25, 0.5, 0.75, 1]} {...AXIS} width={44} />
          <Tooltip content={<TipBody which="an" />} cursor={{ stroke: '#3B475D' }} />
          <Line dataKey="meanAn" stroke="#38BDF8" strokeOpacity={0.5} strokeDasharray="3 3" strokeWidth={1} dot={false} connectNulls={false} isAnimationActive={false} />
          <Line dataKey="maxAn" stroke="#38BDF8" strokeWidth={1.25} dot={{ r: 2, fill: '#38BDF8', strokeWidth: 0 }} activeDot={false} connectNulls={false} isAnimationActive={false} />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  )
}

export function HistoryLegend({ which }: { which: 'cri' | 'an' }) {
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-ink-faint">
      {which === 'cri' ? (
        <>
          <span className="flex items-center gap-1.5"><span className="h-px w-4 bg-ink" /> highest CRI in the bucket, square in its band colour</span>
          <span className="flex items-center gap-1.5"><span className="h-px w-4 border-t border-dashed border-ink-muted" /> mean CRI</span>
          <span className="flex items-center gap-1.5"><svg width="9" height="7"><path d="M0,0 L8,0 L4,6 Z" fill="#F1F5F9" /></svg> bucket holds an alert member day</span>
          <span>shaded bands: LOW / MEDIUM / HIGH / CRITICAL</span>
        </>
      ) : (
        <>
          <span className="flex items-center gap-1.5"><span className="h-px w-4 bg-cyan" /> highest anomaly score</span>
          <span className="flex items-center gap-1.5"><span className="h-px w-4 border-t border-dashed border-cyan/60" /> mean anomaly score</span>
        </>
      )}
      <span>breaks: days not held in the database</span>
    </div>
  )
}
