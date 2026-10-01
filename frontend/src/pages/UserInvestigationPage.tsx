import { useEffect, useMemo, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router'
import { CoverageNote } from '@/components/common/CoverageNote'
import { InSampleFlag } from '@/components/common/InSampleFlag'
import { DayTimeline } from '@/components/common/investigation/DayTimeline'
import { EventTable } from '@/components/common/investigation/EventTable'
import { LineageChain } from '@/components/common/Lineage'
import { CriHistoryChart, HistoryLegend } from '@/components/common/RiskHistoryCharts'
import { Icon } from '@/components/ui/Icon'
import { Panel } from '@/components/ui/Panel'
import { ScoreTrack } from '@/components/ui/ScoreTrack'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { Empty, ErrorPanel, SkeletonBlock, SkeletonRows } from '@/components/ui/States'
import { Tag } from '@/components/ui/Tag'
import { useApi } from '@/hooks/useApi'
import { listEvents } from '@/services/events'
import { investigation } from '@/services/investigations'
import { history } from '@/services/risk'
import type { CertEvent, PageInfo } from '@/types/api'
import { fmtCri, fmtSpan, weekday } from '@/utils/format'
import { MAX_LIMIT } from '@/services/client'
import { toApiError, type ApiError } from '@/utils/errors'

/** Events of one user-day, fetched page by page within the API cap (N66). */
function useDayEvents(user: string, day: string | null) {
  const [state, setState] = useState<{ key: string; items: CertEvent[]; page: PageInfo | null; err: ApiError | null; busy: boolean }>(
    { key: '', items: [], page: null, err: null, busy: false },
  )
  const key = `${user}:${day}`
  const load = async (offset: number, replace: boolean) => {
    if (!day) return
    setState((s) => ({ ...s, key, busy: true, err: null, ...(replace ? { items: [], page: null } : {}) }))
    try {
      const r = await listEvents({ user_id: user, date_from: day, date_to: day, limit: MAX_LIMIT, offset })
      setState((s) => ({ key, items: replace ? r.items : [...s.items, ...r.items], page: r.page, err: null, busy: false }))
    } catch (e) {
      setState((s) => ({ ...s, key, err: toApiError(e), busy: false }))
    }
  }
  useEffect(() => {
    void load(0, true)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key])
  const more = state.page && state.items.length < state.page.total ? () => load(state.items.length, false) : null
  return { ...state, more }
}

/** §27 "What should the analyst investigate?": one user's alerts, risk over persisted days, and a day's activity. */
export default function UserInvestigationPage() {
  const { userId = '' } = useParams()
  const [sp, setSp] = useSearchParams()
  const inv = useApi(`investigation:${userId}`, (s) => investigation(userId, s))
  const hist = useApi(`history:${userId}:day`, (s) => history(userId, 'day', s))
  const [picked, setPicked] = useState<number | null>(null)

  const persistedDays = useMemo(() => hist.data?.buckets.map((b) => b.start) ?? [], [hist.data])
  const defaultDay = useMemo(() => {
    const open = inv.data?.alerts.filter((a) => a.status === 'open').sort((a, b) => b.queue_score - a.queue_score)[0]
    return open?.peak_date ?? persistedDays[persistedDays.length - 1] ?? null
  }, [inv.data, persistedDays])
  const day = sp.get('day') ?? defaultDay
  const ev = useDayEvents(userId, day)
  const setDay = (d: string) => {
    setPicked(null)
    setSp(new URLSearchParams({ day: d }), { replace: true })
  }
  const bucketOfDay = hist.data?.buckets.find((b) => b.start === day)

  if (inv.error) return <div className="panel"><ErrorPanel error={inv.error} onRetry={inv.reload} /></div>
  const s = inv.data?.subject
  const idx = day ? persistedDays.indexOf(day) : -1

  return (
    <div className="flex flex-col gap-6">
      <div className="t-body-sm flex items-center gap-1.5 text-ink-faint">
        <Link to="/users" className="hover:text-ink">Users</Link>
        <Icon name="chevronRight" size={12} />
        <span className="t-code-sm uppercase text-ink-muted">{userId}</span>
      </div>

      {!s ? <SkeletonBlock height={96} className="rounded-[8px]" /> : (
        <header className="panel flex flex-wrap items-center gap-x-8 gap-y-3 p-6">
          <div className="flex flex-col gap-1">
            <div className="flex items-center gap-2.5">
              <h1 className="t-headline-xl font-mono uppercase text-ink-strong">{s.user_id}</h1>
              <SeverityBadge severity={s.max_severity} />
              <InSampleFlag inSample={s.in_sample} />
              {s.in_demo_sample && <Tag title="In the demo sample: validation and test users only (N59)">demo sample</Tag>}
            </div>
            <span className="t-body-sm text-ink-muted">LDAP role {s.ldap_role ?? 'unknown'} · model split {s.model_split}</span>
          </div>
          <dl className="flex flex-wrap gap-x-8 gap-y-2">
            <div className="flex flex-col gap-1"><dt className="t-label">Open alerts</dt><dd className="t-metric">{s.open_alerts}</dd></div>
            <div className="flex flex-col gap-1"><dt className="t-label">Suppressed</dt><dd className="t-metric text-sev-medium-text">{s.suppressed_alerts}</dd></div>
            <div className="flex flex-col gap-1"><dt className="t-label">Highest queue score</dt><dd className="pt-1.5">{s.max_queue_score !== null ? <ScoreTrack value={s.max_queue_score} width={72} /> : <span className="t-code-sm text-ink-ghost">no open alert</span>}</dd></div>
            <div className="flex flex-col gap-1"><dt className="t-label">Persisted days</dt><dd className="t-code pt-1.5 text-ink">{s.persisted_days} <span className="text-ink-faint">· {fmtSpan(s.first_date, s.last_date)}</span></dd></div>
          </dl>
          <Link to={`/users/${encodeURIComponent(s.user_id)}/history`} className="btn btn-secondary ml-auto"><Icon name="history" size={14} /> Risk history</Link>
        </header>
      )}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
        <div className="flex min-w-0 flex-col gap-6 xl:col-span-8">
          <Panel title="Risk over persisted days" meta="click a point to open that day" actions={<Link className="btn btn-ghost" to={`/users/${encodeURIComponent(userId)}/history`}>Full history <Icon name="chevronRight" size={14} /></Link>}>
            {hist.error ? <ErrorPanel error={hist.error} onRetry={hist.reload} compact /> : !hist.data ? <SkeletonBlock height={220} /> : (
              <div className="flex flex-col gap-2 p-5">
                <CriHistoryChart buckets={hist.data.buckets} bucket="day" height={200} onPick={setDay} />
                <HistoryLegend which="cri" />
                <CoverageNote coverage={hist.data.coverage} />
              </div>
            )}
          </Panel>

          <Panel
            title={day ? <>Activity on <span className="t-code-sm normal-case tracking-normal text-ink">{day} {weekday(day)}</span></> : 'Activity'}
            meta={bucketOfDay ? `CRI ${fmtCri(bucketOfDay.max_cri_score)} ${bucketOfDay.max_severity}${bucketOfDay.alert_member_days ? ' · alert member day' : ''}` : undefined}
            actions={
              <span className="flex items-center gap-1">
                <button className="btn btn-ghost" disabled={idx <= 0} onClick={() => setDay(persistedDays[idx - 1])} aria-label="Previous persisted day"><Icon name="chevronLeft" size={14} /></button>
                <select className="input !h-7 !w-auto !pr-6" value={day ?? ''} onChange={(e) => setDay(e.target.value)} aria-label="Persisted day">
                  {!persistedDays.includes(day ?? '') && day && <option value={day}>{day}</option>}
                  {persistedDays.map((d) => <option key={d} value={d}>{d} {weekday(d)}</option>)}
                </select>
                <button className="btn btn-ghost" disabled={idx < 0 || idx >= persistedDays.length - 1} onClick={() => setDay(persistedDays[idx + 1])} aria-label="Next persisted day"><Icon name="chevronRight" size={14} /></button>
              </span>
            }
          >
            {!day ? <Empty title="No persisted day for this user" /> : ev.err ? <ErrorPanel error={ev.err} compact /> : !ev.page ? <SkeletonRows rows={6} /> : ev.items.length === 0 ? (
              <Empty title="No events stored for this day">The database stores events for alert member days and the demo sample only. Pick another persisted day.</Empty>
            ) : (
              <>
                <DayTimeline events={ev.items} picked={picked} onPick={setPicked} />
                <div className="border-t border-line">
                  <EventTable events={ev.items} picked={picked} onPick={setPicked} />
                </div>
                <div className="flex items-center gap-3 border-t border-line px-5 py-2">
                  <span className="t-code-sm text-ink-muted">{ev.items.length} of {ev.page.total} events</span>
                  {ev.more && <button className="btn btn-secondary !h-7" onClick={ev.more} disabled={ev.busy}>{ev.busy ? 'Loading…' : `Load next ${Math.min(MAX_LIMIT, ev.page.total - ev.items.length)}`}</button>}
                </div>
              </>
            )}
          </Panel>
        </div>

        <div className="flex min-w-0 flex-col gap-6 xl:col-span-4">
          <Panel title="Alerts of this user" meta={inv.data ? `${inv.data.alerts.length} in the served run` : undefined}>
            {!inv.data ? <SkeletonRows rows={5} /> : inv.data.alerts.length === 0 ? (
              <Empty title="No alerts">This user is in the database through the demo sample only.</Empty>
            ) : (
              <ul>
                {inv.data.alerts.map((a) => (
                  <li key={a.id} className="border-b border-row-line last:border-0">
                    <Link to={`/alerts/${a.id}`} className={`grid grid-cols-[auto_1fr_auto] items-center gap-3 px-5 py-2 hover:bg-l2 ${a.status !== 'open' ? 'opacity-80' : ''}`}>
                      <span className="t-code text-ink-strong">#{a.id}</span>
                      <span className="flex min-w-0 flex-col leading-tight">
                        <span className="t-code-sm text-ink">{fmtSpan(a.first_date, a.last_date)}</span>
                        <span className="text-[11px] text-ink-faint">
                          {a.status === 'open' ? `open${a.suppressed?.count ? ` · +${a.suppressed.count} suppressed` : ''}` : `suppressed, repeats #${a.duplicate_of_id}`}
                        </span>
                      </span>
                      <SeverityBadge severity={a.max_severity} value={a.max_cri_score} />
                    </Link>
                    <div className="flex gap-2 px-5 pb-2">
                      <button className="t-body-sm link" onClick={() => setDay(a.peak_date)}>Show peak day {a.peak_date.slice(5)}</button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      </div>

      {inv.data && <div className="panel"><LineageChain run={inv.data.run} /></div>}
    </div>
  )
}
