import { Link, useNavigate, useParams, useSearchParams } from 'react-router'
import { CoverageNote } from '@/components/common/CoverageNote'
import { LineageChain } from '@/components/common/Lineage'
import { PageHeader } from '@/components/common/PageHeader'
import { AnomalyHistoryChart, CriHistoryChart, HistoryLegend } from '@/components/common/RiskHistoryCharts'
import { Icon } from '@/components/ui/Icon'
import { Panel } from '@/components/ui/Panel'
import { ScoreTrack } from '@/components/ui/ScoreTrack'
import { Seg } from '@/components/ui/Seg'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { ErrorPanel, SkeletonBlock, SkeletonRows } from '@/components/ui/States'
import { SEVERITIES, SEV_STYLE } from '@/constants/severity'
import { useApi } from '@/hooks/useApi'
import { history } from '@/services/risk'
import { fmtAnomaly, fmtCri, weekday } from '@/utils/format'

/**
 * Risk history of one user, aggregated on the server per day or week. The CRI
 * and the anomaly score are drawn on separate charts with separate axes
 * (N34); breaks mark days the database does not hold (N63).
 */
export default function RiskHistoryPage() {
  const { userId = '' } = useParams()
  const [sp, setSp] = useSearchParams()
  const navigate = useNavigate()
  const bucket = (sp.get('bucket') as 'day' | 'week') || 'day'
  const st = useApi(`history:${userId}:${bucket}`, (s) => history(userId, bucket, s))
  const d = st.data
  const openDay = (day: string) => navigate(`/users/${encodeURIComponent(userId)}?day=${day}`)

  const bandCounts = d
    ? SEVERITIES.map((s) => ({ s, n: d.buckets.filter((b) => b.max_severity === s).length }))
    : []

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        crumbs={<><Link to="/users" className="hover:text-ink">Users</Link><Icon name="chevronRight" size={12} /><Link to={`/users/${encodeURIComponent(userId)}`} className="t-code-sm uppercase hover:text-ink">{userId}</Link></>}
        title={<>Risk history <span className="font-mono uppercase text-ink-muted">{userId}</span></>}
        sub="Highest and mean scores per bucket, over the days the database holds for this user."
        actions={<Seg label="Bucket" value={bucket} onChange={(v) => setSp(new URLSearchParams({ bucket: v }), { replace: true })} options={[{ value: 'day', label: 'Daily' }, { value: 'week', label: 'Weekly' }]} />}
      />

      {st.error ? <div className="panel"><ErrorPanel error={st.error} onRetry={st.reload} /></div> : (
        <>
          {d ? <CoverageNote coverage={d.coverage} /> : null}
          <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
            <div className="flex min-w-0 flex-col gap-6 xl:col-span-9">
              <Panel title="Contextual risk (CRI)" meta="0 to 100, band zones shaded">
                <div className="flex flex-col gap-2 p-5">
                  {d ? <CriHistoryChart buckets={d.buckets} bucket={bucket} height={280} onPick={bucket === 'day' ? openDay : undefined} /> : <SkeletonBlock height={280} />}
                  <HistoryLegend which="cri" />
                </div>
              </Panel>
              <Panel title="Served model anomaly score" meta="0 to 1, a ranking score, not a probability">
                <div className="flex flex-col gap-2 p-5">
                  {d ? <AnomalyHistoryChart buckets={d.buckets} bucket={bucket} height={180} /> : <SkeletonBlock height={180} />}
                  <HistoryLegend which="an" />
                </div>
              </Panel>
            </div>
            <div className="flex min-w-0 flex-col gap-6 xl:col-span-3">
              <Panel title={`${bucket === 'day' ? 'Days' : 'Weeks'} by highest band`}>
                <ul className="flex flex-col gap-2 p-5">
                  {bandCounts.slice().reverse().map(({ s, n }) => (
                    <li key={s} className="flex items-center gap-3">
                      <span className="w-[72px] font-mono text-[11px] font-semibold" style={{ color: SEV_STYLE[s].text }}>{s}</span>
                      <span className="relative h-1.5 flex-1 bg-l2">
                        <span className="absolute inset-y-0 left-0" style={{ width: `${d && d.buckets.length ? (100 * n) / d.buckets.length : 0}%`, background: SEV_STYLE[s].base }} />
                      </span>
                      <span className="t-code w-8 text-right text-ink">{n}</span>
                    </li>
                  ))}
                </ul>
              </Panel>
              {d && (
                <Panel title="Alert member days">
                  <p className="t-body-sm p-5 text-ink-muted">
                    <span className="t-metric mr-2 text-ink-strong">{d.buckets.reduce((a, b) => a + b.alert_member_days, 0)}</span>
                    of {d.coverage.persisted_days} persisted days belong to an alert.
                  </p>
                </Panel>
              )}
            </div>
          </div>

          <Panel title="Buckets" meta={d ? `${d.buckets.length} ${bucket === 'day' ? 'days' : 'weeks'}` : undefined}>
            {!d ? <SkeletonRows rows={8} /> : (
              <div className="max-h-[420px] overflow-auto">
                <table className="grid-table">
                  <thead>
                    <tr>
                      <th>{bucket === 'day' ? 'Day' : 'Week'}</th>
                      <th className="text-right">Days</th>
                      <th>Highest CRI</th>
                      <th className="text-right">Mean CRI</th>
                      <th>Highest anomaly</th>
                      <th className="text-right">Mean anomaly</th>
                      <th className="text-right">In an alert</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[...d.buckets].reverse().map((b) => (
                      <tr key={b.start} className={bucket === 'day' ? 'is-link' : ''} onClick={bucket === 'day' ? () => openDay(b.start) : undefined}>
                        <td className="t-code text-ink">{b.start}{bucket === 'day' ? <span className="ml-2 text-ink-faint">{weekday(b.start)}</span> : <span className="text-ink-faint"> → {b.end.slice(5)}</span>}</td>
                        <td className="t-code text-right text-ink-muted">{b.days}</td>
                        <td><SeverityBadge severity={b.max_severity} value={b.max_cri_score} /></td>
                        <td className="t-code text-right text-ink-muted">{fmtCri(b.mean_cri_score)}</td>
                        <td><ScoreTrack value={b.max_anomaly_score} width={56} /></td>
                        <td className="t-code text-right text-ink-muted">{fmtAnomaly(b.mean_anomaly_score)}</td>
                        <td className={`t-code text-right ${b.alert_member_days ? 'text-ink-strong' : 'text-ink-ghost'}`}>{b.alert_member_days}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {d && <LineageChain run={d.run} />}
          </Panel>
        </>
      )}
    </div>
  )
}
