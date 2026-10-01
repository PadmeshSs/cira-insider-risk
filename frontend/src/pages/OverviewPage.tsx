import { Link, useNavigate } from 'react-router'
import { AlertTable } from '@/components/common/AlertTable'
import { UserChip } from '@/components/common/EntityChip'
import { LineageChain } from '@/components/common/Lineage'
import { PageHeader } from '@/components/common/PageHeader'
import { SeverityMix } from '@/components/common/SeverityMix'
import { WeeklyAlertsChart } from '@/components/common/WeeklyAlertsChart'
import { Icon } from '@/components/ui/Icon'
import { Panel } from '@/components/ui/Panel'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { ErrorPanel, SkeletonBlock, SkeletonRows } from '@/components/ui/States'
import { Stat } from '@/components/ui/Stat'
import { Tag } from '@/components/ui/Tag'
import { useApi } from '@/hooks/useApi'
import { listAlerts } from '@/services/alerts'
import { overview as fetchOverview } from '@/services/risk'
import type { Overview } from '@/types/api'
import { fmtInt, pct, sentenceLabel } from '@/utils/format'

const N52 = 'usb_disconnect_count'

function Kpis({ o }: { o: Overview }) {
  const open = o.counts.open ?? 0
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <Stat label="Open alerts" value={fmtInt(open)} sub="Waiting in the review queue" />
      <Stat label="Repeats kept" value={fmtInt(o.counts.suppressed ?? 0)} accent="#FCD34D" sub="Same pattern again within the cooldown. Kept, not resolved." />
      <div className="panel flex min-w-0 flex-col gap-3 p-5">
        <span className="text-[13px] font-medium text-ink-muted">Open alerts by severity</span>
        <SeverityMix counts={o.open_by_severity} />
      </div>
      <Stat
        label="Raised by the model alone"
        value={<>{fmtInt(o.open_never_above_low)}<span className="ml-2 text-[15px] font-normal text-ink-faint">{pct(o.open_never_above_low, open)}</span></>}
        sub="Open alerts whose context risk never rose above LOW"
      />
    </div>
  )
}

function RiskyUsers({ o }: { o: Overview }) {
  const navigate = useNavigate()
  if (!o.top_users.length) return <p className="p-5 text-[14px] text-ink-muted">No open alerts in the served run.</p>
  return (
    <table className="grid-table">
      <thead>
        <tr>
          <th className="w-12">Rank</th>
          <th>User</th>
          <th>Highest severity</th>
          <th>Model score</th>
          <th className="text-right">Open</th>
          <th className="text-right">Repeats</th>
        </tr>
      </thead>
      <tbody>
        {o.top_users.map((u, i) => (
          <tr key={u.user_id} className="is-link" onClick={() => navigate(`/users/${encodeURIComponent(u.user_id)}`)}>
            <td className="text-[14px] text-ink-faint">{i + 1}</td>
            <td>
              <span className="flex items-center gap-2">
                <UserChip userId={u.user_id} />
                {u.in_sample && <Tag tone="danger" mono={false}>In training data</Tag>}
              </span>
            </td>
            <td><SeverityBadge severity={u.max_severity} /></td>
            <td className="t-code text-[14px] text-ink-strong">{u.max_queue_score.toFixed(3)}</td>
            <td className="text-right text-[14px] text-ink">{u.open_alerts}</td>
            <td className={`text-right text-[14px] ${u.suppressed_alerts ? 'text-sev-medium-text' : 'text-ink-ghost'}`}>{u.suppressed_alerts}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function TopFactors({ o }: { o: Overview }) {
  const max = Math.max(1, ...o.top_features.map((f) => f.open_alerts))
  const open = o.counts.open ?? 0
  return (
    <div className="flex flex-col gap-5 p-5">
      <ul className="flex flex-col gap-4">
        {o.top_features.map((f) => (
          <li key={f.feature} className="flex flex-col gap-1.5">
            <div className="flex items-baseline justify-between gap-3">
              <span className={`truncate text-[14px] ${f.feature === N52 ? 'text-sev-medium-text' : 'text-ink'}`} title={f.feature}>{sentenceLabel(f.feature)}</span>
              <span className="shrink-0 text-[13px] text-ink-muted">{f.open_alerts} alerts · {pct(f.open_alerts, open)}</span>
            </div>
            <span className="h-2 rounded-full bg-l2">
              <span className="block h-full rounded-full bg-prov-model" style={{ width: `${(100 * f.open_alerts) / max}%`, opacity: f.feature === N52 ? 0.5 : 0.85 }} />
            </span>
          </li>
        ))}
      </ul>
      {o.open_led_by_usb_disconnect_count > 0 && (
        <div className="flex gap-3 rounded-lg border border-sev-medium/40 bg-sev-medium-tint p-4">
          <Icon name="warn" size={18} className="mt-0.5 shrink-0 text-sev-medium" />
          <p className="text-[13px] leading-5 text-ink">
            <strong className="font-semibold text-sev-medium-text">{o.open_led_by_usb_disconnect_count} open alerts</strong> are led by
            the number of USB disconnects. In the Chapter 11 validation readout (note N52) this factor led about half of the false alarms, so check these with care. It
            counts disconnects; it says nothing about data leaving.
          </p>
        </div>
      )}
    </div>
  )
}

export default function OverviewPage() {
  const ov = useApi('overview', (s) => fetchOverview(s))
  const next = useApi('alerts:overview-next', (s) => listAlerts({ status: 'open', sort: 'queue', limit: 6, offset: 0 }, s))
  if (ov.error) return <div className="panel"><ErrorPanel error={ov.error} onRetry={ov.reload} /></div>
  const o = ov.data

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Overview"
        sub={
          o ? (
            <>
              Who looks risky right now. Alerts are ordered by <span className="t-code-sm text-ink">{o.queue.ordered_by}</span> under policy{' '}
              <span className="t-code-sm text-ink">{o.queue.policy_version}</span>; severity adds context and does not change the order.
            </>
          ) : 'Who looks risky right now.'
        }
        actions={<Link to="/alerts" className="btn btn-primary">Review the queue <Icon name="chevronRight" size={16} /></Link>}
      />

      {o ? <Kpis o={o} /> : <SkeletonBlock height={136} className="rounded-[10px]" />}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-5">
        <Panel className="xl:col-span-3" title="Riskiest users" meta="Ranked by their highest open alert">
          {o ? <RiskyUsers o={o} /> : <SkeletonRows rows={8} height={56} />}
        </Panel>
        <Panel className="xl:col-span-2" title="What is driving alerts" meta="The factor that raised the model score most, per open alert">
          {o ? <TopFactors o={o} /> : <SkeletonRows rows={6} height={48} />}
        </Panel>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-5">
        <Panel className="xl:col-span-3" title="Next to review" meta="Top of the queue" actions={<Link to="/alerts" className="btn btn-ghost">See all alerts <Icon name="chevronRight" size={16} /></Link>}>
          {next.error ? <ErrorPanel error={next.error} onRetry={next.reload} compact /> : next.data ? <AlertTable items={next.data.items} compact /> : <SkeletonRows rows={6} height={56} />}
        </Panel>
        <Panel className="xl:col-span-2" title="New alerts per week" meta="By the first day of each alert">
          <div className="p-5">{o ? <WeeklyAlertsChart weeks={o.new_open_alerts} /> : <SkeletonBlock height={220} />}</div>
        </Panel>
      </div>

      {o && <details className="panel group"><summary className="cursor-pointer list-none px-5 py-3 text-[13px] text-ink-faint hover:text-ink-muted">Where these numbers come from</summary><LineageChain run={o.run} /></details>}
    </div>
  )
}
