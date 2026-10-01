import { Link, NavLink, Outlet, useLocation, useParams } from 'react-router'
import { UserChip } from '@/components/common/EntityChip'
import { InSampleFlag } from '@/components/common/InSampleFlag'
import { LineageChain } from '@/components/common/Lineage'
import { SuppressedCell } from '@/components/common/SuppressedCell'
import { TriggerTags } from '@/components/common/TriggerTags'
import { Icon } from '@/components/ui/Icon'
import { ScoreTrack } from '@/components/ui/ScoreTrack'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { ErrorPanel, SkeletonBlock } from '@/components/ui/States'
import { Tag } from '@/components/ui/Tag'
import { useApi } from '@/hooks/useApi'
import { getAlert } from '@/services/alerts'
import { fmtDayRange } from '@/utils/format'

const TABS = [
  { to: '', label: 'Summary', q: 'How risky is it?' },
  { to: 'explain', label: 'Explainability', q: 'Why is it risky?' },
  { to: 'mitre', label: 'ATT&CK context', q: 'What does ATT&CK call it?' },
]

/** One alert: header, the three question tabs, and the run it was read from. */
export default function AlertLayout() {
  const { alertId = '' } = useParams()
  const { search } = useLocation()
  const st = useApi(`alert:${alertId}`, (s) => getAlert(alertId, s))
  const d = st.data
  const day = new URLSearchParams(search).get('day')
  const keep = day ? `?day=${day}` : ''

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center gap-1.5 text-[13px] text-ink-faint">
        <Link to="/alerts" className="hover:text-ink">Alerts</Link>
        <Icon name="chevronRight" size={12} />
        <span className="t-code-sm text-ink-muted">#{alertId}</span>
      </div>

      {st.error ? (
        <div className="panel"><ErrorPanel error={st.error} onRetry={st.reload} /></div>
      ) : !d ? (
        <SkeletonBlock height={140} className="rounded-[8px]" />
      ) : (
        <>
          <header className="panel flex flex-col">
            <div className="flex flex-wrap items-center gap-x-10 gap-y-4 px-6 py-5">
              <div className="flex flex-col gap-1.5">
                <div className="flex items-center gap-2.5">
                  <h1 className="t-headline-xl font-mono text-ink-strong">#{d.alert.id}</h1>
                  <SeverityBadge severity={d.alert.max_severity} value={d.alert.max_cri_score} />
                  {d.alert.status === 'open' ? (
                    <Tag tone="cyan">open</Tag>
                  ) : (
                    <Tag tone="warn" title="A kept repeat of an open alert inside its cooldown. Not resolved, not benign (N57).">suppressed</Tag>
                  )}
                  <InSampleFlag inSample={d.alert.in_sample} />
                </div>
                <span className="t-code-sm text-ink-faint" title="alert_key">{d.alert.alert_key}</span>
              </div>
              <dl className="flex flex-wrap gap-x-10 gap-y-3">
                <div className="flex flex-col gap-1"><dt className="t-label">User</dt><dd><UserChip userId={d.alert.user_id} /></dd></div>
                <div className="flex flex-col gap-1">
                  <dt className="t-label">When</dt>
                  <dd className="text-[14px] text-ink">{fmtDayRange(d.alert.first_date, d.alert.last_date)} <span className="text-ink-faint">· {d.alert.n_days} day{d.alert.n_days === 1 ? '' : 's'}</span></dd>
                </div>
                <div className="flex flex-col gap-1"><dt className="t-label" title={`Queue order: ${d.queue.ordered_by}. A ranking score, not a probability.`}>Model score</dt><dd><ScoreTrack value={d.alert.queue_score} width={64} /></dd></div>
                <div className="flex flex-col gap-1"><dt className="t-label">Raised by</dt><dd><TriggerTags triggers={d.alert.triggers} /></dd></div>
                <div className="flex flex-col gap-1"><dt className="t-label">Repeats</dt><dd><SuppressedCell s={d.alert.suppressed} /></dd></div>
              </dl>
            </div>
            {d.duplicate_of && (
              <div className="flex items-center gap-2 border-t border-sev-medium/30 bg-sev-medium-tint px-4 py-2">
                <Icon name="info" size={14} className="text-sev-medium" />
                <span className="t-body-sm text-ink">
                  This alert repeats the pattern of open alert{' '}
                  <Link className="link font-mono" to={`/alerts/${d.duplicate_of.id}`}>#{d.duplicate_of.id}</Link> inside its cooldown, so it was
                  kept out of the queue. It is not resolved.
                </span>
              </div>
            )}
            <nav className="flex gap-2 border-t border-line px-4" aria-label="Alert views">
              {TABS.map((t) => (
                <NavLink
                  key={t.label}
                  end
                  to={`/alerts/${alertId}${t.to ? `/${t.to}` : ''}${keep}`}
                  className={({ isActive }) =>
                    `flex h-14 flex-col justify-center border-b-2 px-3 ${isActive ? 'border-cyan text-ink-strong' : 'border-transparent text-ink-muted hover:text-ink'}`
                  }
                >
                  <span className="text-[14px] font-semibold leading-tight">{t.label}</span>
                  <span className="mt-0.5 text-[12px] leading-tight text-ink-faint">{t.q}</span>
                </NavLink>
              ))}
            </nav>
          </header>
          <Outlet context={{ detail: d }} />
          <details className="panel"><summary className="cursor-pointer list-none px-5 py-3 text-[13px] text-ink-faint hover:text-ink-muted">Where these numbers come from</summary><LineageChain run={d.run} /></details>
        </>
      )}
    </div>
  )
}
