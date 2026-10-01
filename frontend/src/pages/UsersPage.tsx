import { useNavigate, useSearchParams } from 'react-router'
import { UserChip } from '@/components/common/EntityChip'
import { InSampleFlag } from '@/components/common/InSampleFlag'
import { LineageChain } from '@/components/common/Lineage'
import { PageHeader } from '@/components/common/PageHeader'
import { Pager } from '@/components/ui/Pager'
import { ScoreTrack } from '@/components/ui/ScoreTrack'
import { Seg } from '@/components/ui/Seg'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { Empty, ErrorPanel, SkeletonRows } from '@/components/ui/States'
import { Tag } from '@/components/ui/Tag'
import { useApi } from '@/hooks/useApi'
import { listSubjects } from '@/services/investigations'
import { fmtSpan } from '@/utils/format'

type Scope = 'all' | 'alerting' | 'demo'

/** Monitored CERT users with persisted rows in the served run. */
export default function UsersPage() {
  const navigate = useNavigate()
  const [sp, setSp] = useSearchParams()
  const scope = (sp.get('scope') as Scope) || 'alerting'
  const offset = Number(sp.get('offset') || 0)
  const st = useApi(`subjects:${scope}:${offset}`, (s) => listSubjects({ scope, limit: 50, offset }, s))
  const d = st.data
  const win = d?.demo_window as { start?: string; end?: string; rule?: string } | null | undefined

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Users"
        sub="People the console holds data for: everyone with an alert, plus the demo sample. Ranked by their highest model score. Use the search at the top to jump to anyone."
      />
      <div className="panel flex flex-wrap items-center gap-4 p-5">
        <Seg<Scope>
          label="Scope"
          value={scope}
          onChange={(v) => setSp(new URLSearchParams({ scope: v }), { replace: true })}
          options={[
            { value: 'alerting', label: 'With alerts' },
            { value: 'demo', label: 'Demo sample' },
            { value: 'all', label: 'All persisted' },
          ]}
        />
        {win && (
          <span className="t-body-sm text-ink-muted">
            Demo window <span className="t-code-sm text-ink">{fmtSpan(win.start ?? null, win.end ?? null)}</span>
            {win.rule ? <span className="text-ink-faint"> · {win.rule}</span> : null}
          </span>
        )}
      </div>
      <div className="panel">
        {st.error ? <ErrorPanel error={st.error} onRetry={st.reload} /> : !d ? <SkeletonRows rows={12} /> : d.items.length === 0 ? (
          <Empty title="No users in this scope" />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="grid-table">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>LDAP role</th>
                    <th title="Highest queue score among open alerts">Highest queue score</th>
                    <th>Highest band</th>
                    <th className="text-right">Open</th>
                    <th className="text-right">Suppressed</th>
                    <th className="text-right">Persisted days</th>
                    <th>Span</th>
                    <th>Split</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {d.items.map((u) => (
                    <tr key={u.user_id} className="is-link" onClick={() => navigate(`/users/${encodeURIComponent(u.user_id)}`)}>
                      <td><UserChip userId={u.user_id} /></td>
                      <td className="text-[13px] text-ink-muted">{u.ldap_role ?? '—'}</td>
                      <td>{u.max_queue_score !== null ? <ScoreTrack value={u.max_queue_score} width={72} /> : <span className="t-code-sm text-ink-ghost">no open alert</span>}</td>
                      <td><SeverityBadge severity={u.max_severity} /></td>
                      <td className="t-code text-right text-ink">{u.open_alerts}</td>
                      <td className={`t-code text-right ${u.suppressed_alerts ? 'text-sev-medium-text' : 'text-ink-ghost'}`}>{u.suppressed_alerts}</td>
                      <td className="t-code text-right text-ink">{u.persisted_days}</td>
                      <td className="t-code-sm text-ink-muted">{fmtSpan(u.first_date, u.last_date)}</td>
                      <td><InSampleFlag inSample={u.in_sample} split={u.model_split} /></td>
                      <td>{u.in_demo_sample && <Tag title="In the c12 demo sample: validation and test users only (N59)">demo</Tag>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager page={d.page} onOffset={(o) => setSp(new URLSearchParams({ scope, offset: String(o) }), { replace: true })} />
          </>
        )}
        {d && <LineageChain run={d.run} />}
      </div>
    </div>
  )
}
