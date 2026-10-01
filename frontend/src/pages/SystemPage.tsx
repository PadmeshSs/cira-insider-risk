import { PageHeader } from '@/components/common/PageHeader'
import { Panel } from '@/components/ui/Panel'
import { ErrorPanel, SkeletonRows } from '@/components/ui/States'
import { Tag } from '@/components/ui/Tag'
import { useApi } from '@/hooks/useApi'
import { models } from '@/services/models'
import { useHealth } from '@/store/health'
import type { ComponentBlock, RouteReadiness } from '@/types/api'
import { relTime } from '@/utils/format'

const OK = new Set(['loaded', 'reachable', 'configured'])

function Kv({ obj }: { obj: Record<string, unknown> }) {
  const entries = Object.entries(obj).filter(([, v]) => v !== null && v !== undefined && typeof v !== 'object')
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
      {entries.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="t-code-sm text-ink-faint">{k}</dt>
          <dd className="t-code-sm break-all text-ink">{String(v)}</dd>
        </div>
      ))}
    </dl>
  )
}

/** /health and /models in full: what is served, what is loaded, and which route groups can answer. */
export default function SystemPage() {
  const health = useHealth((s) => s.health)
  const herr = useHealth((s) => s.error)
  const checkedAt = useHealth((s) => s.checkedAt)
  const refresh = useHealth((s) => s.refresh)
  const m = useApi('models', (s) => models(s))

  const blocks: [string, ComponentBlock | undefined][] = health
    ? [['anomaly model', health.anomaly_model], ['database', health.database], ['CRI', health.cri], ['ATT&CK', health.mitre], ['explainability', health.explainability], ['alerts', health.alerts], ['auth', health.auth]]
    : []

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="System"
        sub={<>Live from <span className="t-code-sm">/health</span> and <span className="t-code-sm">/models</span>. Checked {relTime(checkedAt)}.</>}
        actions={<button className="btn btn-secondary" onClick={() => void refresh()}>Check now</button>}
      />
      {herr && !health && <div className="panel"><ErrorPanel error={herr} onRetry={() => void refresh()} /></div>}

      {health && (
        <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
          <Panel className="xl:col-span-5" title="Route readiness" meta={`overall: ${health.status}`}>
            <ul>
              {(Object.entries(health.routes) as [string, RouteReadiness][]).map(([k, r]) => (
                <li key={k} className="flex items-start gap-2.5 border-b border-row-line px-5 py-2 last:border-0">
                  <span className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${r.ready ? 'bg-sev-low' : 'bg-sev-critical'}`} />
                  <div className="min-w-0">
                    <div className="t-code text-ink">{k}</div>
                    {r.alert_run_id && <div className="t-code-sm text-ink-faint">serving {r.alert_run_id}</div>}
                    {!r.ready && <div className="t-body-sm text-ink-muted">{r.reason}</div>}
                  </div>
                </li>
              ))}
            </ul>
          </Panel>
          <Panel className="xl:col-span-7" title="Components">
            <div className="grid grid-cols-1 gap-px bg-line md:grid-cols-2">
              {blocks.map(([name, b]) => (
                <div key={name} className="flex flex-col gap-2 bg-l1 p-5">
                  <div className="flex items-center gap-2">
                    <span className={`h-1.5 w-1.5 rounded-full ${OK.has(String(b?.status)) ? 'bg-sev-low' : 'bg-sev-critical'}`} />
                    <span className="text-[13px] font-semibold text-ink">{name}</span>
                    <span className="t-code-sm ml-auto text-ink-muted">{b?.status}</span>
                  </div>
                  {b && <Kv obj={b as Record<string, unknown>} />}
                </div>
              ))}
            </div>
          </Panel>
        </div>
      )}

      <Panel title="Models" meta="served, shadow, and versions behind stored scores">
        {m.error ? <ErrorPanel error={m.error} onRetry={m.reload} /> : !m.data ? <SkeletonRows rows={5} /> : (
          <div className="flex flex-col">
            <div className="grid grid-cols-1 gap-px bg-line md:grid-cols-2">
              <div className="flex flex-col gap-2 bg-l1 p-5">
                <div className="flex items-center gap-2"><Tag tone="cyan">served</Tag><span className="t-code text-ink-strong">{m.data.served?.model_name} {m.data.served?.registry_version}</span></div>
                {m.data.served && <Kv obj={m.data.served as Record<string, unknown>} />}
                {m.data.decision_rule && <p className="t-body-sm text-ink-muted"><span className="text-ink-faint">Decision rule: </span>{m.data.decision_rule}</p>}
                {m.data.score_convention && <p className="t-body-sm text-ink-muted">{m.data.score_convention}</p>}
              </div>
              <div className="flex flex-col gap-3 bg-l1 p-5">
                {m.data.shadow.length === 0 && <p className="t-body-sm text-ink-muted">No shadow model loaded.</p>}
                {m.data.shadow.map((s, i) => (
                  <div key={i} className="flex flex-col gap-2">
                    <div className="flex items-center gap-2"><Tag>shadow</Tag><span className="t-code text-ink">{s.model_name} {s.registry_version}</span></div>
                    <p className="t-body-sm text-ink-muted">{String(s.use ?? '')}</p>
                  </div>
                ))}
              </div>
            </div>
            <div className="overflow-x-auto border-t border-line">
              <table className="grid-table">
                <thead><tr><th>Model</th><th>Registry</th><th>Version</th><th>Run</th><th>Profile</th><th>Split</th><th className="text-right">Inputs</th><th>Trained</th></tr></thead>
                <tbody>
                  {m.data.in_database.map((r) => (
                    <tr key={r.id}>
                      <td className="t-code text-ink">{r.model_name}</td>
                      <td className="t-code text-ink">{r.registry_version}</td>
                      <td className="t-code-sm text-ink-muted">{r.model_version}</td>
                      <td className="t-code-sm text-ink-muted">{r.run_id ?? '—'}</td>
                      <td className="t-code-sm text-ink-muted">{r.profile ?? '—'}</td>
                      <td className="t-code-sm text-ink-muted">{r.split_mode ?? '—'}</td>
                      <td className="t-code text-right text-ink">{r.n_input_columns ?? '—'}</td>
                      <td className="t-code-sm text-ink-muted">{r.trained_at ?? '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </Panel>
    </div>
  )
}
