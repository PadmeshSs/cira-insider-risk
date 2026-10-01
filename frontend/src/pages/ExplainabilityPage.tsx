import { useMemo, useState } from 'react'
import { AttackSection, ContextFactors, ModelFactors, Section } from '@/components/common/alert/ExplanationSections'
import { DayTabs } from '@/components/common/alert/DayTabs'
import { TechniqueDrawer } from '@/components/common/alert/TechniqueDrawer'
import { useAlertOutlet, useSelectedDay } from '@/components/common/alert/context'
import { Icon } from '@/components/ui/Icon'
import { Panel } from '@/components/ui/Panel'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { ErrorPanel, SkeletonRows } from '@/components/ui/States'
import { PROVENANCE } from '@/constants/cri'
import { useApi } from '@/hooks/useApi'
import { alertExplanations } from '@/services/explanations'
import type { MemberExplanation } from '@/types/api'
import { columnLabel, fmtAnomaly, fmtCri } from '@/utils/format'

/** Which raising factors recur across the alert's days: a feature x day grid of TreeSHAP contributions. */
function FactorPersistence({ members, selected, onSelect }: { members: MemberExplanation[]; selected?: string; onSelect: (d: string) => void }) {
  const days = [...members].sort((a, b) => a.activity_date.localeCompare(b.activity_date))
  const feats = new Map<string, { label: string; total: number; n: number }>()
  for (const m of days)
    for (const f of m.sections.model) {
      const e = feats.get(f.feature) ?? { label: f.label, total: 0, n: 0 }
      e.total += f.contribution
      e.n += 1
      feats.set(f.feature, e)
    }
  const rows = [...feats.entries()].sort((a, b) => b[1].n - a[1].n || b[1].total - a[1].total).slice(0, 12)
  const max = Math.max(0.01, ...days.flatMap((m) => m.sections.model.map((f) => f.contribution)))
  if (!rows.length) return <p className="t-body-sm p-5 text-ink-muted">No raising factor stored on any member day.</p>
  return (
    <div className="overflow-x-auto p-5">
      <table className="border-separate border-spacing-[2px]">
        <thead>
          <tr>
            <th />
            {days.map((m) => (
              <th key={m.member_id} className="px-0.5 pb-1">
                <button onClick={() => onSelect(m.activity_date)} className={`t-code-sm ${m.activity_date === selected ? 'text-cyan' : 'text-ink-faint hover:text-ink'}`}>
                  {m.activity_date.slice(5)}
                </button>
              </th>
            ))}
            <th className="t-label pl-2 text-left">days</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([feat, info]) => (
            <tr key={feat}>
              <td className="max-w-[260px] truncate pr-3 text-[12px] text-ink" title={feat}>{info.label || columnLabel(feat)}</td>
              {days.map((m) => {
                const f = m.sections.model.find((x) => x.feature === feat)
                const a = f ? 0.15 + 0.85 * (f.contribution / max) : 0
                return (
                  <td key={m.member_id} className="p-0">
                    <span
                      className={`block h-5 w-10 ${m.activity_date === selected ? 'outline outline-1 outline-cyan/60' : ''}`}
                      style={{ background: f ? `rgba(56, 189, 248, ${a.toFixed(2)})` : '#1E2638' }}
                      title={f ? `${m.activity_date}: ${f.text}` : `${m.activity_date}: not among the raising factors`}
                    />
                  </td>
                )
              })}
              <td className="t-code-sm pl-2 text-ink-muted">{info.n}/{days.length}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="t-body-sm mt-2 text-ink-faint">Cell strength is the factor&apos;s TreeSHAP contribution on that day. Empty cells: the factor was not among that day&apos;s top raising factors.</p>
    </div>
  )
}

function CrossCheck({ e }: { e: MemberExplanation }) {
  const rows: [string, number, number][] = [
    ['model', e.sections.model.length, e.reason_rows.model ?? 0],
    ['model_lowering', e.sections.model_lowering.length, e.reason_rows.model_lowering ?? 0],
    ['cri', e.sections.cri.length, e.reason_rows.cri ?? 0],
    ['mitre', e.sections.mitre?.matches.length ?? 0, e.reason_rows.mitre ?? 0],
  ]
  return (
    <table className="w-full">
      <thead>
        <tr className="t-label text-left"><th className="pb-1 font-semibold">Section</th><th className="pb-1 text-right font-semibold">Shown</th><th className="pb-1 text-right font-semibold">Reason rows</th><th /></tr>
      </thead>
      <tbody className="t-code-sm">
        {rows.map(([k, a, b]) => (
          <tr key={k} className="border-t border-row-line">
            <td className="py-1 text-ink-muted">{k}</td>
            <td className="py-1 text-right text-ink">{a}</td>
            <td className="py-1 text-right text-ink">{b}</td>
            <td className="w-6 py-1 text-right">{a === b ? <Icon name="check" size={12} className="inline text-sev-low" /> : <Icon name="warn" size={12} className="inline text-sev-medium" />}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/** §27 "Why is it risky?": the stored explanation of a member day, in three sections that never mix (N50). */
export default function ExplainabilityPage() {
  const { detail } = useAlertOutlet()
  const [member, select] = useSelectedDay(detail.members)
  const [tech, setTech] = useState<string | null>(null)
  const st = useApi(`explain:${detail.alert.id}`, (s) => alertExplanations(detail.alert.id, s))
  const e = useMemo(() => st.data?.members.find((m) => m.activity_date === member?.activity_date), [st.data, member])

  if (st.error) return <div className="panel"><ErrorPanel error={st.error} onRetry={st.reload} /></div>
  if (!st.data) return <div className="panel"><SkeletonRows rows={10} /></div>

  const mitreHref = `/alerts/${detail.alert.id}/mitre${member ? `?day=${member.activity_date}` : ''}`
  const statusOf = (d: string) => st.data?.members.find((m) => m.activity_date === d)?.status

  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
      <div className="flex min-w-0 flex-col gap-6 xl:col-span-8">
        <div className="panel">
          <DayTabs members={detail.members} selected={member?.activity_date} onSelect={select} mark={(m) => (statusOf(m.activity_date) === 'complete' ? null : 'deferred')} />
        </div>

        {!e ? (
          <div className="panel p-6 t-body-sm text-ink-muted">No stored explanation for this member day.</div>
        ) : (
          <>
            <div className="panel flex flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3">
              <SeverityBadge severity={e.headline.severity ?? null} value={e.headline.cri_score ?? null} />
              <span className="t-body-sm text-ink-muted">CRI <span className="t-code text-ink-strong">{fmtCri(e.headline.cri_score)}</span> of 100</span>
              <span className="t-body-sm text-ink-muted">anomaly score <span className="t-code text-ink-strong">{fmtAnomaly(e.headline.anomaly_score)}</span> from {e.headline.model_name} {e.headline.registry_version}</span>
              <span className={`t-code-sm ml-auto ${e.status === 'complete' ? 'text-ink-faint' : 'text-sev-medium-text'}`}>{e.status}</span>
            </div>

            {e.status !== 'complete' && (
              <div className="flex gap-2 rounded-[8px] border border-sev-medium/40 bg-sev-medium-tint px-5 py-2.5">
                <Icon name="warn" size={14} className="mt-0.5 shrink-0 text-sev-medium" />
                <p className="t-body-sm text-ink">
                  The model explanation for this day is not available: {e.model_unavailable_reason ?? 'not computed'}. The scores and their
                  context stand.
                </p>
              </div>
            )}

            <Section color={PROVENANCE.model.color} title="Why the model scored this day" kicker="served model, TreeSHAP, log-odds" count={e.sections.model.length + e.sections.model_lowering.length}>
              <ModelFactors raising={e.sections.model} lowering={e.sections.model_lowering} />
            </Section>

            <Section color={PROVENANCE.context.color} title="What the CRI added as context" kicker="CRI points, not model reasons" count={e.sections.cri.length}>
              <ContextFactors items={e.sections.cri} />
            </Section>

            <Section color={PROVENANCE.attack.color} title="What ATT&CK calls the behaviour" kicker="context, not a reason the model scored the day" count={e.sections.mitre?.matches.length ?? 0}>
              <AttackSection ctx={e.sections.mitre} onTechnique={setTech} mitreHref={mitreHref} />
            </Section>

            {detail.members.length > 1 && (
              <Panel title="Factors across member days" meta="does the same behaviour drive every day?">
                <FactorPersistence members={st.data.members} selected={member?.activity_date} onSelect={select} />
              </Panel>
            )}
          </>
        )}
      </div>

      <div className="flex min-w-0 flex-col gap-6 xl:col-span-4">
        {e && (
          <>
            <Panel title="Second estimator" meta="KernelSHAP">
              <div className="flex flex-col gap-2 p-5">
                {e.corroboration ? (
                  <>
                    <div className="flex items-baseline justify-between">
                      <span className="t-body-sm text-ink-muted">Top-5 factor overlap with TreeSHAP</span>
                      <span className="t-code text-ink-strong">{e.corroboration.top5_overlap ?? '—'}</span>
                    </div>
                    <div className="flex items-baseline justify-between">
                      <span className="t-body-sm text-ink-muted">Removing top factors beats removing random ones</span>
                      <span className="t-code text-ink-strong">{e.corroboration.deletion_top_beats_random === null || e.corroboration.deletion_top_beats_random === undefined ? '—' : String(e.corroboration.deletion_top_beats_random)}</span>
                    </div>
                    <p className="t-body-sm text-ink-faint">An agreement check between two SHAP estimators. It is never shown as a reason.</p>
                  </>
                ) : (
                  <p className="t-body-sm text-ink-muted">KernelSHAP was not run for this day. TreeSHAP above is the explanation.</p>
                )}
              </div>
            </Panel>

            {Object.keys(e.unavailable).length > 0 && (
              <Panel title="Not available">
                <ul className="flex flex-col gap-1.5 p-5">
                  {Object.entries(e.unavailable).map(([k, v]) => (
                    <li key={k} className="t-body-sm text-ink-muted"><span className="t-code-sm text-ink">{k}</span>: {v}</li>
                  ))}
                </ul>
              </Panel>
            )}

            <Panel title="Stored reason rows" meta="explanation vs alert_reasons">
              <div className="p-5"><CrossCheck e={e} /></div>
            </Panel>

            <Panel title="Stored explanation text" meta={e.explain_run_id}>
              <pre className="t-code-sm max-h-[360px] overflow-auto whitespace-pre-wrap p-5 text-ink-muted">{e.text}</pre>
            </Panel>

          </>
        )}
      </div>
      <TechniqueDrawer id={tech} onClose={() => setTech(null)} />
    </div>
  )
}
