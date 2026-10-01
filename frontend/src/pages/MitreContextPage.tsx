import { useState } from 'react'
import { DayTabs } from '@/components/common/alert/DayTabs'
import { EvidenceTag } from '@/components/common/alert/ExplanationSections'
import { TechniqueDrawer } from '@/components/common/alert/TechniqueDrawer'
import { useAlertOutlet, useSelectedDay } from '@/components/common/alert/context'
import { Icon } from '@/components/ui/Icon'
import { Panel } from '@/components/ui/Panel'
import { ErrorPanel, SkeletonRows } from '@/components/ui/States'
import { Tag } from '@/components/ui/Tag'
import { useApi } from '@/hooks/useApi'
import { alertMitre } from '@/services/mitre'
import type { MitreDay } from '@/types/api'
import { columnLabel, weekday } from '@/utils/format'

const STATUS_TEXT: Record<string, string> = {
  mapped: 'mapped',
  unmapped: 'evaluated, nothing mapped',
  not_evaluated: 'not evaluated',
}

/** Technique x member-day grid: which days carry which technique, and with what evidence grade. */
function TechniqueGrid({ days, techniques, selected, onDay, onTechnique }: {
  days: MitreDay[]
  techniques: { technique_id: string; technique_name: string | null; tactic: string | null; days: number }[]
  selected?: string
  onDay: (d: string) => void
  onTechnique: (id: string) => void
}) {
  return (
    <div className="overflow-x-auto p-5">
      <table className="border-separate border-spacing-[2px]">
        <thead>
          <tr>
            <th />
            {days.map((d) => (
              <th key={d.activity_date} className="px-0.5 pb-1 align-bottom">
                <button onClick={() => onDay(d.activity_date)} className={`flex flex-col items-center ${d.activity_date === selected ? 'text-cyan' : 'text-ink-faint hover:text-ink'}`}>
                  <span className="t-code-sm">{d.activity_date.slice(5)}</span>
                  <span className="text-[10px]">{weekday(d.activity_date)}</span>
                </button>
              </th>
            ))}
            <th className="t-label pl-2 text-left">days</th>
          </tr>
        </thead>
        <tbody>
          {techniques.map((t) => (
            <tr key={t.technique_id}>
              <td className="pr-3">
                <button onClick={() => onTechnique(t.technique_id)} className="flex max-w-[300px] items-baseline gap-2 text-left hover:underline">
                  <span className="t-code text-prov-attack">{t.technique_id}</span>
                  <span className="truncate text-[12px] text-ink">{t.technique_name}</span>
                </button>
              </td>
              {days.map((d) => {
                const m = d.mappings.find((x) => x.status === 'mapped' && x.technique_id === t.technique_id)
                return (
                  <td key={d.activity_date} className="p-0">
                    <span
                      className={`flex h-6 w-11 items-center justify-center ${d.activity_date === selected ? 'outline outline-1 outline-cyan/60' : ''}`}
                      style={{ background: m ? (m.evidence === 'indicated' ? 'rgba(232,121,249,0.12)' : 'rgba(232,121,249,0.35)') : '#1E2638' }}
                      title={m ? `${d.activity_date}: rule ${m.rule_id}, ${m.evidence}, ${m.trigger_column} = ${m.trigger_value}` : `${d.activity_date}: ${STATUS_TEXT[d.status] ?? d.status}`}
                    >
                      {m && <span className={`h-2 w-2 ${m.evidence === 'indicated' ? 'border border-prov-attack' : 'bg-prov-attack'}`} />}
                    </span>
                  </td>
                )
              })}
              <td className="t-code-sm pl-2 text-ink-muted">{t.days}/{days.length}</td>
            </tr>
          ))}
          <tr>
            <td className="pr-3 pt-1 text-[12px] text-ink-faint">day status</td>
            {days.map((d) => (
              <td key={d.activity_date} className="p-0 pt-1 text-center">
                <span className={`font-mono text-[10px] ${d.status === 'mapped' ? 'text-prov-attack' : d.status === 'unmapped' ? 'text-ink-muted' : 'text-sev-medium-text'}`}>
                  {d.status === 'mapped' ? 'map' : d.status === 'unmapped' ? 'none' : 'n/e'}
                </span>
              </td>
            ))}
            <td />
          </tr>
        </tbody>
      </table>
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-ink-faint">
        <span className="flex items-center gap-1.5"><span className="h-2 w-2 bg-prov-attack" /> observed: CERT records the action</span>
        <span className="flex items-center gap-1.5"><span className="h-2 w-2 border border-prov-attack" /> indicated: CERT records a visit, not a transfer</span>
        <span>none: evaluated, nothing mapped · n/e: not evaluated</span>
      </div>
    </div>
  )
}

/** §27 "What contextual evidence supports the risk?": ATT&CK rows of the member days, read through the enrichment run. */
export default function MitreContextPage() {
  const { detail } = useAlertOutlet()
  const [member, select] = useSelectedDay(detail.members)
  const [tech, setTech] = useState<string | null>(null)
  const st = useApi(`mitre:${detail.alert.id}`, (s) => alertMitre(detail.alert.id, s))

  if (st.error) return <div className="panel"><ErrorPanel error={st.error} onRetry={st.reload} /></div>
  if (!st.data) return <div className="panel"><SkeletonRows rows={8} /></div>
  const d = st.data
  const day = d.days.find((x) => x.activity_date === member?.activity_date)
  const mapped = day?.mappings.filter((m) => m.status === 'mapped') ?? []
  const unmappedTags = [...new Set(day?.mappings.flatMap((m) => m.unmapped_behaviours ?? []) ?? [])]

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-start gap-2 rounded-[8px] border border-prov-attack/30 bg-prov-attack/[0.06] px-5 py-2.5">
        <Icon name="info" size={14} className="mt-0.5 shrink-0 text-prov-attack" />
        <p className="t-body-sm text-ink">{d.note}</p>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
        <Panel className="xl:col-span-8" title="Techniques by member day" meta={`${d.techniques.length} technique${d.techniques.length === 1 ? '' : 's'} on ${d.days.filter((x) => x.status === 'mapped').length} of ${d.days.length} days`}>
          {d.techniques.length ? (
            <TechniqueGrid days={d.days} techniques={d.techniques} selected={member?.activity_date} onDay={select} onTechnique={setTech} />
          ) : (
            <p className="t-body-sm p-5 text-ink-muted">No ATT&amp;CK technique is mapped on any member day of this alert. Each day&apos;s status is listed on the right.</p>
          )}
        </Panel>

        <Panel className="xl:col-span-4" title="Techniques" meta="days mapped">
          <ul>
            {d.techniques.map((t) => (
              <li key={t.technique_id}>
                <button onClick={() => setTech(t.technique_id)} className="grid w-full grid-cols-[auto_1fr_auto] items-center gap-3 border-b border-row-line px-5 py-2 text-left hover:bg-l2">
                  <span className="t-code text-prov-attack">{t.technique_id}</span>
                  <span className="flex min-w-0 flex-col leading-tight">
                    <span className="truncate text-[13px] text-ink">{t.technique_name}</span>
                    <span className="truncate text-[11px] text-ink-faint">{t.tactic}</span>
                  </span>
                  <span className="t-code-sm text-ink-muted">{t.days}d</span>
                </button>
              </li>
            ))}
            {d.techniques.length === 0 && <li className="t-body-sm p-5 text-ink-muted">None.</li>}
          </ul>
        </Panel>
      </div>

      <Panel title="Member day" meta={day ? STATUS_TEXT[day.status] ?? day.status : undefined}>
        <DayTabs members={detail.members} selected={member?.activity_date} onSelect={select} mark={(m) => {
          const s = d.days.find((x) => x.activity_date === m.activity_date)?.status
          return s === 'mapped' ? null : s === 'unmapped' ? 'nothing mapped' : 'not evaluated'
        }} />
        <div className="border-t border-line">
          {!day || day.status === 'not_evaluated' ? (
            <p className="t-body-sm p-5 text-ink-muted">
              No ATT&amp;CK row exists for this day in enrichment run {d.run.mitre_run_id ?? '(none)'}. It is shown as not evaluated, never filled in.
            </p>
          ) : (
            <>
              {mapped.map((m) => (
                <div key={m.id} className="grid grid-cols-1 gap-2 border-b border-row-line px-5 py-2.5 md:grid-cols-[minmax(0,1fr)_auto]">
                  <div className="flex min-w-0 flex-col gap-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <button onClick={() => setTech(m.technique_id as string)} className="t-code text-prov-attack hover:underline">{m.technique_id}</button>
                      <span className="text-[13px] text-ink">{m.technique_name}</span>
                      {m.tactic && <Tag>{m.tactic}</Tag>}
                      <EvidenceTag evidence={m.evidence} />
                    </div>
                    <span className="t-body-sm text-ink-muted">
                      Triggered by <span className="t-code-sm text-ink">{m.trigger_column}</span>
                      {m.trigger_column && <> ({columnLabel(m.trigger_column)})</>} = <span className="t-code-sm text-ink">{m.trigger_value ?? 'null'}</span>
                    </span>
                  </div>
                  <dl className="grid grid-cols-[auto_auto] gap-x-3 gap-y-0.5 self-start">
                    <dt className="t-code-sm text-ink-faint">rule</dt><dd className="t-code-sm text-ink">{m.rule_id}</dd>
                    <dt className="t-code-sm text-ink-faint">strength</dt><dd className="t-code-sm text-ink">{m.strength?.toFixed(2) ?? '—'}</dd>
                    <dt className="t-code-sm text-ink-faint">context</dt><dd className="t-code-sm text-ink">{m.mitre_context?.toFixed(3) ?? '—'}</dd>
                  </dl>
                </div>
              ))}
              {day.status === 'unmapped' && <p className="t-body-sm px-5 pt-3 text-ink-muted">The rules ran for this day and mapped no technique.</p>}
              {unmappedTags.length > 0 && (
                <div className="flex flex-wrap items-center gap-2 px-5 py-3">
                  <span className="t-label">Considered, no technique</span>
                  {unmappedTags.map((u) => <Tag key={u}>{u}</Tag>)}
                </div>
              )}
              {day.mappings[0] && (
                <p className="t-code-sm border-t border-line px-5 py-2 text-ink-ghost">
                  ruleset {day.mappings[0].ruleset_version}#{day.mappings[0].ruleset_hash.slice(0, 8)} · ATT&amp;CK {day.mappings[0].attack_version} · {day.mappings[0].mitre_run_id}
                </p>
              )}
            </>
          )}
        </div>
      </Panel>
      <TechniqueDrawer id={tech} onClose={() => setTech(null)} />
    </div>
  )
}
