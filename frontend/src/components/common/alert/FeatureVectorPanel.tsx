import { useMemo, useState } from 'react'
import { Seg } from '@/components/ui/Seg'
import { Tag } from '@/components/ui/Tag'
import type { FeatureValue, FeatureVector } from '@/types/api'

const DOMAIN_ORDER = ['logon', 'device', 'file', 'email', 'http', 'calendar', 'context', 'peer', 'history', 'static']

/**
 * The stored Chapter 5 vector of the day, each value described by the API.
 * Columns the explanation names are marked, so the analyst can read a reason
 * next to the raw value it came from. Static traits are marked and are never
 * model inputs of the served behaviour-only model (N25).
 */
export function FeatureVectorPanel({ fv, highlight }: { fv: FeatureVector; highlight: Map<string, number> }) {
  const [scope, setScope] = useState<'inputs' | 'named' | 'all'>('named')
  const [q, setQ] = useState('')
  const groups = useMemo(() => {
    const term = q.trim().toLowerCase()
    const pick = (v: FeatureValue) =>
      (scope === 'all' || (scope === 'inputs' ? v.model_input : highlight.has(v.column) || (v.model_input && v.value !== null && v.value !== 0))) &&
      (!term || v.column.toLowerCase().includes(term) || v.label.toLowerCase().includes(term))
    const by = new Map<string, FeatureValue[]>()
    for (const v of fv.values.filter(pick)) {
      const list = by.get(v.domain) ?? []
      list.push(v)
      by.set(v.domain, list)
    }
    const rank = (d: string) => (DOMAIN_ORDER.includes(d) ? DOMAIN_ORDER.indexOf(d) : 99)
    return [...by.entries()].sort((a, b) => rank(a[0]) - rank(b[0]) || a[0].localeCompare(b[0]))
  }, [fv, scope, q, highlight])

  const shown = groups.reduce((a, [, v]) => a + v.length, 0)

  return (
    <div className="flex flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-line px-5 py-2">
        <Seg
          label="Columns shown"
          value={scope}
          onChange={setScope}
          options={[
            { value: 'named', label: 'Active inputs', title: 'Model inputs with a non-zero value, and every column the explanation names' },
            { value: 'inputs', label: 'All model inputs' },
            { value: 'all', label: `All ${fv.values.length}` },
          ]}
        />
        <input className="input !h-7 w-48" placeholder="Filter columns" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter columns" />
        <span className="t-code-sm ml-auto text-ink-faint">
          {shown} shown · {fv.model_inputs} model inputs · {fv.profile} · {fv.features_fingerprint.slice(0, 10)}
        </span>
      </div>
      <div className="max-h-[420px] overflow-y-auto">
        {groups.length === 0 && <p className="t-body-sm p-5 text-ink-muted">No column matches.</p>}
        {groups.map(([domain, values]) => (
          <div key={domain}>
            <div className="sticky top-0 z-[1] flex items-center gap-2 border-b border-line bg-l1 px-5 py-1">
              <span className="t-label">{domain}</span>
              <span className="t-code-sm text-ink-ghost">{values.length}</span>
            </div>
            <ul>
              {values.map((v) => {
                const c = highlight.get(v.column)
                return (
                  <li key={v.column} className={`grid grid-cols-[1fr_auto] items-center gap-3 border-b border-row-line px-5 py-1.5 ${c !== undefined ? 'bg-cyan/[0.05]' : ''}`}>
                    <span className="flex min-w-0 flex-col leading-tight">
                      <span className="truncate text-[13px] text-ink" title={v.label}>{v.label}</span>
                      <span className="t-code-sm truncate text-ink-faint">{v.column}</span>
                    </span>
                    <span className="flex items-center gap-2">
                      {c !== undefined && (
                        <Tag tone={c > 0 ? 'cyan' : 'neutral'} title="TreeSHAP contribution of this column on this day, in log-odds">
                          {c > 0 ? '+' : ''}{c.toFixed(2)}
                        </Tag>
                      )}
                      {v.static && <Tag title="Per-user trait, not behaviour; never presented as a reason (N22)">static</Tag>}
                      {!v.model_input && !v.static && <span className="t-code-sm text-ink-ghost" title="The served model does not read this column">not an input</span>}
                      <span className={`t-code min-w-[72px] text-right ${v.value === null ? 'text-ink-ghost' : 'text-ink-strong'}`} title={v.value_text}>
                        {v.value === null ? 'null' : v.value_text.length <= 14 ? v.value_text : v.value.toFixed(3)}
                      </span>
                    </span>
                  </li>
                )
              })}
            </ul>
          </div>
        ))}
      </div>
    </div>
  )
}
