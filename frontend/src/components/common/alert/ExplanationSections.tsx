import { Link } from 'react-router'
import { COMPONENT_META } from '@/constants/cri'
import { Tag } from '@/components/ui/Tag'
import type { AttackContext, ContextFactor, ModelFactor } from '@/types/api'
import { fmtCri, fmtSigned } from '@/utils/format'

/** Section frame with its provenance colour, so a CRI point or a technique never reads as a model reason (N50). */
export function Section({ color, title, kicker, children, count }: {
  color: string
  title: string
  kicker: string
  count?: number
  children: React.ReactNode
}) {
  return (
    <section className="panel overflow-hidden" style={{ borderLeft: `3px solid ${color}` }}>
      <header className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 border-b border-line px-5 py-2">
        <h3 className="t-headline-sm text-ink-strong">{title}</h3>
        <span className="t-body-sm text-ink-faint">{kicker}</span>
        {count !== undefined && <span className="t-code-sm ml-auto text-ink-faint">{count} item{count === 1 ? '' : 's'}</span>}
      </header>
      {children}
    </section>
  )
}

/**
 * Raising and lowering TreeSHAP factors on one log-odds axis centred on zero.
 * Bars grow right for factors that raised the score and left for those that
 * lowered it; the text beside each is the stored analyst wording.
 */
export function ModelFactors({ raising, lowering }: { raising: ModelFactor[]; lowering: ModelFactor[] }) {
  const all = [...raising, ...lowering]
  const max = Math.max(0.01, ...all.map((f) => Math.abs(f.contribution)))
  if (!all.length) return <p className="t-body-sm p-5 text-ink-muted">No model factor stored for this day.</p>
  const Row = ({ f, i }: { f: ModelFactor; i: number | null }) => {
    const w = (50 * Math.abs(f.contribution)) / max
    const up = f.contribution > 0
    return (
      <li className="grid grid-cols-[22px_minmax(0,1.3fr)_minmax(140px,1fr)_64px] items-center gap-3 border-b border-row-line px-5 py-2 last:border-0">
        <span className="t-code-sm text-ink-faint">{i ?? ''}</span>
        <span className="flex min-w-0 flex-col gap-0.5 leading-tight">
          <span className="text-[13px] text-ink">{f.text}</span>
          <span className="t-code-sm truncate text-ink-faint" title={f.feature}>
            {f.feature} = {f.value_text}
          </span>
        </span>
        <span className="relative h-3" aria-hidden="true">
          <span className="absolute inset-y-0 left-1/2 w-px bg-line-float" />
          <span
            className="absolute inset-y-0.5"
            style={up ? { left: '50%', width: `${w}%`, background: '#38BDF8' } : { right: '50%', width: `${w}%`, background: '#64748B' }}
          />
        </span>
        <span className={`t-code text-right ${up ? 'text-cyan' : 'text-ink-muted'}`}>{fmtSigned(f.contribution)}</span>
      </li>
    )
  }
  return (
    <div>
      <div className="grid grid-cols-[22px_minmax(0,1.3fr)_minmax(140px,1fr)_64px] gap-3 px-5 pt-2 text-[11px] text-ink-faint">
        <span />
        <span>Factor and the value it read</span>
        <span className="flex justify-between"><span>lowered</span><span>0</span><span>raised</span></span>
        <span className="text-right">log-odds</span>
      </div>
      <ul>
        {raising.map((f, i) => <Row key={`r-${f.feature}`} f={f} i={f.rank ?? i + 1} />)}
      </ul>
      {lowering.length > 0 && (
        <>
          <div className="t-label border-t border-line px-5 pb-1 pt-2">Lowered the score most</div>
          <ul>{lowering.map((f) => <Row key={`l-${f.feature}`} f={f} i={null} />)}</ul>
        </>
      )}
    </div>
  )
}

export function ContextFactors({ items }: { items: ContextFactor[] }) {
  if (!items.length) return <p className="t-body-sm p-5 text-ink-muted">No context component added points beyond the anomaly score on this day.</p>
  return (
    <ul>
      {items.map((c) => {
        const meta = COMPONENT_META[c.component]
        return (
          <li key={c.component} className="grid grid-cols-[minmax(0,1fr)_120px_60px] items-center gap-3 border-b border-row-line px-5 py-2 last:border-0">
            <span className="flex min-w-0 items-start gap-2">
              <span className="mt-1 h-2 w-2 shrink-0" style={{ background: meta?.color ?? '#818CF8' }} />
              <span className="flex min-w-0 flex-col leading-tight">
                <span className="text-[13px] text-ink">{c.text}</span>
                {c.source.detail_column && <span className="t-code-sm text-ink-faint">{c.source.detail_column}</span>}
              </span>
            </span>
            <span className="relative h-1.5 bg-l2" title="Points on the 0-100 CRI scale">
              <span className="absolute inset-y-0 left-0" style={{ width: `${Math.min(100, c.points)}%`, background: meta?.color ?? '#818CF8' }} />
            </span>
            <span className="t-code text-right text-indigo">{fmtCri(c.points)}</span>
          </li>
        )
      })}
    </ul>
  )
}

export function AttackSection({ ctx, onTechnique, mitreHref }: { ctx: AttackContext | null; onTechnique: (id: string) => void; mitreHref: string }) {
  if (!ctx) return <p className="t-body-sm p-5 text-ink-muted">No ATT&amp;CK section stored for this day.</p>
  return (
    <div className="flex flex-col">
      {ctx.matches.map((m) => (
        <div key={`${m.rule_id}-${m.technique_id}`} className="flex flex-col gap-1.5 border-b border-row-line px-5 py-2.5">
          <div className="flex flex-wrap items-center gap-2">
            <button className="font-mono text-[13px] text-prov-attack hover:underline" onClick={() => onTechnique(m.technique_id)}>{m.technique_id}</button>
            <span className="text-[13px] text-ink">{m.technique_name}</span>
            {m.tactic && <Tag>{m.tactic}</Tag>}
            <EvidenceTag evidence={m.evidence} />
            <span className="t-code-sm ml-auto text-ink-faint">rule {m.rule_id}{m.strength !== null ? ` · strength ${m.strength.toFixed(2)}` : ''}</span>
          </div>
          <span className="t-body-sm text-ink-muted">{m.text}</span>
        </div>
      ))}
      {ctx.status === 'unmapped' && ctx.matches.length === 0 && <p className="t-body-sm px-5 pt-2.5 text-ink-muted">No ATT&amp;CK technique mapped for this day.</p>}
      {ctx.status === 'not_evaluated' && <p className="t-body-sm px-5 pt-2.5 text-ink-muted">The ATT&amp;CK rules could not be evaluated for this day because their columns are null.</p>}
      {ctx.status === 'not_joined' && <p className="t-body-sm px-5 pt-2.5 text-ink-muted">{ctx.text.join(' ')}</p>}
      {ctx.unmapped_behaviours.length > 0 && (
        <div className="flex flex-col gap-1.5 px-5 py-2.5">
          <span className="t-label">Considered, no technique</span>
          {ctx.unmapped_behaviours.map((u) => (
            <span key={u.behaviour} className="t-body-sm text-ink-muted">
              <span className="t-code-sm text-ink">{u.behaviour}</span>
              {u.reason ? `: ${u.reason}` : ''}
            </span>
          ))}
        </div>
      )}
      <div className="px-5 pb-2.5 pt-1">
        <Link to={mitreHref} className="t-body-sm link">Open the ATT&amp;CK view of all member days</Link>
      </div>
    </div>
  )
}

/** `indicated` is a visit CERT recorded, never a transfer (N9, N45). */
export function EvidenceTag({ evidence }: { evidence: string | null }) {
  if (evidence === 'indicated')
    return <Tag tone="warn" title="CERT records the visit, not what was sent or received">indicated</Tag>
  if (evidence === 'observed') return <Tag tone="attack" title="CERT records this action">observed</Tag>
  return evidence ? <Tag>{evidence}</Tag> : null
}
