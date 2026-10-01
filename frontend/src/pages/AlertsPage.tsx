import { useSearchParams } from 'react-router'
import { AlertTable } from '@/components/common/AlertTable'
import { LineageChain } from '@/components/common/Lineage'
import { PageHeader } from '@/components/common/PageHeader'
import { Icon } from '@/components/ui/Icon'
import { Pager } from '@/components/ui/Pager'
import { Seg } from '@/components/ui/Seg'
import { Empty, ErrorPanel, SkeletonRows } from '@/components/ui/States'
import { SEVERITIES } from '@/constants/severity'
import { useApi } from '@/hooks/useApi'
import { listAlerts } from '@/services/alerts'
import type { Severity } from '@/types/api'

const PAGE = 50

function FilterGroup({ label, children, className = '' }: { label: string; children: React.ReactNode; className?: string }) {
  return (
    <div className={`flex flex-col gap-2 ${className}`}>
      <span className="text-[12px] font-medium text-ink-faint">{label}</span>
      {children}
    </div>
  )
}

/** The analyst queue (§27 "What happened?"): correlated incidents, the policy's order, filters in the URL. */
export default function AlertsPage() {
  const [sp, setSp] = useSearchParams()
  const status = (sp.get('status') as 'open' | 'suppressed' | 'all') || 'open'
  const sort = (sp.get('sort') as 'queue' | 'recent') || 'queue'
  const severity = (sp.get('severity') as Severity | null) || null
  const user = sp.get('user') || ''
  const offset = Number(sp.get('offset') || 0)

  const set = (patch: Record<string, string | null>) => {
    const next = new URLSearchParams(sp)
    for (const [k, v] of Object.entries(patch)) {
      if (v === null || v === '') next.delete(k)
      else next.set(k, v)
    }
    if (!('offset' in patch)) next.delete('offset')
    setSp(next, { replace: true })
  }

  const key = `alerts:${status}:${sort}:${severity ?? ''}:${user}:${offset}`
  const q = useApi(key, (s) => listAlerts({ status, sort, severity, user_id: user || null, limit: PAGE, offset }, s))
  const d = q.data

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Alerts"
        sub={
          d
            ? `${d.counts.open} open alerts and ${d.counts.suppressed} repeats. Related days of one user are grouped into a single alert; open one to see why it was raised.`
            : 'Related days of one user grouped into a single alert.'
        }
      />

      <div className="panel flex flex-wrap items-end gap-x-6 gap-y-4 p-5">
        <FilterGroup label="Show">
        <Seg
          label="Status"
          value={status}
          onChange={(v) => set({ status: v })}
          options={[
            { value: 'open', label: 'Open' },
            { value: 'suppressed', label: 'Repeats', title: 'Suppressed alerts: repeats of an open alert inside its cooldown. Kept, not resolved.' },
            { value: 'all', label: 'All' },
          ]}
        />
        </FilterGroup>
        <FilterGroup label="Severity">
        <Seg
          label="Highest band"
          value={(severity ?? 'ANY') as Severity | 'ANY'}
          onChange={(v) => set({ severity: v === 'ANY' ? null : v })}
          options={[{ value: 'ANY' as const, label: 'Any' }, ...SEVERITIES.map((s) => ({ value: s, label: s.charAt(0) + s.slice(1).toLowerCase() }))]}
        />
        </FilterGroup>
        <FilterGroup label="Order">
        <Seg
          label="Sort"
          value={sort}
          onChange={(v) => set({ sort: v })}
          options={[
            { value: 'queue', label: 'Most unusual first', title: 'The alert policy order: model score, highest first' },
            { value: 'recent', label: 'Newest first', title: 'By first day, newest first' },
          ]}
        />
        </FilterGroup>
        <FilterGroup label="User" className="ml-auto">
        <form
          className="relative"
          onSubmit={(e) => {
            e.preventDefault()
            const v = new FormData(e.currentTarget).get('user')
            set({ user: String(v ?? '').trim() })
          }}
        >
          <Icon name="search" size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-ink-faint" />
          <input name="user" defaultValue={user} key={user} className="input w-60 !pl-9" placeholder="User ID, then Enter" aria-label="Filter by user id" />
        </form>
        </FilterGroup>
        {(severity || user || status !== 'open' || sort !== 'queue') && (
          <button className="btn btn-ghost" onClick={() => setSp(new URLSearchParams(), { replace: true })}>Clear filters</button>
        )}
      </div>

      <div className="panel">
        {q.error ? (
          <ErrorPanel error={q.error} onRetry={q.reload} />
        ) : !d ? (
          <SkeletonRows rows={10} height={56} />
        ) : d.items.length === 0 ? (
          <Empty title="No alerts match these filters">Clear a filter to widen the list.</Empty>
        ) : (
          <>
            <AlertTable items={d.items} rankOffset={sort === 'queue' ? offset : 0} showRank={sort === 'queue' && status === 'open'} />
            <Pager page={d.page} onOffset={(o) => set({ offset: String(o) })} />
          </>
        )}
      </div>
      {d && (
        <details className="panel">
          <summary className="cursor-pointer list-none px-5 py-3 text-[13px] text-ink-faint hover:text-ink-muted">Where these numbers come from</summary>
          <LineageChain run={d.run} />
        </details>
      )}
    </div>
  )
}
