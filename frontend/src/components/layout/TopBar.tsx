import { useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { Icon } from '@/components/ui/Icon'
import { useHealth } from '@/store/health'

/**
 * One plain status line instead of a row of codes: either everything the
 * console needs is ready, or the first thing that is not, with a link to
 * the System page for detail (N68). A user search sits on the right.
 */
export function TopBar() {
  const health = useHealth((s) => s.health)
  const error = useHealth((s) => s.error)
  const navigate = useNavigate()
  const [q, setQ] = useState('')

  const notReady = health ? Object.entries(health.routes).filter(([, r]) => !r.ready) : []
  const state: { tone: 'ok' | 'warn' | 'down'; text: string; detail?: string } = !health
    ? error ? { tone: 'down', text: 'Cannot reach the API', detail: 'Start the backend and this will update' } : { tone: 'warn', text: 'Checking the API…' }
    : notReady.length
      ? { tone: 'warn', text: `${notReady.length} service${notReady.length === 1 ? '' : 's'} not ready`, detail: notReady[0][1].reason ?? undefined }
      : { tone: 'ok', text: 'All services ready', detail: health.anomaly_model.served ? `Model ${health.anomaly_model.served.model_name} ${health.anomaly_model.served.registry_version}` : undefined }
  const dot = state.tone === 'ok' ? 'bg-sev-low' : state.tone === 'warn' ? 'bg-sev-medium' : 'bg-sev-critical'

  return (
    <header className="flex h-16 shrink-0 items-center gap-6 border-b border-line bg-canvas/95 px-8 backdrop-blur">
      <Link to="/system" className="flex min-w-0 items-center gap-3 rounded-lg px-2 py-1.5 hover:bg-l1" title={state.detail}>
        <span className={`h-2 w-2 shrink-0 rounded-full ${dot}`} aria-hidden="true" />
        <span className="text-[14px] font-medium text-ink">{state.text}</span>
        {state.detail && <span className="hidden truncate text-[13px] text-ink-faint lg:inline">{state.detail}</span>}
      </Link>
      {health?.routes.alerts_risk_investigations.alert_run_id && (
        <span className="hidden text-[13px] text-ink-faint xl:inline" title="The alert run every view reads from">
          Alert run <span className="t-code-sm text-ink-muted">{health.routes.alerts_risk_investigations.alert_run_id}</span>
        </span>
      )}
      <form
        className="relative ml-auto"
        onSubmit={(e) => {
          e.preventDefault()
          const v = q.trim()
          if (v) {
            navigate(`/users/${encodeURIComponent(v)}`)
            setQ('')
          }
        }}
      >
        <Icon name="search" size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-ink-faint" />
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          className="input w-72 !pl-9"
          placeholder="Find a user by ID, e.g. ACM2278"
          aria-label="Find a user by ID"
        />
      </form>
    </header>
  )
}
