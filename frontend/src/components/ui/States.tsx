import type { ReactNode } from 'react'
import { useHealth } from '@/store/health'
import type { ApiError } from '@/utils/errors'
import { Icon } from './Icon'

export function SkeletonRows({ rows = 6, height = 34 }: { rows?: number; height?: number }) {
  return (
    <div className="flex flex-col gap-px p-2" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="skeleton" style={{ height: height - 6, opacity: 1 - i * (0.6 / rows) }} />
      ))}
    </div>
  )
}

export function SkeletonBlock({ height = 120, className = '' }: { height?: number; className?: string }) {
  return <div className={`skeleton ${className}`} style={{ height }} aria-busy="true" aria-label="Loading" />
}

const COMPONENT_TO_ROUTE: Record<string, keyof NonNullable<ReturnType<typeof useHealth.getState>['health']>['routes']> = {
  alerts: 'alerts_risk_investigations',
  database: 'alerts_risk_investigations',
  anomaly_model: 'anomaly_score',
  cri: 'risk_score',
  mitre: 'mitre_techniques',
  auth: 'auth',
}

/**
 * An API failure, said plainly: what failed and what fixes it. For a 503 the
 * /health routes block is read so the message names the missing component
 * instead of a generic error (N68).
 */
export function ErrorPanel({ error, onRetry, compact = false }: { error: ApiError; onRetry?: () => void; compact?: boolean }) {
  const health = useHealth((s) => s.health)
  const routeKey = error.component ? COMPONENT_TO_ROUTE[error.component] : error.status === 503 ? 'alerts_risk_investigations' : undefined
  const route = routeKey && health ? health.routes[routeKey] : undefined
  const title =
    error.status === 0 ? 'API not reachable'
      : error.status === 404 ? 'Not in the served run'
        : error.status === 409 ? 'Run belongs to another model'
          : error.status === 503 ? `Not ready${error.component ? `: ${error.component.replace(/_/g, ' ')}` : ''}`
            : error.status === 422 ? 'Request rejected'
              : `Request failed (${error.status})`
  return (
    <div className={`flex gap-3 ${compact ? 'p-3' : 'p-5'}`} role="alert">
      <Icon name="warn" className="mt-0.5 shrink-0 text-sev-medium" />
      <div className="flex min-w-0 flex-col gap-1.5">
        <span className="t-headline-sm text-ink-strong">{title}</span>
        <p className="t-body-sm max-w-[72ch] text-ink-muted">{error.message}</p>
        {route && !route.ready && route.reason && route.reason !== error.message && (
          <p className="t-body-sm max-w-[72ch] text-ink-muted">
            <span className="text-ink-faint">Readiness from /health: </span>
            {route.reason}
          </p>
        )}
        <span className="t-code-sm text-ink-ghost">code {error.code}{error.status ? ` · HTTP ${error.status}` : ''}</span>
        {onRetry && (
          <div className="pt-1">
            <button className="btn btn-secondary" onClick={onRetry}>
              <Icon name="refresh" size={14} /> Try again
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col gap-1 p-5">
      <span className="t-headline-sm text-ink">{title}</span>
      {children && <div className="t-body-sm max-w-[72ch] text-ink-muted">{children}</div>}
    </div>
  )
}

/** Render loading / error / data for one useApi state. */
export function Load<T>({ state, children, skeleton }: {
  state: { data: T | null; error: ApiError | null; loading: boolean; reload: () => void }
  children: (data: T) => ReactNode
  skeleton?: ReactNode
}) {
  if (state.error) return <ErrorPanel error={state.error} onRetry={state.reload} />
  if (state.data === null) return <>{skeleton ?? <SkeletonRows />}</>
  return <>{children(state.data)}</>
}
