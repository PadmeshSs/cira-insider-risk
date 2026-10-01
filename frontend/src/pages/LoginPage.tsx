import { zodResolver } from '@hookform/resolvers/zod'
import { useEffect, useState } from 'react'
import { useForm } from 'react-hook-form'
import { Navigate, useLocation, useNavigate } from 'react-router'
import { z } from 'zod'
import { Icon } from '@/components/ui/Icon'
import { useHealthPolling } from '@/hooks/useHealthPolling'
import { API_BASE_URL } from '@/services/client'
import { login, me } from '@/services/auth'
import { useAuth } from '@/store/auth'
import { useHealth } from '@/store/health'
import type { RouteReadiness } from '@/types/api'
import { toApiError } from '@/utils/errors'

const schema = z.object({
  username: z.string().trim().min(1, 'Enter your analyst username').max(64),
  password: z.string().min(1, 'Enter your password').max(256),
})
type Form = z.infer<typeof schema>

const ROUTE_LABEL: Record<string, string> = {
  auth: 'Sign-in',
  alerts_risk_investigations: 'Alerts, risk and investigations',
  anomaly_score: 'On-demand anomaly scoring',
  risk_score: 'On-demand risk scoring',
  mitre_techniques: 'ATT&CK technique lookup',
}

function Readiness() {
  const health = useHealth((s) => s.health)
  const error = useHealth((s) => s.error)
  if (!health && error) {
    return (
      <p className="t-body-sm text-sev-critical-text">
        The API at <span className="t-code-sm">{API_BASE_URL}</span> did not answer /health. Start the backend
        (uvicorn app.main:app --port 8000) and this page will update.
      </p>
    )
  }
  if (!health) return <p className="t-body-sm text-ink-faint">Checking the API…</p>
  const routes = Object.entries(health.routes) as [string, RouteReadiness][]
  return (
    <ul className="flex flex-col">
      {routes.map(([k, r]) => (
        <li key={k} className="flex items-start gap-2.5 border-b border-row-line py-2 last:border-0">
          <span className={`mt-1.5 inline-block h-1.5 w-1.5 shrink-0 rounded-full ${r.ready ? 'bg-sev-low' : 'bg-sev-critical'}`} />
          <div className="min-w-0">
            <div className="t-body-sm text-ink">{ROUTE_LABEL[k] ?? k}</div>
            {r.ready && r.alert_run_id && <div className="t-code-sm text-ink-faint">serving {r.alert_run_id}</div>}
            {!r.ready && r.reason && <div className="t-body-sm text-ink-muted">{r.reason}</div>}
          </div>
        </li>
      ))}
    </ul>
  )
}

export default function LoginPage() {
  useHealthPolling(15_000)
  const navigate = useNavigate()
  const location = useLocation()
  const { signIn, setAnalyst, isValid, endReason } = useAuth()
  const health = useHealth((s) => s.health)
  const [serverError, setServerError] = useState<string | null>(null)
  const { register, handleSubmit, formState, setFocus } = useForm<Form>({ resolver: zodResolver(schema) })

  useEffect(() => setFocus('username'), [setFocus])

  if (isValid()) return <Navigate to="/" replace />
  const from = (location.state as { from?: string } | null)?.from ?? '/'
  const authDown = health && !health.routes.auth.ready

  const onSubmit = async (v: Form) => {
    setServerError(null)
    try {
      const t = await login(v.username, v.password)
      signIn(t.access_token, t.expires_at)
      setAnalyst(await me())
      navigate(from, { replace: true })
    } catch (e) {
      const err = toApiError(e)
      useAuth.getState().signOut(null)
      setServerError(
        err.status === 401 ? 'Username or password is not correct.'
          : err.status === 503 ? `Sign-in is unavailable: ${err.message}`
            : err.message,
      )
    }
  }

  return (
    <div className="flex min-h-full items-center justify-center bg-canvas p-6">
      <div className="grid w-full max-w-[880px] grid-cols-1 overflow-hidden rounded-[8px] border border-line md:grid-cols-[1fr_340px]">
        <form onSubmit={handleSubmit(onSubmit)} className="flex flex-col gap-5 bg-l1 p-8" noValidate>
          <div className="flex items-center gap-3">
            <svg width="28" height="28" viewBox="0 0 32 32" aria-hidden="true">
              <path d="M8 22h4v-6H8zM14 22h4V10h-4zM20 22h4v-9h-4z" fill="#38BDF8" />
              <path d="M7 25h18" stroke="#EF4444" strokeWidth="2" />
            </svg>
            <div>
              <h1 className="t-headline-lg text-ink-strong">CIRA analyst console</h1>
              <p className="t-body-sm text-ink-muted">Insider risk on CERT r4.2: scores, context and reasons</p>
            </div>
          </div>

          {endReason && !serverError && (
            <p className="t-body-sm rounded-sm border border-line-strong bg-l2 px-3 py-2 text-ink">{endReason}</p>
          )}

          <label className="flex flex-col gap-1.5">
            <span className="t-label">Username</span>
            <input className="input" autoComplete="username" {...register('username')} aria-invalid={Boolean(formState.errors.username)} />
            {formState.errors.username && <span className="t-body-sm text-sev-critical-text">{formState.errors.username.message}</span>}
          </label>
          <label className="flex flex-col gap-1.5">
            <span className="t-label">Password</span>
            <input className="input" type="password" autoComplete="current-password" {...register('password')} aria-invalid={Boolean(formState.errors.password)} />
            {formState.errors.password && <span className="t-body-sm text-sev-critical-text">{formState.errors.password.message}</span>}
          </label>

          {serverError && (
            <p role="alert" className="t-body-sm flex items-start gap-2 rounded-sm border border-sev-critical/60 bg-sev-critical-tint px-3 py-2 text-sev-critical-text">
              <Icon name="warn" size={14} className="mt-0.5 shrink-0" /> {serverError}
            </p>
          )}

          <button type="submit" className="btn btn-primary justify-center" disabled={formState.isSubmitting || Boolean(authDown)}>
            {formState.isSubmitting ? 'Signing in…' : 'Sign in'}
          </button>
          <p className="t-body-sm text-ink-faint">
            Accounts are created by an administrator from the command line. There is no self-registration, and every sign-in
            attempt is recorded in the audit log.
          </p>
        </form>

        <aside className="flex flex-col gap-3 border-t border-line bg-ground p-6 md:border-l md:border-t-0">
          <span className="t-label">API readiness</span>
          <Readiness />
          <span className="t-code-sm mt-auto break-all text-ink-ghost">{API_BASE_URL}</span>
        </aside>
      </div>
    </div>
  )
}
