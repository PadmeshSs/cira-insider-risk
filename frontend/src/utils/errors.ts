import { isAxiosError } from 'axios'

/** An API failure, normalised from `{"detail": {"code", "message", "component"}}` (app/api/errors.py). */
export class ApiError extends Error {
  status: number
  code: string
  component: string | null

  constructor(status: number, code: string, message: string, component: string | null = null) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.component = component
  }
}

function fromDetail(status: number, detail: unknown): ApiError {
  if (detail && typeof detail === 'object' && !Array.isArray(detail)) {
    const d = detail as { code?: string; message?: string; component?: string }
    return new ApiError(status, d.code ?? 'error', d.message ?? `HTTP ${status}`, d.component ?? null)
  }
  if (Array.isArray(detail)) {
    // FastAPI request validation (422): list of {loc, msg}
    const msg = detail
      .map((x: { loc?: unknown[]; msg?: string }) => `${(x.loc ?? []).slice(1).join('.')}: ${x.msg ?? ''}`)
      .join('; ')
    return new ApiError(status, 'invalid_input', msg || 'Request rejected')
  }
  if (typeof detail === 'string') return new ApiError(status, status === 401 ? 'unauthorized' : 'error', detail)
  return new ApiError(status, 'error', `HTTP ${status}`)
}

export function toApiError(err: unknown): ApiError {
  if (err instanceof ApiError) return err
  if (isAxiosError(err)) {
    if (err.response) {
      const body = err.response.data as { detail?: unknown } | undefined
      return fromDetail(err.response.status, body?.detail)
    }
    if (err.code === 'ERR_CANCELED') return new ApiError(0, 'canceled', 'Request canceled')
    return new ApiError(0, 'network', 'The API did not answer. Check that the backend is running and reachable.')
  }
  return new ApiError(0, 'error', err instanceof Error ? err.message : String(err))
}

export function isCanceled(err: unknown): boolean {
  return err instanceof ApiError && err.code === 'canceled'
}
