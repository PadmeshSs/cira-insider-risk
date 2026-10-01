import { useCallback, useEffect, useRef, useState } from 'react'
import { type ApiError, isCanceled, toApiError } from '@/utils/errors'

/**
 * Fetch one API resource for a view. `key` identifies the request (null skips
 * it); results are kept for a short time so moving between the tabs of one
 * alert does not refetch. Every value shown comes from this call, never from
 * a fixture.
 */
const cache = new Map<string, { at: number; data: unknown }>()
const TTL_MS = 60_000

function fresh<T>(key: string | null): T | undefined {
  if (!key) return undefined
  const hit = cache.get(key)
  return hit && Date.now() - hit.at < TTL_MS ? (hit.data as T) : undefined
}

export interface ApiState<T> {
  data: T | null
  error: ApiError | null
  loading: boolean
  reload: () => void
}

interface Settled<T> {
  key: string
  nonce: number
  data: T | null
  error: ApiError | null
}

export function useApi<T>(key: string | null, fetcher: (signal: AbortSignal) => Promise<T>): ApiState<T> {
  const [nonce, setNonce] = useState(0)
  const [res, setRes] = useState<Settled<T> | null>(null)
  const fetcherRef = useRef(fetcher)
  useEffect(() => {
    fetcherRef.current = fetcher
  })

  const cached = nonce === 0 ? fresh<T>(key) : undefined

  useEffect(() => {
    if (!key) return
    if (nonce === 0 && fresh<T>(key) !== undefined) return
    const ctrl = new AbortController()
    fetcherRef
      .current(ctrl.signal)
      .then((data) => {
        cache.set(key, { at: Date.now(), data })
        setRes({ key, nonce, data, error: null })
      })
      .catch((err) => {
        const e = toApiError(err)
        if (!isCanceled(e)) setRes({ key, nonce, data: null, error: e })
      })
    return () => ctrl.abort()
  }, [key, nonce])

  const reload = useCallback(() => {
    if (key) cache.delete(key)
    setNonce((n) => n + 1)
  }, [key])

  const settled = res && res.key === key && res.nonce === nonce ? res : null
  const previous = res && res.key === key ? res.data : null
  const data = settled ? settled.data : (cached ?? previous ?? null)
  return {
    data,
    error: settled?.error ?? null,
    loading: Boolean(key) && !settled && cached === undefined,
    reload,
  }
}

export function clearApiCache() {
  cache.clear()
}
