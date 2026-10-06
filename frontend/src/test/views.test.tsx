/**
 * Chapter 15, component level (Bible Ch15 step 2): a view renders what the API
 * returned and nothing when the API fails.
 *
 * The axios adapter is replaced so no network is touched. The values below are
 * test inputs, made up here on purpose and recognisable (user TESTU0042,
 * run test-run-ch15); the assertions check they travel from the response to
 * the screen, and that they are absent when the response is an error. This
 * file is the only place they exist (no-fixtures.test.ts checks that the app
 * never imports from src/test).
 */
import { render, screen, waitFor } from '@testing-library/react'
import type { AxiosAdapter, InternalAxiosRequestConfig } from 'axios'
import { AxiosError } from 'axios'
import { MemoryRouter } from 'react-router'
import { afterEach, beforeAll, describe, expect, it } from 'vitest'
import { clearApiCache } from '@/hooks/useApi'
import OverviewPage from '@/pages/OverviewPage'
import { http } from '@/services/client'
import type { Overview } from '@/types/api'

const RUN = {
  alert_run_id: 'test-run-ch15', policy_version: 'c12-alert-policy-v1', policy_hash: 'h', model_version: 'test-model',
  registry_version: 'v0001', batch_run_id: 'b', cri_run_id: 'c', explain_run_id: 'e', mitre_run_id: null,
}
const OVERVIEW: Overview = {
  counts: { open: 7, suppressed: 2 },
  open_by_severity: { LOW: 5, MEDIUM: 2, HIGH: 0, CRITICAL: 0 },
  open_by_split: { test: 7 },
  open_never_above_low: 5,
  top_features: [{ feature: 'usb_connect_count', open_alerts: 3 }],
  open_led_by_usb_disconnect_count: 0,
  new_open_alerts: [{ start: '2010-01-04', end: '2010-01-10', count: 7 }],
  top_users: [{ user_id: 'TESTU0042', open_alerts: 2, suppressed_alerts: 1, max_queue_score: 0.8761, max_severity: 'MEDIUM', model_split: 'test', in_sample: false }],
  queue: { ordered_by: 'anomaly_score', policy_version: 'c12-alert-policy-v1', policy_hash: 'h', sort: 'queue', context: '' },
  run: RUN,
}
const ALERTS = { items: [], page: { total: 0, limit: 6, offset: 0, max_limit: 200 }, counts: { open: 7, suppressed: 2 }, queue: OVERVIEW.queue, run: RUN }

const original = http.defaults.adapter

function respond(byPath: Record<string, unknown>): AxiosAdapter {
  return async (config: InternalAxiosRequestConfig) => {
    const path = String(config.url)
    if (!(path in byPath)) throw new Error(`unexpected request ${path}`)
    return { data: byPath[path], status: 200, statusText: 'OK', headers: {}, config }
  }
}

const refuse: AxiosAdapter = async (config) => {
  throw new AxiosError('Network Error', 'ERR_NETWORK', config)
}

function renderOverview() {
  return render(<MemoryRouter><OverviewPage /></MemoryRouter>)
}

beforeAll(() => {
  // Recharts' ResponsiveContainer needs ResizeObserver, which jsdom lacks.
  globalThis.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} } as unknown as typeof ResizeObserver
})

afterEach(() => {
  http.defaults.adapter = original
  clearApiCache()
})

describe('Overview renders the API response and only the API response', () => {
  it('shows the user, score and run id the API sent', async () => {
    http.defaults.adapter = respond({ '/risk/overview': OVERVIEW, '/alerts': ALERTS })
    const { container } = renderOverview()
    await waitFor(() => expect(screen.getByText('TESTU0042')).toBeInTheDocument())
    expect(screen.getByText('0.876')).toBeInTheDocument()
    expect(container.textContent).toContain('test-run-ch15')
  })

  it('shows an error and none of those values when the API is unreachable', async () => {
    http.defaults.adapter = refuse
    const { container } = renderOverview()
    await waitFor(() => expect(screen.getByText('API not reachable')).toBeInTheDocument())
    for (const v of ['TESTU0042', '0.876', 'test-run-ch15']) expect(container.textContent).not.toContain(v)
  })

  it('shows the readiness reason, not an empty page, when the API answers 503', async () => {
    http.defaults.adapter = async (config) => {
      throw new AxiosError('503', 'ERR_BAD_RESPONSE', config, undefined, {
        status: 503, statusText: '', headers: {}, config,
        data: { detail: { code: 'unavailable', component: 'alerts', message: 'no alert run is loaded in the database' } },
      })
    }
    renderOverview()
    await waitFor(() => expect(screen.getByText('no alert run is loaded in the database')).toBeInTheDocument())
    expect(screen.queryByText('TESTU0042')).not.toBeInTheDocument()
  })
})
