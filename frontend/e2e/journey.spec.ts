import { expect, test } from '@playwright/test'
import { API, apiClient, manifest, pageText, settled, signIn } from './stack'

/** The run-through record the Bible's Chapter 15 checklist asks for: one screenshot per view. */
const shot = (page: import('@playwright/test').Page, name: string) =>
  page.screenshot({ path: `test-results/ch15-run-through/${name}.png`, fullPage: true })

/**
 * Chapter 15: the last hops of the chain, PostgreSQL -> API -> dashboard, in a browser.
 * Every expected value is read from the API in the same test, never written here,
 * so a screen that showed a fixture would fail.
 */
const m = manifest()
const t = m.trace

interface AlertItem { id: number; alert_key: string; user_id: string; queue_score: number; peak_date: string; techniques: string[] }

test.describe.configure({ mode: 'serial' })

test('every request the dashboard makes goes to the CIRA API or the app itself', async ({ page }) => {
  const hosts = new Set<string>()
  page.on('request', (r) => hosts.add(new URL(r.url()).host))
  await signIn(page, m)
  await settled(page)
  for (const h of hosts) expect([new URL(API).host, new URL(page.url()).host]).toContain(h)
})

test('Overview: who is risky, from /risk/overview', async ({ page, request }) => {
  const get = await apiClient(request, m)
  const ov = await get<{ counts: { open: number; suppressed: number }; top_users: { user_id: string; max_queue_score: number }[]; run: { alert_run_id: string } }>('/risk/overview')
  await signIn(page, m)
  await settled(page)
  const text = await pageText(page)
  for (const u of ov.top_users) expect(text).toContain(u.user_id.toLowerCase())
  expect(ov.top_users.map((u) => u.user_id)).toContain(t.user_id)
  await expect(page.getByText('Open alerts', { exact: true }).locator('..')).toContainText(String(ov.counts.open))
  expect(text).toContain(ov.run.alert_run_id.toLowerCase())                     // "Where these numbers come from"
  expect(ov.run.alert_run_id).toBe(m.alert_run_id)
  await shot(page, '1-overview')
})

test('Alerts: what happened, the queue in policy order', async ({ page, request }) => {
  const get = await apiClient(request, m)
  const q = await get<{ items: AlertItem[] }>('/alerts', { status: 'open', sort: 'queue', limit: 50, offset: 0 })
  await signIn(page, m)
  await page.goto('/alerts')
  await settled(page)
  const rows = page.locator('table.grid-table tbody tr')
  await expect(rows.first()).toContainText(`#${q.items[0].id}`)
  await expect(rows.first()).toContainText(q.items[0].queue_score.toFixed(3))
  expect(q.items[0].alert_key).toBe(t.alert_key)                                // the traced alert heads the queue
  const shown = await rows.count()
  expect(shown).toBe(Math.min(q.items.length, 50))
  await shot(page, '2-alerts')
})

test('Alert details: how risky, and the stored decision reproduces on demand', async ({ page, request }) => {
  const get = await apiClient(request, m)
  const q = await get<{ items: AlertItem[] }>('/alerts', { status: 'open', sort: 'queue', limit: 1, offset: 0 })
  const a = q.items[0]
  const risk = await get<{ cri_score: number; severity: string; anomaly_score: number }>(`/risk/users/${a.user_id}/days/${a.peak_date}`)
  await signIn(page, m)
  await page.goto(`/alerts/${a.id}`)
  await settled(page)
  await expect(page.locator('h1')).toContainText(`#${a.id}`)
  const text = await pageText(page)
  expect(text).toContain(risk.severity.toLowerCase())
  await page.getByRole('button', { name: /Re-score this day/ }).click()
  await expect(page.getByText('The stored decision reproduces from its stored inputs.')).toBeVisible()
  await expect(page.getByText(/persisted: false/)).toBeVisible()
  await page.getByText('The stored decision reproduces from its stored inputs.').scrollIntoViewIfNeeded()
  await shot(page, '3-alert-detail-rescored')
})

test('Explainability: why risky, the stored model factors', async ({ page, request }) => {
  const get = await apiClient(request, m)
  const q = await get<{ items: AlertItem[] }>('/alerts', { status: 'open', sort: 'queue', limit: 1, offset: 0 })
  const e = await get<{ members: { activity_date: string; sections: { model: { feature: string }[] } }[] }>(`/explanations/alerts/${q.items[0].id}`)
  await signIn(page, m)
  await page.goto(`/alerts/${q.items[0].id}/explain`)
  await settled(page)
  const html = await page.content()
  const factors = e.members.flatMap((x) => x.sections.model.map((f) => f.feature))
  expect(factors.length).toBeGreaterThan(0)
  for (const f of factors.slice(0, 5)) expect(html).toContain(f)
  await shot(page, '4-explainability')
})

test('ATT&CK context: the techniques of the alert, or the stated reason there are none', async ({ page, request }) => {
  const get = await apiClient(request, m)
  const q = await get<{ items: AlertItem[] }>('/alerts', { status: 'open', sort: 'queue', limit: 50, offset: 0 })
  const a = q.items.find((x) => x.techniques.length) ?? q.items[0]
  const mm = await get<{ note: string; techniques: { technique_id: string }[] }>(`/mitre/alerts/${a.id}`)
  await signIn(page, m)
  await page.goto(`/alerts/${a.id}/mitre`)
  await settled(page)
  const text = await pageText(page)
  for (const tech of mm.techniques) expect(text).toContain(tech.technique_id.toLowerCase())
  if (!mm.techniques.length) expect(text).toMatch(/unmapped|not evaluated|no technique/)
  await shot(page, '5-attack-context')
})

test('User investigation: the traced raw CSV row is in the day timeline, by its CERT id', async ({ page, request }) => {
  const get = await apiClient(request, m)
  const ev = await get<{ items: { event_id: string }[]; page: { total: number } }>('/events', { user_id: t.user_id, date_from: t.date, date_to: t.date, limit: 200 })
  expect(ev.items.map((e) => e.event_id)).toContain(t.raw_id)
  await signIn(page, m)
  await page.goto(`/users/${encodeURIComponent(t.user_id)}?day=${t.date}`)
  await settled(page)
  const row = page.locator('tr', { hasText: t.raw_id })
  await expect(row).toHaveCount(1)
  await expect(page.getByText(`${Math.min(200, ev.page.total)} of ${ev.page.total} events`)).toBeVisible()
  await row.scrollIntoViewIfNeeded()
  await shot(page, '6-investigation-traced-event')
})

test('Risk history: coverage is the persisted days the API reports', async ({ page, request }) => {
  const get = await apiClient(request, m)
  const h = await get<{ coverage: { persisted_days: number } }>(`/risk/users/${t.user_id}/history`, { bucket: 'day' })
  await signIn(page, m)
  await page.goto(`/users/${encodeURIComponent(t.user_id)}/history`)
  await settled(page)
  await expect(page.getByText(new RegExp(`${h.coverage.persisted_days} persisted day`)).first()).toBeVisible()
  await shot(page, '7-risk-history')
})

test('System: the served model is the one /models names', async ({ page, request }) => {
  const get = await apiClient(request, m)
  const models = await get<{ served: { model_version: string; model_name: string } }>('/models')
  await signIn(page, m)
  await page.goto('/system')
  await settled(page)
  expect(await pageText(page)).toContain(models.served.model_version.toLowerCase())
  await shot(page, '8-system')
})
