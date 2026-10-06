import { expect, test } from '@playwright/test'

/**
 * Chapter 15 on the CERT r4.2 full run (development machine only).
 *
 * The other specs use the synthetic e2e stack. This one runs against the API
 * you started yourself on the database that holds `20261001T062628Z-full-alerts`
 * (or whatever run /health names), and repeats the two checks that matter on
 * real data: every view shows what the API returns, and nothing survives
 * when the API is unreachable. It also re-scores the top alerts through the
 * dashboard's own button. It closes the open item in chapter_14_dashboard.md.
 *
 *   $env:CORS_ORIGINS="http://localhost:5173,http://127.0.0.1:5174"
 *   uvicorn app.main:app --port 8000                          (from backend/, CERT .env)
 *   $env:CIRA_E2E_API_PORT="8000"; $env:CIRA_CERT_USERNAME="padmesh"; $env:CIRA_CERT_PASSWORD="..."
 *   npx playwright test e2e/cert.spec.ts
 *
 * Skipped unless CIRA_CERT_USERNAME is set. Screenshots: test-results/ch15-cert/.
 */
const USER = process.env.CIRA_CERT_USERNAME
const PASS = process.env.CIRA_CERT_PASSWORD ?? ''
const API = `http://127.0.0.1:${process.env.CIRA_E2E_API_PORT ?? 8000}/api/v1`
const RESCORE = Number(process.env.CIRA_CERT_RESCORE ?? 3)

test.skip(!USER, 'set CIRA_CERT_USERNAME and CIRA_CERT_PASSWORD to run against the CERT full run')
test.describe.configure({ mode: 'serial' })
test.setTimeout(180_000)

interface AlertItem { id: number; user_id: string; queue_score: number; peak_date: string }

async function token(request: import('@playwright/test').APIRequestContext) {
  const r = await request.post(`${API}/auth/token`, { form: { username: USER!, password: PASS } })
  expect(r.status(), await r.text()).toBe(200)
  return (await r.json()).access_token as string
}

async function signIn(page: import('@playwright/test').Page) {
  await page.goto('/login')
  await page.getByLabel('Username').fill(USER!)
  await page.getByLabel('Password').fill(PASS)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page).toHaveURL(/\/$/)
}

const settled = (page: import('@playwright/test').Page) => expect(page.locator('[aria-busy="true"]')).toHaveCount(0, { timeout: 60_000 })
const text = async (page: import('@playwright/test').Page) => ((await page.locator('body').textContent()) ?? '').toLowerCase()

test('CERT: every view shows the API values; the top alerts reproduce; nothing survives the API going away', async ({ page, request }) => {
  const auth = { Authorization: `Bearer ${await token(request)}` }
  const get = async <T,>(p: string) => {
    const r = await request.get(`${API}${p}`, { headers: auth })
    expect(r.status(), p).toBe(200)
    return (await r.json()) as T
  }
  const health = await get<{ routes: { alerts_risk_investigations: { alert_run_id: string } } }>('/health')
  const run = health.routes.alerts_risk_investigations.alert_run_id
  const ov = await get<{ counts: { open: number }; top_users: { user_id: string }[]; run: { model_version: string } }>('/risk/overview')
  const q = await get<{ items: AlertItem[] }>('/alerts?status=open&sort=queue&limit=10')
  const top = q.items[0]
  const ev = await get<{ items: { event_id: string }[] }>(`/events?user_id=${top.user_id}&date_from=${top.peak_date}&date_to=${top.peak_date}&limit=200`)
  const tokens = [run.toLowerCase(), ov.run.model_version.toLowerCase(), ...ov.top_users.map((u) => u.user_id.toLowerCase()),
    ...(ev.items[0] ? [ev.items[0].event_id.toLowerCase()] : [])]
  const paths = ['/', '/alerts', `/alerts/${top.id}`, `/alerts/${top.id}/explain`, `/alerts/${top.id}/mitre`, '/users',
    `/users/${encodeURIComponent(top.user_id)}?day=${top.peak_date}`, `/users/${encodeURIComponent(top.user_id)}/history`, '/system']

  await signIn(page)
  const seen = new Set<string>()
  for (const [i, p] of paths.entries()) {
    await page.goto(p)
    await settled(page)
    const t = await text(page)
    for (const tok of tokens) if (t.includes(tok)) seen.add(tok)
    await page.screenshot({ path: `test-results/ch15-cert/${i + 1}-${p.replace(/[^a-z0-9]+/gi, '_').replace(/^_+|_+$/g, '') || 'overview'}.png` })
  }
  expect([...seen]).toEqual(expect.arrayContaining([run.toLowerCase(), ...ov.top_users.map((u) => u.user_id.toLowerCase())]))
  if (ev.items[0]) expect(seen.has(ev.items[0].event_id.toLowerCase()), 'top alert peak-day event in the timeline').toBe(true)

  for (const a of q.items.slice(0, RESCORE)) {
    await page.goto(`/alerts/${a.id}`)
    await settled(page)
    await page.getByRole('button', { name: /Re-score this day/ }).click()
    await expect(page.getByText('The stored decision reproduces from its stored inputs.'), `alert #${a.id}`).toBeVisible({ timeout: 60_000 })
  }

  await page.route(`${API}/**`, (r) => r.abort('connectionrefused'))
  await page.route(/\/health$/, (r) => r.abort('connectionrefused'))
  for (const p of paths) {
    await page.goto(p)
    await settled(page)
    const t = await text(page)
    const leaked = [...seen].filter((tok) => t.includes(tok) && !decodeURIComponent(p).toLowerCase().includes(tok))
    expect(leaked, `${p} with the API down`).toEqual([])
    await expect(page.getByRole('alert').first()).toBeVisible()
  }
})
