import { expect, test } from '@playwright/test'
import { API, apiClient, manifest, pageText, settled, signIn } from './stack'

/**
 * Chapter 15 / N69: the dashboard computes nothing it displays.
 *
 * First pass: the API answers, and the test records data values each view
 * shows (user ids, alert ids, run ids, model version, the traced CERT id).
 * Second pass: every request to the API is aborted, the same views are
 * reloaded, and none of those values may appear. A value that survives
 * came from somewhere other than the API. The one exception is a value the
 * address itself carries (the user id of /users/<id>), which is shown from
 * the URL as a breadcrumb.
 */
const m = manifest()
const t = m.trace

interface AlertItem { id: number; user_id: string; queue_score: number }

async function views(request: Parameters<typeof apiClient>[0]) {
  const get = await apiClient(request, m)
  const q = await get<{ items: AlertItem[] }>('/alerts', { status: 'open', sort: 'queue', limit: 50, offset: 0 })
  const ov = await get<{ top_users: { user_id: string }[]; run: { alert_run_id: string; model_version: string } }>('/risk/overview')
  const a = q.items[0]
  const tokens = [
    ...ov.top_users.map((u) => u.user_id.toLowerCase()),
    ov.run.alert_run_id.toLowerCase(),
    ov.run.model_version.toLowerCase(),
    t.raw_id.toLowerCase(),
    a.queue_score.toFixed(3),
  ]
  const paths = ['/', '/alerts', `/alerts/${a.id}`, `/alerts/${a.id}/explain`, `/alerts/${a.id}/mitre`, '/users',
    `/users/${encodeURIComponent(t.user_id)}?day=${t.date}`, `/users/${encodeURIComponent(t.user_id)}/history`, '/system']
  return { tokens, paths }
}

test('with the API unreachable, no view shows a value it showed with the API up', async ({ page, request }) => {
  const { tokens, paths } = await views(request)
  await signIn(page, m)

  const seen = new Set<string>()
  for (const p of paths) {
    await page.goto(p)
    await settled(page)
    const text = await pageText(page)
    for (const tok of tokens) if (text.includes(tok)) seen.add(tok)
  }
  // The test is only meaningful if the live pass showed the data.
  expect([...seen]).toEqual(expect.arrayContaining([t.raw_id.toLowerCase(), m.alert_run_id.toLowerCase()]))

  await page.route(`${API}/**`, (route) => route.abort('connectionrefused'))
  await page.route(/\/health$/, (route) => route.abort('connectionrefused'))
  for (const p of paths) {
    await page.goto(p)
    await settled(page)
    const text = await pageText(page)
    // A value that is part of the address (the user id in /users/<id>) comes from the URL, not the API.
    const leaked = [...seen].filter((tok) => text.includes(tok) && !decodeURIComponent(p).toLowerCase().includes(tok))
    expect(leaked, `${p} still shows ${leaked.join(', ')} with the API down`).toEqual([])
    await expect(page.getByRole('alert').first(), `${p} must say the API failed`).toBeVisible()
  }
})
