import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { expect, type APIRequestContext, type Page } from '@playwright/test'

/** What `python scripts/e2e_stack.py build` wrote: the analyst, the served run and the traced raw event. */
export interface StackManifest {
  alert_run_id: string
  username: string
  password: string
  trace: { domain: string; raw_id: string; user_id: string; date: string; alert_key: string; queue_score: number }
}

const MANIFEST = fileURLToPath(new URL('../../.e2e/stack.json', import.meta.url))

export function manifest(): StackManifest {
  try {
    return JSON.parse(readFileSync(MANIFEST, 'utf-8')) as StackManifest
  } catch {
    throw new Error(`no e2e stack at ${MANIFEST}: run \`python scripts/e2e_stack.py build\` from the repository root first`)
  }
}

export const API = `http://127.0.0.1:${process.env.CIRA_E2E_API_PORT ?? 8765}/api/v1`

/** The API, read directly with the analyst's token: the reference every screen value is compared with. */
export async function apiClient(request: APIRequestContext, m: StackManifest) {
  const r = await request.post(`${API}/auth/token`, { form: { username: m.username, password: m.password } })
  expect(r.status(), await r.text()).toBe(200)
  const token = (await r.json()).access_token as string
  return async <T = Record<string, unknown>>(path: string, params?: Record<string, string | number>): Promise<T> => {
    const q = params ? `?${new URLSearchParams(Object.entries(params).map(([k, v]) => [k, String(v)]))}` : ''
    const res = await request.get(`${API}${path}${q}`, { headers: { Authorization: `Bearer ${token}` } })
    expect(res.status(), `${path}: ${await res.text()}`).toBe(200)
    return (await res.json()) as T
  }
}

/** Sign in through the login form, as an analyst would. */
export async function signIn(page: Page, m: StackManifest) {
  await page.goto('/login')
  await page.getByLabel('Username').fill(m.username)
  await page.getByLabel('Password').fill(m.password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page).toHaveURL(/\/$/)
}

/** Everything the page holds as text, hidden details included, lower-cased (ids are shown upper-case by CSS). */
export async function pageText(page: Page): Promise<string> {
  return ((await page.locator('body').textContent()) ?? '').toLowerCase()
}

/** Wait until no skeleton is left: every panel has its data or its error. */
export async function settled(page: Page) {
  await expect(page.locator('[aria-busy="true"]')).toHaveCount(0)
}
