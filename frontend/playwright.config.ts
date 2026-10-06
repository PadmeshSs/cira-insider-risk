import { defineConfig, devices } from '@playwright/test'

/**
 * Chapter 15 click-through. Two servers, both real:
 *   - the API, `python ../scripts/e2e_stack.py serve`, on the database that
 *     `python ../scripts/e2e_stack.py build` loaded (raw CSV -> Chapters 5-12);
 *   - the Vite dev server, pointed at that API.
 * Nothing is mocked. The specs read ../.e2e/stack.json for the analyst and
 * the traced raw event.
 *
 * Build the stack first (see docs/chapters/chapter_15_e2e.md), then:
 *   npx playwright install chromium   (once)
 *   npm run test:e2e
 */
const API_PORT = Number(process.env.CIRA_E2E_API_PORT ?? 8765)
const WEB_PORT = Number(process.env.CIRA_E2E_WEB_PORT ?? 5174)
// Quoted, because the path can hold spaces and apostrophes (C:\Users\...\Padmesh 's\...\python.exe).
const PYTHON = `"${(process.env.CIRA_PYTHON ?? 'python').replace(/^"+|"+$/g, '')}"`

export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list'], ['json', { outputFile: 'test-results/e2e-report.json' }]],
  use: {
    baseURL: `http://127.0.0.1:${WEB_PORT}`,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    ...devices['Desktop Chrome'],
    viewport: { width: 1440, height: 1000 },
  },
  webServer: [
    {
      command: `${PYTHON} ../scripts/e2e_stack.py serve --port ${API_PORT} --cors http://127.0.0.1:${WEB_PORT},http://localhost:${WEB_PORT}`,
      url: `http://127.0.0.1:${API_PORT}/health`,
      reuseExistingServer: true,
      timeout: 120_000,
      stdout: 'pipe',
    },
    {
      command: `npm run dev -- --host 127.0.0.1 --port ${WEB_PORT} --strictPort`,
      url: `http://127.0.0.1:${WEB_PORT}`,
      reuseExistingServer: true,
      timeout: 120_000,
      env: { VITE_API_BASE_URL: `http://127.0.0.1:${API_PORT}/api/v1` },
    },
  ],
})
