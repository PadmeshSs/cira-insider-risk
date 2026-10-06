# CIRA dashboard (Chapters 14-15)

React 19 + TypeScript + Vite analyst console over the Chapter 13 API. Every number on screen comes from
an API call; there are no fixtures or mock data in `src/`, and `src/test/no-fixtures.test.ts` keeps it
that way. The data is the stored, batch-scored CERT r4.2 history served by the API, not a live feed.

## Run

```bash
cd frontend
npm install
cp .env.example .env.local      # optional; the default API is http://localhost:8000/api/v1
npm run dev                     # http://localhost:5173
```

The backend must be running (`uvicorn app.main:app --port 8000` from `backend/`) with a loaded alert
run, a usable `SECRET_KEY` and an analyst account
(`python -m app.services.accounts create --username alice --email alice@example.org`).
`CORS_ORIGINS` must include the dashboard origin.

```bash
npm run build    # tsc -b, then a production bundle in dist/
npm run lint
npm test         # vitest: unit, component and no-fixture checks
npm run test:e2e # playwright: the Chapter 15 click-through (see Tests below)
```

## Views and the API calls behind them

| View | Route | §27 question | API |
|---|---|---|---|
| Login | `/login` | | `POST /auth/token`, `GET /users/me`, `GET /health` |
| Overview | `/` | Who is risky? | `GET /risk/overview`, `GET /alerts?limit=8` |
| Alerts | `/alerts` | What happened? | `GET /alerts` (status, band, user, sort, paging) |
| Alert details | `/alerts/:id` | How risky is it? | `GET /alerts/{id}`, `GET /risk/users/{u}/days/{d}`, `GET /anomaly/users/{u}/days/{d}`, `GET /features/users/{u}/days/{d}`, `POST /risk/score` |
| Explainability | `/alerts/:id/explain` | Why is it risky? | `GET /explanations/alerts/{id}` |
| ATT&CK context | `/alerts/:id/mitre` | What contextual evidence supports it? | `GET /mitre/alerts/{id}`, `GET /mitre/techniques/{id}` |
| User investigation | `/users/:id` | What should the analyst investigate? | `GET /investigations/{u}`, `GET /risk/users/{u}/history`, `GET /events` |
| Risk history | `/users/:id/history` | | `GET /risk/users/{u}/history?bucket=day\|week` |
| Users | `/users` | | `GET /investigations?scope=` |
| System | `/system` | | `GET /health`, `GET /models` |

## Tests

| File | Runner | What it checks |
|---|---|---|
| `src/test/units.test.tsx` | Vitest | formatting, API error parsing, severity badge, CERT event wording, score anatomy |
| `src/test/views.test.tsx` | Vitest | the Overview renders the user, score and run id of the API response; on a network error it shows "API not reachable" and none of them; on a 503 it shows the API's reason |
| `src/test/no-fixtures.test.ts` | Vitest | no import from `src/test`, no random numbers or mock libraries, every service goes through `services/client.ts` |
| `e2e/journey.spec.ts` | Playwright | sign-in through the form, every view against the live API, the traced raw CERT id in the event table, "Re-score this day" reproducing the stored decision; one screenshot per view |
| `e2e/no-fabrication.spec.ts` | Playwright | every value a view showed disappears when the API is unreachable, and each view shows an error |
| `e2e/cert.spec.ts` | Playwright | the same checks against the CERT full run; skipped unless `CIRA_CERT_USERNAME` is set |

The Playwright specs run against real servers, never mocks. `playwright.config.ts` starts the API with
`python ../scripts/e2e_stack.py serve` (port 8765) on the database that `python scripts/e2e_stack.py build`
loaded, and Vite on port 5174, or reuses them if they are already running. Once per machine:
`npx playwright install chromium`. If `python` is not the right interpreter, set `CIRA_PYTHON` to its
full path; spaces and apostrophes in it are fine. Screenshots go to `test-results/ch15-run-through/` and
`test-results/ch15-cert/` (gitignored).

For the CERT run, start the API yourself on port 8000 with `CORS_ORIGINS` including
`http://127.0.0.1:5174`, then:

```powershell
$env:CIRA_E2E_API_PORT = "8000"; $env:CIRA_CERT_USERNAME = "<analyst>"; $env:CIRA_CERT_PASSWORD = "<password>"
npx playwright test cert.spec
```

## Source layout

```
src/
  components/ui/         primitives from DESIGN.md: badge, CRI gauge, score track, panel, pager, states
  components/layout/     icon rail, status bar, shell, auth guard
  components/common/     domain components: alert table, score anatomy, explanation sections,
                         day timeline, risk history charts, lineage chain, coverage note
  pages/                 one module per view
  services/              one Axios module per API group
  types/api.ts           the backend's Pydantic models in TypeScript
  store/                 auth session and /health (Zustand)
  hooks/ utils/ constants/ theme/
```

Design tokens are in `src/index.css` (`@theme`), taken from `DESIGN.md` ("Tactical Threat Surface").
MUI renders inside a CSS layer below Tailwind's utilities, so utility classes always win.
