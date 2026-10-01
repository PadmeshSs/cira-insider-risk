# CIRA dashboard (Chapter 14)

React 19 + TypeScript + Vite analyst console over the Chapter 13 API. Every number on screen comes from
an API call; there are no fixtures or mock data in `src/`.

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
npm test         # vitest
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
