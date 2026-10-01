# Chapter 13: FastAPI full integration

Bible Chapter 13 / Architecture Phase 10 (§25, §36, §37), executed under HCEA v1.0 §8 and §13.

Status: IMPLEMENTED (1 October 2026). On the development machine the API serves the CERT r4.2 full
alert run `20261001T062628Z-full-alerts`, `/health` shows every route group ready,
`scripts/verify_chapter13.py --database-url` gives 28 PASS, 0 WARN, 0 FAIL, and the integration tests
pass through testcontainers. The audit is `docs/audits/chapter_13_audit.md`, and the numbers are
there, not in this document.

## What the API is for

Chapters 8 to 12 produce decisions: a served anomaly score, a CRI, ATT&CK context, an explanation
and correlated alerts, stored in PostgreSQL by one bounded load. Chapter 13 puts an HTTP surface over
those decisions so the Chapter 14 dashboard can answer the six questions of §27. It adds no detection
logic. Every number a route returns is either read from the stored run or recomputed by the same
runtimes that produced it, and the second case exists to reproduce the first.

## Layering (Bible Ch13 step 2)

```text
app/api/v1/<group>.py   one function per route: parse, call a service, return       (FastAPI)
app/schemas/<group>.py  Pydantic response and request models                       (no FastAPI)
app/services/<group>.py queries, checks, decisions, error types                     (no FastAPI)
domain modules          scoring, cri, mitre, explainability, alerts.policy          (Chapters 8-12)
app/database/models     the Chapter 2-12 entities
```

A unit test parses every router and fails if a route function holds anything but one `return` of a
service call, or if a router imports anything other than FastAPI, the dependencies, schemas and
services. The same test file checks that services and schemas never import FastAPI, that nothing in
the API layer imports label or offline code (N5), and that nothing in it constructs or inserts an
alert, member, reason, risk or anomaly row (N58).

Services raise `NotFound` (404), `BadRequest` (422), `Conflict` (409), `Unauthorized` (401) and
`Unavailable` (503, with the component). `app/api/errors.py` maps them to a JSON body
`{"detail": {"code", "message", "component"}}`. A database that cannot be reached becomes a 503 with
`component: database` (§36), never an empty list.

## Which run the API serves

The routes read one loaded alert run. It is the newest run whose `alert_run_loaded` audit row exists
(N58) and whose alerts were built for the model served now (N28, N30). `?alert_run_id=` selects an
older loaded run of the same model. A run of another model is refused: 503 when it is the only kind
loaded, 409 when it is asked for by id. The resolution reads only PostgreSQL and the served model, so
the routes work without the Parquet tree. Chapter 12's `AlertRuntime`, which reads the run's meta from
Parquet, still feeds the `alerts` block of `/health`.

Every query is scoped to the run ids the alert run names: the Chapter 8 batch for anomaly scores, the
CRI run for risk rows, the enrichment run for ATT&CK rows. Overlapping user-days of two runs are never
mixed (N50). Every response that carries numbers carries that lineage in a `run` block.

## Routes

All under `/api/v1`. Every group except `auth` and `health` needs a bearer token.

| Group | Route | Answers |
|---|---|---|
| auth | `POST /auth/token` | OAuth2 password flow; a token valid for `ACCESS_TOKEN_MINUTES` |
| users | `GET /users/me` | the signed-in analyst |
| alerts | `GET /alerts` | the queue: open (or suppressed, or all) alerts, ordered as the policy ordered them, paginated |
| alerts | `GET /alerts/{id}` | one alert, its member days with both scores and their triggers, its suppressed repeats, or the open alert it repeats |
| explanations | `GET /explanations/alerts/{id}` | the stored explanation of every member day, section by section |
| explanations | `GET /explanations/users/{user}/days/{day}` | the stored explanation of one member day |
| mitre | `GET /mitre/alerts/{id}` | ATT&CK rows of the member days, mapped, unmapped or not evaluated |
| mitre | `GET /mitre/techniques/{id}` | one technique from the pinned 19.2 table, with the rules that can map to it |
| risk | `GET /risk/overview` | open and suppressed counts, bands, splits, top factors, new alerts per week, ranked users |
| risk | `GET /risk/users/{user}/history?bucket=day\|week` | the user's persisted risk rows, aggregated on the server |
| risk | `GET /risk/users/{user}/days/{day}` | one stored risk row with its anomaly score and the alerts it belongs to |
| risk | `POST /risk/score` | one user-day scored on demand: anomaly, ATT&CK, CRI, band trigger, explanation; not stored |
| anomaly | `POST /anomaly/score` | the served model's score of one feature vector; not stored |
| anomaly | `GET /anomaly/users/{user}/days/{day}` | one stored served score |
| features | `GET /features/users/{user}/days/{day}` | the stored Chapter 5 vector, each value described, model inputs and static traits marked |
| events | `GET /events?user_id=...` | persisted CERT events of one user, oldest first, paginated |
| investigations | `GET /investigations?scope=all\|alerting\|demo` | monitored users with persisted rows, paginated |
| investigations | `GET /investigations/{user}` | one user's alerts and persisted coverage |
| models | `GET /models` | served and shadow models, and the model versions behind stored scores |
| health | `GET /health` (also at `/health`) | every component's status and which route groups can answer |

Each group exists because a Chapter 14 view calls it: Login (`auth`, `users`), Overview (`risk/overview`),
Alerts (`alerts`), Alert Details (`alerts/{id}`, `features`, `anomaly`), Explainability (`explanations`),
MITRE Context (`mitre`), User Investigation and Risk History (`investigations`, `risk/.../history`,
`events`). `models` and `health` serve the status bar. `POST /anomaly/score` is the endpoint the Bible's
Chapter 8 outcome names, and `POST /risk/score` is how a user-day outside the stored explanations is
explained (N50).

`/users` is about analyst accounts, because the `users` table holds analysts. Monitored CERT users are
under `/investigations` (C13-2).

### What the routes return, and what they never do

- The anomaly score and the CRI are two fields everywhere. Neither is recomputed for a stored row, and
  neither is described as a probability; a test checks every occurrence of the word in the OpenAPI
  document (N20, N34).
- The queue is sorted by `queue_score`, which is the anomaly score under `c12-alert-policy-v1`, and the
  response names the ordering. The CRI and band are on every row as context. There is no CRI sort: N55
  allows one only if labelled as the other view, and re-sorting the anomaly-score policy's alerts by
  CRI is not that view, which would change the triggers. `sort=recent` orders by first day instead
  (C13-9).
- `counts` always holds open and suppressed together. Every open alert carries the count and date
  span of the suppressed alerts pointing at it, and a suppressed alert names its original. Nothing is
  labelled resolved (N57, N60).
- Every alert, member, risk row, score and subject carries `model_split` and `in_sample`. The default
  alert run holds no training user; if a `--rows all` run is ever loaded, in-sample rows say so (N31).
- Explanations come back in four sections: `model` (raising TreeSHAP factors), `model_lowering`,
  `cri` (points, context) and `mitre` (techniques, context), with each item's `source` record. Each
  member also returns how many `alert_reasons` rows it has per section, so the two stored forms can be
  checked against each other. KernelSHAP appears only as `corroboration`, an agreement statistic
  (N45, N48, N50).
- ATT&CK rows are read through member days and the run's enrichment id, not through
  `mitre_mappings.alert_id` (C12-11). A member day with no row is `not_evaluated`, never filled in.
- `/models` lists the shadow model with `role: shadow` and the note that it never feeds the CRI,
  alerts or explanations (N32).
- `/features` marks static traits and whether the served model reads each column. The served XGBoost
  is behaviour-only, so no static trait is a model input (N25).

### Pagination and aggregation (HCEA §13)

The three list routes (`/alerts`, `/events`, `/investigations`) take `limit` and `offset`. `limit`
defaults to 50 and is capped at 200; a larger value is a 422, so the cap is visible in the OpenAPI
document and in the response's `page.max_limit` (C13-8). `/events` needs a `user_id`: there is no
corpus-wide listing. The overview and the risk history are aggregated in the service, over the
bounded persisted rows, into a short series (daily or weekly buckets with the maximum and mean of each
score kept apart), so the browser never reduces raw rows.

### What PostgreSQL holds, and what that means for the routes

The API reads PostgreSQL only (C13-5). Chapter 12 persisted alert member days and the 30-day,
20-user demo sample (HCEA D-6); everything else stays in Parquet. So a user's risk history and event
timeline cover those days and nothing else: an alerting user outside the demo window has a history
of their member days only. Every coverage block says so (`Coverage.note`), and the history returns
`persisted_days` with the first and last day. Reading the Parquet runs from the API would widen the
history, but it would also make the API depend on the dataset mount (the container does not have it,
see Chapter 12 "Still open") and could put a training user's days on screen (N31, N59). A wider
history is a larger D-6 sample, decided in a later chapter, not a different reader here.

## Scoring on demand (`POST /anomaly/score`, `POST /risk/score`)

A request carries one user-day's Chapter 5 columns by name, nulls allowed (N4). The anomaly route
scores it with the served model only. The risk route then runs the MITRE rules on it, computes the CRI
through `CRIEngine.compute_event_detail` with that `mitre_context`, applies the alert policy's band
rule, and builds the explanation through `ExplainRuntime.explain_event`. Each step that cannot run
says why in its own field, and the rest still answers (§36). A component without a value is listed
with the engine's own reason, the same text a batch risk run writes, never a default (N35).

The band trigger and the activity rule come from `app.alerts.policy` (`band_trigger`,
`top_k_eligible`), with the policy recorded for the served run (N56). `by_top_k` is always null: a
daily top-k ranks a whole day's population, which only the batch has, and the response says so.

Nothing these routes compute is stored (HCEA §8: scores reach PostgreSQL through the batch and the
bounded load, never row by row over HTTP; N58: alert rows have one writer). A test counts the
`anomaly_scores` rows before and after.

On the synthetic chain the risk route, given a member day's stored feature vector and LDAP role,
returns the stored anomaly score and the stored CRI exactly (difference 0), with the same severity and
the same model factors in the same order as the stored explanation. That is the §37 lineage checked
end to end: stored vector, served model, calibration and enrichment reference reproduce the stored
decision. The verifier repeats it on the top open alerts of whatever run is served.

## Authentication (Bible Ch13 step 3)

The basic version the FYP core needs, in `app/core/security.py` and `app/services/accounts.py`.

- Passwords: scrypt from the Python standard library (n 2^14, r 8, p 1, 16-byte salt), compared in
  constant time. At least 12 characters. No hashing dependency was added (C13-3).
- Tokens: HS256 JWT through PyJWT, with `sub`, `uid`, `role`, `iss`, `iat` and `exp`. `exp`, `sub` and
  `iat` are required on decode and only HS256 is accepted, so an unsigned or re-signed token fails. The
  account is looked up on every request, so a deactivated account's token stops working at once.
- The secret: no token is issued while `SECRET_KEY` is unset, shorter than 32 characters or still the
  `.env.example` placeholder. Login answers 503 with the reason and `/health` shows `auth`
  unavailable.
- Accounts are created and deactivated from the command line
  (`python -m app.services.accounts create|deactivate`). There is no registration route, so nobody can
  give themselves access to insider-risk data over HTTP (C13-4).
- A wrong password and an unknown user give the same 401 body, and an unknown user costs one scrypt
  call too, so a login cannot be used to find usernames.
- Every account change and every login attempt writes an `audit_logs` row: `analyst_created`,
  `analyst_deactivated`, `analyst_login`, `analyst_login_failed`. None is `alert_run_loaded`, so
  `/health`'s count of loaded runs is unaffected (N58), which the integration test checks.

Two roles exist, `analyst` and `admin`, and both read everything. Role-based restrictions, refresh
tokens, lockout after failed attempts and rate limiting are Chapter 18 (production extension).

CORS allows `CORS_ORIGINS` (default `http://localhost:5173`, the Vite dev server), `GET` and `POST`,
and the `Authorization` and `Content-Type` headers only.

## /health (Bible Ch13 step 4)

The top-level `status` keeps its Chapter 8 meaning (C8-7): `healthy` when the served anomaly model is
loaded. Five existing tests rely on that, and the components keep their own blocks, so nothing that
reads `/health` today changes meaning. Two blocks are new (C13-6):

- `auth`: `configured` or `unavailable` with the reason. The secret itself is never in the body.
- `routes`: for each route group, `ready` and, if not, why. The alert, risk and investigation routes
  are ready only when the database is reachable, a model is served and a loaded run was built for it
  (the same audit-row query the routes use), and the block names that run.

`/health` stays at the root for Docker healthchecks and the earlier chapters' tests, and the same body
is at `/api/v1/health`.

The asyncpg engine now gives up connecting after 5 seconds instead of asyncpg's default 60
(`app/database/session.py`), so a request during an outage answers 503 promptly.

## Failure modes (Architecture §36)

| Situation | Behaviour |
|---|---|
| No served model | Score routes 503 `anomaly_model`; read routes 503 (no run can be current); `/health` degraded |
| Only runs of another model are loaded (a rollback) | Read routes 503, code `other_model`, naming the runs; `?alert_run_id=` of such a run 409 (N28) |
| No alert run loaded | Read routes 503 `alerts`, naming `python -m app.alerts.load` |
| PostgreSQL down | 503 `database_unavailable`, after at most 5 s; login also 503; `/health` database unavailable, routes not ready |
| CRI calibration missing or for another model | `POST /risk/score` returns the anomaly score, `risk: null` and the reason (N29) |
| MITRE table or reference missing | CRI computed without `mitre_context`, reason listed under `unavailable_components` |
| Explainer unavailable or a mismatch refused | Explanation null with `explanation_unavailable_reason`; the scores stand |
| Feature vector misses a model input, or holds inf or text | 422 `invalid_feature_vector`; never imputed |
| `SECRET_KEY` unusable | Login 503 `auth`; protected routes 503 |
| Token missing, forged, expired, or account deactivated | 401 with `WWW-Authenticate: Bearer` |
| `limit` above 200 | 422 |

## What was built

| Path | Purpose |
|---|---|
| `backend/app/api/deps.py` | Session, engine, settings and runtimes dependencies; the signed-in analyst; the served run; page parameters |
| `backend/app/api/errors.py` | Service errors and database failures to HTTP |
| `backend/app/api/v1/*.py` | Twelve routers, one-line handlers; `__init__.py` puts the token check on every group but auth and health |
| `backend/app/schemas/*.py` | Response and request models |
| `backend/app/services/runs.py` | `Runtimes`; `current_run` (audit row + served model) |
| `backend/app/services/alerts.py`, `risk.py`, `investigations.py`, `lineage.py`, `explanations.py`, `mitre.py`, `models.py` | The read services |
| `backend/app/services/scoring.py` | On-demand anomaly and risk scoring, never stored |
| `backend/app/services/accounts.py` | Login, token check, account CLI |
| `backend/app/services/health.py` | `/health` with the `auth` and `routes` blocks |
| `backend/app/core/security.py` | scrypt hashing, HS256 tokens, the secret check |
| `backend/app/core/config.py` | `SECRET_KEY`, `ACCESS_TOKEN_MINUTES`, `CORS_ORIGINS` |
| `backend/app/database/session.py` | 5-second connect timeout on asyncpg |
| `backend/app/main.py` | Registers the routers, error handlers and CORS; root `/health` uses the health service |
| `backend/app/cri/engine.py` | `compute_event_detail`: `compute_event` plus the engine's unavailable-component reasons (C13-10) |
| `backend/app/alerts/policy.py` | `band_trigger` and `top_k_eligible`, now used by `triggers` itself (C13-10) |
| `scripts/verify_chapter13.py` | PASS / WARN / FAIL against a running API |
| `backend/tests/unit/test_ch13_api_rules.py` | Security, accounts, layering, label isolation, OpenAPI rules, policy helpers (95 cases with parametrisation) |
| `backend/tests/integration/test_ch13_api.py` | The whole surface over the synthetic chain, on PostgreSQL or SQLite (12 tests) |

`requirements.txt` gains `pyjwt` (tokens) and `aiosqlite` (the SQLite fallback of the API tests). No
migration: the `users`, `audit_logs` and `configurations` tables of earlier chapters already hold
everything Chapter 13 writes.

The two changes to earlier modules are refactors that keep behaviour. `compute_event` now calls
`compute_event_detail` and returns its `risk` part. `triggers` now calls the two policy helpers instead
of holding the same lines. The Chapter 9 and Chapter 12 tests pass unchanged.

## How to run, step by step

From `backend/`, after the Chapter 12 load on the full profile, with PostgreSQL up.

Bash:

```bash
# once: a real secret in ../.env
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48))" >> ../.env
pip install -r requirements.txt                                 # adds pyjwt and aiosqlite
python -m app.services.accounts create --username alice --email alice@example.org
uvicorn app.main:app --port 8000
# in a second shell
curl -s localhost:8000/health | python -m json.tool               # routes block: every group ready
CIRA_ANALYST_PASSWORD='...' python ../scripts/verify_chapter13.py --username alice --database-url "$DATABASE_URL"
```

PowerShell (Windows):

```powershell
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48))" | Add-Content ..\.env
pip install -r requirements.txt
python -m app.services.accounts create --username alice --email alice@example.org
uvicorn app.main:app --port 8000
# second window
$env:CIRA_ANALYST_PASSWORD = '...'
python ..\scripts\verify_chapter13.py --username alice --database-url $env:DATABASE_URL
```

The interactive documentation is at `http://localhost:8000/docs`; its Authorize button uses the same
token route. The API reads the served model from the Chapter 8 decision file, so `MODEL_PATH` and the
CRI and MITRE pins must resolve as they did for Chapters 9 to 12. `CERT_PROCESSED_DIR` is only needed
for the `alerts` block of `/health`.

Tests: `python -m pytest backend/tests/integration/test_ch13_api.py` uses `CIRA_TEST_DATABASE_URL` if set
(a PostgreSQL at head), else a testcontainers `postgres:17` if Docker is running, else SQLite.
`test_database_is_postgres` is skipped on SQLite, so a run without PostgreSQL shows it.

## Verification

`scripts/verify_chapter13.py` signs in with a real account and checks the running API, label-free:

- health: both health routes, the model, database and auth blocks, CRI, MITRE and explainability
  (WARN), every route group ready.
- auth: a wrong password and a missing token refused, sign-in, `/users/me`.
- contract: every API group of §25 present, every `limit` capped at 200, no score called a
  probability.
- queue: counts equal the listed open and suppressed alerts; sorted by the policy's score; both scores
  on every alert; suppressed alerts attached to open alerts with matching counts; no in-sample alert
  (WARN); the cap enforced; the run `/health` names is the run the queue serves.
- alerts: for the top `--sample` open alerts (10 by default), one peak, every member triggered,
  explanation sections of the right kind and equal in number to the `alert_reasons` rows, ATT&CK
  techniques equal to the alert's.
- scoring: the same alerts' peak days re-scored through `POST /risk/score` from their stored feature
  vectors; the anomaly score must match within 1e-9 and the CRI within 1e-6; median and maximum
  latency recorded.
- database (with `--database-url`): the served run has its audit row; stored counts equal the API's.

It writes `experiments/results/chapter13/verification_<stamp>.json` and a `chapter13_verification`
runlog line.

On the synthetic chain, in-process against PostgreSQL 16: 26 PASS, 0 WARN, 0 FAIL, both re-scoring
differences 0. Tampering is caught: the integration test adds 1.0 to the stored CRI of the top
alert's peak day, and the verifier FAILs on "CRI reproduces the stored one", then the row is restored.

## Carry-forward compliance

| Note | How Chapter 13 satisfies it |
|---|---|
| N5 | API, services and schemas statically checked: no label, ground-truth or offline import; no label path |
| N6 | The API serves whatever run is loaded; only full is reportable, and the verifier's numbers are quoted with the run id |
| N8 | Thread caps stay first in the lifespan handler |
| N9, N45 | No signal CERT lacks is added; ATT&CK `indicated` matches keep the stored "visit" wording |
| N20 | No field or description calls a score a probability (OpenAPI test, verifier) |
| N21, N28, N30 | Scoring through the registry-loaded service; read routes refuse a run built for another model |
| N25 | `/features` marks static traits; none is a model input of the served model |
| N31, N59 | `model_split` and `in_sample` on every row; demo scope lists the c12-demo-sample-v1 users |
| N32 | Only served scores; the shadow appears only on `/models`, labelled |
| N33, N35 | On-demand CRI through the calibrated engine; unavailable components listed with the engine's reasons |
| N34 | Two fields everywhere; stored values never recomputed; on-demand values shown to equal the stored ones |
| N39 | Each member's `by_band` and `by_top_k` returned separately |
| N47, N48, N50 | Stored TreeSHAP explanations; KernelSHAP only as `corroboration`; sections kept apart with reason-row counts |
| N52 | Overview counts open alerts led by `usb_disconnect_count`; `/features` gives the value |
| N55 | Queue sorted by `queue_score`; ordering named; CRI as context; no unlabelled CRI sort |
| N56 | Band and activity rules through `app.alerts.policy`; top-k never evaluated for one day |
| N57, N60 | Counts together; suppressed span and count on every open alert; suppressed never shown as resolved |
| N58 | Run resolution and `/health` by audit row; no route writes an alert row; login audit rows do not count as loads |

## Deviation register additions

| Id | What | Status |
|---|---|---|
| C13-1 | Route paths name the subject and day (`/risk/users/{user}/days/{day}`) rather than mixing them in one segment, so no two routes can match the same URL | Applied |
| C13-2 | `/users` is analyst accounts (the `users` table); monitored CERT users are `/investigations` | Applied |
| C13-3 | Passwords hashed with stdlib scrypt; `pyjwt` added for tokens; `aiosqlite` added for the SQLite fallback of the tests | Applied |
| C13-4 | No registration route; accounts created and deactivated by CLI; every login attempt audited | Applied |
| C13-5 | The API reads PostgreSQL only; history and events cover the D-6 rows and say so | Applied |
| C13-6 | `/health` keeps its top-level meaning (C8-7) and gains `auth` and `routes` blocks | Applied |
| C13-7 | On-demand scores are never stored; `by_top_k` is not evaluated for a single user-day | Applied |
| C13-8 | `limit` above 200 is a 422 at HTTP (the cap is in the OpenAPI document); services clamp for direct callers | Applied |
| C13-9 | No CRI sort of the queue; `sort=recent` instead (N55) | Applied |
| C13-10 | `CRIEngine.compute_event_detail` and `alerts.policy.band_trigger` / `top_k_eligible` added; behaviour of the earlier functions unchanged | Applied |
| C13-11 | asyncpg connect timeout of 5 s in `app/database/session.py` | Applied |
| C13-12 | Stored explanations for member days only; other user-days explained through `POST /risk/score` | Applied |
| C13-13 | The SQLite test database is built from the ORM and stamped at head, the equivalent of `alembic stamp head` | Applied |
| C13-14 | `backend/alembic.ini` gains `path_separator = os` (Alembic 1.16+ warned without it, found on the development machine). A Chapter 2 file; no migration changes | Applied |
| C13-15 | The integration test imports `testcontainers.community.postgres`, falling back to `testcontainers.postgres` (deprecated in the installed version) | Applied |

## Before reporting anything

- Nothing in this document is a CERT result. CERT figures for the API (the verifier's counts and the
  re-scoring differences) are quoted from `docs/audits/chapter_13_audit.md`, with the alert run id
  and policy hash.
- The re-scoring check shows the stored decision can be reproduced. It says nothing about whether the
  decision is right; that is Chapter 16.
- Latency measured by the verifier is for one development machine and a single client.

## Acceptance checklist

Bible Chapter 13:

- [x] Every listed API group has at least the endpoints the dashboard (Chapter 14) calls (route table;
  `test_every_api_group_of_the_architecture_is_present`)
- [x] No route handler contains business logic beyond request/response marshalling
  (`test_routers_only_marshal`)
- [x] Integration tests hit a real database via testcontainers and pass (12 passed on the development
  machine, container branch; also 12 of 12 against PostgreSQL 16 through `CIRA_TEST_DATABASE_URL`)
- [x] `/health` accurately reflects DB and model status (`database`, `anomaly_model`, `routes`; outage
  test)

HCEA §13:

- [x] Every list endpoint paginated with a hard server-side cap
- [x] Overview and history aggregated on the server

Real runs (N62):

- [x] The development machine's API serves the full alert run; `/health` routes all ready
- [x] `verify_chapter13.py --database-url` with 0 FAIL against it (28 PASS, 0 WARN)
- [x] The integration tests through testcontainers on the development machine
- [x] `docs/audits/chapter_13_audit.md` written from that output
