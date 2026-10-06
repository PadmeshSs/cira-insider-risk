# Chapter 15: End-to-end validation and testing

Bible Chapter 15 / Architecture Phase 12 (§12, §36, §37, §45), executed under HCEA v1.0 §14.

Status: IMPLEMENTED (6 October 2026). `scripts/verify_chapter15.py --browser` on the development machine,
with the CERT full API and dashboard checks: 27 PASS, 0 WARN, 0 FAIL. Audit:
`docs/audits/chapter_15_audit.md`.

## What Chapter 15 proves, and what it does not

The Bible asks for one event pushed through every stage until it reaches the dashboard as an explained,
scored alert:

```text
Raw event -> normalized event -> features -> model -> anomaly score
-> CRI -> MITRE -> explanation -> alert -> PostgreSQL -> API -> dashboard
```

Chapter 15 automates that chain and checks each hop against the value the previous hop produced. It
says nothing about how well CIRA detects insiders on CERT; that is Chapter 16. Numbers produced by the
synthetic stack are never results (N72).

The model hop needs one sentence of care. The Bible writes "TabNet -> anomaly score". Since Chapter 8
(C8-1) the served model is XGBoost and TabNet runs as shadow. The tests follow the chain as built:
XGBoost produces the served score; TabNet is trained, scores every row, and is checked to reach no CRI,
alert or explanation (N71).

## Is the dashboard showing real data?

Checked before writing Chapter 15, and re-checked by the tests below.

- Every value in `frontend/src` comes from an Axios call through `services/client.ts`. There are no
  fixtures, mock libraries or random numbers in application code; `src/test/no-fixtures.test.ts`
  now enforces this (it fails if a page gains a `Math.random`, which was tried and reverted).
- The API reads PostgreSQL only and answers 503 or 404 with a reason instead of an empty or default
  response.
- With the API unreachable, every view shows an error and none of the values it showed while the API
  was up (`frontend/e2e/no-fabrication.spec.ts`). The one exception is the user id in `/users/<id>`,
  which the breadcrumb takes from the address, not from the API.
- It is not real-time. The pipeline batch-scores the historical CERT r4.2 data (2010-2011) and stores
  the decisions; the dashboard reads them. The only automatic refresh is the `/health` poll every 30 s,
  and the only live computation is "Re-score this day" (`POST /risk/score`, never stored, N64). Live
  alert delivery (SSE) is Chapter 17. The report should not describe the dashboard as real-time.

## The stack (`backend/tests/e2e/ch15_stack.py`)

One build per pytest session, in this order, through the production entry points:

| Step | Entry point |
|---|---|
| Raw CSV tree, 32 users, 13 planted insiders | `tests/fixtures/synthetic_ch6.build` |
| Stage 0 (Chapter 4 policy) and the user-day matrix | `app.feature_engineering.pipeline.run_pipeline` |
| Served model, XGBoost | `app.scoring.gbdt_candidate` |
| Shadow model, TabNet, 3 epochs | `app.tabnet.train` |
| Scores, served and shadow | `app.scoring.batch --with-shadow` |
| CRI calibration, ATT&CK reference, enrichment, CRI with `mitre_context` | `app.cri.calibrate`, `app.mitre.calibrate`, `app.mitre.batch`, `app.cri.batch` |
| Explanations | `app.explainability.batch` |
| Alert run | `app.alerts.batch` |
| Fresh PostgreSQL database at Alembic head | `CREATE DATABASE cira_e2e_<hex>`, `alembic upgrade head` |
| Load with a refused connection (must store nothing) | `app.alerts.load` against port 1 |
| Load that loses its connection while writing `alert_reasons` (must roll back) | `app.alerts.load` with `persistence._insert` failing |
| The real load, read back | `app.alerts.load` |
| One analyst | `app.services.accounts.create` |
| Retraining with the same split and seed | `app.scoring.gbdt_candidate` into a second registry |

The traced raw row is chosen after the run: the top open alert's peak day, and that user's first USB
connect on it (then a logon, then anything). Nothing is planted to make the trace pass.

PostgreSQL comes from `CIRA_E2E_DATABASE_URL` (a server where the tests may create a database), then
`CIRA_TEST_DATABASE_URL` (its server only), then testcontainers. There is no SQLite fallback; without
PostgreSQL the suite skips with the reason, and the verifier counts the skip as a FAIL.

Measured on the build container: 23 s for the build (0.5 s migration, 16 s for Chapters 5-12, 2 s for
the real load), 31 s for the 30 tests. HCEA §14 asked for a small checkpointed model committed under
`tests/fixtures/`. That is not done (C15-1): the chain trains in seconds, so the suite retrains from raw
CSV each run, which also means a committed checkpoint can never go stale against the feature pipeline.

## The tests

### `test_ch15_chain.py`: one raw row, hop by hop (15 tests)

| Hop | Check |
|---|---|
| raw | the traced row is that line of the CSV |
| raw -> normalized | Chapter 3 loader + Chapter 4 `normalize_event` give the same user, device and timestamp as the Stage 0 Parquet row; no label key in either (N5) |
| normalized -> features | `usb_connect_count` (or `login_count`) of the user-day equals a count taken straight from the raw CSV |
| features -> score | the served XGBoost and the shadow TabNet both scored the day; the day is out of sample (N31); `score_event` reproduces the batch score with its model version; an empty registry raises instead of scoring (§36) |
| score -> CRI | the CRI row carries the same anomaly score (N34), its band follows the configured maxima, and its points add up to the CRI |
| shadow | every alert member's score is the served score, never the shadow one (N32) |
| CRI -> MITRE | the day was evaluated; every match names a rule, technique, trigger column and evidence; unmapped days have no match |
| MITRE -> explanation | TreeSHAP on the served model, additivity within tolerance (N47), every factor a matrix column |
| explanation -> alert | the day is the peak member of the traced alert, triggered, explanation complete |
| alert -> PostgreSQL | one SQL join from `event_logs.event_id` (the raw CERT id) through `feature_vectors`, `anomaly_scores`, `model_versions`, `risk_scores`, `alert_members` to `alerts`; every stored value equals the Parquet value; reasons and ATT&CK rows present |
| database | no label key in any stored vector or event detail; no alert on a training user; Alembic at head |
| §45 item 16 | retraining with the same split and seed gives the same model version and metrics |

### `test_ch15_api_journey.py`: the six §27 questions over HTTP (9 tests)

`/health` ready with one loaded run; the overview ranks the traced user at the top score (users tied on
it are ordered by id); the queue starts with the traced alert; alert detail, risk row and anomaly row
equal the database; explanation sections equal the `alert_reasons` rows; ATT&CK status equals the
Chapter 10 run; `/events` returns the traced raw row by its CERT id, linked to the feature vector;
re-scoring from `/features` and `/risk` (the request the dashboard builds) reproduces the anomaly score
exactly and the CRI to 1e-9, with no row written; every login is audited and none counts as a load.

### `test_ch15_failure_modes.py`: §36 end to end (6 tests)

| Situation | Expected |
|---|---|
| load, connection refused | exit 3, `NOT STORED`, every lineage table empty |
| load, connection lost after alerts and members were sent | exit 3, everything rolled back |
| the two failures and the real load | two `not_stored` and one `stored` runlog lines; one audit row |
| database cut while the API serves (TCP proxy in front of PostgreSQL) | 503 `database_unavailable` on reads and login; `/health` database unavailable and routes not ready (N68); after the cut is restored the same requests answer 200 with the same items, no restart |
| no loaded alert run | 503 `component: alerts` naming `app.alerts.load`; routes not ready |
| no served model | 503 `component: anomaly_model` on reads and `POST /risk/score`; `/health` degraded |

### Frontend

| File | What it checks |
|---|---|
| `src/test/views.test.tsx` (Vitest) | Overview renders the user, score and run id of the response; with a network error it shows "API not reachable" and none of them; with a 503 it shows the API's reason |
| `src/test/no-fixtures.test.ts` (Vitest) | no import from `src/test`, no random numbers or mock libraries, every service goes through `client.ts` |
| `e2e/journey.spec.ts` (Playwright) | sign in through the form; each view against the live API: overview, queue order, alert detail and the "Re-score this day" control, explanation factors, ATT&CK techniques, the traced raw row in the event table, risk-history coverage, served model on System; every request goes to the API or the app; one screenshot per view |
| `e2e/no-fabrication.spec.ts` (Playwright) | the values each view showed disappear when every API request is refused, and each view shows an error |
| `e2e/cert.spec.ts` (Playwright) | the same checks against the CERT full run on the development machine, plus re-scoring the top alerts through the dashboard; skipped unless `CIRA_CERT_USERNAME` is set |

The screenshots are the "documented run-through" of the Bible's checklist:
`frontend/test-results/ch15-run-through/` (synthetic) and `frontend/test-results/ch15-cert/` (CERT).

## Running it

From the repository root, with PostgreSQL reachable (the compose service works):

```powershell
$env:CIRA_E2E_DATABASE_URL = "postgresql+asyncpg://cira:<password>@localhost:5433/postgres"
python -m pytest backend/tests/e2e                      # 30 passed, 0 skipped

cd frontend; npm install; npx playwright install chromium; cd ..
python scripts/e2e_stack.py build                       # keeps a database and writes .e2e/stack.json
cd frontend; $env:CIRA_PYTHON = "python"; npm run test:e2e; cd ..
python scripts/e2e_stack.py teardown
```

`npm run test:e2e` starts `scripts/e2e_stack.py serve` (API on 8765) and Vite (5174) itself, or reuses
them if they are already running.

All of it, with a report:

```powershell
Remove-Item Env:CIRA_TEST_DATABASE_URL -ErrorAction SilentlyContinue   # integration tests use testcontainers
python scripts/verify_chapter15.py --browser
```

Never point `CIRA_TEST_DATABASE_URL` at `insider_threat_db`. The Chapter 13 integration tests load their
own synthetic alert run into that database, and the API serves the newest loaded run, so the CERT
dashboard would then show synthetic alerts. Leave it unset (Docker runs a throwaway container) or point
it at a separate database such as `cira_test`. `CIRA_E2E_DATABASE_URL` is safe on the compose server:
the e2e suite only ever creates and drops its own `cira_e2e_<hex>` databases.

The verifier runs pytest unit, integration and e2e (one JUnit file each), eslint, build, Vitest and,
with `--browser`, the Playwright click-through. It then maps each of the sixteen §45 items to named
tests and passes an item only if all of them ran and passed. It writes
`experiments/results/chapter15/verification_<stamp>.json` and `.md` and a `chapter15_verification`
runlog line.

## Closing the chapter (development machine, CERT full)

1. `python -m pytest backend/tests/e2e` with 0 skipped.
2. Start the CERT API with the dashboard's origin allowed:
   ```powershell
   $env:CORS_ORIGINS = "http://localhost:5173,http://127.0.0.1:5174"
   cd backend; uvicorn app.main:app --port 8000
   ```
3. In another shell: `python scripts/verify_chapter15.py --browser --cert-username <analyst> --cert-database-url $env:DATABASE_URL`, 0 FAIL.
4. Write `docs/audits/chapter_15_audit.md` from the generated report: the counts, every WARN explained,
   the CERT screenshots, the re-scoring result, and the timings. Then retire N73.

Step 3 is also the check `chapter_14_dashboard.md` left open: the dashboard opened against the CERT run.
Done on 6 October 2026; see the audit.

If the hidden password prompt refuses a password you are sure of, set it visibly first
(`$env:CIRA_ANALYST_PASSWORD = Read-Host "analyst password"`) and test it with
`Invoke-RestMethod -Method Post http://127.0.0.1:8000/api/v1/auth/token -Body @{username='<analyst>'; password=$env:CIRA_ANALYST_PASSWORD}`.

## Development machine record (6 October 2026)

| Layer | Result |
|---|---|
| backend unit | 376 passed |
| backend integration, testcontainers PostgreSQL | 85 passed, 2 skipped (`test_cert_chapter4_sample`: CERT lives on `D:`; `test_ch12_pipeline.py:142`: needs `CIRA_TEST_DATABASE_URL`, left unset on purpose) |
| backend e2e | 30 passed, 0 skipped, 39.9 s in pytest |
| frontend | lint and build clean; Vitest passed |
| Playwright, synthetic | 10/10 |
| CERT API (`verify_chapter13`, analyst `padmesh-ch15`) | 28 PASS, 0 WARN, 0 FAIL |
| CERT dashboard (`cert.spec.ts`) | passed |

## Build container record (synthetic, not a result)

| Layer | Result |
|---|---|
| backend unit | 373 passed |
| backend integration, `CIRA_TEST_DATABASE_URL` on PostgreSQL 16 | 86 passed, 1 skipped (`test_cert_chapter4_sample`: CERT r4.2 not present on the container) |
| backend e2e | 30 passed, 0 skipped, about 31 s |
| frontend | lint and build clean; Vitest 15 passed |
| Playwright | 10 passed (journey 9, no-fabrication 1); `cert.spec.ts` exercised against the synthetic API to check the spec itself, not against CERT |

## Deviations

- **C15-1** No committed model checkpoint under `tests/fixtures/` (HCEA §14). The chain trains from raw
  CSV in about 16 s on one CPU, so the e2e suite stays under a minute without one, and nothing binary
  can drift from the feature pipeline.
- **C15-2** The mid-load failure is injected by replacing `app.alerts.persistence._insert` for one load,
  so the failure happens on a real PostgreSQL connection after real rows were sent. Stopping PostgreSQL
  mid-transaction would be closer to an outage but cannot be timed reliably in a test.
- **C15-4** `app/core/run_stamp.py` added and used by the 11 pipeline entry points (Chapters 6-12) to
  stop same-second run ids from overwriting each other. A code change outside Chapter 15's own files,
  made because the end-to-end work exposed it; costs at most about a second per back-to-back run.
- **C15-5** `playwright.config.ts` quotes the Python path. The development machine's path contains a
  space and an apostrophe (`...\Padmesh 's\...`); unquoted, the API web server never started and the
  verifier saw "0/0 passed". The verifier also filters specs by name (`journey.spec`), not by a path with
  forward slashes.
- **C15-6** The verifier signs in once before the CERT checks, reads child output as UTF-8 (Windows
  decoded it as cp1252 and garbled Playwright's message), quotes Playwright's own error from its JSON
  report and prints every failing test by name. Reporting only.
- **C15-3** The database cut for the API runs through an in-process TCP proxy, so PostgreSQL itself never
  stops and recovery can be asserted in the same test.

## Found while testing

- **Run ids could collide (fixed, C15-4).** Every pipeline entry point named its run by the UTC second.
  Two runs of the same kind started within one second got the same id and the second overwrote the
  first's results folder, metrics and runlog identity. On the development machine `test_ch7_runner`
  failed intermittently because of it (the ablation and resume runs started in the same second as the
  first run; their runlog lookup returned the first run's line). `app/core/run_stamp.py` now hands out
  stamps that are strictly increasing within a process, waiting for the next second when needed; the
  format and ordering are unchanged. All 11 entry points use it, and
  `tests/unit/test_ch15_run_stamp.py` fails if a module builds a run id from the clock again. Two runs
  in separate processes within one second can still collide; that needs two terminals started together
  and is left as a known limit.

- The "CERT id" column of the event table is clipped at 1440 px wide when the right-hand panel is shown;
  it scrolls sideways. Cosmetic.
- `app/database/session.py` echoes every SQL statement when `ENVIRONMENT=development` (the
  `.env.example` default). Worth turning off before the CERT dashboard check, or the uvicorn console
  floods.

## Carry-forward

New notes N70 (the e2e suite is the regression gate), N71 (XGBoost served, TabNet checked as shadow),
N72 (synthetic e2e numbers are never results), N73 (status, retired 6 October 2026) and N74 (run ids
from `app.core.run_stamp` only). Notes satisfied here: N5, N31, N32, N34,
N47, N58 (the outage tests repeated end to end), N63, N64, N65, N68 (outage checks read `routes`), N69
(the re-score control driven as the lineage check).
