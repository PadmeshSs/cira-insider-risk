# Chapter 15 audit (6 October 2026)

Scope: Chapter 15 (end-to-end validation and testing), checked against the Bible Chapter 15 checklist,
Architecture §12, §36, §37 and the sixteen §45 acceptance items, HCEA v1.0 §14, and CARRY_FORWARD
N1-N74.

Evidence, all from the development machine (Windows, Python venv under `backend\venv`, Docker
PostgreSQL 17 on port 5433): the console output of `scripts/verify_chapter15.py --browser
--cert-username padmesh-ch15 --cert-database-url ...` and its report
`experiments/results/chapter15/verification_20261006T110956Z.md` (gitignored), the
`verify_chapter13` report it produced, `experiments/results/chapter15/verification_20261006T111502Z.json`
(gitignored), and the screenshots in `frontend/test-results/ch15-run-through/` (synthetic) and
`frontend/test-results/ch15-cert/` (CERT). Every number below is copied from those.

Result: **27 PASS, 0 WARN, 0 FAIL.** Chapter 15 is IMPLEMENTED.

## What was run

| Layer | What it exercises | Result |
|---|---|---|
| backend unit | 376 tests, including the 3 of `test_ch15_run_stamp.py` | 376 passed, 35 s |
| backend integration | Chapters 6-13 against PostgreSQL through testcontainers | 85 passed, 2 skipped, 185 s |
| backend e2e | raw CSV through Chapters 5-12 into a fresh PostgreSQL database, then the API (`backend/tests/e2e`) | 30 passed, 0 skipped, 39.9 s in pytest |
| frontend | eslint, `tsc -b` + Vite build, Vitest | clean, clean, passed |
| browser, synthetic | Playwright journey (9) and no-fabrication (1) against the e2e stack | 10/10, 28 s |
| CERT API | `verify_chapter13` against uvicorn on port 8000, analyst `padmesh-ch15`, with `--database-url` | 28 PASS, 0 WARN, 0 FAIL |
| CERT dashboard | `frontend/e2e/cert.spec.ts`: nine views, three re-scores, API cut | passed, 14 s |

The two integration skips, both expected:

- `test_cert_chapter4_sample` reads `datasets/raw/cert_r4.2` under the repository; CERT r4.2 lives on
  `D:` on this machine (HCEA R5). Chapters 3-4 on the real files are covered by the Chapter 1-5 audit.
- `test_ch12_pipeline.py:142` runs only with `CIRA_TEST_DATABASE_URL`. It was left unset on purpose:
  pointing it at `insider_threat_db` would load a synthetic alert run into the CERT database, and the API
  serves the newest run. The same refused-connection and mid-load failures run on PostgreSQL in
  `test_ch15_failure_modes.py`.

## §45 acceptance

Each item passes only when every named test that evidences it ran and passed
(`ACCEPTANCE` in `scripts/verify_chapter15.py`).

| Item | Evidence | Result |
|---|---|---|
| 1 project starts | `/health` healthy with every route ready; dashboard builds | PASS |
| 2 migrations run | fresh database at the Alembic head revision | PASS |
| 3 events ingest | the traced row is that line of the raw CSV | PASS |
| 4 events normalize | Chapter 3 loader + Chapter 4 `normalize_event` equal the Stage 0 row | PASS |
| 5 features generate | the user-day count feature equals a count taken from the raw CSV | PASS |
| 6 TabNet trains and evaluates | TabNet trained and scored every row as shadow; nothing downstream used it | PASS |
| 7 inference produces a score | `score_event` reproduces the batch score with its model version; no model, no score | PASS |
| 8 CRI | same anomaly score on the CRI row (N34); band and points consistent | PASS |
| 9 MITRE | day evaluated; every match traceable to rule, technique, column and evidence | PASS |
| 10 explanation | TreeSHAP on the served model, additive within tolerance (N47) | PASS |
| 11 alert persists | one SQL join from the raw CERT id to the alert; mid-load failure rolls back | PASS |
| 12 FastAPI exposes it | queue, events and the database-cut recovery over HTTP | PASS |
| 13 React displays it | traced raw row in the event table; queue order; no value survives the API | PASS |
| 14 analyst understands why | stored explanation over HTTP and on screen; alert detail with re-score | PASS |
| 15 tests cover core components | all three pytest layers and Vitest green | PASS |
| 16 metrics reproducible | same split and seed give the same model version and metrics (fixture) | PASS |

Items 3-14 are proved on synthetic CERT-shaped data (32 users, 13 planted insiders). They prove the code
path, not detection quality (N72). Item 16 on CERT is Chapter 16's.

## The traced event

The e2e stack follows one raw CSV row chosen after the run from the top open alert's peak day. On this
machine it was device row `{S0000001943}`, user `u0008`, 2010-01-11 12:33:06, alert `492fe53af3b99f8a`,
the same row as on the build container, since the fixture and seed are fixed. The row was found at every
hop: Stage 0 Parquet, the feature matrix, the served and shadow scores, the CRI row, the ATT&CK context,
the explanation, the alert member, the PostgreSQL foreign-key chain, `/events`, and the dashboard's event
table (`ch15-run-through/6-investigation-traced-event.png`).

## CERT full run

Read from `verification_20261006T111502Z.json` (the `verify_chapter13` report, top-level fields and
`checks`):

| What | Value |
|---|---|
| Alert run served | `20261001T062628Z-full-alerts`, policy hash `21cd9391fd48`, the run the Chapter 12 and 13 audits record; `/health` and the queue name the same run |
| Served model | `gbdt-chapter8-v1-077a3dae6cee` (as in the Chapter 13 audit); CRI, MITRE and explainability loaded |
| Database | reachable at Alembic `9f3b2c7d4e81`; the served run's `alert_run_loaded` audit row exists once |
| Queue | 232 open and 33 suppressed, counted together; ordered by `anomaly_score`; both scores on every alert; all 33 suppressed alerts attached to open alerts; 0 alerts from training users (N31); `limit` capped at 200 on `/events`, `/alerts`, `/investigations` and 201 refused with 422 |
| Stored counts | {open 232, suppressed 33} in the database, equal to the API's |
| Ten open alerts in depth | members, explanation sections and ATT&CK techniques consistent (N45, N50) |
| On-demand re-scoring, 10 alerts | anomaly score max abs diff 0.00e+00; CRI max abs diff 0.00e+00 (N34) |
| `POST /risk/score` time | median 0.045 s, max 0.051 s, n = 10 |
| Auth | wrong password and missing token refused with 401; analyst `padmesh-ch15` signs in; `/users/me` is that analyst |
| Contract | every API group of Architecture §25 present; no score described as a probability (N20) |

Result: 28 PASS, 0 WARN, 0 FAIL.

In the browser (`cert.spec.ts`, 14 s): signed in through the login form; on all nine views the run id,
the served model version, the overview's top users and the top alert's first peak-day event (by CERT
id) were on screen as the API returned them; "Re-score this day" on the top three open alerts showed
"The stored decision reproduces from its stored inputs."; with every API request refused, each view
showed an error and none of those values (the user id in a `/users/<id>` address excepted, which the
breadcrumb takes from the URL).

This closes the item `chapter_14_dashboard.md` left open: the dashboard checked against the CERT run.

## Is the dashboard showing real data

Yes, within one limit. Every value comes from the API, which reads PostgreSQL; the static check
(`no-fixtures.test.ts`), the component test (`views.test.tsx`) and the browser checks above all fail if a
value appears without a response behind it. The limit: the data is the batch-scored CERT r4.2 history
(2010-2011), not a live feed. The dashboard refreshes `/health` every 30 s and computes nothing itself;
the only live computation is "Re-score this day", which is never stored. Live alert delivery is Chapter
17. The report must not call the dashboard real-time.

## Problems found on the development machine, and what was done

| Found by | Problem | Fix |
|---|---|---|
| verifier runs `20261006T091235Z`, `20261006T092140Z`: Playwright "0/0 passed in 2 s" | the Python path (`...\Padmesh 's\...`) was pasted unquoted into the Playwright web-server command; the apostrophe broke it, the API never started | path quoted in `playwright.config.ts`; spec filters made slash-neutral (C15-5) |
| verifier run `20261006T093548Z`: 4 failures in `test_ch7_runner.py`, passing when run alone | run ids were the UTC second; two Chapter 7 runs in one second shared an id and the second overwrote the first's results, metrics and runlog identity | `app/core/run_stamp.py`, used by all 11 entry points; enforced by `test_ch15_run_stamp.py` (C15-4, N74) |
| first CERT attempt: `verify_chapter13` 13 PASS 1 FAIL, CERT spec failed with an unreadable message | sign-in as `padmesh` refused (401); cause not pinned down, most likely the hidden password prompt; the message was cp1252-garbled UTF-8 | separate analyst `padmesh-ch15` created with `app.services.accounts create`; verifier now checks sign-in first, reads child output as UTF-8 and quotes Playwright's own error (C15-6) |

The record run above used the verifier before the C15-6 changes, which affect reporting only (one extra
sign-in row, readable errors); a run of the committed script reports 28 checks.

## Deviations

C15-1 (no committed model checkpoint; the chain retrains in seconds), C15-2 (mid-load failure injected on
a real connection), C15-3 (database cut through an in-process TCP proxy), C15-4 (run stamps), C15-5
(quoted interpreter path), C15-6 (verifier diagnostics). Details in `docs/chapters/chapter_15_e2e.md`.

## Carry-forward

N73 retired. N70 (the e2e suite is the regression gate), N71 (XGBoost served, TabNet checked as shadow),
N72 (synthetic e2e numbers are never results) and N74 (run ids from `app.core.run_stamp` only) carry into
Chapters 16-19.
