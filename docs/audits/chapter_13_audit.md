# Chapter 13 audit (1 October 2026)

Scope: Chapter 13 (FastAPI full integration), checked against the Bible Chapter 13 acceptance list,
Architecture §25, §36 and §37, HCEA v1.0 §8 and §13, and CARRY_FORWARD N1-N68.
Evidence, all from the development machine: the `/health` body returned by `uvicorn app.main:app`
(served model loaded at 2026-10-01T13:56:10Z), the console output of
`scripts/verify_chapter13.py` and its report
`experiments/results/chapter13/verification_20261001T140218Z.json` (gitignored), and the console
output of `python -m pytest backend/tests/integration/test_ch13_api.py`. Every number below is copied
from those. Chapter 13 has no sign-off script, so this audit was written by hand from that output.

Served model: gbdt v0003 (`gbdt-chapter8-v1-077a3dae6cee`), 106 inputs, no static input, from the
Chapter 8 decision file (`c8-serving-rule-v1`). The shadow tabnet v0005 loaded with no error and
appears only on `/models` (N32).

## Reported runs

| What | Id |
|---|---|
| Alert run served | `20261001T062628Z-full-alerts` (policy `c12-alert-policy-v1`, hash `21cd9391fd48`, no override) |
| Database | `insider_threat_db` at Alembic `9f3b2c7d4e81`, one alert run loaded (load `20261001T063107Z`) |
| CRI calibration | `20260929T095921Z-full-cri`, config `297bbbe7add7`, no override |
| MITRE reference | `20260929T184428Z-full-mitre`, ATT&CK 19.2, rules `c10-rules-v1` / `d58ec9c75bc6` |
| Explainer | TreeSHAP on gbdt v0003, iteration range 0-591 (best iteration 590) |
| Verifier | `verification_20261001T140218Z`, analyst `padmesh`, `--sample 10`, with `--database-url` |

These are the runs the earlier audits report. Chapter 13 built no new run and changed no stored row.

## Verification record

| What | Result |
|---|---|
| `/health` | `healthy`; anomaly model, CRI, MITRE, explainability and alerts `loaded`; database `reachable`; auth `configured`; every entry of `routes` ready, and `alerts_risk_investigations` names `20261001T062628Z-full-alerts` |
| `verify_chapter13.py --database-url` | 28 PASS, 0 WARN, 0 FAIL |
| `test_ch13_api.py` on the development machine | 12 passed, 0 skipped, 54.6 s, Windows, Python 3.13.3, against a testcontainers postgres:17 |
| Whole test suite | 459 passed, 1 skipped on Linux, Python 3.12, PostgreSQL 16 (where the chapter was built); not yet run as a whole on the development machine |

The `/health` alerts block shows 232 open and 33 suppressed alerts and 519 complete explanations,
the counts in `docs/audits/chapter_12_audit.md`. The API serves the run Chapter 12 loaded, unchanged.

### How the testcontainers branch is known to have run

The test chooses its database in order: `CIRA_TEST_DATABASE_URL`, then a testcontainers container,
then SQLite. Two things in the output place it in the second branch. The run printed Alembic's
`path_separator` warning, which comes from `_migrate`, and only the container branch migrates. And
no test was skipped, so `test_database_is_postgres` ran and found PostgreSQL at `9f3b2c7d4e81`.
That closes the Bible's "integration tests hit a real database via testcontainers" item.

The same run printed a deprecation warning for `testcontainers.postgres`. The test now imports
`testcontainers.community.postgres` first and falls back to the old path (C13-15). The Alembic
warning is fixed in `backend/alembic.ini` (C13-14). Both changes are checked on Linux only, so the
next run on the development machine should show neither warning.

## The verifier, section by section

| Section | Checks | Result |
|---|---|---|
| health | both health routes 200; model, database, auth, CRI, MITRE, explainability; every route group ready | 8 PASS |
| auth | wrong password 401; no token 401; sign-in; `/users/me` | 4 PASS |
| contract | all twelve API groups of §25; every `limit` capped at 200 (`/events`, `/alerts`, `/investigations`); no score called a probability | 3 PASS |
| queue | open 232 and suppressed 33 counted together; ordered by `anomaly_score`; both scores on every alert; all 33 suppressed alerts attached to open alerts; 0 alerts from training users; `limit=201` refused with 422; `/health` and the queue name the same run | 7 PASS |
| alerts | top 10 open alerts: one peak each, every member triggered, explanation sections of the right kind and equal in number to the `alert_reasons` rows, ATT&CK techniques equal to the alert's | 1 PASS |
| scoring | the 10 peak days re-scored through `POST /api/v1/risk/score` from their stored feature vectors and LDAP roles | 3 PASS |
| database | the served run's `alert_run_loaded` audit row exists once; stored counts {open 232, suppressed 33} equal the API's | 2 PASS |

### Re-scoring

For each of the ten highest-queue open alerts, the verifier read the peak day's stored feature vector
and LDAP role, sent them to `POST /api/v1/risk/score`, and compared the result with the stored rows.
The largest difference was 0.00e+00 for the anomaly score and 0.00e+00 for the CRI. So on CERT, the
stored vector, the served gbdt v0003, the CRI calibration and the MITRE reference reproduce the stored
decision exactly, through the API's own path (§37, N34, N64). This is a reproducibility check. It
says nothing about whether those ten alerts are right; detection quality is Chapter 16.

The verifier also records the median and maximum latency of those ten requests in the report JSON
(`risk_score_seconds`). They were not in the console output this audit was written from, so they are
not quoted here.

## What this shows and does not show

- The API serves the Chapter 12 run as stored: the counts, the ordering and the suppression links
  agree with the database and with the Chapter 12 audit.
- The lineage holds end to end on ten real alerts. Ten is the verifier's default sample, chosen from
  the top of the queue, not at random. The other 222 open alerts were checked only through the queue
  section.
- No label was read. The verifier is label-free, and the sample contains validation and test users'
  alerts as stored, so nothing was tuned on it.
- Login, the 401 paths and the cap were checked once each against the running API. Load, concurrency
  and token expiry under real use were not tested.

## Checklist

Bible Chapter 13:

- [x] Every listed API group has at least the endpoints the dashboard (Chapter 14) calls (contract
  section: all twelve groups present)
- [x] No route handler contains business logic beyond request/response marshalling
  (`test_routers_only_marshal`)
- [x] Integration tests hit a real database via testcontainers and pass (12 passed on the development
  machine, container branch, see above)
- [x] `/health` accurately reflects DB and model status (health section; the database block shows the
  revision and loaded runs; the outage test in the suite)

HCEA §13:

- [x] Every list endpoint paginated with a hard server-side cap (contract and queue sections)
- [x] Overview and history aggregated on the server

N62:

- [x] `SECRET_KEY` set and an analyst created on the development machine
- [x] the API serves `20261001T062628Z-full-alerts`; `/health` shows every route group ready
- [x] `verify_chapter13.py --database-url` with 0 FAIL (28 PASS, 0 WARN)
- [x] the integration tests through testcontainers, `test_database_is_postgres` passing
- [x] this audit

## Still open

- The whole test suite has not been run on the development machine for Chapters 12 and 13 (the
  Chapter 12 audit lists the same gap). Run `pytest` from the repo root once before Chapter 14.
- The two warning fixes (C13-14, C13-15) were checked on Linux only.
- The Docker backend image still predates Chapter 12 and does not mount the dataset or the model
  registry. `/health` and the verifier ran against `uvicorn` on the host. Chapter 14 can develop
  against `uvicorn`; the container is rebuilt in Chapter 18.
- The analyst password used for this sign-off was shared in a chat transcript. It is a local
  development account; replace it (deactivate and create a new one) before the account is used
  anywhere shared.
