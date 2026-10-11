# Repository structure against Bible §2

Bible §2 is the target end state, and it also says directories are created only when a chapter needs them.
This file lists where the repository differs from §2 and why, so that Chapter 19 step 4 ("no orphaned or
unused directories") is checked rather than asserted. `scripts/verify_chapter19.py` reads it: every §2 path
must be tracked in git or appear in the first table, and every tracked top-level entry must be in §2 or in
the second.

## §2 paths that are not tracked in git

| §2 path | Why |
|---|---|
| `docker-compose.prod.yml` | The production overlay belongs to Chapters 17-18, which were scoped out. |
| `backend/pyproject.toml` | Dependencies are in `backend/requirements.txt` with exact versions in `backend/requirements.lock.txt` (N87); pytest is configured by `pytest.ini` at the root. Nothing is packaged, so a pyproject would add nothing. |
| `backend/app/core/logging.py` | No central logging setup was needed. Pipeline entry points print progress and append one line per run to `experiments/runlog.jsonl` (HCEA R8), which is the record the audits cite; the API error handler and the scoring service log through `logging.getLogger`. |
| `backend/app/utils` | Shared helpers live next to their users: `backend/app/feature_engineering/common.py` (repo root, runlog), `backend/app/core/runtime.py` (thread caps, HCEA R6), `backend/app/core/run_stamp.py` (N74), `backend/app/services/common.py` (paging). An empty utils package would be the "module for visual completeness" §2 forbids. |
| `datasets/raw` | Gitignored. CERT r4.2 is downloaded from KiltHub; on the development machine it sits outside the repository (HCEA R5) and `CERT_RAW_DIR` points at it. |
| `datasets/processed` | Gitignored, created by the pipeline under `CERT_PROCESSED_DIR`; far too large for git at the full profile. |
| `datasets/sample` | Not used. The tests run on generated CERT-shaped fixtures under `backend/tests/fixtures`, never on a CERT extract. |
| `models/saved_models` | Gitignored. The append-only registry with sha256 per file (N21) is created on the first registration; the committed `experiments/*_reference_runs.json` and `experiments/chapter8_serving_decision.json` pin its versions. |
| `models/checkpoints` | Gitignored. TabNet's per-epoch checkpoints (resume, HCEA R7) are written here by default (`--checkpoint-dir`), created on the first training run. |
| `models/artifacts` | Not used; every artifact belongs to a registry version or a run folder. |
| `notebooks` | No notebook was used. Every number comes from a command-line run with a runlog line (N79). |
| `tests` | The cross-cutting tests §2 puts at the root are `backend/tests/e2e` (raw CSV to dashboard, N70) and the chapter verifiers in `scripts/`. A second root test folder would split the regression gate. |
| `docker/postgres/init.sql` | Optional in §2. Alembic creates the schema (`alembic upgrade head`), and the e2e suite proves it on a fresh server. |

## Tracked entries that §2 does not name

| Entry | Why |
|---|---|
| `scripts/` | Command-line checks that sit outside the application package: dataset inventory and smoke tests (Chapters 3-4), label tables and the label-blind host review (Chapter 5), the per-chapter verifiers and sign-off scripts, the e2e stack helper. Each one is referenced from the README or a chapter document. |
| `docs/` | Carry-forward notes (`docs/CARRY_FORWARD.md`), chapter design documents, audits, dataset notes, this file, `docs/COMPONENT_STATUS.md`, and the HCEA under `docs/governance/`. |
| `pytest.ini` | Root pytest configuration (`pythonpath = backend`, the e2e marker), so `pytest` runs all three layers from the repository root. |
| `.dockerignore` | Keeps `.env`, data, models and `experiments/` out of image build contexts. |

## Differences in shape, not in substance

The frontend pages are one file per view under `frontend/src/pages/` (for example `AlertsPage.tsx`) rather than
one folder per view; the views are the ones §2 lists plus Users, System and Not found. Several backend
packages have more modules than §2 names (batch, calibrate, evaluate, runtime and sources modules per
chapter); every module §2 names exists.
