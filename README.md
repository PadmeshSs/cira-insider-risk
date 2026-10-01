# CIRA: Context-Aware Insider Risk Analytics

Final-year project. Behavioural insider-risk detection on CERT r4.2 with
TabNet, contextual risk scoring, MITRE ATT&CK enrichment and a SOC dashboard.

Governing documents: `CIRA_FINAL_ARCHITECTURE.md` (architecture),
`CIRA_IMPLEMENTATION_BIBLE.md` (sequencing), HCEA v1.0 (execution budget).

## Status

Statuses follow the Bible's taxonomy and are only raised after code runs and
passes its checks.

| Chapter | Component | Status |
|---|---|---|
| 1 | Repository foundation | IMPLEMENTED |
| 2 | Database, ORM, migrations, FastAPI `/health` | IMPLEMENTED |
| 3 | CERT r4.2 ingestion + ground-truth separation | IMPLEMENTED |
| 3 | TWOS (secondary dataset) | PLANNED (access request pending) |
| 4 | Preprocessing and normalization | IMPLEMENTED |
| 5 | Feature engineering (Stage 0-4) | IMPLEMENTED; dev, mid and full runs recorded |
| 6 | Baselines: rule, Isolation Forest, LOF, LSTM autoencoder, XGBoost | IMPLEMENTED; verified on mid (user, time) and full (user) |
| 7 | TabNet, model registry, same-harness comparison with the baselines | IMPLEMENTED |
| 8 | Anomaly scoring service, served-model decision, batch scoring, API model loading | IMPLEMENTED; serving gbdt v0003 |
| 9 | Contextual Risk Intelligence (CRI), Asset entity | IMPLEMENTED; calibrated for gbdt v0003 |
| 10 | MITRE ATT&CK enrichment (19.2), MITREMapping entity, CRI `mitre_context` | IMPLEMENTED; reference 20260929T184428Z-full-mitre, ATT&CK 19.2 |
| 11 | Explainability: TreeSHAP on the served XGBoost, KernelSHAP corroboration, TabNet mask view, analyst reasons | IMPLEMENTED; explain run 20260930T190519Z-full-explain |
| 12 | Alert correlation, deduplication and persistence; lineage entities | IMPLEMENTED; alert run 20261001T062628Z-full-alerts, policy 21cd9391fd48 |
| 13 | FastAPI integration: twelve route groups, analyst login, on-demand scoring, `/health` readiness | IMPLEMENTED; serves alert run 20261001T062628Z-full-alerts, verifier 28 PASS / 0 FAIL |
| 14 | React + TypeScript SOC dashboard: eight views over the Chapter 13 API | IMPLEMENTED on the synthetic chain; CERT full check pending |
| 15-16 | End-to-end validation, evaluation | PLANNED |
| 17-18 | Kafka, Redis, Celery, SSE, OpenSearch, observability, K8s | NOT IMPLEMENTED (production extensions) |

See `docs/audits/chapter_1_5_audit.md`, `docs/audits/chapter_6_audit.md` and `docs/audits/chapter_7_audit.md`, `docs/audits/chapter_8_audit.md`, `docs/audits/chapter_9_audit.md` and
`docs/audits/chapter_10_audit.md`, `docs/audits/chapter_11_audit.md`, `docs/audits/chapter_12_audit.md` and `docs/audits/chapter_13_audit.md` for the chapter reviews, and
`docs/CARRY_FORWARD.md` for the rules every later chapter must follow.
Chapter 6 is described in `docs/chapters/chapter_6_baselines.md`, Chapter 7
in `docs/chapters/chapter_7_tabnet.md`, Chapter 8 in
`docs/chapters/chapter_8_scoring.md`, Chapter 9 in `docs/chapters/chapter_9_cri.md`,
Chapter 10 in `docs/chapters/chapter_10_mitre.md`, Chapter 11 in
`docs/chapters/chapter_11_explainability.md`, Chapter 12 in `docs/chapters/chapter_12_alerts.md`,
Chapter 13 in `docs/chapters/chapter_13_api.md`, Chapter 14 in `docs/chapters/chapter_14_dashboard.md`
(run steps in `frontend/README.md`).

## Running Chapter 5

Set `CERT_RAW_DIR`, `CERT_GROUND_TRUTH_DIR`, `CERT_PROCESSED_DIR` and
`CIRA_PROFILE` in `.env` (see `.env.example`), then from `backend/`:

```bash
python -m app.feature_engineering.pipeline --profile dev
python ../scripts/build_labels.py            # evaluation-only label tables
python ../scripts/http_host_inventory.py     # label-blind review of host classes
```

Work up the profile ladder (dev, then mid, then full). Numbers from `dev`
are never reported (HCEA R10). Every run appends to `experiments/runlog.jsonl`.

## Running Chapter 6

After the Chapter 5 matrix and the label tables exist for a profile, from
`backend/`:

```bash
python -m app.baselines.run --profile mid                # user split, all five baselines
python -m app.baselines.run --profile mid --split time   # time-ordered check
```

The first run writes the user split to `experiments/splits/`; later runs
reuse it. Metrics go to `experiments/results/chapter6/<run_id>/metrics.json`
(gitignored), one headline line per model to `experiments/runlog.jsonl`,
scores to `<CERT_PROCESSED_DIR>/scores/chapter6/<run_id>/`.

Check and explain a run (the run id is printed at the end of each run):

```bash
python ../scripts/verify_chapter6.py --profile mid --run-id <run id> --reload-models --permutation-test
python ../scripts/inspect_scores.py  --profile mid --run-id <run id>      # validation split
```

Design: `docs/chapters/chapter_6_baselines.md`. Results, the reported run
ids and the verification record: `docs/audits/chapter_6_audit.md`.

## Running Chapter 7

After Chapter 6 (the TabNet run reuses its split file), from `backend/`:

```bash
python -m app.tabnet.train --profile mid --exclude-features psych_,peer_department_size
python -m app.tabnet.train --profile mid --exclude-features psych_,peer_department_size --split time
python ../scripts/verify_chapter7.py --profile mid --reload-models --permutation-test --baselines
python -m app.evaluation.compare --profile mid --split user --run-id <run id>   # validation table
```

Each run writes scores to `<CERT_PROCESSED_DIR>/scores/chapter7/<run_id>/`,
metrics to `experiments/results/chapter7/<run_id>/`, a new registry version
under `models/saved_models/tabnet/` and one line to `experiments/runlog.jsonl`.
Training checkpoints every epoch and resumes after an interruption; use
`--fresh` for a from-scratch re-run. The reported models are behaviour-only,
hence `--exclude-features` (N25); they are listed in
`experiments/chapter7_reference_runs.json`. Design and run order:
`docs/chapters/chapter_7_tabnet.md`; results: `docs/audits/chapter_7_audit.md`.

## Running Chapter 8

Chapter 8 chooses the served model between TabNet and a behaviour-only
XGBoost, using a rule fixed in advance and applied on validation. It then
serves that model. The whole real-data sign-off is one resumable command,
from `backend/`:

```bash
python ../scripts/signoff_chapter8.py              # stops at the first FAIL; re-run after a fix
python ../scripts/signoff_chapter8.py --finalize   # after explaining every WARN in the audit draft
```

The same steps by hand:

```bash
python -m app.scoring.gbdt_candidate --profile full        # also --profile mid, and mid --split time
python ../scripts/verify_chapter8.py --profile full --candidate-run-id <run id> --permutation-test --no-decision
python -m app.scoring.select --gbdt full/user=<run> --gbdt mid/user=<run> --gbdt mid/time=<run>
python -m app.scoring.select --report-test                  # once, after the decision
python -m app.scoring.batch --profile full --with-shadow
python ../scripts/verify_chapter8.py --profile full --candidate-run-id <full user run>
```

The decision goes to `experiments/chapter8_serving_decision.json` (commit
it). The API loads the decided model once at startup, on CPU, and
`/health` reports it. Batch scores go to
`<CERT_PROCESSED_DIR>/scores/chapter8/<batch_run_id>/`. Rows tagged
`model_split=train` are in-sample (N31). Design, the rule and the full run
order: `docs/chapters/chapter_8_scoring.md`.

## Running Chapter 9

Chapter 9 turns the served model's anomaly score into a 0-100 contextual
risk score and a severity band. Every component is put on one rarity scale,
fitted to the served model's validation user-days, so the same weights and
bands work whichever model is served; a calibration belongs to one
model_version and is refused for any other (N29, N33). The real-data
sign-off is one resumable command, from `backend/`:

```bash
python ../scripts/signoff_chapter9.py              # stops at the first FAIL; re-run after a fix
python ../scripts/signoff_chapter9.py --finalize   # after explaining every WARN in the audit draft
```

The same steps by hand:

```bash
python -m app.cri.calibrate --profile full         # label-free; pins experiments/chapter9_cri_calibration.json
python -m app.cri.batch --profile full             # risk scores to <CERT_PROCESSED_DIR>/risk/chapter9/<run id>/
python ../scripts/verify_chapter9.py --profile full --no-readout
python -m app.cri.evaluate --profile full          # validation readout, once (reads labels)
python ../scripts/verify_chapter9.py --profile full
```

Remove any `CRI_*` values from your `.env` that differ from `.env.example`;
an override is reported and the run is then not the calibrated default.
Apply the `assets` migration with `alembic upgrade head`. Design, the
formula and the bands: `docs/chapters/chapter_9_cri.md`.

## Running Chapter 10

Chapter 10 maps behaviour CERT r4.2 actually records to candidate ATT&CK
techniques per user-day, and turns the strongest one into the CRI's
`mitre_context`. It reads behaviour only, never a model score, because the
served XGBoost and the shadow TabNet find different insiders; a technique
on a user-day does not change with the served model (N42). From `backend/`,
after Chapter 9 and with `MITRE_ATTACK_VERSION=19.2` in `.env`:

```bash
python -m app.mitre.calibrate --profile full          # label-free; pins experiments/chapter10_mitre_reference.json
python -m app.mitre.batch --profile full              # enrichment run to <CERT_PROCESSED_DIR>/mitre/chapter10/<run id>/
python -m app.cri.batch --profile full --with-mitre   # CRI with mitre_context; run id ends in -mitre
python ../scripts/verify_chapter10.py --profile full --no-readout
python ../scripts/verify_chapter9.py --profile full --cri-run-id <the -mitre run> --no-readout
python -m app.mitre.evaluate --profile full           # validation readout, once (reads labels)
python ../scripts/verify_chapter10.py --profile full
alembic upgrade head                                  # mitre_mappings table
```

The ATT&CK technique table is committed under `backend/app/mitre/data/`.
`python -m app.mitre.stix_loader --download` regenerates it from the pinned
bundle and is only needed if the pin changes. Design, the rules, what is
deliberately left unmapped and why: `docs/chapters/chapter_10_mitre.md`.

## Running Chapter 11

Chapter 11 explains why a user-day was scored as it was. Chapter 8 serves the
behaviour-only XGBoost, so the model-side explanation is exact TreeSHAP on that
model, checked on every row to add up to the margin it scored (N30, N47).
KernelSHAP runs on a bounded, label-free set as the corroborating signal (HCEA
D-5). TabNet's masks appear only in the offline readout, labelled as the shadow
model's view (N32). An explanation keeps model factors, CRI points and ATT&CK
context in separate sections, each traced to its source. From `backend/`, after
Chapter 10:

```bash
python -m app.explainability.batch --profile full        # every user-day + the bounded set
python ../scripts/verify_chapter11.py --profile full --no-readout
python -m app.explainability.evaluate --profile full     # validation readout, once (reads labels)
python ../scripts/verify_chapter11.py --profile full
```

Runs go to `<CERT_PROCESSED_DIR>/explanations/chapter11/<run id>/`; the written
explanations for the bounded set are in `reasons.jsonl`. `/health` gains an
`explainability` block. Design, the deviations from D-5 and what makes the
chapter IMPLEMENTED: `docs/chapters/chapter_11_explainability.md`.

## Running Chapter 12

Chapter 12 turns triggered user-days into correlated alerts. A user-day
triggers when its CRI band is HIGH or CRITICAL or it has the day's highest
served anomaly score. Nearby triggered days of one user become one alert, and
an alert that repeats an open one inside the cooldown is kept as suppressed.
Every member day carries the Chapter 11 explanation. The load writes the alert
run, its lineage rows and a bounded demo sample into PostgreSQL in one
transaction (HCEA D-6). From `backend/`, after Chapter 11, with PostgreSQL up:

```bash
export CERT_PROCESSED_DIR=/path/to/datasets/processed   # read from the shell, not from .env
alembic upgrade head
python -m app.alerts.batch --profile full
python ../scripts/verify_chapter12.py --profile full --no-readout
python -m app.alerts.load --profile full                # DATABASE_URL from .env
python ../scripts/verify_chapter12.py --profile full --no-readout --database-url "$DATABASE_URL"
python -m app.alerts.evaluate --profile full            # validation readout, once (reads labels)
python ../scripts/verify_chapter12.py --profile full --database-url "$DATABASE_URL"
```

PowerShell uses `$env:CERT_PROCESSED_DIR = "..."` and `$env:DATABASE_URL`; the
chapter document has the full PowerShell version. Runs go to
`<CERT_PROCESSED_DIR>/alerts/chapter12/<run id>/`. `/health` gains `alerts` and
`database` blocks. Design, deviations and what makes the chapter IMPLEMENTED:
`docs/chapters/chapter_12_alerts.md`.

## Running Chapter 13

The API serves the loaded alert run of the model served now, from PostgreSQL,
to signed-in analysts. From `backend/`, after the Chapter 12 load:

```bash
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48))" >> ../.env
pip install -r requirements.txt                      # adds pyjwt and aiosqlite
python -m app.services.accounts create --username alice --email alice@example.org
uvicorn app.main:app --port 8000                     # docs at http://localhost:8000/docs
CIRA_ANALYST_PASSWORD='...' python ../scripts/verify_chapter13.py --username alice --database-url "$DATABASE_URL"
```

Every route is under `/api/v1`; only `auth/token` and `health` are public.
Lists are capped at 200 rows per page, and nothing computed over HTTP is
stored. `/health` gains `auth` and `routes` blocks. Design, routes, failure
modes and what makes the chapter IMPLEMENTED: `docs/chapters/chapter_13_api.md`.

## Tests

```bash
pytest            # from the repo root
```
