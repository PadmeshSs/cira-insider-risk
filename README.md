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
| 5 | Feature engineering (Stage 0-4) | IMPLEMENTED; verified on dev and mid, full run pending |
| 6 | Baselines: rule, Isolation Forest, LOF, LSTM autoencoder, XGBoost | PARTIALLY IMPLEMENTED; tested on synthetic data, mid/full runs pending |
| 7-16 | TabNet, CRI, MITRE, XAI, alerts, API, dashboard, evaluation | PLANNED |
| 17-18 | Kafka, Redis, Celery, SSE, OpenSearch, observability, K8s | NOT IMPLEMENTED (production extensions) |

See `docs/audits/chapter_1_5_audit.md` for the Chapter 1-5 review, and
`docs/CARRY_FORWARD.md` for the rules every later chapter must follow.
Chapter 6 is described in `docs/chapters/chapter_6_baselines.md`.

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
scores to `<CERT_PROCESSED_DIR>/scores/chapter6/<run_id>/`. See
`docs/chapters/chapter_6_baselines.md`.

## Tests

```bash
pytest            # from the repo root
```
