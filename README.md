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
| 9-16 | CRI, MITRE, XAI, alerts, API, dashboard, evaluation | PLANNED |
| 17-18 | Kafka, Redis, Celery, SSE, OpenSearch, observability, K8s | NOT IMPLEMENTED (production extensions) |

See `docs/audits/chapter_1_5_audit.md`, `docs/audits/chapter_6_audit.md` and `docs/audits/chapter_7_audit.md` and `docs/audits/chapter_8_audit.md` for the chapter reviews, and
`docs/CARRY_FORWARD.md` for the rules every later chapter must follow.
Chapter 6 is described in `docs/chapters/chapter_6_baselines.md`, Chapter 7
in `docs/chapters/chapter_7_tabnet.md`, Chapter 8 in
`docs/chapters/chapter_8_scoring.md`.

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

## Tests

```bash
pytest            # from the repo root
```
