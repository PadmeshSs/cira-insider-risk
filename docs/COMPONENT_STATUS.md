# CIRA component status

The Bible's Appendix B table, filled in at Chapter 19. Statuses use the Bible's five words only:
IMPLEMENTED, PARTIALLY IMPLEMENTED, PLANNED, OPTIONAL, PRODUCTION EXTENSION. A component is IMPLEMENTED
only when it ran on CERT r4.2 (full profile where the chapter required it) and passed its verifier; the
evidence column names the file that records that. `scripts/verify_chapter19.py` checks every row: the
status is one of the five, every cited file exists, the TWOS row matches the loader, and no production
extension is claimed without code in the repository behind it.

Run ids are quoted as recorded in the audits. Numbers are not repeated here; they live in the audits and
in `experiments/chapter16_evaluation_report.md` (N79).

| Component | Status | Evidence |
|---|---|---|
| Repository foundation | IMPLEMENTED | `docs/audits/chapter_1_5_audit.md` |
| DB/FastAPI skeleton | IMPLEMENTED | four Alembic revisions in `backend/alembic/versions` (head `9f3b2c7d4e81`); the e2e suite migrates a fresh PostgreSQL to head on every run (`backend/tests/e2e/test_ch15_chain.py`); `docs/audits/chapter_1_5_audit.md` |
| CERT ingestion | IMPLEMENTED | `backend/app/ingestion/cert_loader.py`, inventory in `experiments/dataset_inventory.txt`, ground truth kept apart by `backend/app/ingestion/ground_truth.py`; `docs/datasets/cert.md`, `docs/audits/chapter_1_5_audit.md` |
| TWOS ingestion | PLANNED | access depends on the TWOS release agreement and the data has not arrived; `backend/app/ingestion/twos_loader.py` defines the interface and reports `TWOS_RELEASE_STATUS`; `docs/datasets/TWOS.md` |
| Preprocessing | IMPLEMENTED | `backend/app/preprocessing/normalize.py`, rejected-row sink; `docs/audits/chapter_1_5_audit.md` |
| Feature engineering | IMPLEMENTED | dev, mid and full runs in `experiments/runlog.jsonl`; label-blind host review `experiments/http_host_category_review.txt`; `docs/audits/chapter_1_5_audit.md` |
| Baselines (rule/IF/LOF/LSTM-AE/GBDT) | IMPLEMENTED | all five on mid (user, time) and full (user): `experiments/chapter6_reference_runs.json`, `docs/audits/chapter_6_audit.md` |
| TabNet | IMPLEMENTED | trained, registered and evaluated on mid and full; runs as the shadow model since C8-1. `experiments/chapter7_reference_runs.json`, `docs/audits/chapter_7_audit.md` |
| Anomaly scoring service | IMPLEMENTED | serves the behaviour-only XGBoost, registry `gbdt` v0003, decided by `c8-serving-rule-v1`: `experiments/chapter8_serving_decision.json`, `docs/audits/chapter_8_audit.md` |
| CRI | IMPLEMENTED | calibration for the served model_version `experiments/chapter9_cri_calibration.json`; `docs/audits/chapter_9_audit.md` |
| MITRE enrichment | IMPLEMENTED | ATT&CK 19.2, ruleset `c10-rules-v1`, reference `experiments/chapter10_mitre_reference.json`; `docs/audits/chapter_10_audit.md` |
| Explainability (masks + SHAP) | IMPLEMENTED | TreeSHAP on the served XGBoost is the explanation, KernelSHAP corroborates on a bounded set, TabNet masks appear only as the shadow model's view (N30, N48, N51). Explain run `20260930T190519Z-full-explain`: `experiments/chapter11_reference_runs.json`, `docs/audits/chapter_11_audit.md` |
| Alert correlation/persistence | IMPLEMENTED | alert run `20261001T062628Z-full-alerts`, policy `21cd9391fd48`, loaded in one transaction with its audit row: `docs/audits/chapter_12_audit.md` |
| FastAPI full integration | IMPLEMENTED | twelve route groups over the loaded run, `scripts/verify_chapter13.py` 28 PASS / 0 FAIL on CERT full: `docs/audits/chapter_13_audit.md` |
| React dashboard | IMPLEMENTED | eight views over the API, checked against the CERT full run by the Chapter 15 browser checks: `docs/audits/chapter_14_audit.md`, `docs/audits/chapter_15_audit.md` |
| E2E validation | IMPLEMENTED | raw CSV to dashboard on every run, §36 failure modes, §45 items mapped to tests; `scripts/verify_chapter15.py --browser` 27 PASS / 0 WARN / 0 FAIL with the CERT checks: `docs/audits/chapter_15_audit.md` |
| Evaluation/ablations | IMPLEMENTED | pinned test readout `20261010T072243Z-full-test-c16`, six seeds, user-clustered bootstrap, experiments A to E; `scripts/verify_chapter16.py --recompute` 29 PASS / 0 WARN / 0 FAIL: `experiments/chapter16_test_readout.json`, `experiments/chapter16_evaluation_report.md`, `docs/audits/chapter_16_audit.md` |
| Docker Compose (FYP baseline) | PARTIALLY IMPLEMENTED | the `postgres` service in `docker-compose.yml` is the database every chapter from 12 on used. The `backend` and `frontend` images build from `docker/backend.Dockerfile` and `docker/frontend.Dockerfile` but are not the verified run path: the backend image has no serving decision or registry to load (N86) |
| Kafka/Redpanda | PRODUCTION EXTENSION | not implemented; Chapter 17 scoped out. The FYP core is dataset-driven and does not need it (Architecture §7) |
| Redis | PRODUCTION EXTENSION | not implemented; Chapter 17 scoped out |
| Celery | PRODUCTION EXTENSION | not implemented; Chapter 17 scoped out |
| SSE | PRODUCTION EXTENSION | not implemented; Chapter 17 scoped out. The dashboard reads stored decisions, not a live feed |
| OpenSearch | PRODUCTION EXTENSION | not implemented; Chapter 18 scoped out |
| Prometheus/Grafana | PRODUCTION EXTENSION | not implemented; Chapter 18 scoped out. `/health` is the only operational signal |
| Auth/RBAC hardening | PRODUCTION EXTENSION | not implemented; Chapter 18 scoped out. What exists is Chapter 13's basic login: HS256 JWT, CLI-created analysts, every login audited, `analyst` and `admin` read the same data (N65) |
| Docker productionization | PRODUCTION EXTENSION | not implemented; no `docker-compose.prod.yml` (Chapter 18 scoped out) |
| Kubernetes | PRODUCTION EXTENSION | not implemented; explicitly not required for the FYP core (Bible Chapter 18) |
| CI/CD | PRODUCTION EXTENSION | not implemented; no GitHub Actions workflow. The regression gate is run by hand with `scripts/verify_chapter15.py` (N70) |

## Reading the table in the viva

The chain the repository supports is baselines, TabNet (shadow), XGBoost (served), XGBoost + CRI, XGBoost +
CRI + MITRE (N77). "TabNet is the detection model" is not a claim this repository makes (N71).
