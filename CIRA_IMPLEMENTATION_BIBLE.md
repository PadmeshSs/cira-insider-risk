# CIRA — Implementation Bible
### Context-Aware Insider Risk Analytics — Full Build Guide, Chapter by Chapter

**Status of this document:** Build guide / execution plan.
**Canonical architecture source:** `CIRA_FINAL_ARCHITECTURE.md` (all component roles, non-negotiable rules, and the target repository structure in this bible are taken directly from that document).
**Supporting governance source:** `CLAUDE.md` (coding workflow, honesty rules, technology decisions).
**Not authoritative on their own:** `Implementation_docs.pdf` (Executive Summary), `projetsetup.pdf` — used only where they don't conflict with the two documents above.

---

## 0. How to Use This Document

This is a chapter-by-chapter build plan. Each chapter is a **unit of work** with:

- **Objective** — what this chapter accomplishes and why it exists in the architecture.
- **Prerequisites** — what must already be true (prior chapters, accounts, downloads) before starting.
- **Outcome** — the concrete, verifiable state of the repository once the chapter is done.
- **Implementation** — the steps, commands, file contents, and code skeletons to execute.
- **Acceptance checklist** — how you (or an AI coding agent) verify the chapter is actually done, not just attempted.

**Rules that apply across every chapter (inherited from `CLAUDE.md` and `CIRA_FINAL_ARCHITECTURE.md`):**

1. Never claim a component is IMPLEMENTED unless it runs and passes its checks. Use the status taxonomy: `IMPLEMENTED / PARTIALLY IMPLEMENTED / PLANNED / OPTIONAL / PRODUCTION EXTENSION`.
2. Build the **FYP core vertical slice first** (Chapters 1–15). Do **not** start Kafka, Redis, Celery, OpenSearch, Prometheus/Grafana, or Kubernetes (Chapters 17–18) before the core slice works end-to-end.
3. Never fabricate benchmark numbers, MITRE mappings, or claimed test coverage.
4. Every architectural change is explained before it is made — nothing silent.
5. Secrets never get committed. `.env` is gitignored; `.env.example` is committed.

### On phase-numbering: reconciling `CIRA_FINAL_ARCHITECTURE.md` and `CLAUDE.md`

The two governing documents number phases differently — `CIRA_FINAL_ARCHITECTURE.md` §44 uses 13 phases, `CLAUDE.md` §22 uses 16. They are not contradictory in *content* or *order*, only in *granularity*: `CLAUDE.md`'s 16 phases are a finer-grained decomposition of the same work (e.g., it splits "TabNet" and "Anomaly Scoring" into two steps where the architecture doc treats them as one phase, and it separates initial FastAPI/DB scaffolding from later full API integration). This bible uses **20 chapters**, built on `CLAUDE.md`'s finer granularity (because it maps more directly to actionable units of work), with each chapter's heading annotated with its corresponding `CIRA_FINAL_ARCHITECTURE.md` phase number so traceability to the canonical architecture document is never lost. This reconciliation is a documentation-organization decision only — it changes no technology, no order of dependency, and no architectural rule.

| Bible Chapter | CLAUDE.md Phase | Architecture Phase |
|---|---|---|
| 1. Repository Foundation | 1 | 1 |
| 2. Database + FastAPI Skeleton | 2 | 1 |
| 3. Dataset Acquisition & Ingestion | 3 | 2 |
| 4. Preprocessing & Normalization | 4 | 2 |
| 5. Feature Engineering | 5 | 3 |
| 6. Baseline Models | 6 | 4 |
| 7. TabNet Model | 7 | 5 |
| 8. Anomaly Scoring & Serving | 8 | 5 |
| 9. Contextual Risk Intelligence (CRI) | 9 | 6 |
| 10. MITRE ATT&CK Enrichment | 10 | 7 |
| 11. Explainability (TabNet masks + SHAP) | 11 | 8 |
| 12. Alert Correlation & Persistence | 12 | 9 |
| 13. FastAPI Full Integration | 13 | 10 |
| 14. React + TypeScript Dashboard | 14 | 11 |
| 15. End-to-End Validation & Testing | 15 | 12 |
| 16. Evaluation Protocol & Ablations | — (cross-cutting) | §39–40 |
| 17. Production Extensions I: Kafka, Redis, Celery, SSE | 16 | 13 |
| 18. Production Extensions II: OpenSearch, Observability, Docker/K8s, Auth hardening, CI/CD | 16 | 13 |
| 19. Repository Finalization & Submission | — | §45 Acceptance Criteria |
| 20. Appendix | — | — |

---

## 1. Master Tech Stack

| Layer | Technology | Role | FYP-mandatory? |
|---|---|---|---|
| Language | Python 3.12/3.13 | Backend + ML | Yes |
| API | FastAPI + Pydantic v2 | Backend API | Yes |
| ORM | SQLAlchemy 2.x (async) | Data access | Yes |
| Migrations | Alembic (async template) | Schema versioning | Yes |
| Database | PostgreSQL 17 | Durable source of truth | Yes |
| ML framework | PyTorch + `pytorch-tabnet` | Core behavioural model | Yes |
| Data processing | Pandas, NumPy | Feature engineering | Yes |
| Baselines | Scikit-learn (Isolation Forest, LOF), XGBoost/CatBoost | Benchmarking | Yes |
| Explainability | TabNet masks + SHAP | XAI | Yes |
| Threat context | MITRE ATT&CK (`mitreattack-python`) | Enrichment | Yes |
| Frontend | React + TypeScript + Vite | SOC dashboard | Yes |
| Styling | Tailwind CSS + MUI | UI | Yes |
| State | Zustand | Frontend state | Yes |
| Forms | React Hook Form + Zod | Validation | Yes |
| Charts | Recharts | Risk visualizations | Yes |
| HTTP client | Axios | API calls | Yes |
| Containerization | Docker / Docker Compose | Dev + deploy | Yes (FYP baseline) |
| Streaming | Apache Kafka (prod) / Redpanda (local dev) | Production ingestion | Production extension |
| Cache | Redis | Hot cache / temp state | Production extension |
| Async jobs | Celery | Heavy background work | Production extension |
| Real-time push | SSE (native FastAPI or `sse-starlette`) | Live alerts | Production extension |
| Search | OpenSearch | Large-scale event search | Production extension |
| Observability | Prometheus + Grafana | System monitoring | Production extension |
| Orchestration | Kubernetes | Production scale-out | Production extension, not required |
| Testing (backend) | pytest, pytest-asyncio, httpx, testcontainers, factory_boy | Test suite | Yes |
| Testing (frontend) | Vitest, React Testing Library | Test suite | Yes |
| Datasets | CERT Insider Threat r4.2 (primary), TWOS (secondary) | Training/eval data | Yes |

Full current version pins and installation commands for every row above are documented separately in the **CIRA Implementation Research Brief** (companion reference artifact). Treat that brief as the version/command source of truth; treat this bible as the sequencing/structure source of truth.

---

## 2. Canonical Repository Structure

This is the **target end-state** structure (per `CIRA_FINAL_ARCHITECTURE.md` §41, expanded to file level). Directories are created **when the chapter that needs them is reached** — never create empty modules for visual completeness.

```text
cira-insider-risk/
├── CLAUDE.md
├── CIRA_FINAL_ARCHITECTURE.md
├── CIRA_IMPLEMENTATION_BIBLE.md          # this document
├── README.md
├── .env.example
├── .gitignore
├── docker-compose.yml                     # FYP: backend, frontend, postgres
├── docker-compose.prod.yml                # Production extensions overlay
│
├── backend/
│   ├── pyproject.toml
│   ├── requirements.txt
│   ├── alembic.ini
│   ├── alembic/
│   │   ├── env.py
│   │   └── versions/
│   ├── app/
│   │   ├── main.py
│   │   ├── core/
│   │   │   ├── config.py                  # pydantic-settings
│   │   │   ├── logging.py
│   │   │   └── security.py                # JWT/OAuth2 helpers
│   │   ├── database/
│   │   │   ├── session.py                 # async engine + sessionmaker
│   │   │   └── base.py                    # DeclarativeBase + naming convention
│   │   ├── ingestion/
│   │   │   ├── cert_loader.py
│   │   │   └── twos_loader.py
│   │   ├── preprocessing/
│   │   │   ├── normalize.py
│   │   │   └── validate.py
│   │   ├── feature_engineering/
│   │   │   ├── authentication.py
│   │   │   ├── file_activity.py
│   │   │   ├── email.py
│   │   │   ├── usb.py
│   │   │   ├── network.py
│   │   │   ├── application.py
│   │   │   ├── temporal.py
│   │   │   ├── historical_baseline.py
│   │   │   ├── peer_group.py
│   │   │   └── pipeline.py                # orchestrates all of the above
│   │   ├── baselines/
│   │   │   ├── rule_based.py
│   │   │   ├── isolation_forest.py
│   │   │   ├── lof.py
│   │   │   ├── lstm_autoencoder.py
│   │   │   └── gbdt.py                    # XGBoost/CatBoost
│   │   ├── tabnet/
│   │   │   ├── dataset.py
│   │   │   ├── train.py
│   │   │   ├── infer.py
│   │   │   └── model_registry.py          # versioning
│   │   ├── cri/
│   │   │   ├── config.py                  # configurable weights
│   │   │   └── engine.py
│   │   ├── mitre/
│   │   │   ├── stix_loader.py
│   │   │   ├── mapping_rules.py
│   │   │   └── enrich.py
│   │   ├── explainability/
│   │   │   ├── tabnet_masks.py
│   │   │   ├── shap_explainer.py
│   │   │   └── reason_builder.py
│   │   ├── alerts/
│   │   │   ├── correlation.py
│   │   │   └── deduplication.py
│   │   ├── api/
│   │   │   ├── deps.py
│   │   │   └── v1/
│   │   │       ├── auth.py
│   │   │       ├── users.py
│   │   │       ├── events.py
│   │   │       ├── features.py
│   │   │       ├── anomaly.py
│   │   │       ├── risk.py
│   │   │       ├── alerts.py
│   │   │       ├── investigations.py
│   │   │       ├── mitre.py
│   │   │       ├── explanations.py
│   │   │       ├── models.py
│   │   │       └── health.py
│   │   ├── schemas/                       # Pydantic request/response models
│   │   ├── services/                      # business-logic layer between API and domain
│   │   ├── evaluation/
│   │   │   ├── metrics.py
│   │   │   ├── splitting.py
│   │   │   └── ablation.py
│   │   └── utils/
│   ├── tests/
│   │   ├── unit/
│   │   ├── integration/
│   │   └── e2e/
│   └── models/ORM entity files live under database/models/
│
├── frontend/
│   ├── package.json
│   ├── vite.config.ts
│   ├── tsconfig.json
│   └── src/
│       ├── main.tsx
│       ├── App.tsx
│       ├── components/{common,layout,ui}/
│       ├── pages/{Overview,Alerts,AlertDetail,UserInvestigation,RiskHistory,Explainability,MitreContext,Login}/
│       ├── hooks/
│       ├── services/                       # axios API clients
│       ├── store/                          # zustand stores
│       ├── utils/
│       ├── constants/
│       └── types/
│
├── datasets/
│   ├── raw/
│   ├── processed/
│   └── sample/
│
├── models/
│   ├── saved_models/
│   ├── checkpoints/
│   └── artifacts/
│
├── experiments/
├── notebooks/
├── tests/                                   # cross-cutting/system-level tests
└── docker/
    ├── backend.Dockerfile
    ├── frontend.Dockerfile
    └── postgres/init.sql (optional)
```

**Note on the repo root name:** the current live repository is `cira-insider-risk`; `CIRA_FINAL_ARCHITECTURE.md` §41 also names it `cira-insider-risk`; earlier drafts referenced `cira-insider-threat`. This bible uses **`cira-insider-risk`** as canonical, matching the actual repository and the architecture document, and flags `cira-insider-threat` as the deprecated/inconsistent name to eliminate from any remaining references.

---

## Chapter 1 — Repository Foundation
*(CLAUDE.md Phase 1 / Architecture Phase 1)*

### Objective
Establish the version-controlled skeleton, environment tooling, and dependency management that every later chapter builds on.

### Prerequisites
- Git installed; GitHub account with access to `PadmeshSs/cira-insider-risk`.
- Python 3.12 or 3.13 installed; Node.js 20+ installed.
- Docker + Docker Compose installed.
- `uv` (recommended) or `pip`/`venv` for Python dependency management.

### Outcome
A cloned repository with the two canonical docs, `.gitignore`, `.env.example`, empty-but-structured `backend/` and `frontend/` roots, and a working Python + Node toolchain — with **no application logic yet**.

### Implementation
1. Clone the repo and confirm the two canonical docs and `.gitignore` are present (they already are, per the current repository state).
2. Create the Python project:
   ```bash
   cd backend
   uv init --python 3.12
   uv add "fastapi[standard]" "sqlalchemy[asyncio]" asyncpg alembic pydantic-settings \
          pandas numpy scikit-learn torch pytorch-tabnet shap mitreattack-python stix2
   uv add --dev pytest pytest-asyncio httpx testcontainers factory_boy ruff
   ```
3. Create `backend/app/` with only `main.py` and `core/config.py` for now (see Chapter 2 for content — this chapter just creates the empty package `__init__.py` files and directory skeleton listed in §2 above, **without** populating modules that belong to later chapters).
4. Create the frontend skeleton (scaffolding only — no pages yet, that's Chapter 14):
   ```bash
   npm create vite@latest frontend -- --template react-ts
   ```
5. Write `.env.example` at repo root with placeholders for every variable listed in `CIRA_FINAL_ARCHITECTURE.md` §43 (`DATABASE_URL`, `SECRET_KEY`, `ENVIRONMENT`, `LOG_LEVEL`, `MODEL_PATH`, `MODEL_VERSION`, `CRI_*`, `MITRE_*`, plus production-extension variables commented out for now: `REDIS_URL`, `KAFKA_BOOTSTRAP_SERVERS`, `OPENSEARCH_URL`, `CELERY_BROKER_URL`, `CORS_ORIGINS`).
6. Confirm `.gitignore` already excludes `.env`, `__pycache__/`, `node_modules/`, `datasets/raw/*`, `models/saved_models/*`, etc. (it does, per the current repository state — do not duplicate rules).
7. Initial commit: repository skeleton only.

### Acceptance checklist
- [ ] `backend/` builds a virtual environment and imports FastAPI without error.
- [ ] `frontend/` runs `npm install && npm run dev` and serves the default Vite page.
- [ ] `.env` is not committed; `.env.example` is.
- [ ] No feature/model/API code exists yet — this chapter is scaffolding only.

---

## Chapter 2 — Database, ORM, Migrations & FastAPI Skeleton
*(CLAUDE.md Phase 2 / Architecture Phase 1)*

### Objective
Stand up PostgreSQL as the durable source of truth, SQLAlchemy 2.x async as the ORM, Alembic for migrations, and a FastAPI app with a working health endpoint — the foundation every later API and persistence chapter depends on.

### Prerequisites
Chapter 1 complete.

### Outcome
`docker compose up` brings up PostgreSQL + a FastAPI backend that responds on `/health`; `alembic upgrade head` runs cleanly against an empty schema.

### Implementation
1. **`docker-compose.yml`** (FYP baseline — backend, frontend, postgres only, per `CIRA_FINAL_ARCHITECTURE.md` §33):
   ```yaml
   services:
     postgres:
       image: postgres:17
       environment:
         POSTGRES_USER: cira
         POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
         POSTGRES_DB: insider_threat_db
       ports: ["5433:5432"]
       volumes: ["pgdata:/var/lib/postgresql/data"]
       healthcheck:
         test: ["CMD-SHELL", "pg_isready -U cira -d insider_threat_db"]
         interval: 5s
         timeout: 5s
         retries: 5

     backend:
       build: { context: ./backend, dockerfile: ../docker/backend.Dockerfile }
       env_file: .env
       ports: ["8000:8000"]
       depends_on:
         postgres: { condition: service_healthy }

     frontend:
       build: { context: ./frontend, dockerfile: ../docker/frontend.Dockerfile }
       ports: ["5173:5173"]
       depends_on: [backend]

   volumes:
     pgdata:
   ```
2. **`app/database/base.py`** — `DeclarativeBase` with a MetaData naming convention (so Alembic autogenerate produces stable constraint names for `ix`/`uq`/`ck`/`fk`/`pk`).
3. **`app/database/session.py`** — `create_async_engine` (postgresql+asyncpg dialect), `async_sessionmaker`, and a `get_session` FastAPI dependency.
4. **`app/core/config.py`** — `pydantic-settings` `BaseSettings`/`SettingsConfigDict` reading everything from `.env`.
5. **`app/main.py`** — FastAPI app, `/health` route, and router registration placeholders (empty until Chapter 13).
6. **Alembic:** `alembic init -t async alembic`; set `target_metadata` to the shared `Base.metadata`; confirm `env.py` uses `async_engine_from_config` + `connection.run_sync(...)`.
7. Define the **first entities** from `CIRA_FINAL_ARCHITECTURE.md` §20 that have an immediate purpose at this stage: `User`, `Configuration`. (Do **not** create `Asset`, `EventLog`, `FeatureVector`, `AnomalyScore`, `RiskScore`, `Alert`, `AlertReason`, `MITREMapping`, `ModelVersion`, or `AuditLog` yet — each is created in the chapter that actually needs it, per the "no speculative tables" rule.)
8. Generate and review the first migration: `alembic revision --autogenerate -m "initial schema"` → inspect the diff → `alembic upgrade head`.

### Acceptance checklist
- [ ] `docker compose up` brings up all three services; Postgres passes its healthcheck before backend starts.
- [ ] `GET /health` returns 200 from a running container.
- [ ] `alembic upgrade head` succeeds against a fresh database.
- [ ] Only `User` and `Configuration` tables exist — no speculative entities.

---

## Chapter 3 — Dataset Acquisition & Ingestion
*(CLAUDE.md Phase 3 / Architecture Phase 2)*

### Objective
Acquire CERT (primary) and TWOS (secondary) datasets and build dataset-loader ingestion that converts raw records into the canonical event contract defined in `CIRA_FINAL_ARCHITECTURE.md` §8.

### Prerequisites
Chapter 2 complete. Internet access for dataset download.

### Outcome
`datasets/raw/` contains the CERT r4.2 extract; `app/ingestion/cert_loader.py` (and, once available, `twos_loader.py`) can parse raw files into a list of canonical event dicts/DataFrames, without leaking labels into features.

### Implementation
1. **CERT r4.2:** download directly (free, no request form) from Carnegie Mellon's KiltHub repository, DOI `10.1184/R1/12841247.v1` — the single KiltHub article bundles all CERT releases (r1 through r6.2) plus `answers.tar.bz2` ground truth. Extract only r4.2 into `datasets/raw/cert_r4.2/`.
2. **TWOS (secondary):** submit the signed release agreement early — access is manual (email request + supervisor confirmation), not an instant download, so start this in parallel with Chapter 1–2 rather than waiting until this chapter. Do not fabricate TWOS access as complete until the dataset is actually in hand.
3. Build `cert_loader.py`: parse CERT's per-domain CSVs (`logon.csv`, `file.csv`, `email.csv`, `device.csv`, `http.csv`, `psychometric.csv`, LDAP snapshots) into the canonical event contract (`event_id`, `timestamp`, `user_id`, `device_id`, `source_type`, `event_type`, etc., per §8). Preserve traceability to the source record (store original row reference in `metadata`).
4. Keep `answers.tar.bz2` (ground truth) **separate** from the feature pipeline — it is for evaluation labels only, never a model input (data-leakage rule, §9).
5. Write a small ingestion smoke test: load a sample of each CERT domain file, assert schema conformance, and report row counts per domain.

### Acceptance checklist
- [ ] CERT r4.2 downloaded and extracted; file inventory matches the known r4.2 structure (~32.77M events, 7,323 labeled malicious instances per released ground truth).
- [ ] `cert_loader.py` produces canonical-schema events for every domain file.
- [ ] Ground-truth labels are stored separately from the feature-input path.
- [ ] TWOS request submitted (status tracked honestly as PLANNED/IN-PROGRESS until data actually arrives).

---

## Chapter 4 — Preprocessing & Normalization
*(CLAUDE.md Phase 4 / Architecture Phase 2)*

### Objective
Turn raw ingested events into clean, validated, schema-conformant records ready for feature engineering.

### Prerequisites
Chapter 3 complete.

### Outcome
`app/preprocessing/normalize.py` and `validate.py` transform raw CERT events into normalized, deduplicated, schema-validated events, with malformed records flagged rather than silently dropped.

### Implementation
Implement each responsibility listed in `CIRA_FINAL_ARCHITECTURE.md` §9 as a discrete, testable function:
1. Parse source-specific records (per-domain CERT parsers built in Chapter 3 feed this stage).
2. Normalize timestamps to a single timezone-aware ISO-8601 format.
3. Normalize user/device identifiers (consistent casing/format across all domains).
4. Handle missing values (explicit policy per field — do not silently zero-fill numeric fields that mean "absent" vs "zero").
5. Remove or flag malformed records (write to a `rejected_records` sink for later inspection, not silent drop).
6. Normalize categorical values (canonical enums for `source_type`, `event_type`).
7. Validate event schemas (Pydantic schema validation against the canonical contract from §8).
8. Remove obvious duplicates (dedupe key: `event_id` or content hash if `event_id` is synthetic).
9. Preserve traceability to the source record (already captured in `metadata` from Chapter 3 — verify it survives normalization).

### Acceptance checklist
- [ ] A normalization pass over a CERT sample produces zero schema-validation failures on the *accepted* stream.
- [ ] Rejected/malformed records are captured with a reason, not silently discarded.
- [ ] No target labels (malicious/benign) are present anywhere in the normalized feature-input path.

---

## Chapter 5 — Feature Engineering
*(CLAUDE.md Phase 5 / Architecture Phase 3)*

### Objective
Build the full behavioural feature set described in `CIRA_FINAL_ARCHITECTURE.md` §10 — the single most important layer of CIRA.

### Prerequisites
Chapter 4 complete.

### Outcome
`app/feature_engineering/pipeline.py` produces one feature vector per user-day (or user-session), assembled from every sub-module below, output as a `[N_samples × N_features]` matrix ready for TabNet and the baseline models.

### Implementation
Build one module per feature domain, each independently unit-tested, then a `pipeline.py` that orchestrates them:

1. **Authentication** (`authentication.py`): login count, failed/successful login count, login hour, off-hours flag, unusual login time, new device/IP, authentication frequency.
2. **File activity** (`file_activity.py`): files created/modified/deleted/accessed, sensitive-file-access flags, abnormal volume, unusual timing.
3. **Email** (`email.py`): messages sent/received, attachment count/size, internal/external recipient ratio, unusual recipient behaviour. (NLP on message content stays OPTIONAL and out of scope unless text data is actually available and justified — §10.3.)
4. **USB/removable media** (`usb.py`): insertion/removal counts, abnormal usage, file-transfer association.
5. **Network** (`network.py`): inbound/outbound bytes, connection count, destination diversity, unusual destination, unusual transfer volume, cloud/storage activity.
6. **Application/process** (`application.py`): application/process counts, unusual application/process flags, abnormal timing.
7. **Temporal** (`temporal.py`): hour of day, day of week, weekend indicator, off-hours indicator, rolling activity counts, activity-window statistics.
8. **Historical baseline** (`historical_baseline.py`): per-user deviation from their own rolling history (`current_login_hour − user's normal distribution`, etc., per §10.8). Choose and document the statistical method (e.g., z-score against a trailing 30-day window) — do not silently invent one without recording the choice.
9. **Peer-group** (`peer_group.py`): deviation from role/department peer norms — **only** where the dataset actually supports peer metadata (CERT includes LDAP role/department data); do not invent peer relationships where unsupported.
10. **Pipeline orchestration** (`pipeline.py`): joins all of the above into one feature matrix keyed by `(user_id, date)`, persists to `datasets/processed/`, and writes a `feature_schema.json` documenting every column (name, dtype, source domain) for reproducibility and later SHAP labeling.

### Acceptance checklist
- [ ] Every feature sub-domain has unit tests against synthetic input.
- [ ] The full pipeline runs over the CERT r4.2 sample and outputs a feature matrix with a documented schema.
- [ ] No feature column derives from or leaks the ground-truth label.
- [ ] Peer-group features are present only where CERT's role/department data genuinely supports them.

---

## Chapter 6 — Baseline Models
*(CLAUDE.md Phase 6 / Architecture Phase 4)*

### Objective
Implement every baseline required for honest benchmarking against TabNet, per `CIRA_FINAL_ARCHITECTURE.md` §13 — these exist for comparison, not production use.

### Prerequisites
Chapter 5 complete (feature matrix available).

### Outcome
Four working, evaluable baselines: rule-based, Isolation Forest, LOF, and an LSTM Autoencoder, plus an optional XGBoost/CatBoost supervised baseline where CERT's labels support it.

### Implementation
1. **Rule-based** (`rule_based.py`): simple threshold rules (e.g., "off-hours login" → flag) as the non-ML floor baseline that any real model must beat.
2. **Isolation Forest** (`isolation_forest.py`): scikit-learn `IsolationForest` on the feature matrix, unsupervised.
3. **LOF** (`lof.py`): scikit-learn `LocalOutlierFactor`, unsupervised, local-density anomaly detection.
4. **LSTM Autoencoder** (`lstm_autoencoder.py`): sequence-aware reconstruction-error baseline over per-user time-ordered feature windows.
5. **XGBoost/CatBoost** (`gbdt.py`): supervised baseline using the ground-truth labels from Chapter 3, held strictly separate from the unsupervised training path (leakage-safe split, per Chapter 15/16).
6. Each baseline exposes a uniform interface (`fit(X_train)`, `score(X_test) -> anomaly_score`) so Chapter 16's evaluation harness can call all of them, including TabNet, polymorphically.

### Acceptance checklist
- [ ] All four mandatory baselines run end-to-end on the same feature matrix and produce anomaly scores.
- [ ] Baseline outputs are stored in a format directly comparable to TabNet's output (same score range/convention).
- [ ] No baseline result is reported without having actually been run.

---

## Chapter 7 — TabNet Model
*(CLAUDE.md Phase 7 / Architecture Phase 5)*

### Objective
Train the primary behavioural model, per `CIRA_FINAL_ARCHITECTURE.md` §12 — tabular representation, learned feature selection, interpretable masks.

### Prerequisites
Chapter 6 complete (baselines exist for later comparison).

### Outcome
A trained, versioned TabNet model artifact under `models/saved_models/`, with a documented training configuration and a leakage-safe train/validation split.

### Implementation
1. **`dataset.py`**: build train/validation splits **by user or time period**, never by random row-mixing (leakage rule, §39/CLAUDE §19) — hold out the last N weeks or a disjoint set of users for validation.
2. **`train.py`**: `TabNetClassifier` (or `TabNetPretrainer` for a semi-supervised pretraining phase on "normal" slices, then fine-tune) using `pytorch-tabnet`. Log `n_d`, `n_a`, `n_steps`, `mask_type` (`sparsemax` default), and all other hyperparameters explicitly — TabNet's hyperparameter interaction is a documented pain point, so record every run's config alongside its metrics.
3. Address class imbalance: apply resampling (e.g., SMOTE on the minority class) or class-weighted loss, and record which technique was used — insider-threat positives are extremely rare.
4. **`model_registry.py`**: on `.save_model(...)`, record model name, version, training dataset/version, feature-schema version, training timestamp, and evaluation metrics (per §38) — never overwrite a saved artifact without bumping the version.
5. **`infer.py`**: `load_model(...)` + `.predict_proba(X)` wrapper exposing a single `score(X) -> float[0,1]` function, matching the baseline interface from Chapter 6.

### Acceptance checklist
- [ ] TabNet trains without error on the Chapter 5 feature matrix and produces a saved, versioned artifact.
- [ ] Train/validation split is leakage-safe (by user or time, documented explicitly).
- [ ] Class-imbalance handling is implemented and recorded, not silently skipped.
- [ ] TabNet is benchmarked against the Chapter 6 baselines using the same evaluation harness (results may be finalized in Chapter 16, but the plumbing to compare is ready now).

---

## Chapter 8 — Anomaly Scoring & Model Serving
*(CLAUDE.md Phase 8 / Architecture Phase 5)*

### Objective
Turn the trained model into a callable scoring service that produces the raw anomaly score described in `CIRA_FINAL_ARCHITECTURE.md` §14 — explicitly **not yet** the final business risk score.

### Prerequisites
Chapter 7 complete.

### Outcome
A `score_event(feature_vector) -> anomaly_score ∈ [0,1]` function/service, backed by the versioned TabNet model, callable both from a batch job and (later, Chapter 13) from a FastAPI endpoint.

### Implementation
1. Load the latest (or a pinned) model version from the registry built in Chapter 7.
2. Wrap inference behind a stable interface so the CRI engine (Chapter 9) never talks to TabNet directly — it only consumes anomaly scores.
3. Define the failure mode explicitly per `CIRA_FINAL_ARCHITECTURE.md` §36 ("Model unavailable"): return an explicit service error or safe degraded state — **never fabricate a risk score** if the model can't be loaded or inference fails.
4. Add a model-version tag to every returned score so downstream persistence (Chapter 12) can trace which model produced which score (§37 Data Lineage).

### Acceptance checklist
- [ ] Scoring a batch of held-out feature vectors returns anomaly scores with the associated model version.
- [ ] A simulated model-load failure returns an explicit error, not a fabricated score.
- [ ] Anomaly score and (future) contextual risk score are kept in clearly separate code paths, per §14.

---

## Chapter 9 — Contextual Risk Intelligence (CRI)
*(CLAUDE.md Phase 9 / Architecture Phase 6)*

### Objective
Build the contextual risk layer described in `CIRA_FINAL_ARCHITECTURE.md` §15 — combining the raw anomaly score with user, asset, historical, peer, and threat context into a normalized, explainable risk score.

### Prerequisites
Chapter 8 complete.

### Outcome
`app/cri/engine.py` produces a `0–100` composite risk score and a severity band (`LOW/MEDIUM/HIGH/CRITICAL`) from a documented, **configurable** weighting formula.

### Implementation
1. **`config.py`**: define CRI weights and severity band thresholds (defaults: `0–24 LOW / 25–49 MEDIUM / 50–74 HIGH / 75–100 CRITICAL`, per §15) as configuration, not hard-coded constants — expose them via environment/config so they can be tuned without a code change.
2. **`engine.py`**: implement the composite function:
   ```text
   CRI = f(anomaly_score, user_context, asset_criticality,
            historical_deviation, peer_deviation, mitre_context)
   ```
   Start with an explicit, documented linear weighting (e.g., weighted sum normalized to 0–100); note in code comments that the exact formula is a configurable implementation decision, not an invented "final" formula (§15/CLAUDE §12).
3. Wire in `User`/`Asset` context tables (create the `Asset` entity now, since this is the chapter that actually needs it — extend `database/models/` accordingly and run an Alembic migration).
4. Keep the raw anomaly score and the CRI output as two distinct, separately persisted values — never collapse them into one field (architectural rule, §14/§15).

### Acceptance checklist
- [ ] CRI produces a 0–100 score and severity band for a batch of scored events.
- [ ] Weights and thresholds are configurable, not hard-coded.
- [ ] `Asset` entity created only now, with a real purpose (asset criticality lookup), not speculatively.
- [ ] Ablation hook exists to disable individual CRI components (needed for Chapter 16's ablation studies).

---

## Chapter 10 — MITRE ATT&CK Enrichment
*(CLAUDE.md Phase 10 / Architecture Phase 7)*

### Objective
Add traceable threat-context enrichment per `CIRA_FINAL_ARCHITECTURE.md` §16 — contextual, not the entire detection engine.

### Prerequisites
Chapter 9 complete.

### Outcome
`app/mitre/enrich.py` maps observed behavioural patterns to candidate ATT&CK techniques, feeding the CRI's `mitre_context` input, with every mapping traceable and unmapped behaviour explicitly marked as such rather than fabricated.

### Implementation
1. **`stix_loader.py`**: load a **pinned** `enterprise-attack` STIX bundle version via `mitreattack-python`'s `MitreAttackData`, and materialize a local technique-lookup table (technique ID → name, tactic, description) so the mapping is reproducible and has no runtime network dependency.
2. **`mapping_rules.py`**: define an explicit, small expert map from feature/behavioural patterns to ATT&CK technique IDs (e.g., "large file archive followed by external transfer" → `T1560` + `T1537`-style candidates) — document the reasoning for each mapping in code comments.
3. **`enrich.py`**: given a scored event/user-day, return zero or more candidate technique matches; if no confident match exists, mark the record `unmapped` explicitly rather than forcing a technique (§16).
4. Create the `MITREMapping` entity now (only now — it's the chapter that needs it), storing technique ID, tactic, matched pattern, and confidence/traceability metadata.

### Acceptance checklist
- [ ] MITRE technique table loads from a pinned STIX version and is queryable offline.
- [ ] Every emitted mapping is traceable to the specific behavioural pattern that triggered it.
- [ ] Ambiguous cases are marked `unmapped`, never force-mapped.
- [ ] CRI's `mitre_context` input is now live-wired (no longer a placeholder).

---

## Chapter 11 — Explainability (TabNet masks + SHAP)
*(CLAUDE.md Phase 11 / Architecture Phase 8)*

### Objective
Build the explanation layer described in `CIRA_FINAL_ARCHITECTURE.md` §18 — answering "why was this user/session considered risky?" using real model/context outputs only.

### Prerequisites
Chapter 10 complete.

### Outcome
`app/explainability/reason_builder.py` produces analyst-facing, plain-language reasons for a given alert, backed by TabNet's native masks and a SHAP explanation, never a generic "model predicted high risk" statement.

### Implementation
1. **`tabnet_masks.py`**: call `clf.explain(X)` to get the global importance matrix and per-decision-step masks; also expose `clf.feature_importances_`. Use `grouped_features` for any one-hot/derived feature groups so importance isn't artificially fragmented.
2. **`shap_explainer.py`**: wrap the model's `predict_proba` in `shap.KernelExplainer` (robust, model-agnostic, works directly with TabNet's sklearn-style API) as the secondary, corroborating explanation signal. Use a small (100–1000 sample) background set, not the full training set.
3. **`reason_builder.py`**: combine TabNet masks + SHAP contributions + CRI contextual factors + historical deviation + MITRE context into a structured, human-readable explanation matching the format in §18:
   ```text
   HIGH RISK
   Primary contributing factors:
   1. Off-hours authentication
   2. File activity substantially above baseline
   3. New device observed
   4. High-criticality asset accessed
   5. Behaviour associated with a relevant ATT&CK technique
   ```
4. Every listed factor must trace back to an actual computed feature/model output — no invented reasons (§18 non-negotiable rule).

### Acceptance checklist
- [ ] A sample alert produces a reason list traceable to real TabNet mask values, SHAP values, and CRI factors.
- [ ] No generic/meaningless explanation strings appear anywhere in the output.
- [ ] SHAP failure (per §36) degrades gracefully — the alert still exists with model score/context; explanation can retry asynchronously later (relevant once Celery exists in Chapter 17).

---

## Chapter 12 — Alert Correlation & Persistence
*(CLAUDE.md Phase 12 / Architecture Phase 9)*

### Objective
Avoid one alert per closely-related event (per `CIRA_FINAL_ARCHITECTURE.md` §17) and durably persist the full risk decision chain to PostgreSQL.

### Prerequisites
Chapter 11 complete.

### Outcome
Related high-risk events for the same user/short time window are correlated into a single `Alert` (with child `EventLog` links) rather than duplicated; every alert is persisted with its full lineage.

### Implementation
1. **`correlation.py`**: deterministic, testable, configurable rules that group related events (e.g., unusual login → large file access → archive creation → external transfer within a rolling window) into one incident, per the §17 example.
2. **`deduplication.py`**: prevent re-alerting on the same underlying pattern within a configurable cooldown window.
3. Create the remaining entities now that they have real purpose: `EventLog`, `FeatureVector`, `AnomalyScore`, `RiskScore`, `Alert`, `AlertReason`, `ModelVersion`, `AuditLog` (per §20) — run the corresponding Alembic migration(s), reviewing each autogenerated diff before applying.
4. Implement the full data-lineage chain from §37: `Source Event → Normalized Event → Feature Vector → Model Version → Anomaly Score → CRI Inputs → Final Risk Score → MITRE Mapping → Alert` — every step traceable via foreign keys or stored references.
5. Implement the "PostgreSQL unavailable" failure mode from §36: fail safely, never claim an alert was durably stored when it wasn't.

### Acceptance checklist
- [ ] A cluster of related synthetic events produces exactly one correlated `Alert`, not four separate ones.
- [ ] Every persisted `Alert` can be traced back through the full lineage chain to its source event(s).
- [ ] A simulated DB outage during alert write fails safely and visibly, not silently.

---

## Chapter 13 — FastAPI Full Integration
*(CLAUDE.md Phase 13 / Architecture Phase 10)*

### Objective
Expose the complete pipeline through the FastAPI backend, per `CIRA_FINAL_ARCHITECTURE.md` §25, with a clean routers → schemas → services → domain-logic separation.

### Prerequisites
Chapters 2–12 complete (every domain module this chapter wires together must already exist).

### Outcome
A running FastAPI app exposing the full route surface (`/auth /users /events /features /anomaly /risk /alerts /investigations /mitre /explanations /models /health`), backed by real service-layer calls into the pipeline built in prior chapters — no mocked responses.

### Implementation
1. For each router in `app/api/v1/`, implement only endpoints the product actually needs (§25 — don't implement speculative endpoints).
2. Enforce the layering rule: routers call `services/`, which call domain logic (`cri`, `mitre`, `tabnet`, `explainability`, `alerts`), which call `database`/ML/infra — no business logic directly inside route handlers (§25/CLAUDE §16).
3. Implement `/auth` with JWT/OAuth2 (basic version now; RBAC hardening is a production extension in Chapter 18, but a working login is part of the FYP core since the dashboard needs it).
4. Implement `/health` to report the actual status of DB connectivity and the loaded model version (not just "200 OK").
5. Write integration tests using `httpx.AsyncClient(transport=ASGITransport(app=app))` against a real (testcontainers) PostgreSQL instance, overriding the DB dependency via FastAPI's dependency-override mechanism.

### Acceptance checklist
- [ ] Every listed API group has at least the endpoints the dashboard (Chapter 14) actually calls.
- [ ] No route handler contains business logic beyond request/response marshalling.
- [ ] Integration tests hit a real database via testcontainers and pass.
- [ ] `/health` accurately reflects DB and model status.

---

## Chapter 14 — React + TypeScript SOC Dashboard
*(CLAUDE.md Phase 14 / Architecture Phase 11)*

### Objective
Build the analyst-facing dashboard described in `CIRA_FINAL_ARCHITECTURE.md` §27, answering the six investigation questions it specifies.

### Prerequisites
Chapter 13 complete (a live API to call).

### Outcome
A working React + TypeScript app with Login, Overview, Alerts, Alert Details, User Investigation, Risk History, Explainability, and MITRE Context views, all backed by real API calls — no decorative/static mockups.

### Implementation
1. Install and configure the frontend stack (Tailwind v4 via the Vite plugin, MUI + Emotion, Zustand, React Router, React Hook Form + Zod, Axios, Recharts) per the version pins in the companion research brief.
2. Structure `src/` per the layout in §2 of this bible (`components/{common,layout,ui}`, `pages/`, `hooks/`, `services/`, `store/`, `utils/`, `constants/`, `types/`); configure the `@/*` path alias in both `tsconfig.json` and `vite.config.ts`.
3. Build each view to directly answer one of the six questions from §27:
   1. **Overview** → *Who is risky?* (ranked risk list)
   2. **Alerts** → *What happened?* (correlated incident list)
   3. **Alert Details** → *How risky is it?* (CRI score, severity band)
   4. **Explainability** → *Why is it risky?* (Chapter 11's reason list, rendered)
   5. **MITRE Context** → *What contextual evidence supports the risk?* (mapped techniques)
   6. **User Investigation / Risk History** → *What should the analyst investigate?* (timeline, historical deviation charts via Recharts)
4. `services/` holds one Axios client module per API group from Chapter 13, with typed request/response models mirroring the backend Pydantic schemas.
5. Every visualization must support an investigation or decision (no decorative charts, per §27 non-negotiable rule).

### Acceptance checklist
- [ ] All eight views render live data from the Chapter 13 API, not hardcoded fixtures.
- [ ] Each of the six analyst questions from §27 is answerable from the UI.
- [ ] Login/auth flow works end-to-end against the backend.
- [ ] No purely decorative UI elements without investigative purpose.

---

## Chapter 15 — End-to-End Validation & Testing
*(CLAUDE.md Phase 15 / Architecture Phase 12)*

### Objective
Verify the complete chain from `CIRA_FINAL_ARCHITECTURE.md` §12 works as one system, and that the acceptance criteria in §45 are genuinely met.

### Prerequisites
Chapters 1–14 complete.

### Outcome
A documented, reproducible end-to-end test that pushes a raw CERT event through every stage and confirms it reaches the dashboard as an explained, correctly-scored alert.

### Implementation
1. Verify the full chain manually once, end to end:
   ```text
   Raw event → normalized event → features → TabNet → anomaly score
   → CRI → MITRE → explanation → alert → PostgreSQL → API → dashboard
   ```
2. Automate this as an `e2e` test suite (backend: pytest against testcontainers Postgres + a small trained model checkpoint; frontend: Vitest + React Testing Library for component-level checks, plus a manual or Playwright-driven click-through if time allows).
3. Confirm every item in `CIRA_FINAL_ARCHITECTURE.md` §45 Acceptance Criteria (1–16) is checkable and checked: project starts, migrations run, events ingest, events normalize, features generate, TabNet trains/evaluates, inference produces a score, CRI converts it to contextual risk, MITRE context attaches where relevant, an explanation generates, an alert persists, FastAPI exposes it, React displays it, an analyst can understand why, tests cover core components, evaluation metrics are reproducible.
4. Run regression checks: re-run the full test suite after every subsequent change (Chapters 16–19) to confirm existing behaviour is not broken.

### Acceptance checklist
- [ ] All 16 items in `CIRA_FINAL_ARCHITECTURE.md` §45 are met and demonstrably true (not asserted).
- [ ] A single documented run-through (screenshot/log trail) exists showing one event traveling the full chain to a dashboard alert.
- [ ] Test suite is green: unit, integration, and e2e layers.

---

## Chapter 16 — Evaluation Protocol & Ablation Studies
*(Cross-cutting — Architecture §39–40)*

### Objective
Produce the rigorous, honest evaluation that justifies every design choice in the report/viva — never fabricated.

### Prerequisites
Chapters 6, 7, 15 complete (baselines, TabNet, and a working e2e pipeline to evaluate).

### Outcome
A reproducible evaluation report comparing TabNet against all baselines, plus ablations isolating the contribution of CRI and MITRE context, all computed from actual runs.

### Implementation
1. **Metrics** (§39/CLAUDE §19): Precision, Recall, F1, ROC-AUC, PR-AUC, False Positive Rate, Detection Latency, Top-k Precision, Risk Coverage — never rely on accuracy alone given class imbalance.
2. **Leakage-safe splitting** (§39): time-aware or user-aware splits, consistent with Chapter 7's training split.
3. **Comparison chain** (§39):
   ```text
   Baseline → TabNet → TabNet + CRI → TabNet + CRI + MITRE/context
   ```
4. **Ablation experiments** (§40):
   - Experiment A: TabNet, core behavioural features only.
   - Experiment B: TabNet + contextual features.
   - Experiment C: TabNet + CRI.
   - Experiment D: TabNet + CRI + MITRE.
   - Experiment E: explainability/operational evaluation (does adding interpretability constraints cost accuracy?).
5. Statistical rigor: report confidence intervals (bootstrap or cross-validation), and apply a paired significance test (e.g., paired t-test or Wilcoxon) for the headline TabNet-vs-best-baseline comparison rather than reporting a single-run number as definitive.
6. Store all results under `experiments/results/` with the exact config/model-version that produced them (traceable, per §37/§38) — never write a number into the report that wasn't produced by an actual run.

### Acceptance checklist
- [ ] Every reported metric traces to a stored, reproducible experiment run.
- [ ] The four ablation experiments (A–D) are executed, not simulated/estimated.
- [ ] Class-imbalance-aware metrics (F1, PR-AUC) are reported alongside — not instead of — the full metrics table.
- [ ] No number in the final report lacks a corresponding logged experiment.

---

## Chapter 17 — Production Extensions I: Kafka, Redis, Celery, SSE
*(CLAUDE.md Phase 16 / Architecture Phase 13)*

### Objective
Extend the working FYP core toward the real-time production architecture in `CIRA_FINAL_ARCHITECTURE.md` §1.2 — **only after** Chapters 1–16 are genuinely complete.

### Prerequisites
Chapters 1–16 complete and passing. This chapter must not be started early (non-negotiable rule, §46).

### Outcome
Local streaming ingestion (Redpanda for dev / Kafka 4.x KRaft documented for production), a Redis cache layer, Celery for heavy background work, and live SSE alert delivery to the dashboard — each explicitly labeled PRODUCTION EXTENSION until verified working.

### Implementation
1. **Streaming:** for local/FYP development, run **Redpanda** (Kafka-API-compatible, single lightweight container, faster to stand up); document **Kafka 4.x in KRaft mode** (no ZooKeeper) as the production target, so producer/consumer code ports unchanged. Never let Kafka/Redpanda sit anywhere in the core detection path shown in §1.1 (that path remains dataset-driven for the FYP, per §7 "Kafka is not required to make the FYP dataset-driven pipeline work").
2. **Redis:** cache layer only — hot risk values, recent feature windows, session/temp state, dedup state (§23). Never treat it as the source of truth.
3. **Celery:** background workloads only — SHAP batch calculations, model retraining, report generation, large batch processing, periodic baseline recalculation (§28). **Never** place Celery between Kafka and TabNet on the real-time detection path — verify this explicitly in the code review for this chapter, since it's called out as a specific incorrect pattern to avoid.
4. **SSE:** implement using native FastAPI SSE (`EventSourceResponse`, available since FastAPI 0.135+) for the live alert stream from `Risk/Alert Engine → FastAPI SSE endpoint → React EventSource → Live alert` (§26). Reach for `sse-starlette` only if multi-channel broadcast/keepalive needs exceed native support. For multi-instance scaling, back SSE with Redis pub/sub.
5. Implement the remaining §36 failure modes relevant to this chapter: Kafka unavailable (buffer/replay tolerance), Redis unavailable (fall back to durable source of truth, no silent corruption), SSE disconnected (dashboard reconnects and re-syncs via normal APIs).
6. Update `docker-compose.prod.yml` (separate from the FYP-baseline `docker-compose.yml`) to add Redpanda/Kafka, Redis, and a Celery worker + Flower, using Compose V2 syntax with `healthcheck`/`depends_on: condition: service_healthy` ordering.

### Acceptance checklist
- [ ] Streaming ingestion runs locally via Redpanda and can be swapped for Kafka 4.x without code changes.
- [ ] Celery never appears between Kafka and TabNet in the real-time path — verified by code review, not just documentation.
- [ ] SSE delivers a live alert to the dashboard within the target latency, and the dashboard reconnects cleanly after a disconnect.
- [ ] Every component in this chapter is labeled PRODUCTION EXTENSION and only marked IMPLEMENTED once it demonstrably runs.

---

## Chapter 18 — Production Extensions II: OpenSearch, Observability, Docker/K8s, Auth Hardening, CI/CD
*(CLAUDE.md Phase 16 / Architecture Phase 13)*

### Objective
Complete the remaining production-oriented architecture: large-scale search, observability, container orchestration, hardened auth, and CI/CD.

### Prerequisites
Chapter 17 complete (or explicitly and consciously skipped with the same "not required for FYP" caveat).

### Outcome
Optional production-grade layers, each independently addable and each clearly distinguished as PRODUCTION EXTENSION, not silently presented as part of the FYP core.

### Implementation
1. **OpenSearch** (§24): single-node dev container for large-scale event search/investigation, separate from PostgreSQL's role as structured relational state. Not introduced merely for architectural appearance — only if event volume/analyst-search actually motivates it.
2. **Prometheus/Grafana** (§29): instrument FastAPI with `prometheus-fastapi-instrumentator` (`/metrics` auto-exposed); scrape Celery health via Flower; visualize in Grafana. These monitor CIRA itself — never the threat decision (§29 non-negotiable distinction). Track P95/P99 latency, not just averages.
3. **ML monitoring** (§30): separate from infrastructure monitoring — track feature/data drift, prediction distribution shifts, model performance decay, false-positive trend, retraining triggers.
4. **Authentication/RBAC hardening** (§31): expand the basic auth from Chapter 13 into role-based permissions (`Admin / SOC Analyst / Security Manager / Viewer`) — only once the core application actually requires it, not preemptively.
5. **Docker productionization / Kubernetes** (§33–34): expand `docker-compose.prod.yml` toward production-hardened images; Kubernetes manifests are a production-scale option, explicitly **not required** for the FYP core.
6. **CI/CD** (§35): GitHub Actions pipeline — lint → unit tests → integration tests → build → container validation → deploy — introduced only once tests and application structure are stable, not before.

### Acceptance checklist
- [ ] Each sub-component (OpenSearch, Prometheus/Grafana, RBAC, Kubernetes, CI/CD) is only claimed IMPLEMENTED if it's actually running and verifiable.
- [ ] Prometheus/Grafana dashboards show real metrics from the running system, not placeholders.
- [ ] RBAC roles are enforced on real endpoints, not just modeled in the database.
- [ ] CI pipeline runs the full Chapter 15 test suite on every commit.

---

## Chapter 19 — Repository Finalization & Submission
*(Architecture §45 Acceptance Criteria — final pass)*

### Objective
Confirm the entire system, end to end, against every criterion in `CIRA_FINAL_ARCHITECTURE.md` §45, and finalize documentation for submission.

### Prerequisites
Chapters 1–18 (or 1–16 if production extensions were deliberately scoped out) complete.

### Outcome
A submission-ready repository: working system, complete documentation, reproducible evaluation, and an honest IMPLEMENTED/PARTIALLY IMPLEMENTED/PLANNED/OPTIONAL/PRODUCTION EXTENSION status table for every component.

### Implementation
1. Re-run the full Chapter 15 e2e validation one final time against the finished repository state.
2. Fill in `README.md` properly (it is currently a near-empty placeholder): project description, architecture diagram reference, setup instructions, how to run tests, how to reproduce the Chapter 16 evaluation.
3. Produce a final component-status table (see Appendix template below) — this is the single most important honesty artifact for the report/viva.
4. Confirm the repository structure matches §2 of this bible / §41 of the architecture doc exactly, with no orphaned or unused directories.
5. Confirm no secrets are committed (`git log -p` scan of `.env`-shaped content), and `.env.example` is complete and current.
6. Tag a release commit.

### Acceptance checklist
- [ ] Final e2e run passes.
- [ ] `README.md` is complete, not a placeholder.
- [ ] Component status table is accurate and matches actual repository state.
- [ ] No secrets in git history.

---

## 20. Appendix

### A. Non-Negotiable Architecture Rules (verbatim reference — `CIRA_FINAL_ARCHITECTURE.md` §47)
All 24 rules from the architecture document apply throughout every chapter above without exception — notably: PostgreSQL is the source of truth (rule 1); Celery must never sit between Kafka and TabNet (rule 8); CRI is separate from the raw anomaly score (rule 14); MITRE is contextual enrichment only (rule 15); no planned component may be claimed implemented without verification (rule 22); no experimental result may be fabricated (rule 23).

### B. Component Status Table Template (fill in at Chapter 19)

| Component | Status | Evidence |
|---|---|---|
| Repository foundation | | |
| DB/FastAPI skeleton | | |
| CERT ingestion | | |
| TWOS ingestion | | |
| Preprocessing | | |
| Feature engineering | | |
| Baselines (rule/IF/LOF/LSTM-AE/GBDT) | | |
| TabNet | | |
| Anomaly scoring service | | |
| CRI | | |
| MITRE enrichment | | |
| Explainability (masks + SHAP) | | |
| Alert correlation/persistence | | |
| FastAPI full integration | | |
| React dashboard | | |
| E2E validation | | |
| Evaluation/ablations | | |
| Kafka/Redpanda | | |
| Redis | | |
| Celery | | |
| SSE | | |
| OpenSearch | | |
| Prometheus/Grafana | | |
| Auth/RBAC hardening | | |
| Docker productionization | | |
| Kubernetes | | |
| CI/CD | | |

### C. Known Documentation Contradictions and Their Resolution in This Bible
1. **Phase numbering** (`CIRA_FINAL_ARCHITECTURE.md` §44 vs `CLAUDE.md` §22): resolved by the mapping table in §0 above — 20 chapters built on `CLAUDE.md`'s finer granularity, cross-referenced to the architecture doc's 13 phases.
2. **CIRA acronym expansion**: use **"Context-Aware Insider Risk Analytics"** consistently (matches the architecture doc's own header and the live repository name `cira-insider-risk`).
3. **Root folder name** (`cira-insider-risk/` vs `cira-insider-threat/`): resolved as `cira-insider-risk` throughout this bible (§2 note above).
4. **Kafka's FYP-vs-production role**: resolved per §7/§46 — Kafka/Redpanda is a Chapter 17 production extension; the FYP core (Chapters 1–16) remains dataset-driven and does not depend on it.
5. **Captum omission**: not included as a required tool in this bible — SHAP is the mandated explainability tool per `CLAUDE.md` §5 and §9; Captum may be added as an optional supplementary technique in Chapter 11 if time permits, but is never required.
6. **Stale source filename references**: this bible references only the module/file names defined in §2 above; any stale filename elsewhere in older documents should be treated as superseded by this structure.

### D. Full Version-Pinned Tech Stack and Setup Commands
See the companion **CIRA Implementation Research Brief** artifact for exact, currently-verified (August 2026) package versions, install commands, and code-level API usage for every technology in §1's table above.
