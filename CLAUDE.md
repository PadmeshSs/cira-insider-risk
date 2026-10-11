# CIRA — Claude Project & Coding Instructions

## 1. Project Identity

**Project:** CIRA — Context-Aware Insider Risk Analytics

CIRA is a context-aware insider-threat / insider-risk analytics system intended to detect abnormal user behaviour, contextualize the resulting anomaly, map relevant behaviour to MITRE ATT&CK where appropriate, explain why an alert was generated, and present the result through a SOC-style dashboard.

The project is a final-year academic project. The implementation must prioritize a genuinely working end-to-end detection pipeline over unnecessary enterprise infrastructure.

---

## 2. Source of Truth

The project knowledge contains the project documents:

- `Executive Summary.pdf`
- `Implementation docs.pdf`
- `projetsetup.pdf`
- `CIRA_FINAL_ARCHITECTURE.md`

Use these as the primary project context.

`CIRA_FINAL_ARCHITECTURE.md` is the canonical consolidated architecture specification.

Do not silently replace project terminology, research framing, datasets, or stated design decisions with unrelated alternatives.

If a requirement is not defined:

1. State that it is not currently defined.
2. Propose the simplest reasonable option if needed.
3. Clearly distinguish the proposal from an existing project decision.

---

## 3. Core Architecture

The canonical analytical path is:

```text
CERT / TWOS / Security Events
        ↓
Ingestion
        ↓
Preprocessing / Normalization
        ↓
Feature Engineering
        ↓
TabNet
        ↓
Anomaly Score
        ↓
Contextual Risk Intelligence (CRI)
        ↓
MITRE ATT&CK Enrichment
        ↓
Alert Correlation / Deduplication
        ↓
Explainability + Persistence
        ↓
FastAPI
        ↓
React + TypeScript Dashboard
```

For production real-time deployment, Kafka sits between ingestion and stream processing.

SSE is used for server-to-browser live alert delivery.

---

## 4. FYP Core vs Production Extensions

### Mandatory FYP core

The following must become a genuinely working vertical slice:

```text
CERT / TWOS
→ preprocessing
→ feature engineering
→ TabNet
→ anomaly score
→ CRI
→ MITRE
→ explainability
→ PostgreSQL
→ FastAPI
→ React dashboard
```

### Production/scalability extensions

These are architectural extensions and must not be falsely described as implemented:

- Kafka
- Redis
- SSE
- Celery
- OpenSearch
- Prometheus
- Grafana
- production authentication/RBAC
- production ML monitoring
- Docker hardening
- Kubernetes
- CI/CD
- distributed scaling

Implement these only when the core pipeline is stable or when explicitly requested.

---

## 5. Non-Negotiable Technology Decisions

### Backend

- Python
- FastAPI
- Pydantic

### Database

- PostgreSQL
- SQLAlchemy ORM
- Alembic migrations

**Do not introduce Prisma.**

The backend is Python/FastAPI, so SQLAlchemy is the canonical ORM.

### ML / data

- PyTorch
- PyTorch TabNet
- Pandas
- NumPy
- Scikit-learn
- SHAP

### Frontend

- React
- TypeScript
- MUI and/or Tailwind according to the project implementation

### Production infrastructure

- Kafka — event streaming
- Redis — hot cache / temporary state
- Celery — asynchronous heavy jobs
- SSE — live browser alerts
- OpenSearch — large-scale event search/investigation
- Prometheus — metrics
- Grafana — observability
- Docker / Docker Compose — containerization
- Kubernetes — production orchestration

### Threat context

- MITRE ATT&CK

---

## 6. Infrastructure Rules

### PostgreSQL

PostgreSQL is the durable relational source of truth.

Use it for structured application data such as:

- users
- assets
- events/metadata
- feature/risk records where appropriate
- anomaly/risk results
- alerts
- MITRE mappings
- model versions
- audit records
- configuration

### Redis

Redis is only a fast cache / temporary state layer.

Examples:

- current risk cache
- recent feature windows
- session/temporary state
- alert deduplication state

Redis must NOT replace PostgreSQL as the source of truth.

### Kafka

Kafka is the production event-streaming backbone.

It should provide:

- event buffering
- decoupling
- partitioning
- replay
- scalable ingestion

Do not make Kafka mandatory for the first FYP vertical slice if the existing implementation is dataset-driven.

### Celery

Celery is for asynchronous heavy work:

- SHAP batch calculations
- model retraining
- report generation
- large batch processing
- periodic baseline calculations

**Never put Celery between Kafka and TabNet on the low-latency detection path.**

Correct:

```text
Kafka
 ↓
Stream processing
 ↓
Feature engineering
 ↓
TabNet
 ↓
CRI
```

Incorrect:

```text
Kafka
 ↓
Celery
 ↓
TabNet
```

### SSE

SSE is for server-to-browser real-time alert delivery.

Use it when the backend needs to push:

- new high-risk alerts
- risk changes
- investigation updates where appropriate

Do not introduce WebSockets unless the product develops a genuine bidirectional real-time requirement.

### OpenSearch

OpenSearch is a production-scale event search/investigation layer.

Use it for large event volumes and analyst search.

Do not introduce it merely to replace PostgreSQL in the FYP.

### Prometheus/Grafana

Prometheus/Grafana are observability infrastructure.

They monitor CIRA itself, not the threat decision.

Possible metrics:

- API latency
- API error rate
- throughput
- Kafka lag
- model inference latency
- worker health
- CPU/RAM
- alert rate
- database latency

ML-specific monitoring is separate and should cover:

- feature/data drift
- prediction distribution
- model performance
- false-positive behaviour
- retraining triggers

---

## 7. Existing Repository Protection

The repository may contain existing work.

Before modifying anything:

1. Inspect the repository.
2. Search for existing implementations.
3. Understand dependencies.
4. Prefer extending working code.
5. Avoid unnecessary restructuring.

Do NOT:

- create duplicate modules
- create duplicate FastAPI applications
- create duplicate React applications
- create duplicate database layers
- create duplicate configuration systems
- rename files unnecessarily
- move files unnecessarily
- delete working code without justification
- replace working implementations merely for stylistic reasons

Before creating a new file, search for equivalent functionality.

Before deleting or moving a file, identify its consumers and dependencies.

If a structural migration is necessary, explain the proposed migration before performing a large-scale change.

---

## 8. Coding Workflow

For substantial tasks use:

```text
Inspect
  ↓
Explain current state
  ↓
Propose changes
  ↓
Implement
  ↓
Run tests/checks
  ↓
Review diff
  ↓
Report exactly what changed
```

For major architectural changes, ask for approval before making them.

Do not silently change the architecture.

Do not implement speculative enterprise infrastructure unless requested.

---

## 9. ML Rules

TabNet is the primary behavioural model for the project.

The justification is based on:

- tabular behavioural data
- learned feature selection/attention
- interpretability through feature masks
- suitability for structured insider-risk features
- alignment with the project's research framing

Do not claim that TabNet is universally superior.

Benchmark against suitable alternatives where data permits:

- rule-based baseline
- Isolation Forest
- LOF
- LSTM Autoencoder
- XGBoost/CatBoost

Never fabricate benchmark results.

---

## 10. Feature Engineering

Use project-relevant behavioural features such as:

### Authentication

- login counts
- login timing
- off-hours logins
- unusual login times
- new device/IP indicators

### File activity

- file creation
- file modification
- file deletion
- sensitive file access
- abnormal file volume

### Email

- email counts
- attachment behaviour
- internal/external recipient behaviour

### USB

- insertion/removal activity
- abnormal removable-media behaviour

### Network

- inbound/outbound volume
- unusual destinations
- unusual transfer volume
- cloud/storage activity where available

### Application/process

- unusual applications
- suspicious process/activity indicators
- abnormal application usage

### Context

- user role
- department/group
- privilege
- tenure where available
- asset criticality

### Behavioural baseline

Use historical user behaviour where available.

Examples:

- rolling averages
- normal login-time distribution
- normal file-access volume
- deviation from historical behaviour

### Peer behaviour

Where appropriate, compare a user against a relevant peer group.

Do not invent peer-group information when the dataset cannot support it.

---

## 11. NLP Rule

NLP is an optional multimodal extension.

Only use NLP when actual text/email/message content is available and the project scope explicitly includes it.

Tokenization itself does NOT guarantee higher TabNet accuracy.

Do not add NLP merely because it sounds advanced.

---

## 12. CRI Rules

Keep the model anomaly score and contextual risk score conceptually separate.

Conceptual flow:

```text
TabNet anomaly score
        +
User role / privilege
        +
Asset criticality
        +
Historical deviation
        +
Peer-group deviation
        +
Threat context / MITRE
        ↓
Contextual Risk Intelligence
        ↓
Normalized risk score
        ↓
Severity
```

A practical normalized range may be:

```text
0–100
```

with configurable severity bands such as:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

Weights must be configurable rather than permanently hard-coded.

Do not fabricate a formula if the project specification has not finalized exact weights. Treat the exact formula as a configurable implementation decision.

---

## 13. MITRE ATT&CK Rules

MITRE ATT&CK is contextual enrichment.

It is not the entire detection model.

Use:

```text
Observed behaviour
        ↓
Possible ATT&CK technique/tactic
        ↓
Contextual enrichment
        ↓
Risk/alert explanation
```

Do not invent mappings.

If a mapping is uncertain, mark it as uncertain/unmapped rather than fabricating a technique.

---

## 14. Explainability

The system should answer:

> Why was this user/event considered risky?

Use:

- TabNet feature masks
- SHAP contributions
- CRI contextual factors
- baseline deviation
- MITRE context

Prefer explanations such as:

```text
Risk increased because:
- login occurred outside the user's normal hours
- file activity was significantly above baseline
- a new device was observed
- the accessed asset has high criticality
```

Avoid meaningless explanations such as:

```text
The model predicted high risk.
```

---

## 15. Database Rules

Use SQLAlchemy models and Alembic migrations.

Potential entities include:

- User
- Asset
- EventLog
- FeatureVector
- AnomalyScore
- RiskScore
- Alert
- AlertReason
- MITREMapping
- ModelVersion
- AuditLog
- Configuration

Only create entities that have a real purpose.

Do not create dozens of speculative enterprise tables.

Alembic migrations must be committed to Git.

---

## 16. API Rules

FastAPI should separate:

```text
API routers
    ↓
Pydantic schemas
    ↓
Services
    ↓
Domain logic
    ↓
Database / ML / infrastructure
```

Do not put substantial business logic directly in route handlers.

Potential API areas:

```text
/auth
/users
/events
/features
/anomaly
/risk
/alerts
/investigations
/mitre
/explanations
/models
/health
```

Only implement endpoints actually required by the product.

---

## 17. Frontend Rules

React + TypeScript is the SOC dashboard.

Core views should support investigation:

- login/authentication when implemented
- overview dashboard
- alert list
- alert details
- user investigation
- risk history
- explainability
- MITRE context
- system/model status where appropriate

Do not prioritize decorative UI over working backend functionality.

---

## 18. Security

Never commit:

- passwords
- API keys
- JWT secrets
- database credentials
- private tokens

Use `.env` locally.

Commit `.env.example`.

Keep `.env` ignored.

Do not expose sensitive insider-threat data unnecessarily in logs.

Use appropriate authentication/RBAC when production security is implemented.

---

## 19. Evaluation

Do not optimize only for accuracy.

Relevant metrics include:

- Precision
- Recall
- F1
- ROC-AUC
- PR-AUC
- False Positive Rate
- Detection Latency
- Top-k Precision
- Risk Coverage

Because insider-threat datasets can be highly imbalanced, pay particular attention to:

- precision
- recall
- F1
- PR-AUC
- false positives

Avoid data leakage.

Use leakage-safe splits, including time/user-aware splitting where appropriate.

Never fabricate experimental results.

---

## 20. Testing

Test at multiple levels:

### Unit

- preprocessing
- feature engineering
- CRI
- MITRE mapping
- schemas
- utility functions

### Integration

- PostgreSQL
- SQLAlchemy
- FastAPI
- ML service integration

### End-to-end

Verify:

```text
event
→ features
→ model
→ anomaly score
→ CRI
→ alert
→ database
→ API
→ dashboard
```

### Regression

Existing working behaviour must continue to work after changes.

---

## 21. Repository Structure

Preferred structure:

```text
cira-insider-risk/
├── CLAUDE.md
├── CIRA_FINAL_ARCHITECTURE.md
├── README.md
├── .env.example
├── .gitignore
├── docker-compose.yml
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── database/
│   │   ├── ingestion/
│   │   ├── preprocessing/
│   │   ├── feature_engineering/
│   │   ├── tabnet/
│   │   ├── baselines/
│   │   ├── cri/
│   │   ├── mitre/
│   │   ├── explainability/
│   │   ├── schemas/
│   │   ├── services/
│   │   ├── evaluation/
│   │   ├── utils/
│   │   └── main.py
│   ├── tests/
│   └── alembic/
│
├── frontend/
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
├── tests/
└── docker/
```

This is the target structure, not a command to create every directory immediately. Create modules when they are actually needed.

---

## 22. Implementation Order

Recommended order:

### Phase 1
Repository and development foundation

### Phase 2
PostgreSQL + SQLAlchemy + Alembic + FastAPI foundation

### Phase 3
CERT/TWOS ingestion

### Phase 4
Preprocessing and normalization

### Phase 5
Feature engineering

### Phase 6
Baseline models

### Phase 7
TabNet

### Phase 8
Anomaly scoring

### Phase 9
CRI

### Phase 10
MITRE enrichment

### Phase 11
Explainability

### Phase 12
Alert correlation and persistence

### Phase 13
FastAPI integration

### Phase 14
React dashboard

### Phase 15
End-to-end testing

### Phase 16
Production extensions:

- Kafka
- Redis
- SSE
- Celery
- OpenSearch
- Prometheus/Grafana
- authentication/RBAC hardening
- Docker productionization
- Kubernetes
- ML monitoring/drift

Do not allow production infrastructure to block the working FYP vertical slice.

---

## 23. Honesty Rule

Always distinguish:

- IMPLEMENTED
- PARTIALLY IMPLEMENTED
- PLANNED
- OPTIONAL
- PRODUCTION EXTENSION

Never claim a component works unless the repository actually contains a working implementation and relevant checks/tests pass.

This applies to:

- Kafka
- Redis
- Celery
- SSE
- OpenSearch
- Prometheus/Grafana
- Kubernetes
- TabNet
- SHAP
- CRI
- MITRE
- authentication

---

## 24. AI Coding Agent Handoff Rules

The primary objective is:

```text
Build a working CIRA vertical slice first.

CERT/TWOS
→ preprocessing
→ feature engineering
→ TabNet
→ anomaly score
→ CRI
→ MITRE
→ explainability
→ PostgreSQL
→ FastAPI
→ React
```

Everything else must support this objective.

When uncertain:

1. inspect the repository;
2. inspect the architecture document;
3. inspect the project documents;
4. prefer the smallest implementation satisfying the requirement;
5. do not introduce technology for appearance alone;
6. do not fabricate functionality;
7. do not silently redesign the system.
