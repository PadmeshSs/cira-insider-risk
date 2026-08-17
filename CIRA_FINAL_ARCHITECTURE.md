# CIRA — Final Architecture & Implementation Specification

**Project:** CIRA — Context-Aware Insider Risk Analytics  
**Purpose:** Final-year project implementation and production-oriented architecture reference  
**Canonical status:** This document is the consolidated architecture source of truth for implementation.

---

# 1. Executive Architecture

CIRA is a context-aware insider-risk analytics framework.

The system detects anomalous user behaviour, enriches the anomaly with contextual information, maps relevant behaviour to MITRE ATT&CK where appropriate, produces an explainable risk assessment, stores the result, exposes it through a backend API, and presents it through a SOC-style web dashboard.

## 1.1 FYP core

The complete working FYP vertical slice is:

```text
CERT / TWOS
    ↓
Preprocessing
    ↓
Feature Engineering
    ↓
TabNet
    ↓
Anomaly Score
    ↓
Contextual Risk Intelligence (CRI)
    ↓
MITRE ATT&CK
    ↓
Explainability
    ↓
PostgreSQL
    ↓
FastAPI
    ↓
React + TypeScript Dashboard
```

## 1.2 Full-scale real-time product

The production-oriented architecture adds streaming, caching, search, asynchronous processing, observability, security and orchestration:

```text
Security / Endpoint / Identity / Email / Network / Cloud Sources
    ↓
Collectors / APIs
    ↓
Kafka
    ↓
Stream Processing
    ↓
Preprocessing / Normalization
    ↓
Feature Engineering
    ↓
Feature Cache / Online Context
    ↓
TabNet + Baselines/Additional Models
    ↓
Anomaly Score
    ↓
CRI
    ↓
MITRE ATT&CK / Threat Context
    ↓
Alert Correlation / Deduplication
    ↓
Explainability
    ↓
PostgreSQL + OpenSearch
    ↓
FastAPI
    ↓
React Dashboard
    ↑
   SSE
```

Supporting services:

```text
Celery → SHAP batches / retraining / reports / large batch jobs
Redis → hot cache / temporary state
Prometheus → metrics
Grafana → observability
Docker → containerization
Kubernetes → production orchestration
```

---

# 2. Scope and Design Philosophy

The project must not become a collection of technologies added merely to look enterprise-grade.

The primary success criterion is a working end-to-end detection and investigation flow.

The design therefore has two explicit layers:

## Layer A — FYP implementation

A controlled, reproducible implementation using CERT/TWOS-style data and a complete analytical pipeline.

## Layer B — production architecture

A scalable extension showing how the same analytical pipeline can operate on real-time enterprise telemetry.

Components in Layer B must not be falsely represented as implemented if they have only been designed.

---

# 3. Core Problems Addressed

CIRA is intended to address limitations of conventional insider-threat detection:

- static rules can generate excessive false positives;
- unusual behaviour is not always malicious;
- the same event can have different significance depending on user role;
- asset sensitivity changes the impact of an action;
- historical behaviour is important for detecting meaningful deviations;
- analysts need explanations rather than opaque risk scores;
- large event volumes require scalable ingestion and search;
- contextual threat knowledge can improve investigation.

The project therefore combines behavioural modelling with contextual risk assessment.

---

# 4. Research/Technical Position

The project focuses on structured behavioural telemetry and contextual risk scoring.

The primary model is TabNet because the core representation is tabular and behavioural.

TabNet is not assumed to be universally superior. It should be experimentally compared with appropriate baselines.

The project also emphasizes explainability through:

- TabNet feature masks;
- SHAP;
- contextual CRI factors;
- historical deviations;
- MITRE ATT&CK enrichment.

---

# 5. High-Level Module Map

```text
┌─────────────────────────────────────────────────────────────┐
│                       DATA SOURCES                          │
│ Windows | Linux | VPN | IAM | Email | USB | Network | Cloud│
└────────────────────────────┬────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────┐
│                        INGESTION                            │
│ Dataset loaders / APIs / collectors / Kafka producers       │
└────────────────────────────┬────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────┐
│                 STREAM / DATA PROCESSING                    │
│ Parsing | validation | normalization | windowing             │
└────────────────────────────┬────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────┐
│                  FEATURE ENGINEERING                        │
│ Behaviour | temporal | historical | peer | context          │
└────────────────────────────┬────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────┐
│                         TABNET                              │
│ Structured behavioural anomaly/risk modelling               │
└────────────────────────────┬────────────────────────────────┘
                             ↓
                     Anomaly Score
                             ↓
┌─────────────────────────────────────────────────────────────┐
│                    CRI ENGINE                               │
│ User | role | asset | baseline | peers | threat context     │
└────────────────────────────┬────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────┐
│                 MITRE ATT&CK ENRICHMENT                     │
└────────────────────────────┬────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────┐
│             ALERT CORRELATION / DEDUPLICATION               │
└────────────────────────────┬────────────────────────────────┘
                             ↓
                 Explainability + Persistence
                             ↓
┌─────────────────────────────┐       ┌────────────────────────┐
│ PostgreSQL                  │       │ OpenSearch (production) │
│ Durable relational state    │       │ Event search            │
└──────────────┬──────────────┘       └─────────────┬──────────┘
               └────────────────┬───────────────────┘
                                ↓
                         FastAPI Backend
                                ↓
                      React + TypeScript
                                ↑
                               SSE
```

---

# 6. Data Sources

## FYP

The project primarily uses CERT/TWOS-style insider-threat datasets as the experimental foundation.

Typical data domains include:

- authentication;
- file activity;
- device/USB activity;
- email;
- web/network activity;
- application/process activity;
- user/role context.

## Production extension

A real enterprise deployment could ingest:

- Windows event logs;
- Linux audit logs;
- VPN;
- IAM;
- EDR;
- email systems;
- cloud activity;
- file systems;
- removable media;
- network telemetry;
- SaaS/cloud audit logs;
- HR/user context.

The production architecture should normalize these different sources into a common event contract.

---

# 7. Event Ingestion

## FYP mode

Dataset loaders can read CERT/TWOS data and convert records into a canonical internal event representation.

## Production mode

Collectors publish events to Kafka.

```text
Collector
   ↓
Kafka topic
   ↓
Consumer
   ↓
Normalizer
```

Kafka responsibilities:

- decoupling producers and consumers;
- buffering;
- replay;
- partitioning;
- horizontal scaling.

Kafka is not required to make the FYP dataset-driven pipeline work.

---

# 8. Canonical Event Contract

A normalized event should conceptually contain:

```json
{
  "event_id": "unique-event-id",
  "timestamp": "ISO-8601 timestamp",
  "user_id": "user identifier",
  "device_id": "device identifier",
  "source_type": "authentication|file|email|usb|network|application",
  "event_type": "event subtype",
  "source_ip": "optional",
  "destination": "optional",
  "resource": "optional",
  "action": "optional",
  "bytes_in": 0,
  "bytes_out": 0,
  "metadata": {}
}
```

The exact fields depend on the source dataset.

Do not force unavailable fields into the data model.

---

# 9. Preprocessing and Normalization

Responsibilities:

1. parse source-specific records;
2. normalize timestamps;
3. normalize user/device identifiers;
4. handle missing values;
5. remove or flag malformed records;
6. normalize categorical values;
7. validate event schemas;
8. remove obvious duplicates;
9. preserve traceability to the source record.

The preprocessing layer must not leak target labels into model features.

---

# 10. Feature Engineering

Feature engineering is one of the most important parts of CIRA.

## 10.1 Authentication

Examples:

- login count;
- failed login count;
- successful login count;
- login hour;
- off-hours login;
- unusual login time;
- new device;
- new IP;
- authentication frequency.

## 10.2 File activity

Examples:

- files created;
- files modified;
- files deleted;
- files accessed;
- sensitive file accesses;
- abnormal file volume;
- unusual access timing.

## 10.3 Email

Examples:

- messages sent;
- messages received;
- attachment count;
- attachment size;
- internal/external recipient ratio;
- unusual recipient behaviour.

Actual message-content NLP is optional and must only be used when text data is available.

## 10.4 USB/removable media

Examples:

- USB insertion;
- USB removal;
- number of removable-media events;
- abnormal removable-media usage;
- file transfer associated with removable media.

## 10.5 Network

Examples:

- inbound bytes;
- outbound bytes;
- number of connections;
- destination diversity;
- unusual destination;
- unusual transfer volume;
- cloud/storage activity.

## 10.6 Application/process

Examples:

- application count;
- unusual application;
- process count;
- unusual process;
- abnormal application timing.

## 10.7 Temporal features

Examples:

- hour of day;
- day of week;
- weekend indicator;
- off-hours indicator;
- rolling activity count;
- activity-window statistics.

## 10.8 Historical baseline

A user should be compared against their own normal behaviour when sufficient history exists.

Examples:

```text
current_login_hour - user's normal login-hour distribution
current_file_volume - user's historical file volume
current_network_volume - user's normal network volume
```

The exact statistical method should be chosen according to the available data.

## 10.9 Peer-group behaviour

Where appropriate:

```text
User behaviour
      ↓
Compare with relevant peer group
      ↓
Peer deviation
```

Peer groups could be based on role, department or other organizational context when such metadata exists.

Do not invent peer relationships when the dataset cannot support them.

---

# 11. User and Asset Context

Contextual risk requires more than event-level anomaly detection.

Potential user context:

- user ID;
- role;
- department;
- privilege level;
- tenure;
- peer group.

Potential asset context:

- asset ID;
- asset type;
- sensitivity;
- criticality;
- owner/group.

The exact fields depend on available project data.

---

# 12. TabNet

## Role

TabNet is the primary model for structured behavioural features.

Input:

```text
Feature Vector
```

Output:

```text
Anomaly / prediction score
```

and, where configured, feature-selection/attention masks.

## Rationale

TabNet is appropriate because:

- the data is primarily tabular;
- the model learns feature selection;
- feature masks support interpretability;
- the approach aligns with structured behavioural risk analysis.

## Important constraint

Do not claim:

> TabNet is always more accurate than all alternatives.

Instead:

```text
TabNet
vs
Isolation Forest
vs
LOF
vs
LSTM Autoencoder
vs
XGBoost/CatBoost
```

should be evaluated using the same leakage-safe experimental protocol where appropriate.

---

# 13. Baseline Models

Potential baselines:

### Rule-based

A simple threshold/rule system provides a non-ML baseline.

### Isolation Forest

Useful for unsupervised anomaly detection.

### LOF

Useful for local-density anomaly detection.

### LSTM Autoencoder

Useful when sequential temporal behaviour is represented appropriately.

### XGBoost/CatBoost

Useful supervised tabular baselines when labels support supervised learning.

Do not force every baseline into the final production pipeline. Baselines are primarily for experimental comparison unless a model proves useful operationally.

---

# 14. Anomaly Score

The ML layer produces an anomaly/prediction score.

Conceptually:

```text
0.00 ───────────────────────────── 1.00
normal                              anomalous
```

The anomaly score is not automatically the final business risk.

That distinction is important.

---

# 15. Contextual Risk Intelligence (CRI)

CRI is the project's contextual risk layer.

Conceptually:

```text
                  TabNet anomaly score
                           +
                    User context
                           +
                   Asset criticality
                           +
                 Historical deviation
                           +
                    Peer deviation
                           +
                  Threat/MITRE context
                           ↓
                         CRI
                           ↓
                 Contextual Risk Score
                           ↓
                      Severity
```

A normalized 0–100 risk score is appropriate.

Example severity bands:

```text
0–24   LOW
25–49  MEDIUM
50–74  HIGH
75–100 CRITICAL
```

These thresholds are configuration examples, not immutable scientific facts. They should be configurable and evaluated.

The exact CRI weighting formula must be defined in implementation/configuration rather than silently invented.

---

# 16. MITRE ATT&CK

MITRE ATT&CK provides threat-context enrichment.

The flow is:

```text
Observed behaviour
      ↓
Candidate ATT&CK technique/tactic
      ↓
Contextual enrichment
      ↓
Risk / investigation
```

MITRE should help an analyst understand what type of adversarial behaviour a pattern may represent.

It should not replace the behavioural model.

Mappings must be traceable and should not be fabricated.

---

# 17. Alert Correlation and Deduplication

A production system should avoid generating a separate analyst-facing incident for every closely related event.

Example:

```text
Unusual login
    ↓
Large file access
    ↓
Archive creation
    ↓
External transfer
```

Instead of:

```text
Alert 1
Alert 2
Alert 3
Alert 4
```

the system can correlate them into:

```text
Incident
  ├── event 1
  ├── event 2
  ├── event 3
  └── event 4

Risk = HIGH/CRITICAL
```

Deduplication and correlation logic should remain deterministic, testable and configurable.

---

# 18. Explainability

The explanation layer combines:

- TabNet masks;
- SHAP;
- CRI factors;
- historical deviation;
- MITRE context.

Example analyst-facing explanation:

```text
HIGH RISK

Primary contributing factors:
1. Off-hours authentication
2. File activity substantially above baseline
3. New device observed
4. High-criticality asset accessed
5. Behaviour associated with a relevant ATT&CK technique
```

The explanation should be tied to actual computed features and model outputs.

Never fabricate a reason that is not supported by the data/model.

---

# 19. NLP / Tokenization Extension

NLP is optional.

It is only relevant if the system receives actual textual data such as:

- email bodies;
- message content;
- document text;
- other textual communication.

Possible extension:

```text
Text
 ↓
Tokenization
 ↓
Text representation
 ↓
NLP model
 ↓
Text-derived features
 ↓
Multimodal fusion
 ↓
Risk engine
```

Tokenization does not inherently improve TabNet accuracy.

The NLP branch should only be added when data and experiments justify it.

---

# 20. PostgreSQL

PostgreSQL is the durable relational source of truth.

Potential entities:

```text
User
Asset
EventLog
FeatureVector
AnomalyScore
RiskScore
Alert
AlertReason
MITREMapping
ModelVersion
AuditLog
Configuration
```

Not every entity must be implemented immediately.

Use normalized relational design where appropriate.

---

# 21. SQLAlchemy ORM

SQLAlchemy is the canonical ORM.

Reasons:

- native Python ecosystem;
- strong FastAPI compatibility;
- type-safe/model-based persistence patterns;
- relationship handling;
- transaction support;
- mature PostgreSQL support.

Use:

```text
SQLAlchemy Models
       ↓
Session / Repository / Service
       ↓
PostgreSQL
```

Avoid putting raw database logic throughout route handlers.

---

# 22. Alembic

Alembic manages schema migrations.

Development pattern:

```text
SQLAlchemy model change
       ↓
Alembic migration
       ↓
Review migration
       ↓
Apply to PostgreSQL
```

Migration files must be version-controlled.

Do not modify the database manually as the normal development workflow.

---

# 23. Redis

Redis is a performance/support layer.

Use for:

- hot risk values;
- recent feature windows;
- temporary session/state;
- deduplication state;
- short-lived cache.

Do not use Redis as the permanent source of truth.

---

# 24. OpenSearch

For production-scale event volumes:

```text
PostgreSQL
→ structured relational application state

OpenSearch
→ large-scale event search/investigation
```

OpenSearch is useful for analyst queries across large event collections.

It should not be introduced into the FYP merely for architectural appearance.

---

# 25. FastAPI

FastAPI is the backend API and integration layer.

Recommended logical separation:

```text
backend/app/
├── api/
├── schemas/
├── services/
├── database/
├── core/
└── main.py
```

The API should expose application functionality rather than expose internal implementation details.

Potential API groups:

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

---

# 26. SSE

SSE provides server-to-browser alert delivery.

```text
Risk/Alert Engine
       ↓
FastAPI SSE endpoint
       ↓
React EventSource
       ↓
Live alert
```

Use SSE because the principal requirement is server → browser notification.

Use WebSockets only if a future requirement genuinely needs bidirectional communication.

---

# 27. React + TypeScript

The dashboard is designed for security analysts.

Core views:

```text
Overview
Alerts
Alert Details
User Investigation
Risk History
Explainability
MITRE Context
```

The dashboard should answer:

1. Who is risky?
2. What happened?
3. How risky is it?
4. Why is it risky?
5. What contextual evidence supports the risk?
6. What should the analyst investigate?

---

# 28. Celery

Celery is a background processing system.

Suitable workloads:

```text
Celery
├── SHAP batch calculations
├── model retraining
├── report generation
├── large dataset processing
└── periodic baseline calculation
```

It must not be inserted into the low-latency detection chain.

Real-time:

```text
Kafka
 ↓
Processing
 ↓
Features
 ↓
TabNet
 ↓
CRI
 ↓
Alert
```

Background:

```text
Celery
 ↓
Heavy/slow work
```

---

# 29. Monitoring and Observability

## Prometheus

Prometheus collects system/application metrics.

Examples:

- request count;
- request latency;
- error count;
- throughput;
- Kafka lag;
- model inference latency;
- worker status;
- CPU;
- memory;
- database latency;
- alert volume.

## Grafana

Grafana visualizes those metrics.

Prometheus/Grafana do not decide whether a user is malicious.

---

# 30. ML Monitoring

ML monitoring is separate from Prometheus infrastructure monitoring.

Track:

- feature distribution changes;
- data drift;
- prediction distribution;
- model performance;
- false-positive changes;
- class/label distribution where labels exist;
- model version;
- retraining events.

Potential lifecycle:

```text
Training
   ↓
Validation
   ↓
Model Version
   ↓
Deployment
   ↓
Monitoring
   ↓
Drift/performance issue
   ↓
Retraining
   ↓
New Model Version
```

---

# 31. Authentication and RBAC

Production deployment should support authenticated users and role-based permissions.

Possible roles:

```text
Admin
SOC Analyst
Security Manager
Viewer
```

Example:

```text
SOC Analyst
→ investigate alerts

Manager
→ view reports and risk summaries

Admin
→ configure users/system
```

Do not implement complicated authorization before the core application requires it.

---

# 32. Security and Privacy

Security requirements:

- secrets must never be committed;
- use `.env` locally;
- provide `.env.example`;
- encrypt transport with TLS in production;
- apply least-privilege database access;
- protect sensitive event data;
- audit security-sensitive actions;
- avoid unnecessary PII exposure;
- secure model and dataset artifacts;
- validate incoming events.

Insider-threat telemetry can be highly sensitive and must be handled accordingly.

---

# 33. Docker

Docker provides reproducible development/deployment environments.

FYP target:

```text
Docker Compose
├── backend
├── frontend
└── postgres
```

Production can expand to:

```text
backend
frontend
postgres
kafka
redis
celery
opensearch
monitoring
```

Do not containerize unnecessary services before the core application works.

---

# 34. Kubernetes

Kubernetes is a production-scale orchestration option.

Possible workloads:

```text
FastAPI pods
Model-serving pods
Workers
Kafka infrastructure
Frontend
Monitoring
```

Kubernetes is not required for the core FYP.

---

# 35. CI/CD

A production pipeline should eventually perform:

```text
Commit
 ↓
Lint
 ↓
Unit tests
 ↓
Integration tests
 ↓
Build
 ↓
Container validation
 ↓
Deploy
```

Do not introduce complicated CI/CD before tests and application structure are stable.

---

# 36. Failure Modes

## Kafka unavailable

Production ingestion should tolerate temporary downstream failure through Kafka buffering/replay where configured.

## PostgreSQL unavailable

The application must fail safely rather than claim an alert was durably stored when it was not.

## Redis unavailable

The system should continue using the durable source of truth where feasible. Cache failure must not silently corrupt risk state.

## Model unavailable

Return an explicit service/model error or safe degraded state. Do not fabricate a risk score.

## SHAP unavailable

The alert can still exist with model score/context, while explanation generation can be retried asynchronously.

## SSE disconnected

The dashboard should reconnect and obtain current state through normal APIs.

---

# 37. Data Lineage

Every risk decision should be traceable as far as practical:

```text
Source Event
   ↓
Normalized Event
   ↓
Feature Vector
   ↓
Model Version
   ↓
Anomaly Score
   ↓
CRI Inputs
   ↓
Final Risk Score
   ↓
MITRE Mapping
   ↓
Alert
```

This is important for debugging, research reproducibility and analyst trust.

---

# 38. Model Versioning

Each model result should be associated with a model version where practical.

Store metadata such as:

- model name;
- model version;
- training dataset/version;
- feature schema/version;
- training timestamp;
- evaluation metrics;
- artifact location.

Do not overwrite a production model artifact without versioning.

---

# 39. Evaluation Protocol

Primary metrics:

- Precision
- Recall
- F1
- ROC-AUC
- PR-AUC
- False Positive Rate
- Detection Latency
- Top-k Precision
- Risk Coverage

Because insider-threat data is often imbalanced, do not use accuracy as the sole metric.

Evaluate:

```text
Baseline
   ↓
TabNet
   ↓
TabNet + CRI
   ↓
TabNet + CRI + MITRE/context
```

where the data and experimental design support the comparison.

Use leakage-safe splitting.

Never fabricate results.

---

# 40. Ablation Strategy

Useful experiments:

### Experiment A

TabNet using core behavioural features.

### Experiment B

TabNet + contextual features.

### Experiment C

TabNet + CRI.

### Experiment D

TabNet + CRI + MITRE contextualization.

### Experiment E

Explainability/operational evaluation.

The goal is to demonstrate whether contextual enrichment actually contributes value.

---

# 41. Repository Structure

Target repository:

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

This is a target logical organization. Do not create empty modules just for visual completeness.

---

# 42. Dependency Map

```text
Data Sources
    ↓
Ingestion
    ↓
Preprocessing
    ↓
Feature Engineering
    ↓
┌───────────────────────┐
│ Behavioural Features  │
└───────────┬───────────┘
            ↓
        TabNet
            ↓
      Anomaly Score
            ↓
           CRI
       ↙    ↓    ↘
 User     Asset   History
 Context  Context  /Peers
            ↓
        MITRE Context
            ↓
     Alert Correlation
            ↓
   ┌────────┴────────┐
   ↓                 ↓
Explainability   Persistence
   ↓                 ↓
   └────────┬────────┘
            ↓
         FastAPI
            ↓
          React
```

Production dependencies:

```text
Kafka → ingestion/streaming
Redis → cache/temporary state
Celery → background workloads
OpenSearch → event search
SSE → live browser updates
Prometheus → metrics
Grafana → dashboards
Docker → deployment
Kubernetes → scale/orchestration
```

---

# 43. Configuration

Use environment/configuration rather than hard-coding:

```text
DATABASE_URL
SECRET_KEY
ENVIRONMENT
LOG_LEVEL

MODEL_PATH
MODEL_VERSION

CRI_* configuration
MITRE_* configuration

REDIS_URL
KAFKA_BOOTSTRAP_SERVERS

OPENSEARCH_URL

CELERY_BROKER_URL

CORS_ORIGINS
```

Only define variables required by the enabled components.

`.env` must never be committed.

`.env.example` contains safe placeholders.

---

# 44. Implementation Roadmap

## Phase 1 — Foundation

- repository structure;
- Python environment;
- FastAPI;
- PostgreSQL;
- SQLAlchemy;
- Alembic;
- React;
- configuration;
- health endpoint.

## Phase 2 — Data

- CERT/TWOS ingestion;
- canonical event schema;
- preprocessing;
- validation.

## Phase 3 — Features

- behavioural features;
- temporal features;
- historical baselines;
- context features.

## Phase 4 — Baselines

- rule-based;
- Isolation Forest;
- LOF;
- additional baselines where appropriate.

## Phase 5 — TabNet

- dataset preparation;
- training;
- validation;
- model persistence;
- inference.

## Phase 6 — Risk

- anomaly score;
- CRI;
- severity;
- configurable weights.

## Phase 7 — Threat context

- MITRE mapping;
- contextual evidence.

## Phase 8 — Explainability

- TabNet masks;
- SHAP;
- alert reasons.

## Phase 9 — Alert system

- persistence;
- deduplication;
- correlation;
- incident representation.

## Phase 10 — Backend

- FastAPI services;
- API schemas;
- risk/alert endpoints.

## Phase 11 — Frontend

- SOC dashboard;
- alert investigation;
- risk views;
- explainability;
- MITRE context.

## Phase 12 — End-to-end validation

Verify:

```text
Raw event
→ normalized event
→ features
→ TabNet
→ anomaly score
→ CRI
→ MITRE
→ explanation
→ alert
→ PostgreSQL
→ API
→ dashboard
```

## Phase 13 — Production extensions

Only after the core system works:

- Kafka;
- Redis;
- SSE;
- Celery;
- OpenSearch;
- Prometheus/Grafana;
- authentication/RBAC hardening;
- Docker productionization;
- Kubernetes;
- ML monitoring/drift;
- CI/CD.

---

# 45. Acceptance Criteria

The FYP core is considered functionally complete when:

1. project starts successfully;
2. database migrations run successfully;
3. dataset events can be ingested;
4. events are normalized;
5. behavioural features are generated;
6. TabNet can be trained/evaluated;
7. inference produces an anomaly score;
8. CRI converts anomaly/context into contextual risk;
9. relevant MITRE context can be attached;
10. an explanation can be generated;
11. an alert can be persisted;
12. FastAPI exposes the result;
13. React displays the alert/risk;
14. an analyst can understand why the alert was generated;
15. tests cover important core components;
16. evaluation metrics are reproducible.

---

# 46. Do Not Over-Engineer the FYP

Do not add a technology simply because a production security platform might use it.

Examples:

### Do not do this first

```text
Kubernetes
Kafka
Redis
Celery
OpenSearch
Prometheus
Grafana
Service Mesh
Microservices
```

while the TabNet/CRI pipeline is unfinished.

### Do this first

```text
Dataset
 ↓
Features
 ↓
TabNet
 ↓
CRI
 ↓
Explainability
 ↓
PostgreSQL
 ↓
FastAPI
 ↓
React
```

A smaller system that genuinely works is stronger than a large architecture whose components are placeholders.

---

# 47. Non-Negotiable Architecture Rules

1. PostgreSQL is the durable relational source of truth.
2. SQLAlchemy is the ORM.
3. Alembic manages migrations.
4. Prisma is not used.
5. Redis is a cache/temporary-state layer, not the source of truth.
6. Kafka is the production event-streaming backbone.
7. Celery handles background heavy work.
8. Celery must not sit between Kafka and TabNet on the real-time path.
9. SSE is sufficient for server-to-browser live alerts unless bidirectional requirements appear.
10. OpenSearch is for production-scale event search/investigation.
11. Prometheus/Grafana are observability, not threat detection.
12. ML drift monitoring is separate from infrastructure monitoring.
13. TabNet is the primary behavioural model, but it must be benchmarked.
14. CRI is separate from the raw model anomaly score.
15. MITRE ATT&CK is contextual enrichment, not the entire detection engine.
16. Explainability must use actual model/context outputs.
17. NLP is optional and only justified by actual text data.
18. Tokenization is not an automatic accuracy improvement.
19. Docker is sufficient for the FYP deployment baseline.
20. Kubernetes is a production extension.
21. Existing working code should be extended rather than unnecessarily replaced.
22. No planned component should be claimed as implemented without verification.
23. No experimental result should be fabricated.
24. Security-sensitive secrets must never be committed.

---

# 48. AI Coding Agent Handoff

The AI coding agent should treat this document as the canonical architecture.

The immediate priority is NOT to build every production component.

The immediate priority is:

```text
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

The agent should implement this vertical slice incrementally, test each layer, and preserve clear module boundaries.

Production infrastructure should be introduced only after the core behaviour is correct or when explicitly requested.

The agent must always distinguish:

```text
IMPLEMENTED
PARTIALLY IMPLEMENTED
PLANNED
OPTIONAL
PRODUCTION EXTENSION
```

No architectural change should be made silently.
