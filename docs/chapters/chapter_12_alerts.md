# Chapter 12: alert correlation and persistence

Bible Chapter 12 / Architecture Phase 9 (§17, §20, §36, §37), executed under HCEA v1.0 §12
(deviation D-6, bounded persistence).

Status: IMPLEMENTED (1 October 2026). The full alert run `20261001T062628Z-full-alerts` is verified
(0 FAIL), loaded into the development machine's PostgreSQL, read on validation, and shown loaded by
`/health`. The audit is `docs/audits/chapter_12_audit.md`, and the numbers are there, not in this
document.

## What an alert is here

CIRA scores user-days, not single events (Chapter 5). The §17 example (an unusual logon, a large file
access, an archive and an external transfer) is therefore already one user-day when it happens on one
day. When the same user's related activity spreads over a few days, each of those days may be
scored high, and without correlation the analyst would get one alert per day for one incident.

So an alert is one correlated incident: the triggered user-days of one user that lie close together
in time, stored as one `Alert` row with one `AlertMember` row per day. Every member day links to its
risk score, and through it to the anomaly score, the feature vector, the model version and the source
events (§37). An alert never mixes users, and it never recomputes or changes a score (N34).

## The alert policy (`c12-alert-policy-v1`)

The policy was fixed before any alert number existed, with one exception described below. It is set
by command-line flags of `python -m app.alerts.batch`, never by `.env`, and every run records it with
its hash. A value that differs from the default is listed under `policy_overrides`, and the verifier
WARNs on it.

| Setting | Default | What it does |
|---|---|---|
| `band_severities` | HIGH, CRITICAL | a user-day whose CRI severity is in the list triggers |
| `top_k_per_day` | 1 | the day's top-k user-days by the queue ordering trigger |
| `ordering` | `anomaly_score` | what orders the queue and picks the daily top-k |
| `require_activity` | on | a user-day with no recorded event cannot take a top-k slot |
| `correlation_gap_days` | 3 | two triggered days of one user join if at most 3 calendar days apart |
| `max_span_days` | 14 | no alert spans more than 14 calendar days |
| `cooldown_days` | 7 | window in which a repeat of an open alert's pattern is suppressed |
| `tie_break_seed` | `CIRA_SEED` | seeds the tie-break inside a day |

### Triggers: both views, recorded separately (N39)

A user-day triggers if its band is HIGH or CRITICAL or if it is in the day's top-1. The band is a
global threshold and can be quiet on some days and busy on others. The top-1 is a daily budget an
analyst can work through. Each member day records which of the two fired (`by_band`, `by_top_k`), the
batch summary counts them separately, and the readout reads them separately, so neither view hides
the other.

The daily top-k uses the same seeded tie-break as `app.evaluation.metrics.daily_top_k`. The function
is copied into `app/alerts/policy.py` rather than imported, because serving code must not import the
evaluation package (N5), and a unit test checks that the two agree on tied data.

### Queue ordering: the anomaly score, with the CRI as context (N40, N46)

The queue is ordered by the served model's anomaly score. The CRI score and severity band are shown
next to it as context. On full / user validation the anomaly score has the highest PR-AUC of the
three orderings (0.915, against 0.694 for the default CRI and 0.557 for the CRI with ATT&CK context),
and no ordering dominates on insiders caught at the daily top-1. That choice was made after those
validation readouts existed, so it is recorded as validation-informed (`queue.validation_informed` in
the meta). The batch reports, label-free, what the CRI ordering would have put in the daily top-k,
and the validation readout reads both orderings the same way.

### Idle days never take a top-k slot

A daily budget fires on every calendar day, weekends included. On a day when almost nobody did
anything, the top-1 goes to whoever is least quiet. The synthetic chain showed this: its first run
alerted on a Sunday on which the user had no recorded event at all. With `require_activity` a
user-day whose Chapter 5 `total_event_count` is 0 cannot take a top-k slot, and the slot goes to the
highest-scoring user who did something that day. The band trigger is unaffected. This rule was added
while building the chapter, after that synthetic run; no CERT number informed it (C12-4). The batch
summary counts triggered days with no recorded activity and, under `activity_rule_view`, the
user-days and dates whose top-k slot the rule changes (N56). `--allow-inactive-top-k` turns the rule off as a recorded
override.

### Correlation (Bible Ch12 step 1)

Per user, triggered days are taken in date order. A day joins the current alert if it is at most 3
calendar days after the previous triggered day and less than 14 days after the alert's first day.
Otherwise it starts a new alert. Friday to Monday is one incident, and a user who triggers every day
for a month becomes three alerts, not one endless one.

The alert's peak day is the member with the highest queue score (ties go to the earlier day), and
`queue_score` is that score. `max_severity` and `max_cri_score` are taken over the members,
`techniques` is the union of the members' ATT&CK techniques, and `top_feature` is the peak day's top
raising model factor. `alert_key` is a hash of the policy, the user and the first day, so the same
policy over the same scores gives the same keys.

### Deduplication (Bible Ch12 step 2)

An alert's signature is its ATT&CK technique ids plus `factor:<top_feature>`: what the analyst would
read first. A new alert of a user is suppressed if it starts at most 7 days after that user's most
recent open alert ends, its signature is not empty, and every element of it is already in that open
alert's signature. Otherwise it is open.

Three details keep this honest. A suppressed alert is kept: it is written to Parquet and to PostgreSQL
with `status = 'suppressed'` and `duplicate_of` naming the open alert it repeats (C12-9). The
comparison is always with an open alert, so a chain of suppressed repeats cannot drift away from the
pattern the analyst actually saw. An empty signature never suppresses anything, because nothing
identifies the pattern. The readout reports how many malicious days sit only in suppressed alerts,
and the guard WARNs if there are any (N57).

## Explanations on alerts (N47, N48, N50)

Every member day of every alert, open or suppressed, gets the full analyst explanation from Chapter
11's `build_explanation`. The model side is read from the explain run's stored TreeSHAP attributions
(every scored user-day is in them and each adds up to the served margin, N47), so no model is loaded
and nothing is recomputed. Days outside Chapter 11's bounded set are explained this way, which is the
"on demand" path N50 asks for.

The risk row comes from the CRI run the explain run names, and the attributions from that explain
run, so one explanation always describes one score. The builder refuses a model_version or
anomaly-score mismatch. That refusal is not worked around: the day is written with status
`model_explanation_deferred` and the reason, and its alert still exists with its score and context
(§36).

`alert_reasons` holds one row per explanation item. The `section` column keeps the kinds apart:
`model` (a raising TreeSHAP factor, with its log-odds contribution and raw value), `model_lowering`,
`cri` (a CRI point, with its component) and `mitre` (an ATT&CK match, with its rule and triggering
value). Each row keeps the builder's `source` record. N50 names three sections; the lowering factors
are a fourth because the §18 text shows them, and they are still model output (C12-8). Where Chapter
11 ran KernelSHAP on a member day, its top-5 overlap and deletion result are stored on the member row
as statistics. They are never a reason row (N48).

## The demo sample (`c12-demo-sample-v1`, D-6)

D-6 persists alert-linked rows plus "a bounded, deterministic sample for demonstration purposes
(suggested: all events for ~20 users across the demo window)", with the selection rule recorded in
configuration. The rule, label-free:

- Window: 30 consecutive days. Among open alerts of test users (validation users if no test user has
  one), the window starting on an alert's peak day that contains the most open-alert peaks; ties go
  to the earliest start.
- Users: at most 20. First up to 10 users with an open alert peaking in the window (test before
  validation, higher queue score first), then users with no open alert anywhere in the run, ordered
  by `sha256(seed|user_id)`. The dashboard needs quiet users too.
- Rows: every scored user-day of those users inside the window.

Only validation and test users are eligible. In-sample rows are never example material (N31), and
test users come first because validation chose the model (N59). The rule and the users and window it
chose are written to `alert_meta.json` and, when the run is loaded, to the `configurations` table
under `c12-demo-sample-v1:<alert_run_id>`.

## What PostgreSQL holds (§20, §37, D-6)

Migration `9f3b2c7d4e81` (revises `7c1e4a9d2b60`) adds the §20 entities that now have a purpose.

| Table | One row per | Holds | Bounded by |
|---|---|---|---|
| `model_versions` | served model version | registry entry with the sha256 of every artifact (N21) | one per model |
| `feature_vectors` | user-day | every Chapter 5 column as JSON (nulls stay null, N4), matrix fingerprint and path | member and demo days |
| `event_logs` | CERT event | Stage 0 row: CERT event id, time, device, domain details, source part file, its feature vector | events of member and demo days |
| `anomaly_scores` | user-day | served margin and anomaly score, split tag, batch run; `role = 'served'` is a check constraint (N32) | member and demo days |
| `risk_scores` | user-day | CRI, severity, components, points, calibration and run ids; points at its anomaly score and keeps its value (N34) | member and demo days |
| `alerts` | incident | policy, status, `duplicate_of_id`, span, peak, queue score, context, every run id | the alert run |
| `alert_members` | member day | alert, risk score, triggers, the full explanation and its text | the alert run |
| `alert_reasons` | explanation item | section, subject, rule, value, weight, text, source (N50) | member days |
| `audit_logs` | action | `alert_run_loaded`, written in the load's own transaction | one per load |

`mitre_mappings` gains `alert_id`, linking the ATT&CK rows of a member day to the alert that covers
it; demo-only days have none. A column holds one alert, so a day in two alert runs keeps its first
link; the canonical path from an alert to its ATT&CK rows is alert → member → (user, day, enrichment
run), which never depends on it. The policy is recorded in `configurations` under
`c12-alert-policy-v1:<hash>`. A configuration key is written once, and a different value under an
existing key is refused.

The check constraints enforce what the earlier chapters promised: only served scores (N32), scores in
range, a suppressed alert names its original, an open one does not, the peak lies inside the span, a
deferred explanation carries its reason, an ATT&CK reason names its rule (N45), a model reason
carries its contribution.

`user_id` in these tables is a monitored subject's CERT id. The existing `users` table holds analyst
accounts and is not referenced.

### The lineage chain

Every step of §37 is a foreign key or a stored run reference:

```text
event_logs.feature_vector_id -> feature_vectors      (Source Event -> Normalized Event -> Feature Vector)
anomaly_scores.feature_vector_id, .model_version_id  (Feature Vector + Model Version -> Anomaly Score)
risk_scores.anomaly_score_id                         (Anomaly Score -> CRI inputs -> Final Risk Score)
mitre_mappings.alert_id + (user_id, day, mitre_run)  (MITRE Mapping)
alert_members.risk_score_id, alert_reasons.member_id (-> Alert, with its reasons)
```

The full score set stays in Parquet, referenced by path, fingerprint and (user_id, activity_date).
PostgreSQL stores decisions and their lineage, not the corpus (R12).

## The load (`python -m app.alerts.load`)

1. The plan is built from Parquet, and lineage is checked on the way. The model served now must be
   the one the alert run names (N28). Its registry entry must verify by sha256 (N21). The matrix
   fingerprint must be unchanged. Every member day must have its feature row, served score and risk
   row, with the same anomaly score in both (N34). Anything wrong here is refused with exit 2, before
   the database is touched.
2. Events are read from Stage 0 Parquet for member and demo days only: month by month, filtered by
   user, never the whole corpus. More than `--max-events` (500,000 by default) is refused. The load
   is bounded by design, not by luck.
3. Everything is written in one transaction, in lineage order, with the audit row last. Rows that
   already exist under their natural key (an event id, a user-day of the same matrix, batch, CRI run
   or enrichment run) are reused, so two alert runs over the same scores share their lineage rows.
4. A new connection reads the load back. Only if it agrees does the command print `stored`, write
   `loads/load_<stamp>.json` next to the run and append a `chapter12_alert_load` runlog line.

The same function runs on the application's asyncpg engine (through `run_sync`) and on a plain
SQLite or psycopg URL, so the tests exercise the code path production uses. Rows are written with
chunked `executemany`, not `COPY` (C12-7). At the expected size (below) that is seconds, and it keeps
one dialect-neutral path.

### PostgreSQL unavailable (§36)

Any error during the write rolls the whole transaction back. The command prints
`chapter12 load NOT STORED: <reason>`, appends a runlog line with `status: not_stored`, writes no
load record and exits 3. The audit row that would claim the load is part of the same transaction, so
it exists only if everything else committed (N58). `/health` probes the database with a 2-second
timeout and reports `database.status = unavailable` with the reason instead of hanging. The Parquet
alert run is unaffected either way, and the load can be retried; a second load of a committed run is
refused with exit 2.

Checked on the local PostgreSQL 16: an integrity error raised after most rows were written left every
table empty; a refused connection (wrong port) reported NOT STORED with no load record; the reload of
a stored run was refused.

## Failure modes (Architecture §36)

| Situation | Behaviour |
|---|---|
| No served model, or the served model is not the one the explain run explains | Batch refuses (N28, N30); `/health` alerts block unavailable with the reason |
| Explain run's CRI run is an ablation variant, from another batch or model_version | Batch refuses (N29, N33, N50) |
| Matrix changed since the batch, CRI run or explain run | Batch and load refuse (fingerprint) |
| Explain run does not cover the alert rows (`--rows` differs) | Batch refuses with the fix |
| Enrichment run named by the CRI run is missing | Batch refuses; a CRI run without ATT&CK context is allowed and WARNed |
| An explanation cannot be built for a member day | Day written as `model_explanation_deferred` with the reason; the alert keeps its score and context |
| Registry artifacts do not verify | Load refuses (N21) |
| Too many events for the member and demo days | Load refuses (`--max-events`, D-6) |
| PostgreSQL down or an error mid-load | Rolled back; `NOT STORED`, exit 3, runlog `not_stored`, no load record |
| Same alert run loaded twice | Refused, exit 2 |
| A recorded policy or demo rule would be overwritten | Load refuses; nothing written |
| Alert run built for a model that is no longer served (rollback) | `/health` alerts block unavailable; load refuses |

## What was built

| Path | Purpose |
|---|---|
| `backend/app/alerts/policy.py` | `AlertPolicy`, `c12-alert-policy-v1`, seeded daily top-k, `triggers` |
| `backend/app/alerts/correlation.py` | Triggered user-days to alerts and member days |
| `backend/app/alerts/deduplication.py` | Signature and cooldown suppression |
| `backend/app/alerts/demo.py` | `c12-demo-sample-v1` |
| `backend/app/alerts/explain.py` | Member-day explanations through the Chapter 11 builder; `alert_reasons` rows |
| `backend/app/alerts/sources.py` | Run layout and reading |
| `backend/app/alerts/batch.py` | `python -m app.alerts.batch` |
| `backend/app/alerts/persistence.py` | `LoadPlan`, `persist` (one transaction), `check_stored` |
| `backend/app/alerts/load.py` | `python -m app.alerts.load` |
| `backend/app/alerts/runtime.py` | `AlertRuntime` and `database_status` for `/health` |
| `backend/app/alerts/evaluate.py` | Offline validation readout and guard (reads labels) |
| `backend/app/database/models/*.py` | `ModelVersion`, `FeatureVector`, `EventLog`, `AnomalyScore`, `RiskScore`, `Alert`, `AlertMember`, `AlertReason`, `AuditLog`; `MITREMapping.alert_id` |
| `backend/alembic/versions/9f3b2c7d4e81_chapter_12_alerts_and_lineage.py` | The migration (autogenerated against PostgreSQL, reviewed) |
| `backend/alembic/env.py`, `backend/app/main.py` | Register every entity; `/health` gains `alerts` and `database`; the engine pool is disposed at shutdown |
| `scripts/verify_chapter12.py` | PASS / WARN / FAIL over policy, lineage, alerts, explanations, demo, database, readout |
| `backend/tests/unit/test_ch12_alerts.py`, `backend/tests/integration/test_ch12_pipeline.py` | 26 tests (the Postgres one runs when `CIRA_TEST_DATABASE_URL` points at a database at head); the whole suite gives 352 passed, 1 skipped (the CERT sample test) |
| `backend/tests/unit/test_ch10_mitre.py` | Migration test now checks the chain instead of assuming Chapter 10 is the head |

The Bible names `correlation.py` and `deduplication.py`. The other modules keep label-free serving
code, the offline readout and the command-line runners apart, as Chapters 8 to 11 did. No dependency
was added.

The migration was generated with `alembic revision --autogenerate` against the local PostgreSQL at
`7c1e4a9d2b60` and reviewed. The one hand change puts `mitre_mappings.alert_id` inside
`batch_alter_table` so the same file runs on SQLite. On PostgreSQL: upgrade, `alembic check` (no
diff), downgrade and upgrade again all pass. On SQLite the unit test applies the whole chain and
compares it with the ORM (no diff).

### Run layout

`<CERT_PROCESSED_DIR>/alerts/chapter12/<alert_run_id>/`:

| File | Rows | Content |
|---|---|---|
| `alerts.parquet` | one per alert | span, peak, scores, context, signature, status, `duplicate_of`, run ids |
| `alert_members.parquet` | one per member day | alert key, triggers, scores, split tag, explanation status |
| `alert_reasons.parquet` | one per explanation item | section, subject, rule, value, weight, text, source |
| `explanations.jsonl` | one per member day | the full Chapter 11 explanation, with any KernelSHAP statistics |
| `demo_sample.parquet` | one per demo user-day | the D-6 sample keys |
| `alert_meta.json` | - | policy and hash, overrides, queue choice, demo record, lineage, summary, timings, peak RSS |
| `loads/load_<stamp>.json` | one per committed load | database (password hidden), counts per table |

Run ids end in `-alerts`. One `chapter12_alert_batch` runlog line per run (R8).

## How to run, step by step

From `backend/`, after Chapters 8 to 11 on the full profile (served batch, CRI calibration, enrichment
run, CRI run with ATT&CK context, explain run), with PostgreSQL up (`docker compose up -d postgres`).
Every Chapter 12 entry point needs the processed directory, either as `--processed-dir` or as
`CERT_PROCESSED_DIR` in the shell; the variable is read from the process environment, not from
`.env`. The verifier checks the database only when given `--database-url`, so that URL has to be in
the shell as well. `app.alerts.load` falls back to `DATABASE_URL` from `.env` on its own.

Bash:

```bash
export CERT_PROCESSED_DIR="$(realpath ../datasets/processed)"
export DATABASE_URL="$(grep '^DATABASE_URL=' ../.env | cut -d= -f2-)"
alembic upgrade head                                            # 9f3b2c7d4e81: the Chapter 12 tables
python -m app.alerts.batch --profile full                       # alerts, explanations, demo sample to Parquet
python ../scripts/verify_chapter12.py --profile full --no-readout
python -m app.alerts.load --profile full                        # one transaction into DATABASE_URL
python ../scripts/verify_chapter12.py --profile full --no-readout --database-url "$DATABASE_URL"
python -m app.alerts.evaluate --profile full                    # validation readout, once (reads labels)
python ../scripts/verify_chapter12.py --profile full --database-url "$DATABASE_URL"
```

PowerShell (Windows):

```powershell
$env:CERT_PROCESSED_DIR = (Resolve-Path ..\datasets\processed).Path
$env:DATABASE_URL = ((Get-Content ..\.env | Select-String '^DATABASE_URL=').Line -replace '^DATABASE_URL=', '')
alembic upgrade head
python -m app.alerts.batch --profile full
python ..\scripts\verify_chapter12.py --profile full --no-readout
python -m app.alerts.load --profile full
python ..\scripts\verify_chapter12.py --profile full --no-readout --database-url $env:DATABASE_URL
python -m app.alerts.evaluate --profile full
python ..\scripts\verify_chapter12.py --profile full --database-url $env:DATABASE_URL
```

After each step, `$LASTEXITCODE` (PowerShell) or `$?` (bash) is 0 on success; the load exits 2 when
it refuses and 3 when nothing was stored.

The batch uses the newest explain run for the profile unless `--explain-run-id` is given. `--rows
all` includes the served model's training users (they take top-k slots and are in-sample, so the
default leaves them out, C12-5). Policy flags (`--band`, `--top-k-per-day`, `--ordering`,
`--gap-days`, `--max-span-days`, `--cooldown-days`, `--allow-inactive-top-k`) and demo flags are
recorded as overrides. Only full is reportable (N6).

Expected cost on the development machine is not measured yet. An estimate from known sizes: the
evaluation rows are the validation and test users of the 464,687 user-days, the daily top-1 gives at
most one triggered day per calendar day (about 500), and band days are unknown until the run. With
roughly 70 events per user-day (32.8M events over 464,687 user-days), a few thousand member and demo
days means a few hundred thousand events at most, under the 500,000 guard. The runlog lines record
wall-clock and peak RSS, and the first real run replaces this paragraph.

## Verification

`scripts/verify_chapter12.py` recomputes everything it can from the source runs, label-free, and
compares it with what was stored:

- policy: `c12-alert-policy-v1` with a hash that reproduces; overrides (WARN); the queue choice
  recorded with its reason.
- lineage: served model, explain run, batch, CRI run and matrix agree now; no label column in any
  output; the CRI run carries ATT&CK context (WARN).
- alerts: triggers, alerts, spans, peaks, statuses, suppressions and members all reproduce from the
  risk run; every triggered day is in exactly one alert with one peak; gap and span rules hold; every
  suppressed alert repeats an open alert of the same user inside the cooldown with a covered,
  non-empty signature; no alert from training users (WARN); only served scores; the N52 count is
  reported.
- explanations: one per member day, each byte-for-byte equal to a fresh build through the Chapter 11
  builder; a deferred one carries its reason; no explanation deferred (WARN); model factors only from
  the served model; no generic statement; every `indicated` ATT&CK match worded as a visit;
  `alert_reasons` equal to the explanations; no KernelSHAP value stored as a reason; no CRI point or
  ATT&CK match stored as a model reason.
- demo: validation or test users only; the rule reproduces the sample; at most 5,000 user-days.
- database (with `--database-url`): a load record and its audit row; alert, member and reason counts
  equal the run; every member traces alert → risk score → anomaly score → feature vector → model
  version, with the run ids the alert names; risk and anomaly rows hold the same score; only served
  scores; every member day has its source events (WARN); ATT&CK rows of member days linked to an
  alert (WARN); policy and demo rule in `configurations`; artifact sha256s on the model version row.
- readout: validation only; of this alert run; both orderings read; every guard warning as a WARN.

Tampering is caught: the integration test flips one stored alert's severity and the verifier FAILs
on "alerts, spans, peaks and statuses reproduce". A readout written for an earlier alert run also
FAILs ("readout is of this alert run").

On the synthetic chain, following the steps above against the local PostgreSQL 16 from an empty
database: 36 PASS before the load, 50 PASS with the database checks, and 53 PASS, 1 WARN, 0 FAIL with
the readout. The WARN is the guard noting that the band trigger never fired on validation: the toy
CRI never reaches HIGH, so on this data the policy is top-k only.

## The validation readout

`python -m app.alerts.evaluate` is the only Chapter 12 module that reads labels, in memory, through
`app.evaluation`. Validation only (`--part test` is refused), written once (`--supersede "<reason>"`
keeps the old one inside). For the policy as built and for the same policy with the other ordering
(recomputed from the same risk run) it reports open alerts and alerts per day, alert precision,
malicious days in open alerts per scenario, insiders caught per scenario with latency, member days by
trigger, false-alarm alerts by top factor with the `usb_disconnect_count` count (N52), malicious days
that sit only in suppressed alerts, and insiders whose only alerts were suppressed. Masquerade
account-days are neither a hit nor a false alarm (N1).

Guard `c12-alert-guard-v1` WARNs, and never changes the policy, when a malicious validation day is
only in suppressed alerts, when the band trigger never fires on validation, or when an open alert's
peak explanation is deferred.

One limitation is built in. The daily top-1 ranks validation and test users together, because the
queue an analyst sees is not split by the model's training split. A validation alert therefore
depends on test users' scores on the same day, and the readout says so in its caveats.

## Carry-forward compliance

| Note | How Chapter 12 satisfies it |
|---|---|
| N1 | Masquerade account-days are counted as excluded in the readout, neither hit nor false alarm |
| N4 | Feature vectors stored with nulls as null |
| N5 | Serving modules statically checked label-free (including `evaluation.metrics`); only `evaluate.py` reads labels, in memory |
| N6, N8 | Only full is reportable; thread caps first in every entry point; events read month by month and bounded; RSS logged |
| N21 | The load verifies the registry entry by sha256 and stores the digests on `model_versions` |
| N28, N30 | Batch, load and `/health` refuse or report an alert run for a model that is not served now |
| N31 | Default rows exclude training users; demo sample from validation and test users only; verifier WARNs on any training-user alert |
| N32 | Only served rows ranked; `anomaly_scores.role = 'served'` is a check constraint |
| N33 | The CRI run must be the default variant of the same batch and model_version |
| N34 | Queue score and CRI kept as two values; risk rows point at, and equal, their anomaly score; never recomputed |
| N35 | Unavailable components stay listed as unavailable in every explanation |
| N39 | Band and top-k recorded per member day and reported separately |
| N40, N46 | Queue ordering chosen explicitly and recorded as validation-informed; both orderings reported |
| N42, N45 | Techniques are alert context and part of the dedup signature; never a model reason |
| N47, N48 | Explanations from stored TreeSHAP that adds up; KernelSHAP only as member-row statistics |
| N50 | `alert_reasons` from `build_explanation` for every member day, section and source kept; deferred status with reason; no run mixing |
| N52 | Batch summary and readout count alerts led by `usb_disconnect_count` |

## Deviation register additions

| Id | What | Status |
|---|---|---|
| C12-1 | An alert correlates user-days, not individual events; events attach through feature vectors (CERT is scored per user-day, Chapter 5) | Applied |
| C12-2 | Queue ordered by the served anomaly score with the CRI as context; validation-informed (N40, N46) | Applied |
| C12-3 | `alert_members` added: §20 has no membership entity, and correlation needs one | Applied |
| C12-4 | `require_activity`: an idle user-day cannot take a daily top-k slot; found on the synthetic chain, no CERT number | Applied |
| C12-5 | Default alert population is the served model's validation and test users (`--rows evaluation`); training users are in-sample (N31) | Applied |
| C12-6 | Indexes created with the tables, not after the bulk load as HCEA §12 suggests; the load is bounded (D-6) | Applied |
| C12-7 | Chunked `executemany` instead of `COPY`; one dialect-neutral path for asyncpg, psycopg and SQLite | Applied |
| C12-8 | `alert_reasons` has a fourth section, `model_lowering`, next to N50's three | Applied |
| C12-9 | Suppressed alerts are persisted with `duplicate_of`, not dropped | Applied |
| C12-10 | `/health` gains `alerts` and `database` blocks; top-level status keeps its Chapter 8 meaning | Applied |
| C12-11 | `mitre_mappings.alert_id` holds the first alert that covers a day; the canonical link is through the member's user-day | Applied |
| C12-12 | The policy and demo rule are recorded in the existing `configurations` table, write-once per key | Applied |
| C12-13 | The API's alert runtime follows the served model's profile; `CIRA_PROFILE` (the batch budget, `dev` on the development machine) is only the fallback. Found at the first `/health` check on CERT full | Applied |

## Synthetic results (not results)

On the synthetic chain (about 32 users over two months, a toy XGBoost), the batch ranked 785
validation and test user-days: 45 triggered (all by the daily top-1, none by the band), which became
36 open and 5 suppressed alerts, 33 of them one day long. The load wrote 325 feature vectors, 3,298
events, 41 alerts, 45 members, 230 reason rows and 463 ATT&CK rows in under a second. The readout
found 7 of 19 open validation alerts containing a malicious day, with both orderings. These numbers
show that the plumbing works. They say nothing about CERT.

## Before reporting anything

- The CERT numbers are in `docs/audits/chapter_12_audit.md`, for alert run
  `20261001T062628Z-full-alerts` and policy hash `21cd9391fd48`. Validation only, one seed.
- Alert precision, insiders caught and alerts per day from the readout are validation numbers, one
  seed, and depend on the policy. Quote them with the policy hash and served model, per scenario
  (N15), with both orderings (N55).
- Alert counts undercount what the model flagged, because suppressed alerts leave the queue. Quote
  the suppressed count and the malicious days that sit only in suppressed alerts next to them (N57).

## Acceptance checklist

Bible Chapter 12:

- [x] A cluster of related synthetic events produces exactly one correlated `Alert`, not four separate
  ones (`test_related_days_become_one_alert_not_four`)
- [x] Every persisted `Alert` can be traced back through the full lineage chain to its source events
  (verifier database section; synthetic chain on PostgreSQL 16)
- [x] A simulated DB outage during alert write fails safely and visibly, not silently (mid-load error
  rolled back on PostgreSQL; refused connection reports NOT STORED, exit 3, no load record)

HCEA §12 / D-6:

- [x] EventLog, FeatureVector, AnomalyScore and RiskScore hold alert-linked rows plus the deterministic
  demo sample only; the full set stays in Parquet
- [x] The demo sample's selection rule is recorded in configuration

Real runs (N54):

- [x] `alembic upgrade head` on the development machine's PostgreSQL
- [x] full alert batch verified with 0 FAIL (`--no-readout`): 36 PASS
- [x] load stored, verifier 0 FAIL with `--database-url`: 50 PASS
- [x] validation readout written once, verifier 0 FAIL again: 53 PASS, 2 WARN (explained in the audit)
- [x] `/health` shows `alerts` loaded and `database` reachable (alerts after the C12-13 fix)
- [x] `docs/audits/chapter_12_audit.md` written from those runs, every WARN explained
