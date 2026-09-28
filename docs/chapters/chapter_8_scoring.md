# Chapter 8: anomaly scoring and serving

Bible Chapter 8 / Architecture Phase 5, executed under HCEA v1.0 §8.

Status: IMPLEMENTED (28 September 2026). Verified on CERT r4.2 with 0 FAIL; the runs, the decision and
every WARN are in `docs/audits/chapter_8_audit.md`. Served model: gbdt
v0003 (`gbdt-chapter8-v1-077a3dae6cee`), recorded in
`experiments/chapter8_serving_decision.json`. Reported runs: `experiments/chapter8_reference_runs.json`.

## The question this chapter had to answer

The Bible says Chapter 8 serves "the versioned TabNet model". Chapter 7 then
reported that TabNet ranks insiders clearly worse than XGBoost, and handed
the choice of served model to this chapter (N26). The Chapter 7 numbers,
primary view, from `docs/audits/chapter_7_audit.md`:

| Split | Validation TabNet | Validation XGBoost | Test TabNet | Test XGBoost |
|---|---|---|---|---|
| full / user | 0.749 | not reviewed in Chapter 7 | 0.359 | 0.828 |
| mid / user | 0.734 | 0.923 | 0.220 | 0.843 |
| mid / time | 0.947 | 0.989 | 0.888 | 0.991 |

Most of the gap is scenario 2. At full top-1, TabNet puts 86 of 170
scenario-2 test days in the daily top alert against 125 for XGBoost. On
scenario 1 TabNet does as well or better (12/16 days against 9/16). Neither
model's scenario-3 result means much with 4 test days (N15).

Reading those numbers as "XGBoost is the better model" has two problems.

1. **The two models did not see the same inputs.** The adopted TabNet is
   behaviour-only (N25). The Chapter 6 XGBoost was trained on every
   Chapter 5 column, including the five psychometric scores and
   `peer_department_size`. Its top 10 by gain held no static trait, but
   the models still differ in more than architecture. The TabNet ablation
   suggests static traits do not explain the gap (TabNet with them scored
   lower on validation, 0.639), but that was measured on TabNet, not on
   XGBoost.
2. **The Chapter 6 XGBoost cannot be served as it stands.** It was saved
   under `models/saved_models/baselines/<run_id>/gbdt/` with no registry
   entry and no sha256 record, so it fails N21. Serving it would also score
   people partly on a personality test, which no analyst-facing reason
   could honestly explain (N22).

So Chapter 8 does two things before it serves anything. It trains one
behaviour-only XGBoost, registered like TabNet, as the second candidate
(C8-2). Then it chooses between the two with a rule written down before
that XGBoost existed.

## The serving rule (c8-serving-rule-v1)

Written into this document and into `app/scoring/select.py` before any
behaviour-only XGBoost was trained. `select.py` applies it mechanically,
copies it into the decision file, and the verifier fails a decision whose
rule differs from the code.

**Candidates.** Each candidate has one run per profile/split, scored on
identical validation rows:

- the adopted TabNet, from `experiments/chapter7_reference_runs.json`;
- the behaviour-only XGBoost, from `app.scoring.gbdt_candidate`.

**Gates.** Each gate applies to the full-profile artifact that would be
served. A candidate that fails any gate cannot be served:

- registered, with every file's sha256 verified (N21);
- reportable (N6);
- trained on the full profile;
- no static per-user trait among its inputs (N25).

**Criterion.** Validation PR-AUC, primary view (N1, N2). Let d be the
XGBoost PR-AUC minus the TabNet PR-AUC on full / user validation. XGBoost
is served only if both of these hold:

- d is greater than 0.10;
- XGBoost is also ahead on mid / user and mid / time validation.

Otherwise TabNet is served. The candidate not served becomes the shadow
model.

**Why TabNet is the default.** The Bible names it the primary model, and
Chapter 11 is planned around its masks. The project should not drift away
from its own design on a small or inconsistent difference, so the burden of
proof sits with the deviation.

**Why 0.10.** It is the epoch-to-epoch swing of TabNet's validation PR-AUC
measured in Chapter 7. The static-trait ablation used the same threshold.
A smaller gap cannot be told apart from TabNet's model-selection noise.

**Why validation, and why that is conservative.** Test is looked at once
per model (N11). TabNet's validation numbers are optimistic, because early
stopping keeps a noisy peak (mid: 0.734 on validation, 0.220 on test). The
criterion therefore leans towards TabNet, and an XGBoost win under this rule
is not an artefact of that optimism.

**Why three splits.** full / user is the reported profile and the model
that would be served. The mid splits guard against a full-profile result
that one seed or one split happens to favour. The mid / time gap was only
0.04 in Chapter 7; the rule asks only that XGBoost be ahead there, not
ahead by the margin.

The rule can go either way. The deciding number is the behaviour-only
XGBoost's full / user validation PR-AUC, which does not exist yet. For the
record, `select.py` also computes the Chapter 6 all-features XGBoost on the
same validation rows (`gbdt_ch6_all_feat`). It is a reference row, never a
candidate, and it shows how much the static traits were worth to XGBoost.

### What each outcome means downstream

| | TabNet served | XGBoost served (C8-1) |
|---|---|---|
| CRI (Chapter 9) | consumes TabNet's score | consumes XGBoost's score; thresholds are tied to that model_version (N29) |
| Explanations (Chapter 11) | TabNet masks primary, KernelSHAP corroborating, as planned | TreeSHAP on XGBoost (`shap` is already in the stack, exact and cheap for trees). TabNet masks may not be shown as the reason for an XGBoost score (N30) |
| Write-up | TabNet served; XGBoost reported as the stronger ranker, in shadow | TabNet built, evaluated and kept in shadow; the served detector is XGBoost; the case for TabNet rests on its masks (N23) |
| Bible deviation | none | C8-1, recorded in the decision file |

### Options not taken

**An ensemble of the two models.** Averaging their scores was never
evaluated on validation. Choosing one would mean designing and tuning a
third model after both have been read on test. `service.py` does not
combine scores (C8-4).

**Serving the Chapter 6 XGBoost.** It fails N21 and uses static traits,
as described above.

**Tuning TabNet until it catches up.** N23 forbids tuning on test, and the
HCEA §7.6 budget of 12 configurations is for honest search, not for closing
a known gap. Chapter 16 still runs several seeds per model.

## What was built

| Path | Purpose |
|---|---|
| `backend/app/scoring/contracts.py` | Score contract, the three errors, input validation, `ModelPin` (refuses "latest") |
| `backend/app/scoring/gbdt_model.py` | `BehaviourGBDTDetector`: Chapter 6 XGBoost settings, `sigmoid(margin)` score, `gbdt-chapter8-v1-*` versions |
| `backend/app/scoring/adapters.py` | Loads a pinned registry version of either model, sha256-verified, on CPU; refuses unreportable models |
| `backend/app/scoring/serving_config.py` | Served model from the decision file, or from `CIRA_SERVED_MODEL` for rollback |
| `backend/app/scoring/service.py` | `AnomalyScoringService`: `score_frame`, `score_event`, `status`; served and shadow roles |
| `backend/app/scoring/batch.py` | `python -m app.scoring.batch`: every user-day to Parquet with lineage and in-sample tags |
| `backend/app/scoring/gbdt_candidate.py` | Offline: trains and registers the behaviour-only XGBoost |
| `backend/app/scoring/select.py` | Offline: applies the rule on validation, writes the decision; one test readout afterwards |
| `backend/app/main.py` | Lifespan handler loads the served model once; `/health` reports it |
| `scripts/verify_chapter8.py` | PASS / WARN / FAIL over candidate, decision, served model and batch |
| `scripts/signoff_chapter8.py` | The whole real-data sequence in one resumable command, the audit draft, `--finalize` |
| `backend/tests/unit/test_ch8_scoring.py`, `test_ch8_selection.py`, `backend/tests/integration/test_ch8_pipeline.py`, `test_ch8_signoff.py` | 44 tests |

`app/scoring/` is not in the Bible §2 tree (C8-5). The tree names no module
for Chapter 8, and the scoring service is model-agnostic, so it fits in
neither `tabnet/` nor `baselines/`. It is the domain module that
Chapter 13's `services/` layer will call, the way `cri/` and `mitre/` will
be. No technology was added: XGBoost, torch, pytorch-tabnet and FastAPI
were already in `backend/requirements.txt`.

The package is split into two groups.

- **Serving modules:** contracts, gbdt_model, adapters, serving_config,
  service and batch. They never import label code, `evaluation.compare`
  or an offline module; a unit test checks this statically (N5).
- **Offline modules:** gbdt_candidate and select. They join labels in
  memory, like `app.tabnet.train`.

## Score contract

```text
raw_score     = the model's margin (TabNet: logit(malicious) - logit(benign); XGBoost: log-odds)
anomaly_score = sigmoid(raw_score), float64, in [0, 1], higher = more anomalous
```

This is the Chapter 7 convention (N10, C7-3) applied to both models. For
XGBoost it equals `predict_proba` up to float32 rounding, without the ties
at 1.0 that a float32 probability produces (C8-3). Both models were trained
with a positive weight of negatives / positives, so both scores are ranking
scores, not probabilities of malice (N20).

Every score carries its lineage: `model_name`, `model_version` (hash of
config and seed), `registry_version` (the verified artifact) and `role`.
Batch rows also carry `model_split` and `batch_run_id` (Architecture §37).
The anomaly score is never the CRI score (§14); nothing in this package adds
context.

Input policy:

- a feature vector carries raw Chapter 5 columns by name;
- extra columns are ignored;
- a missing column is an error, never imputed at serving time;
- a null is allowed, because Chapter 5 nulls are deliberate (N4) and each
  model handles them as it was trained to;
- infinite and non-numeric values are errors.

## Failure modes (Architecture §36)

| Situation | Behaviour |
|---|---|
| No decision file and no env pin | Service starts unavailable with the reason; `/health` says `degraded`; the batch job exits 2 and writes nothing |
| Pin does not resolve, artifact tampered, dev-profile model | `ScoringUnavailableError` at load; same as above |
| Model raises, or returns NaN, inf or a wrong shape | `ScoringFailedError`; no partial or default score |
| Missing column, inf, non-numeric value | `ScoringInputError` |
| Shadow fails to load or score | Served scoring continues unchanged; the failure is counted in `status()` and the batch meta |
| Split file changed since training | Batch refuses: the in-sample tags would be wrong |
| Feature `pipeline_version` differs from training | Batch refuses unless `--allow-schema-change`, which is logged |

There is no fallback model and no "latest". A served model is always a
pinned `vNNNN` (N21).

## Batch scoring (HCEA §8)

`python -m app.scoring.batch --profile full [--with-shadow] [--rows evaluation]`
scores the matrix in chunks of 100,000 rows. It writes
`<processed>/scores/chapter8/<batch_run_id>/anomaly_scores.parquet` and
`batch_meta.json` atomically, and appends one `chapter8_batch_scoring`
runlog line. It reads no labels and computes no metrics.

Each row's `model_split` is the split the served model put that user in.
It comes from the split file named in the model's registry entry, after the
file's sha256 is checked. `train` rows are in-sample: the model saw their
labels. They are scored, because Chapter 12's demo and the dashboard need a
continuous timeline, but a detection claim or a demo alert must never come
from them (N31). Use `--rows evaluation` for a file without them.

Loading into PostgreSQL is not done here. The `AnomalyScore` entity is
created in Chapter 12, which does the bounded load from this Parquet
(HCEA §12, D-6; C8-6).

## API startup (HCEA §8)

`app.main` loads the service once, in the lifespan handler, on CPU, and
stores it on `app.state.scoring`. A failed load does not stop the API.
`/health` returns `anomaly_model` (status, served and shadow model,
source, rule version, reason when unavailable), and the top-level status
becomes `degraded` when no model is loaded (C8-7). Chapter 13 adds the
scoring routes on top of `app.state.scoring`. This chapter adds none.

## Sign-off: one command

From `backend/`:

```bash
python ../scripts/signoff_chapter8.py
```

It loads the repository `.env` for any variable not already set, then runs
the sequence below. Each heavy step runs in its own process, one at a time.
It stops at the first FAIL with the reason. Run it again after a fix:
finished steps are skipped, test is never read twice, and nothing that exists
is overwritten. The output of every step is kept in
`experiments/results/chapter8/signoff_logs/`.

| Step | What |
|---|---|
| 0 | Preflight: env, feature files, labels, split files, Chapter 6/7 reference score files, TabNet v0003-v0005 sha256 |
| 1 | The full pytest suite must pass (`--skip-tests` to skip) |
| 2 | The three XGBoost candidates. mid / time uses the dates stored in the Chapter 7 mid / time registry entry, so both models are scored on the same rows |
| 3 | Each candidate verified with `--permutation-test`, 0 FAIL |
| 4-5 | The decision on validation, then the single test readout |
| 6-7 | Full batch scoring with shadow; the final verification, 0 FAIL |
| 8 | The FastAPI app starts in-process and `/health` must report the decided model on CPU |
| 9 | `experiments/chapter8_reference_runs.json` and the audit draft `docs/audits/chapter_8_audit.md` |

The audit draft contains only numbers copied from the output files. Each WARN
becomes a `TO EXPLAIN` line. Replace each one with the reason that WARN is
acceptable, then run:

```bash
python ../scripts/signoff_chapter8.py --finalize
```

`--finalize` refuses while any `TO EXPLAIN` remains. It then:

- retires N27;
- sets the README row and this document's status to IMPLEMENTED, naming
  the served model;
- ticks the real-run checklist;
- prints the `git add` / `git commit` to use.

If a text anchor it expects has been edited, it names that file instead of
guessing.

`CIRA_SERVED_MODEL` is ignored during the sign-off, which always serves the
recorded decision.

## How to run, step by step

The same sequence by hand, from `backend/`, with `.env` pointing at the
dataset. Steps 1-3 train; nothing is served before step 4.

```bash
# 1. behaviour-only XGBoost candidates (each prints its run id and registry version)
python -m app.scoring.gbdt_candidate --profile mid
python -m app.scoring.gbdt_candidate --profile mid --split time
python -m app.scoring.gbdt_candidate --profile full

# 2. verify each candidate before its numbers are used
python ../scripts/verify_chapter8.py --profile mid  --candidate-run-id <mid user run>  --permutation-test --no-decision
python ../scripts/verify_chapter8.py --profile mid  --candidate-run-id <mid time run>  --permutation-test --no-decision
python ../scripts/verify_chapter8.py --profile full --candidate-run-id <full user run> --permutation-test --no-decision

# 3. decide on validation (writes experiments/chapter8_serving_decision.json; commit it)
python -m app.scoring.select --gbdt full/user=<run> --gbdt mid/user=<run> --gbdt mid/time=<run>

# 4. read test once, for the write-up (refuses before the decision, and a second time)
python -m app.scoring.select --report-test

# 5. batch scoring with the decided model
python -m app.scoring.batch --profile full --with-shadow

# 6. verify decision, served model and batch
python ../scripts/verify_chapter8.py --profile full --candidate-run-id <full user run>

# 7. API: start it, then check /health reports the decided model
uvicorn app.main:app
```

The candidate trains on CPU by default (C8-9), because the model is served
on CPU: the scores the decision is made on are then the scores that get
served. The candidate runner prints validation only (C7-9 practice). A decision is
made once: re-running `select` refuses while a decision exists, and
`--supersede "<reason>"` replaces it while keeping the old one inside the
new file. For a rollback without a new decision, set
`CIRA_SERVED_MODEL=tabnet:v0005` (or another pin). The status and the batch
runlog then say the pin came from the environment.

`--decisive` and `--consistency` exist only so the synthetic tests (one
profile) can run the whole chain. A decision made with them is marked
`split_keys_overridden`, and the verifier flags it with a WARN saying never
to report it.

## Verification

`scripts/verify_chapter8.py` runs four sections. "Reproduces" means
exact for a CPU-trained XGBoost reloaded on CPU, and within 1e-5 wherever
rows are re-scored in a different batch composition (C8-10). The detail
line always prints the actual maximum difference.

- **candidate:** checks each of these:
  - profile and N6 flag; static traits excluded, none among the inputs;
  - split loaded and unchanged; masquerade days dropped (N13);
  - `scale_pos_weight` equal to negatives / positives on the training
    rows; runlog line;
  - registry sha256; reload reproduces the stored scores exactly;
  - same rows and feature matrix as the Chapter 6 reference (N18);
  - optionally, three shuffled-label fits judged by Chapter 7's
    PASS/WARN/FAIL rule (C7-8), imported from `verify_chapter7.py` so
    there is one definition.
- **decision:** checks each of these:
  - the rule is unchanged from the code, decided on validation;
  - the served model is pinned and passed every gate, with C8-1 recorded
    when XGBoost is served;
  - the evidence reproduces from the score files, and the rule applied
    again gives the same answer;
  - test was read after the decision, and the decision is unchanged since
    (sha256); the test readout harness matches every logged test PR-AUC.
- **served:** checks each of these:
  - the service loads the decided model on CPU, behaviour-only;
  - the serving path reproduces the training-time scores exactly;
  - a tampered copy of the artifact is refused without a score.
- **batch:** checks each of these:
  - contract columns, no label columns, scores finite and in [0, 1];
  - one model version; one row per user-day and role;
  - every matrix row scored, with `model_split` tags matching the split;
  - batch scores equal the training-time scores on validation and test
    rows;
  - no saturated score, runlog line, peak RSS under the 10 GB target.

On the synthetic chain the verifier passes with one expected WARN (the
overridden split keys). The integration test also edits the rule's margin
in a copy of the decision file and confirms the verifier fails it.

## Carry-forward compliance

| Note | How Chapter 8 satisfies it |
|---|---|
| N1 masquerade | Decision evidence uses the primary view with masquerade days excluded; the candidate drops them from training (N13) |
| N2 imbalance | PR-AUC decides; ROC-AUC shown as secondary; no accuracy; `scale_pos_weight` from training rows only |
| N3, N11 split | Candidate loads the saved split; batch tags rows from the served model's own split file, hash-checked |
| N5 labels | Serving modules statically checked label-free; batch file holds no label column |
| N6 profiles | Unreportable models cannot be served; only a full-profile model passes the gates |
| N8 resources | Thread caps first in every entry point and in the lifespan handler; chunked batch; RSS in every runlog line |
| N9 signals | No new signal; the serving layer scores the Chapter 5 matrix only |
| N10, N20 score | One convention for both models; `model_version` on every row; a ranking score |
| N12 causal | Both models score a row from its own past and same-day features |
| N15 per scenario | Decision evidence records recall and insiders caught per scenario at top-1 |
| N17 budgets | Precision ceiling carried into the decision evidence |
| N18, N24 references | Chapter 6 and 7 reference runs used as they are; nothing retrained to compare |
| N21 registry | Both models load through the registry with sha256; pins only, never "latest" |
| N22, N25 static traits | Served candidates must be behaviour-only (gate) |
| N23, N26 | The choice is made by a rule fixed in advance, on validation, and recorded with its evidence |

## Deviation register additions

| Id | What | Status |
|---|---|---|
| C8-1 | Serve XGBoost instead of the Bible's TabNet, if and only if rule c8-serving-rule-v1 says so | Conditional; recorded in the decision file |
| C8-2 | A behaviour-only XGBoost trained and registered in Chapter 8 as the second candidate. The Chapter 6 reference run is unchanged and stays the baseline row (N18) | Applied |
| C8-3 | XGBoost score is `sigmoid(margin)` in float64 instead of float32 `predict_proba`, as C7-3 did for TabNet | Applied |
| C8-4 | No ensemble of the two models (never evaluated) | Scope decision |
| C8-5 | New package `backend/app/scoring/`, not in the Bible §2 tree | Applied, explained above |
| C8-6 | Bounded PostgreSQL load of scores left to Chapter 12, where `AnomalyScore` is created | Deferred |
| C8-7 | `/health` reports model status now (a small part of Bible Ch13 step 4) and says `degraded` without a model | Applied |
| C8-8 | Hidden `--decisive` / `--consistency` flags so the synthetic tests can run the chain; decisions made with them are marked and flagged | Tests only |
| C8-9 | The XGBoost candidate trains on CPU by default instead of `CIRA_DEVICE=auto` (HCEA R11: the GPU is optional except for the LSTM) | Applied |
| C8-10 | Re-scoring checks allow 1e-5 where the same rows are scored in a different batch composition. TabNet's float32 matmuls move by up to about 6e-6 on the score when rows are batched differently, measured on synthetic data; Chapter 7's own batch-composition test uses the same 1e-5. XGBoost's reload check stays exact when trained on CPU | Applied |

## Before reporting anything

- No Chapter 8 number exists yet. The synthetic tests prove the plumbing,
  nothing about CERT.
- Whatever is served, the write-up reports both candidates' validation and
  test numbers, per scenario, with the profile named.
- The decision rests on one seed per model. Chapter 16 adds seeds and
  bootstrap intervals (C6-2, C7-7).

## Acceptance checklist

Bible Chapter 8:

- [x] Scoring a batch of held-out feature vectors returns anomaly scores with the model version (synthetic)
- [x] A simulated model-load failure returns an explicit error, not a fabricated score (unit, integration, verifier)
- [x] Anomaly score and the future CRI score are in separate code paths (§14): nothing in `app/scoring/` combines or adds context
- [x] `score_event(feature_vector) -> anomaly_score in [0, 1]` with model version, callable from a batch job and from FastAPI (lifespan)

HCEA §8:

- [x] Loaded once at FastAPI startup (lifespan; unit test counts loads)
- [x] Served on CPU
- [x] Batch scoring to Parquet, no row-by-row HTTP inserts (Postgres load in Chapter 12, C8-6)
- [x] Explicit error, never a fabricated score
- [x] Every score carries its model version

Real runs (N27):

- [x] behaviour-only XGBoost at mid / user, mid / time and full / user, each verified with `--permutation-test`, 0 FAIL
- [x] decision written by `select` and committed
- [x] test readout written once
- [x] full batch run verified with 0 FAIL
- [x] `/health` shows the decided model on the development machine
- [x] `docs/audits/chapter_8_audit.md` written from those runs, every WARN explained
