# Chapter 11: explainability

Bible Chapter 11 / Architecture Phase 8 (§18), executed under HCEA v1.0 §11 (deviation D-5).

Status: IMPLEMENTED (30 September 2026). Verified on CERT r4.2 full with 0 FAIL; the runs, the
validation readout and both WARNs are in `docs/audits/chapter_11_audit.md`. Explain run
`20260930T190519Z-full-explain` (TreeSHAP on gbdt v0003). Reported run:
`experiments/chapter11_reference_runs.json`.

## Why this chapter does not follow the Bible's plan

The Bible assumed TabNet would be served. Its masks were going to be the primary explanation, with
KernelSHAP corroborating them. Chapter 8 served the behaviour-only XGBoost instead (gbdt v0003,
`gbdt-chapter8-v1-077a3dae6cee`, deviation C8-1) and kept TabNet v0005 in shadow. Two carry-forward
notes then decide the shape of this chapter:

- N30: an explanation comes from the model whose score produced the alert. For XGBoost that is
  TreeSHAP. TabNet's masks describe TabNet's attention; they are not a reason for an XGBoost score.
- N32: shadow output never feeds anything an analyst sees.

So the served-model explanation is exact TreeSHAP on XGBoost. The mask code exists and is tested. It
becomes the primary explanation automatically if TabNet is ever served (a `CIRA_SERVED_MODEL`
rollback), and it feeds one clearly labelled "second model's view" in the offline validation readout.
Chapter 8 wrote this down before any XGBoost was trained ("What each outcome means downstream").
This chapter carries it out.

This also changes what D-5 was protecting against. The HCEA budgeted SHAP carefully because
KernelSHAP on TabNet is expensive, and it relied on masks for coverage ("TabNet masks already cover
every row"). TreeSHAP on a tree model is exact and cheap, so it now provides that coverage: every
scored user-day is explained. KernelSHAP stays bounded, as D-5 requires, and becomes what the Bible
always called it: the corroborating signal.

## What an explanation contains

Architecture §18 asks for "why was this user-day considered risky?", answered from real outputs
only. Three things feed a risk decision in CIRA, and they are kept in three separate sections because
they mean different things.

| Section | Comes from | What it claims | What it does not claim |
|---|---|---|---|
| Model factors | TreeSHAP on the served XGBoost (log-odds, signed) | which of this user-day's values moved the model's score, and by how much | anything about intent |
| Contextual factors | CRI points per component (Chapter 9) | how much each context term added to the 0-100 CRI | that the model used them (N34) |
| ATT&CK context | Chapter 10 matches | what ATT&CK calls the observed behaviour, with its evidence grade | that the model scored the day because of it (N45) |

The plain-text layout follows §18:

```text
HIGH RISK
CRI 57.3 of 100; anomaly score 0.97000 from gbdt v0003 (a ranking score, not a probability)
Primary contributing factors (served model gbdt v0003, TreeSHAP):
1. Files copied to removable media: 14 (raised the score by +2.10 log-odds)
2. Removable-device connects compared with this user's own previous 30 days: 4.2 standard deviations above their usual level (raised the score by +1.20 log-odds)
3. Hour of the first logon or logoff: no value (no such activity that day) (raised the score by +0.40 log-odds)
Lowered the score most: emails sent, 2 (-0.30 log-odds)
Not shown as a reason: psychometric score: openness (static per-user trait; never a behavioural reason (N22))
Contextual factors (CRI points, not model reasons):
- Largest rise above the user's own previous 30 days: removable-device connects, 4.2 standard deviations above their usual level: 9.1 points
- ATT&CK context, listed below: 8.2 points
ATT&CK context (what ATT&CK calls the observed behaviour; not a reason the model scored this day):
- T1052.001 Exfiltration Over Physical Medium: Exfiltration over USB [Exfiltration]: Files copied to removable media: 14; observed: CERT records this action (rule R01_removable_media_copy)
- T1567 Exfiltration Over Web Service [Exfiltration]: Requests to leak or paste sites: 3; indicated: CERT records the visit, not what was sent or received (rule R02_leak_site_access)
- job_search: considered, no ATT&CK technique
Not available: asset criticality (CERT r4.2 has no asset inventory)
```

That is the builder's exact output for the unit-test fixture, not a CERT result (the fixture's
psychometric factor exists only to show the suppression). Things to notice in it:

- A value is taken from the raw Chapter 5 row (N22) and written in words. A null is described by
  what it means, never as 0 (N4). Factor 3 is a null that raised the score: XGBoost routes missing
  values down a learned branch, so "no logon that day" can itself be what the model reacted to.
  The explanation says exactly that rather than hiding it.
- The Bible's example list includes "New device observed" and "High-criticality asset accessed".
  The first appears only when the model's attributions actually put `new_device_count` or
  `new_device_flag` among the raising factors. The second never appears, because CERT r4.2 has no
  asset criticality; the component is listed under "Not available" (N35).
- A leak-site visit is worded as a visit. r4.2 records no upload, bytes or method (N9, N45).
- When nothing raised the score, the explanation says so instead of promoting the smallest
  contribution to a reason.

### Traceability is enforced, not described

Every factor carries a `source` naming exactly what produced it: the attribution (method,
model_version, feature, value, contribution), the CRI component (points, calibration, run) or the
ATT&CK match (rule, technique, triggering column and value). `validate_explanation` re-checks each
factor against its input, and `build_explanation` refuses to return anything that fails. It also
refuses:

- attributions from a model with `role != "served"` (N32);
- a risk row from another model_version, or one whose anomaly score differs from the attributions'
  ("one explanation, one score");
- a generic sentence such as "model predicted high risk" (§18);
- a model factor or context line that claims a signal CERT does not record (N9). The phrases are in
  `features.FORBIDDEN_PHRASES`;
- a static trait (psychometrics, department size) presented as a reason. It is moved to
  `suppressed` with the reason (N22). The served XGBoost has no static input (N25), so this is a
  guard, and the verifier reports any occurrence.

The verifier repeats the whole check for every written explanation against the stored attributions,
the risk run and the enrichment run.

## TreeSHAP on the served XGBoost

`shap_explainer.TreeShapExplainer` uses XGBoost's own TreeSHAP (`Booster.predict(pred_contribs=True)`),
the same path-dependent algorithm `shap.TreeExplainer` runs for a tree model without a background
set. The verifier cross-checks the two on 500 rows; on the synthetic model they agree exactly
(difference 0, shap 0.52, xgboost 3.4.1).

The contributions are in the model's margin units and must satisfy

```text
sum_j phi_j + expected_value = margin the served model produces for that row
```

That identity is checked on every row, against `adapter.raw_score`, with a tolerance of 1e-3
log-odds. A row that does not add up raises `ExplanationFailedError`. The batch also checks that the
margin it recomputes equals the Chapter 8 batch's stored `raw_score` (1e-4), so the explained score
is the one the CRI used.

One detail makes the check necessary. The served model early-stopped. The sklearn wrapper scores with
the best iteration, but a raw `Booster.predict` uses every tree unless it is told otherwise. On a
probe model with 106 inputs the contributions were off by 4.56 log-odds without the iteration range,
and by 1e-6 with it. The explainer sets `iteration_range = (0, best_iteration + 1)`, and a unit test
fails if that is ever dropped: it confirms the fixture model really stopped early, removes the range,
and expects the refusal.

Every user-day is explained in 50,000-row chunks (HCEA §11.1). Only the top 10 features per row by
absolute contribution are kept, in long format, never the dense matrix.

## KernelSHAP corroboration and the deletion check (D-5)

`KernelCorroborator` runs `shap.KernelExplainer` on the same margin function, only on the bounded
set below. Per row it reports:

- `top5_overlap`: Jaccard overlap of KernelSHAP's top five features with TreeSHAP's;
- `rank_correlation`: Spearman correlation of absolute values over the union of both top tens;
- `sign_agreement` on TreeSHAP's top five (null for masks, which have no sign);
- `kernel_additivity_error`: KernelSHAP's own additivity against the margin;
- a deletion check. Replace the row's top raising features (up to five, by the primary
  explanation) with background values and measure how far the margin falls, then do the same with as
  many features picked at random. If the explanation names what the model relied on, deleting those
  features should cost more.

Perfect agreement is not expected. KernelSHAP estimates interventional SHAP against a 50-row
background; TreeSHAP computes the path-dependent value. The verifier therefore WARNs, never FAILs,
on low agreement (median top-5 overlap below 0.4, or deletion beating random on fewer than 80% of
rows). A WARN is explained in the audit and never changes the explainer.

Two settings depart from D-5's literal text.

**Background (C11-2).** D-5 says `shap.kmeans(X_train, 50)`. XGBoost reads raw columns with native
nulls; `shap.kmeans` cannot take NaN, and a centroid would turn "no activity" into a fractional
count that routes differently through the trees. For XGBoost the background is 50 real training
user-days, drawn label-free from a user-stratified pool of 5,000 training rows. The training rows
come from the split file named in the served model's registry entry, sha256-checked through the
Chapter 8 helper, not from the Chapter 8 batch, which may have been run with `--rows evaluation`. For
TabNet (preprocessed, no nulls) `shap.kmeans` is used as D-5 says.

**nsamples (C11-3).** D-5 says 100, raised to 200 if unstable. The served model has 106 inputs, so
100 samples leave KernelSHAP's regression underdetermined. The default is shap's own "auto",
`2 * M + 2048` (2,260 for 106 inputs), and any value at or below M is refused. On XGBoost the cost is
small: about 0.16 s per row in the probe.

A KernelSHAP failure is recorded in the run meta and does not stop the batch: the TreeSHAP
explanations and the written reasons still stand, and the corroboration is retried later
(Architecture §36). Until Celery exists (Chapter 17) "later" means re-running the batch.

## The bounded set (`c11-selection-v1`)

D-5 limits KernelSHAP to "alert rows plus the dashboard's top-k". Alerts do not exist until Chapter
12, and Chapter 12 has not chosen the analyst-queue ordering. N40 and N46 say no ordering dominates
on validation, so this rule does not choose one either. A user-day is selected if any of these holds:

- its CRI severity is HIGH or CRITICAL (the band view, N39);
- it is in its day's top 1 by the served anomaly score;
- it is in its day's top 1 by the CRI score;

and it belongs to a validation or test user of the served model's split (N31: in-sample rows are
never examples). If the union exceeds `--max-bounded-rows` (default 300), test users are kept first
(N31 prefers them), then higher severity, CRI and anomaly score. The number cut is recorded, and the
verifier WARNs on any cut. Ties inside a day are broken by user_id. That is acceptable for picking
examples, and it is never used as a detection metric, where the evaluation harness keeps its seeded
tie-break.

For the bounded rows the batch writes the full analyst explanation to `reasons.jsonl`. Chapter 12
explains its own alert rows through the same code (N50).

## TabNet's masks: a second model's view, offline only

`tabnet_masks.TabNetMaskExplainer` calls `clf.explain` in 50,000-row chunks and normalises each row
to shares that sum to 1. It then sums each feature's value column and its `isnull__` indicator
(`app.tabnet.dataset.feature_groups`, N22, C7-5). A mask has no direction, so a mask factor is
written as "N% of the model's attention (TabNet mask: importance, not direction)", never as
"raised the score".

With XGBoost served, masks appear only in `evaluate.py`. The readout computes the shadow TabNet's
masks on the malicious validation days and reports, per scenario, the most frequent top mask feature
and the mean top-5 Jaccard overlap with XGBoost's TreeSHAP. The block is labelled "SECOND MODEL'S
VIEW (shadow TabNet masks); never shown to an analyst". Chapter 7 left the case for TabNet resting on
its masks (N23, N26), and Chapter 10 showed that TabNet finds scenario-1 days XGBoost misses (N46).
This view is where that case gets examined. It is one seed, on validation.

## The validation readout

`python -m app.explainability.evaluate` joins labels in memory, on the served model's validation
user-days only, and reports:

- for each scenario, the most frequent top raising factor on malicious days, the share led by a
  calendar column, and the domain mix of the top three factors;
- the same for false alarms: benign validation days in the served model's daily top-1 (seeded
  tie-break, masquerade account-days excluded, N1). This is what an analyst would read on a wrong
  alert;
- the second model's view above.

Guard `c11-explain-guard-v1` WARNs on any served explanation with a static trait in its top five, and
on any scenario whose most frequent top factor on malicious days is `day_of_week` or `is_weekend`. A
model that is right for calendar reasons is worth knowing about. A WARN is explained in the audit and
never changes the model, the explainer or a description. Validation only (`--part test` is refused);
written once, `--supersede "<reason>"` keeps the old readout inside.

## What was built

| Path | Purpose |
|---|---|
| `backend/app/explainability/features.py` | Plain-language label, kind and domain for all 112 Chapter 5 columns; value formatting; null meanings; forbidden phrases (N9) |
| `backend/app/explainability/attributions.py` | The `Attributions` contract, top-k long format, per-row summary, `explainer_for` (N30) |
| `backend/app/explainability/shap_explainer.py` | `TreeShapExplainer`, `KernelCorroborator`, deletion check, `shap.TreeExplainer` cross-check |
| `backend/app/explainability/tabnet_masks.py` | `TabNetMaskExplainer`: chunked, normalised, grouped masks |
| `backend/app/explainability/reason_builder.py` | `build_explanation`, `validate_explanation`, the §18 text |
| `backend/app/explainability/selection.py` | `c11-selection-v1` |
| `backend/app/explainability/sources.py` | Run layout, the default risk run, aligned reads |
| `backend/app/explainability/batch.py` | `python -m app.explainability.batch` |
| `backend/app/explainability/runtime.py` | `ExplainRuntime`: loaded at startup, `/health` block, `explain_event` for Chapter 13 |
| `backend/app/explainability/evaluate.py` | Offline validation readout and guard |
| `backend/app/main.py` | Lifespan builds the explainer for the served model; `/health` gains `explainability` |
| `scripts/verify_chapter11.py` | PASS / WARN / FAIL over describer, run, selection, KernelSHAP, reasons and readout |
| `backend/tests/unit/test_ch11_explainability.py`, `backend/tests/integration/test_ch11_pipeline.py` | 34 tests |

The Bible names `tabnet_masks.py`, `shap_explainer.py` and `reason_builder.py`. The others split
label-free serving code, the offline readout and the CLI runners apart, as Chapters 8 to 10 did
(C11-7). No dependency was added: `shap`, `xgboost` and `pytorch-tabnet` were already in
`requirements.txt`.

### Run layout

`<CERT_PROCESSED_DIR>/explanations/chapter11/<explain_run_id>/`:

| File | Rows | Content |
|---|---|---|
| `explanations.parquet` | one per scored user-day | method, margin, expected value, additivity error, top raising factor, static and calendar flags, lineage |
| `attributions.parquet` | up to 10 per user-day | feature, contribution, direction, raw value, static and calendar flags |
| `selection.parquet` | bounded set | which rule selected each row |
| `kernel_corroboration.parquet` | bounded set | agreement and deletion check |
| `reasons.jsonl` | bounded set | the full analyst explanation, structured and as text |
| `explain_meta.json` | - | served model, explainer settings, source batch, risk run, enrichment run, fingerprint, selection, KernelSHAP settings with background keys and split record, summary, timings, peak RSS |

Run ids end in `-explain`. One `chapter11_explain_batch` runlog line per run (R8).

## Failure modes (Architecture §36)

| Situation | Behaviour |
|---|---|
| No served model | Batch refuses; `/health` shows `explainability.status = unavailable` with the reason |
| A served model with no explainer, or an input without a written description | Runtime unavailable with the reason; batch refuses |
| Contributions that do not add up to the served margin | `ExplanationFailedError`; nothing is written from them |
| Chapter 8 batch scored by another model than the one served now (for example after a rollback) | Batch refuses: explanations come from the model that scored (N30) |
| Risk run from another batch or model_version; batch or risk run from another matrix | Batch refuses |
| KernelSHAP fails (no split file, shap error) | Recorded as `failed` with the reason; TreeSHAP and reasons still written; verifier WARNs |
| Explainer fails for one event in the API | Explanation returned with status `model_explanation_deferred` and the reason; score and context unchanged |
| A shadow model's attributions passed to the reason builder | Refused (N32) |

## How to run, step by step

From `backend/`, after Chapters 8 to 10 on the full profile (served batch, CRI calibration, CRI run
with MITRE):

```bash
python -m app.explainability.batch --profile full                  # every user-day + the bounded set
python ../scripts/verify_chapter11.py --profile full --no-readout
python -m app.explainability.evaluate --profile full               # validation readout, once (reads labels)
python ../scripts/verify_chapter11.py --profile full
```

`--no-kernel` skips KernelSHAP (TreeSHAP and reasons only). `--rows evaluation` skips the served
model's training users. `--max-bounded-rows`, `--select-top-k-per-day`, `--kernel-nsamples` and
`--n-background` are recorded in the meta. Only full is reportable (N6); a mid run is for debugging.

Expected cost on the development machine is not measured yet. TreeSHAP is XGBoost's multi-threaded
C++ path and the matrix is roughly 400,000 rows, so minutes rather than hours is the expectation;
the runlog line records wall-clock and peak RSS (R8), and the verifier checks RSS against 10 GB.

## Verification

`scripts/verify_chapter11.py` sections:

- **describe:** every input of the served model has a written description; every Chapter 5 column
  does (WARN); no description claims a signal CERT lacks; nulls are described by meaning.
- **run:** contract columns; no label column; explains the model served now with the explainer N30
  requires; no static input; source batch from the same model_version; same matrix; one row per
  scored user-day in batch order; every row adds up (<= 1e-3); stored margin equals the batch
  (<= 1e-4); split tags equal the batch; a recomputation on up to 2,000 sampled rows reproduces the
  stored top-k; TreeSHAP equals `shap.TreeExplainer` on 500 rows (WARN if shap cannot parse the
  model); no static trait in any top five; calendar-led share (WARN at 0.5 or above); runlog; RSS.
- **selection:** validation or test only; the rule reproduces the set from the risk run; nothing
  cut (WARN).
- **kernel:** ran; one row per bounded user-day; nsamples above the input count; background from the
  served model's training users only; additivity, agreement and deletion (WARN only).
- **reasons:** one per bounded row; every factor, point and match re-checked; no generic statement;
  model factors only from the served model; no static trait; CRI and ATT&CK never listed as model
  factors; every `indicated` match worded as a visit.
- **readout:** validation only; of this run; the second model's view present and labelled (WARN);
  every guard warning as a WARN.

On CERT full: 45 PASS, 2 WARN (the bounded-set cap and KernelSHAP agreement, both explained in the
audit), 0 FAIL. On the synthetic chain: 46 PASS, 1 WARN (the bounded set is capped at 40 rows in the test, so 47
candidates were cut), 0 FAIL. The synthetic XGBoost early-stops almost immediately and leans on one
feature, so its KernelSHAP agreement (median overlap 1.0) says nothing about CERT. Those are numbers
from a toy model that show the plumbing works, not results.

## Carry-forward compliance

| Note | How Chapter 11 satisfies it |
|---|---|
| N4 nulls | A null is described by its Chapter 5 meaning; XGBoost's native null routing is explained as it is |
| N5 labels | Serving modules statically checked label-free; only `evaluate.py` reads labels, in memory |
| N6 profiles | Only full is reportable; every run logs `reportable` |
| N8 resources | Thread caps first in every entry point; 50,000-row chunks; top-k only; RSS logged and checked |
| N9 signals | Forbidden phrases checked in every description and every model or context line |
| N20, N34 | The score is "a ranking score, not a probability"; CRI points are a separate section |
| N21, N28 | The explainer is built from the pinned, sha256-verified served adapter |
| N22 | Values from the raw row; TabNet value and indicator grouped; static traits suppressed and reported |
| N25 | Verifier FAILs if the served model has a static input |
| N30 | TreeSHAP for XGBoost; masks only for a served TabNet; the batch refuses a batch from another model |
| N31 | Bounded set and examples from validation or test users only; test preferred |
| N32 | No shadow explanation reaches `reasons.jsonl` or the API; masks only in the labelled readout view |
| N35 | Unavailable components listed as not available with their reason, never filled in |
| N39, N40, N46 | The bounded set uses the band view and both daily orderings; it does not choose a queue |
| N41, N45 | ATT&CK in its own section with rule, column, value and grade; `indicated` worded as a visit |

## Deviation register additions

| Id | What | Status |
|---|---|---|
| C11-1 | The served-model explanation is TreeSHAP on XGBoost, not TabNet masks (follows C8-1, N30); masks become primary only if TabNet is served, and otherwise appear only in the offline readout (N32) | Applied |
| C11-2 | KernelSHAP background for XGBoost: 50 real training user-days from a user-stratified pool, not `shap.kmeans` (nulls); kmeans kept for TabNet | Applied |
| C11-3 | KernelSHAP nsamples `2 * M + 2048` instead of 100; values at or below M refused | Applied |
| C11-4 | TreeSHAP computed by XGBoost's `pred_contribs` with the early-stopping iteration range; `shap.TreeExplainer` is the verifier's cross-check | Applied |
| C11-5 | Explanations persisted to Parquet and `reasons.jsonl`; `AlertReason` rows are Chapter 12's job (bounded, D-6) | Deferred |
| C11-6 | KernelSHAP runs on a label-free bounded set (`c11-selection-v1`) because alerts do not exist yet | Applied |
| C11-7 | Modules beyond the Bible's three (see "What was built") | Applied |
| C11-8 | `/health` gains an `explainability` block; top-level status keeps its Chapter 8 meaning | Applied |
| C11-9 | A label-free deletion check added next to KernelSHAP as a faithfulness test | Applied |
| C11-10 | The Bible's example factor "High-criticality asset accessed" is never produced: CERT r4.2 has no asset criticality (N35) | Recorded |

## First real readout (full / user validation)

From `experiments/chapter11_validation_readout.json`; the audit has the full record.

- Every one of the 464,687 user-days adds up to the served margin (max error 3.9e-05 log-odds), and
  TreeSHAP equals `shap.TreeExplainer` exactly. The whole run took 243 s with a 2.6 GB peak.
- Scenario 1: leak-site visits lead 15 of 19 malicious days; partly by construction (N41), and the
  served model still ranks only 7 of them at the daily top-1 (N46).
- Scenario 2: web volume above peers leads 114 of 179 days; job-search visits never lead one.
- False alarms: `usb_disconnect_count` leads 192 of 366 benign top-1 days (N52).
- KernelSHAP agrees with TreeSHAP on a median of one feature in five, but deleting TreeSHAP's top
  raising features lowers the margin more than random ones on 300 of 300 rows (N48).
- The shadow TabNet explains the same malicious days with almost disjoint features (mean top-5
  Jaccard 0.05 to 0.16), led by off-hours USB activity and, on 31 scenario-2 days, `is_weekend` (N53).

## Before reporting anything

- Explanation statistics from the readout are validation numbers, one seed. Quote them with the
  served model named and per scenario (N15). A top factor that matches a public scenario description
  is partly by construction of the dataset (N41).
- KernelSHAP agreement describes how two SHAP estimators agree on the bounded set. It is not a
  detection result and not evidence that an explanation is "correct".

## Acceptance checklist

Bible Chapter 11:

- [x] A sample alert produces a reason list traceable to real model attributions, CRI factors and
  ATT&CK matches (TreeSHAP on the served model per N30; TabNet masks in the labelled second-model
  view; synthetic)
- [x] No generic explanation strings (enforced by `validate_explanation` and the verifier)
- [x] SHAP failure degrades gracefully: the alert keeps its score and context, and the explanation or
  corroboration is marked deferred or failed with the reason

HCEA §11 / D-5:

- [x] Masks computed in chunks, top-k persisted, never the dense matrix
- [x] KernelSHAP bounded, with a small background and recorded nsamples (C11-2, C11-3)

Real runs (N49):

- [x] full explain run verified with 0 FAIL (`--no-readout`)
- [x] validation readout written once, verifier 0 FAIL again
- [x] `/health` shows the `explainability` block loaded on the development machine
- [x] `docs/audits/chapter_11_audit.md` written from those runs, every WARN explained
