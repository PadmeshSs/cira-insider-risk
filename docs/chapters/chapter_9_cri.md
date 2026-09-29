# Chapter 9: Contextual Risk Intelligence (CRI)

Bible Chapter 9 / Architecture Phase 6 (§15), executed under HCEA v1.0 §9.

Status: IMPLEMENTED (29 September 2026). Verified on CERT r4.2 with 0 FAIL; the runs, the validation
readout and every WARN are in `docs/audits/chapter_9_audit.md`. Calibration `20260929T095921Z-full-cri` for
gbdt v0003 (`gbdt-chapter8-v1-077a3dae6cee`). Reported runs:
`experiments/chapter9_reference_runs.json`.

## What the CRI has to cope with

Chapter 8 serves the behaviour-only XGBoost (gbdt v0003,
`gbdt-chapter8-v1-077a3dae6cee`) instead of the Bible's TabNet (C8-1), with
TabNet v0005 in shadow. Three facts from `docs/audits/chapter_8_audit.md`
shape this chapter.

**The two models put their scores on unrelated scales.** The served
XGBoost's full batch has a median score of 8.4e-8, a 99th percentile of
5.0e-4 and a 99.9th percentile of 0.99999. A weighted sum over that raw
number would make the anomaly term nearly binary, and a threshold chosen for
XGBoost would mean something else for TabNet. N29 already said the
thresholds belong to one model_version. This chapter makes that concrete.

**XGBoost ranks better overall but catches fewer scenario-1 insiders.**
Full / user, primary view:

| | Validation PR-AUC | Test PR-AUC | Validation caught at top-1 | Validation scenario 1 at top-1 (days; insiders) | Test scenario 1 at top-1 (days; insiders) |
|---|---|---|---|---|---|
| TabNet v0005 | 0.749 | 0.359 | 12/14 | 14/19; 6/6 | 12/16; 6/6 |
| XGBoost v0003 (served) | 0.915 | 0.827 | 9/14 | 7/19; 3/6 | 9/16; 5/6 |

Scenario 1 in r4.2 is a user who starts logging in after hours and using a
removable drive when they did not before. That is the pattern the
historical-deviation component measures (rises in off-hours logins and USB
use against the user's own trailing baseline). Whether the CRI recovers
some of XGBoost's scenario-1 misses is this chapter's main question. It is
answered on validation only, with weights fixed before any number existed,
and it is descriptive: six validation insiders in scenario 1 cannot settle
it (N15). Chapter 16 adds seeds and intervals.

**TabNet's weakness sits where severity bands operate.** On test, TabNet's
ROC-AUC is close to XGBoost's (0.982 against 0.998) while its PR-AUC is far
lower (0.359 against 0.827). High ROC-AUC with low average precision means
its errors concentrate among the highest-ranked user-days. Severity bands
are global thresholds at the top of the ranking, so band volume and band
precision are properties of the model, not of the CRI formula. This is a
second reason every CRI calibration is tied to one model_version.

## The design

### One scale for every component: rarity

For a value x and a reference sample of n values:

```text
p(x)      = (#{reference >= x} + 1) / (n + 1)          exceedance probability
rarity(x) = min(1, log10(1 / p(x)) / D)                D = CRI_RARITY_DECADES = 5
```

0 means as common as the bulk of the reference; 1 means rarer than 1 in
100,000 reference user-days. The map is monotone and strictly increasing
across distinct reference values, so the anomaly component alone ranks the
reference rows exactly as the anomaly score does (N10). The verifier and the
readout both check this.

D is fixed rather than set to log10(n + 1) so that a band means the same
exceedance probability for every model and profile. A small reference
cannot certify extreme rarity: with the 89,018 full validation rows the
highest reachable rarity is log10(89,019) / 5 = 0.99. On the synthetic test
world (546 reference rows) it is 0.55, so nothing reaches HIGH there; that
is the rule working, not a bug.

Values above the whole reference share the top rarity. That is a resolution
limit of a finite reference; the batch meta counts those rows per split.

### The reference: the served model's validation rows

Not all rows and not train rows. The model saw the labels of its training
rows (N31), so their scores are in-sample, and test rows stay unread (N11).

Before the first real run this document guessed that the extreme tail of the
pooled batch would be mostly in-sample training insiders. The calibration
report does not support that: the 99.9th percentile of the served score is
about 1 in every split (train, validation and test alike), so the
out-of-sample tail is just as extreme. The reason to exclude train rows is
that they are in-sample, not a measured difference in their tail.

The calibration reads the batch's `model_split` tags, never a label. It is
label-free, which is why `calibrate.py` is a serving-side module.

### Components

| Component | Statistic | On the rarity scale |
|---|---|---|
| anomaly | the served `anomaly_score` | rarity |
| historical_deviation | max over `hist_z_<feature>` of max(z, 0): the largest rise above the user's own 30-day baseline; a drop is not risk | rarity |
| peer_deviation | per feature, max(`peer_dev_<feature>`, 0) put on its own rarity scale (units differ: logins, emails, hosts); take the largest | rarity of that largest value, because a maximum of several columns is inflated by construction |
| user_context | 1.0 if the LDAP role that month is in `CRI_PRIVILEGED_ROLES` (default `ITAdmin`), 0.0 otherwise, null without an LDAP row | no; it is a policy prior, not a statistic |
| asset_criticality | highest known criticality of assets touched that day | unavailable on CERT, see below |
| mitre_context | supplied by Chapter 10 in [0, 1] | unavailable until Chapter 10 |

All statistics come from columns Chapter 5 already built, read by name from
the same matrix the Chapter 8 batch scored (fingerprint checked). Nothing
looks ahead: the baselines exclude the current day, peers are same-day, and
the role is the snapshot of that month (N3, N12).

**Double counting, disclosed.** The served model already sees `hist_z_*`
and `peer_dev_*`. The CRI uses them again on purpose, as the Architecture's
named "historical deviation" and "peer deviation" terms, so an analyst gets
a separately stated reason. Chapter 16's ablations measure what they add.

### Formula

```text
w_c       configured weight, renormalised over the components this deployment can provide
points_c  = 100 * w_c * component_c        (0 when the row has no value for c)
cri_score = sum of points_c                in [0, 100]
severity  = LOW 0-24 / MEDIUM 25-49 / HIGH 50-74 / CRITICAL 75-100
```

A null on one row means "no contextual evidence" and contributes 0. The
other weights are not inflated for that row. A component the deployment
cannot provide at all is removed from the formula with its reason recorded.
Nothing is imputed.

Default weights, written before any CRI number existed (N37):

| anomaly | historical | peer | user context | MITRE | asset |
|---|---|---|---|---|---|
| 0.60 | 0.15 | 0.10 | 0.05 | 0.10 | 0.00 |

The anomaly score is the only input validated against labels (Chapters
6-8), so it carries more than all the context together. With MITRE and
asset unavailable, the effective weights are 0.667, 0.167, 0.111 and 0.056.

What the bands then mean, from the formula alone (arithmetic, not results):

- the anomaly score by itself tops out at 100 × 0.667 × 0.99 = 66, which is
  HIGH; a CRITICAL needs corroborating context;
- to reach MEDIUM on the anomaly score alone a user-day must be rarer than
  about 1 in 75 validation user-days (p ≤ 10^-1.875);
- to reach HIGH alone, rarer than about 1 in 5,600 (p ≤ 10^-3.75).

The real per-day band volumes are in the batch meta and the audit.

### Asset criticality: not in CERT, not invented

The Bible asks for an `Asset` entity here, created because the CRI reads it.
It exists (`backend/app/database/models/asset.py`, migration `50ba9f46d2ed`)
with a lookup in `app/cri/assets.py`. CERT r4.2 names PCs but gives no
criticality, owner register or classification (N9), and `.env.example` has
said since Chapter 1 that this chapter must not synthesise one. So:

- `assets.criticality` is nullable, and a check constraint requires a
  `criticality_source` whenever it is set;
- nothing in the repository fills it from CERT;
- the CERT batch path has no user-day-to-asset map (the Chapter 5 matrix is
  per user-day), so the component is unavailable for the whole run and its
  weight leaves the formula, with the reason in every risk run's meta.

An organisation with an inventory fills the table and supplies the map;
Chapter 12 persists events, which is where that map will come from.

### User context and scenario 3

`ITAdmin` is the only r4.2 LDAP role whose name implies administrative
access, and privileged access is a standard insider-risk factor. It was
chosen from the role name. It also happens that r4.2 scenario 3 is a
disgruntled system administrator, so this component lifts scenario-3
insiders by construction. Any scenario-3 difference it produces is not
evidence and must not be claimed (N36); with 4 test days nothing about
scenario 3 can be claimed anyway (N15). The calibration report states how
many users and what share of reference user-days the role covers, so the
breadth of the uplift is visible.

### Rollback to TabNet

If `CIRA_SERVED_MODEL=tabnet:v0005` is set, the pinned calibration no longer
matches the served model_version. The batch refuses, and the API reports the
CRI unavailable with the reason. The fix is a new calibration for TabNet
(`calibrate --supersede "<reason>"`) and a new validation readout. The band
thresholds keep their numeric values, but the reference behind them is
refitted, which is what N29 asks for. The shadow model's scores are never
turned into a CRI while it is the shadow (N32).

## What was built

| Path | Purpose |
|---|---|
| `backend/app/cri/config.py` | Weights, severity maxima, privileged roles, rarity scale, ablation variants, config hash; env overrides are listed, never silent |
| `backend/app/cri/calibration.py` | Rarity maps, two-stage peer statistic, the pinned calibration with sha256 on load |
| `backend/app/cri/context.py` | Historical, peer and role statistics from the Chapter 5 matrix and LDAP; reads only the columns it needs |
| `backend/app/cri/assets.py` | Asset-criticality lookup over the `assets` table; the unavailable reason |
| `backend/app/cri/engine.py` | `CRIEngine`: components, `combine` (the ablation hook), `compute`, `compute_variants`, `compute_event` |
| `backend/app/cri/runtime.py` | What the API holds: loads once, checks the calibration against the served model, never raises |
| `backend/app/cri/sources.py` | Finds Chapter 8 batches and Chapter 9 risk runs |
| `backend/app/cri/calibrate.py` | `python -m app.cri.calibrate`: fits and pins the reference; label-free report including served-vs-shadow disagreement |
| `backend/app/cri/batch.py` | `python -m app.cri.batch`: risk scores to Parquet with lineage |
| `backend/app/cri/evaluate.py` | Offline: validation readout of the CRI and its ablations, the do-no-harm guard |
| `backend/app/database/models/asset.py`, `backend/alembic/versions/50ba9f46d2ed_chapter_9_asset_entity.py` | The `Asset` entity |
| `backend/app/main.py` | Lifespan loads the CRI runtime; `/health` gains a `cri` block |
| `scripts/verify_chapter9.py` | PASS / WARN / FAIL over configuration, calibration, risk run and readout |
| `scripts/signoff_chapter9.py` | The real-data sequence in one resumable command, the audit draft, `--finalize` |
| `backend/tests/unit/test_ch9_cri.py`, `test_ch9_asset.py`, `backend/tests/integration/test_ch9_pipeline.py` | 40 tests |

The Bible §2 tree names `cri/config.py` and `cri/engine.py` only. The other
modules split out work the Bible's two files would otherwise mix: label-free
serving code, the offline readout that reads labels, and the CLI runners, the
same split Chapter 8 used (C9-6). No dependency was added.

Serving modules (config, calibration, context, assets, engine, runtime,
sources, batch, calibrate) never import label code or `evaluate`; a unit
test checks this statically (N5). `evaluate.py` is the only module that
reads labels.

## Risk score contract

Every row of `risk_scores.parquet`:

```text
user_id, date, model_split, model_name, model_version, registry_version,
anomaly_score                                    carried through unchanged (§14)
component_<c>, points_<c>                        for each of the six components
cri_score, severity
missing_components                               per-row nulls among active components
anomaly_beyond_reference                         above every reference score
historical_top_feature, peer_top_feature, role   what drove the context (for Chapter 11)
cri_version, cri_config_hash, cri_variant, calibration_id, cri_run_id, source_batch_run_id
```

The anomaly score and the CRI are separate columns, and the run keeps the
Chapter 8 batch id, so lineage runs risk row → batch row → model_version →
registry entry (Architecture §37). Rows tagged `train` are in-sample (N31).

## Failure modes (Architecture §36)

| Situation | Behaviour |
|---|---|
| No calibration pin, or a file whose sha256 differs from the pin | `CRIUnavailableError`; batch exits 2 and writes nothing; `/health` shows `cri.status = unavailable` with the reason |
| Scores from another model_version (for example a rollback) | `CRIModelMismatchError` (N29) |
| Shadow rows | Refused (N32) |
| Missing, non-finite or out-of-range anomaly score | `CRIInputError`; no score, no CRI |
| Context misaligned with scores, or a peer column the calibration expects is absent | `CRIInputError` |
| Feature matrix differs from the one the batch scored | Batch and calibration refuse (fingerprint) |
| Configuration invalid (anomaly weight 0, bands out of order) | `CRIConfigError` |
| `CRI_*` set in the environment | Allowed; listed in `overrides`, written into the meta, WARN in the verifier, and the run is not the calibrated default |

The top-level `/health` status keeps its Chapter 8 meaning (is an anomaly
model loaded). The CRI reports its own status in the `cri` block until
Chapter 13 adds the risk routes (C9-5).

## The validation readout and the guard

`python -m app.cri.evaluate` reads the default risk run's validation rows,
joins labels in memory and reports, for the anomaly score and for the
variants `anomaly_only`, `default`, `no_historical_deviation`,
`no_peer_deviation` and `no_user_context`:

- PR-AUC (primary view), ROC-AUC as a secondary number;
- recall and insiders caught at daily top-1 and top-5;
- malicious days and insiders caught per scenario at top-1 (N15);
- the band view: alerts, precision, recall and insiders caught at HIGH or
  above and at CRITICAL, and alerts per day.

Variants are recombined from the stored components, not recomputed (HCEA §9).
TabNet appears only as a reference row copied from the Chapter 8 decision
evidence on the same rows; it is never turned into a CRI.

Harness checks: `anomaly_only` must give the same PR-AUC as the anomaly
score, and on full the anomaly score's PR-AUC must equal the Chapter 8
decision evidence (0.915 for gbdt v0003).

Guard `c9-cri-guard-v1`: a WARN if the default CRI has a lower validation
PR-AUC than the anomaly score, catches fewer insiders at top-1 or top-5, or
has fewer malicious days at top-1 in any scenario. There is no margin; every
decrease is stated and explained in the audit. A WARN is never a reason to
change a weight in this chapter (N37).

The readout is validation only (`--part test` is refused) and written once
(`--supersede "<reason>"` keeps the old one inside the new file). The CRI's
test readout is Chapter 16's ablation C.

## Sign-off: one command

From `backend/`:

```bash
python ../scripts/signoff_chapter9.py
```

| Step | What |
|---|---|
| 0 | Preflight: the Chapter 8 decision; the newest full Chapter 8 batch was scored by the served model; features, LDAP and labels exist; no `CRI_*` value in `.env` or the environment differs from the defaults (stops here otherwise, before anything is fitted) |
| 1 | The full pytest suite (`--skip-tests` to skip) |
| 2 | Calibration. An existing pin for the served model and the same batch is reused; a pin for another model stops the run, never superseded automatically |
| 3 | The CRI batch; refuses to continue unless it is the calibrated default configuration |
| 4 | Verifier without the readout, 0 FAIL, before any label is read |
| 5 | The validation readout, once |
| 6 | Verifier with the readout, 0 FAIL |
| 7 | The FastAPI app starts and `/health` reports the CRI loaded with the pinned calibration |
| 8 | `experiments/chapter9_reference_runs.json` and the audit draft `docs/audits/chapter_9_audit.md` |

Each step runs in its own process; logs go to
`experiments/results/chapter9/signoff_logs/`. Finished steps are skipped on
a re-run. Every WARN becomes a `TO EXPLAIN` line in the audit draft. Replace
each with the reason it is acceptable, then:

```bash
python ../scripts/signoff_chapter9.py --finalize
```

`--finalize` refuses while any `TO EXPLAIN` remains, then retires N38, sets
the README row and this document's status to IMPLEMENTED and ticks the
real-run checklist.

The preflight check on `CRI_*` exists because the first real attempt showed
the gap: a `.env` still holding the Chapter 1 placeholder weights (anomaly
0.40, asset 0.15) would have been used for the calibration too, so the risk
run would have counted as "the calibrated default" and the sign-off would
have gone green with only a verifier WARN. The test suite is also isolated
from developer `CRI_*` values (`backend/tests/conftest.py`).

Three flags exist for the synthetic tests only: `--dotenv` (read a given
file instead of the repository `.env`), `--skip-health` (the synthetic world has no registered model to load;
the audit then says SKIPPED) and `--min-reference-rows`. Neither may be used for the real
sign-off (C9-9).

## How to run, step by step

From `backend/`, with `.env` pointing at the dataset and no `CRI_*`
overrides:

```bash
python -m app.cri.calibrate --profile full           # fits and pins the reference for the served model
python -m app.cri.batch --profile full                # writes <processed>/risk/chapter9/<cri_run_id>/
python ../scripts/verify_chapter9.py --profile full --no-readout
python -m app.cri.evaluate --profile full             # validation readout, once
python ../scripts/verify_chapter9.py --profile full
python -m app.cri.batch --profile full --variant anomaly_only   # an ablation, for Chapter 16
```

Only full is reportable for the served model, which is a full-profile model.
A mid calibration can be made for debugging; its numbers are not reported.

## Verification

`scripts/verify_chapter9.py` sections:

- **config:** valid; no environment override (WARN otherwise); effective
  weights sum to 1.
- **calibration:** loads with sha256 verified; fitted for the model served
  now; rarity scale matches the configuration; no label column; the
  reference is exactly the served model's validation rows of its batch,
  with identical scores; rarity monotone, strict across distinct values and
  in [0, 1].
- **risk:** contract columns; no label column; the pinned calibration; the
  calibrated default configuration; one model_version; one risk row per
  served batch row in the same order; anomaly score and split tags carried
  through unchanged; CRI in [0, 100]; points sum to the CRI; severity
  matches the bands; unavailable components carry no value and no points;
  recombination and a from-scratch recomputation both reproduce every row
  exactly; another model_version and shadow rows are refused; runlog line;
  peak RSS under 10 GB.
- **readout:** validation only; of this risk run; the harness checks; the
  guard.

On the synthetic chain: 36 PASS, 1 WARN (the Chapter 8 evidence check does
not apply to synthetic rows), 0 FAIL.

## Carry-forward compliance

| Note | How Chapter 9 satisfies it |
|---|---|
| N1 masquerade | The readout uses the primary view with masquerade days excluded |
| N2 imbalance | PR-AUC and daily budgets lead; ROC-AUC secondary; no accuracy |
| N3, N12 no look-ahead | Baselines exclude the current day; peers same-day; LDAP role of that month |
| N5 labels | Serving modules statically checked label-free; only `evaluate.py` reads labels, in memory |
| N6 profiles | Only full is reportable for the full-profile served model; every run logs `reportable` |
| N8 resources | Thread caps first in every entry point; only the needed columns read; RSS in every runlog line |
| N9 signals | Asset criticality not in CERT: excluded, never invented. No new signal |
| N10 score convention | The CRI consumes the served score and never talks to a model; the anomaly map is monotone |
| N11 test | The CRI is not read on test in this chapter |
| N15 per scenario | The readout reports days and insiders per scenario |
| N17 budgets | Top-1 and top-5 reported; band volumes per day |
| N20 ranking score | The score is used as a ranking input through rarity, never as a probability |
| N21 pins | Calibration pinned with sha256, loaded or refused |
| N22, N25 static traits | Neither the CRI nor its context uses psychometrics or department size |
| N28, N29 served model | Calibration tied to the served model_version; mismatch refused |
| N31 in-sample | Split tags carried into every risk row; train rows excluded from the reference and from the readout |
| N32 shadow | Shadow rows refused by the engine; used only for the label-free disagreement report |

## Deviation register additions

| Id | What | Status |
|---|---|---|
| C9-1 | Default weights changed from the Chapter 1 placeholders in `.env.example` (0.40 / 0.15 / 0.15 / 0.05 / 0.10) to 0.60 / 0.15 / 0.10 / 0.05 / 0.10, asset 0.00, before any CRI number existed | Applied |
| C9-2 | Every component is put on a rarity scale fitted to the served model's validation rows instead of combining raw values | Applied |
| C9-3 | `Asset` created with a nullable criticality that CERT never fills; the component is unavailable on CERT | Applied |
| C9-4 | `mitre_context` defined but unavailable until Chapter 10; its weight is excluded from the renormalisation until then | Applied |
| C9-5 | `/health` gains a `cri` block; the top-level status keeps its Chapter 8 meaning | Applied |
| C9-6 | Modules beyond the Bible's `config.py` and `engine.py` (see "What was built") | Applied, explained above |
| C9-7 | Risk scores stay in Parquet; the `RiskScore` entity and the bounded PostgreSQL load are Chapter 12 (as C8-6) | Deferred |
| C9-8 | The CRI's test readout is Chapter 16's ablation C | Deferred |
| C9-9 | Sign-off flags `--dotenv`, `--skip-health` and `--min-reference-rows` for the synthetic tests only | Tests only |
| C9-10 | Historical and peer components reuse model inputs; disclosed as double counting, measured by Chapter 16 ablations | Scope decision |

## First real readout (full / user validation)

From `experiments/chapter9_validation_readout.json`; the audit has the full
record. The default CRI ranks validation insiders worse than the anomaly
score it is built on:

| Ranking | PR-AUC | Caught at top-1 | Scenario 1 days at top-1 | Scenario 2 days at top-1 | Scenario 3 days at top-1 |
|---|---|---|---|---|---|
| anomaly score (gbdt v0003) | 0.915 | 9/14 | 7/19 | 125/179 | 2/4 |
| CRI default | 0.694 | 11/14 | 9/19 | 110/179 | 1/4 |
| CRI without historical deviation | 0.653 | 9/14 | 7/19 | 109/179 | 1/4 |
| CRI without peer deviation | 0.824 | 10/14 | 7/19 | 116/179 | 1/4 |
| CRI without user context | 0.822 | 11/14 | 9/19 | 117/179 | 1/4 |
| TabNet v0005 anomaly score (Chapter 8) | 0.749 | 12/14 | 14/19 | 97/179 | 0/4 |

What this does and does not show is in N40. The weights are not changed in
this chapter (N37).

## Before reporting anything

- No Chapter 9 number exists on CERT yet. The synthetic tests prove the
  plumbing, nothing about CERT.
- Report the CRI with the served model named, on full, on validation, per
  scenario, next to the anomaly score and TabNet's Chapter 8 row.
- One seed per model. Chapter 16 adds seeds and bootstrap intervals.

## Acceptance checklist

Bible Chapter 9:

- [x] CRI produces a 0-100 score and a severity band for a batch of scored events (synthetic)
- [x] Weights and thresholds are configurable, not hard-coded (`CRI_*`, reported when overridden)
- [x] `Asset` entity created now, with a real purpose (the criticality lookup), not speculatively
- [x] Ablation hook to disable individual CRI components (`CRIConfig.variant`, `batch --variant`, `combine`)
- [x] Raw anomaly score and CRI kept as distinct values

HCEA §9:

- [x] Vectorised over the whole frame, no per-row Python loop
- [x] Ablations switch components by configuration over one scored matrix

Real runs (N38):

- [x] calibration fitted for the served model on the full Chapter 8 batch
- [x] full CRI batch verified with 0 FAIL
- [x] validation readout written once
- [x] `/health` shows the CRI loaded on the development machine
- [x] `docs/audits/chapter_9_audit.md` written from those runs, every WARN explained
