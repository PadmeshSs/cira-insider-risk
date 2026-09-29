# CIRA carry-forward notes

Rules that earlier chapters created and later chapters must obey.
Read this at the start of every chapter. Add to it at the end of every
chapter. Never delete a note; mark it `RETIRED (chapter N, reason)` instead.

How to use it when prompting a chapter:

> Before starting Chapter N, read `docs/CARRY_FORWARD.md` and list which
> notes apply to this chapter and how the plan satisfies each one.
> At the end, propose any new notes this chapter creates.

| Note | Applies to chapters |
|---|---|
| N1 masquerade | 6, 7, 8, 16 |
| N2 imbalance and metrics | 6, 7, 8, 16 |
| N3 user-level split | 6, 7, 8, 16 |
| N4 imputation | 6, 7 |
| N5 label isolation | every chapter |
| N6 profile ladder | every chapter that runs data |
| N7 host list | 5 (re-runs), any feature change |
| N8 resource rules | every heavy entry point |
| N9 unsupported signals | 7, 9, 10, 16 (reporting) |
| N10 score convention | 7, 8, 9, 16 |
| N11 one saved split | 7, 16 |
| N12 causal scoring | 7, 8, 16, any sequence model |
| N13 masquerade in training | 7, 16 |
| N14 Chapter 6 status (RETIRED) | - |
| N15 report per scenario | 7, 16, 19 (reporting) |
| N16 time split: seen/new breakdown | 7, 16 |
| N17 budget depends on profile | 7, 16 |
| N18 baseline reference runs | 7, 16 |
| N19 Chapter 7 status (RETIRED) | - |
| N20 TabNet score is a ranking score | 8, 9, 11, 16 |
| N21 models load through the registry | 8, 12, 13, 16 |
| N22 model input columns | 11, 14 |
| N23 supervised comparison | 16, 19 (reporting) |
| N24 Chapter 7 reference runs | 8, 16 |
| N25 adopted TabNet is behaviour-only | 7 (re-runs), 8, 11, 16 |
| N26 TabNet trails XGBoost; noisy selection | 8, 11, 16, 19 (reporting) |
| N27 Chapter 8 status (RETIRED) | - |
| N28 the served model is decided once, by rule | 9, 11, 12, 13, 14, 16 |
| N29 CRI is tied to the served model_version | 9, 16 |
| N30 explanations come from the served model | 11, 14 |
| N31 in-sample scores are not detections | 12, 14, 15, 16 |
| N32 shadow scores never feed CRI or alerts | 9, 12, 13, 14 |
| N33 CRI rarity is calibrated per served model_version | 9, 10, 11, 12, 13, 16 |
| N34 CRI and anomaly score stay separate values | 11, 12, 13, 14 |
| N35 unavailable components are excluded, never imputed | 10, 12, 16 |
| N36 user_context lifts scenario 3 by construction | 16, 19 (reporting) |
| N37 CRI weights fixed a priori; CRI test readout is Chapter 16 | 16, 19 (reporting) |
| N38 Chapter 9 status (RETIRED) | - |
| N39 bands are global; budgets are per day | 12, 14, 16 |
| N40 the default CRI ranks below the anomaly score (validation) | 12, 14, 16, 19 (reporting) |

---

## N1. Scenario 3 account masquerading  (from Chapter 5)

In r4.2 scenario 3 the insider sends email while logged in with a
supervisor's keylogged credentials, so those malicious events are recorded
under the supervisor's account.

Label tables (built by `scripts/build_labels.py`):

- `labels/insider_user_days.parquet`, the PRIMARY view, keyed by the
  incident insider (answer filename). 70 users, 966 user-days on the full
  ground truth.
- `labels/account_user_days.parquet`, the SECONDARY view, keyed by the
  account the event was logged under. Masquerade rows have
  `is_masquerade = 1`.

Evaluation policy:

1. Headline metrics use the primary view.
2. Supervisor account-days with `is_masquerade = 1` are excluded from the
   negative set in the primary evaluation. They are neither a true positive
   nor a false positive: the account did carry malicious activity, but not
   by its owner.
3. Also report the secondary view once, with those account-days as
   positives, and state how many rows differ.
4. Report recall per scenario. Scenario 3 is expected to be the weakest,
   because part of that insider's activity is not in their own feature row.
   Say so in the write-up; do not tune it away.

## N2. Class imbalance and metrics  (from Chapter 5)

The mid profile has 966 malicious user-days in 106,914 rows (about 0.9%).

- Never report accuracy as a headline metric.
- Headline: PR-AUC (average precision), plus recall and precision at a fixed
  daily alert budget (for example the top-k user-days per day an analyst
  could review).
- Also report detection per user: an insider counts as caught if any of
  their malicious days is alerted within the budget.
- Report ROC-AUC only as a secondary number.
- Class weighting (`class_weight`, `scale_pos_weight`) is computed from the
  training split only. Never resample the test split.

## N3. Split by user, never by row  (from Chapter 5)

- Every user's rows go to exactly one of train, validation or test.
- Spread insiders across splits stratified by scenario, with a fixed seed
  (`CIRA_SEED`). Save the user-to-split assignment under `experiments/` so
  every model uses the same split.
- Consider an additional time-ordered check (train on earlier months,
  test on later) because insider activity clusters in time.
- Historical and peer features already use only past and same-day data;
  do not add any feature that looks ahead.

## N4. Nulls are deliberate; impute on train only  (from Chapter 5)

The feature matrix keeps nulls where a value is undefined: ratios with a
zero denominator, first/last hours on days without that activity,
baselines before 7 prior days, peers without a department.

- Fit any imputer on the training split only, then apply it to validation
  and test.
- Add a missing-value indicator for hour, ratio, baseline and peer columns
  so the model can tell "no activity" apart from a real value.
- Tree models that accept nulls natively may skip imputation, but must be
  evaluated on the same split.

## N5. Label isolation  (from Chapters 3 and 5)

- Labels live only under `<processed>/labels/`. They are joined to features
  only inside evaluation or training code, in memory, never written back
  into `features/`.
- `app/feature_engineering` must never import the ground-truth module
  (enforced by `test_feature_package_never_imports_ground_truth`).
- The pipeline's label-leakage guard must stay on.

## N6. Profile ladder  (HCEA R9, R10)

- dev: debugging only. Never report its numbers.
- mid: development and model selection.
- full: the only profile whose numbers are reported.
- Every run appends a line to `experiments/runlog.jsonl`.

## N7. Host categories  (from Chapter 5)

- `network_domains.py` is changed only by host category, never by which
  users visited a host (reviewed label-blind, see
  `experiments/http_host_category_review.txt`).
- Any change must bump `HOST_CATEGORIES_VERSION`, which rebuilds the
  Stage 1 cache.

## N8. Resource rules  (HCEA R6, R8)

- Call `app.core.runtime.apply_thread_caps()` at the top of every heavy
  entry point (training, tuning, SHAP), before importing numpy or torch.
- Measured mid peak is 1.63 GB. Before the full run, kill it once during
  the http stage and confirm it resumes.

## N9. Signals CERT r4.2 does not contain  (from Chapter 5)

No failed logins, source IPs, byte volumes, file create/modify/delete
events, or application/process logs. Features for these are omitted, not
fabricated. Explanations, MITRE mappings and the dashboard must not claim
them.

## N10. One score convention for every detector  (from Chapter 6)

Every detector exposes `score(frame) -> [0, 1]`, higher = more anomalous,
with any calibration fitted on training rows only
(`app/baselines/base.py`). The map must be monotone so ranking metrics are
unchanged. Every stored score row carries `model_version`.

- TabNet's `infer.score()` (Chapter 7/8) follows the same convention, so
  Chapter 16 can compare all detectors with one harness.
- Chapter 9 CRI consumes this score; it never talks to a model directly.

## N11. Load the saved split, never recompute it  (from Chapter 6)

The user split lives in `experiments/splits/user_split_<profile>_seed<seed>.json`.
Chapter 7 and Chapter 16 load it with `app.evaluation.splitting.load_split`
(or go through `load_or_create_split`, which refuses a mismatch). The rule is
population-independent, so a user has the same split in mid and full.

- Changing the split needs `--rebuild-split` and a line in the write-up.
- Model selection uses validation only; test is looked at once per model.

## N12. Sequence models score causally  (from Chapter 6)

A score for day t may only use rows dated t or earlier. The LSTM
autoencoder scores day t from the window that ends on t. Any later sequence
model, or any window-based explanation, follows the same rule.

## N13. Masquerade days are out of supervised training too  (from Chapter 6)

Supervisor account-days with `is_masquerade = 1` are dropped from training
and validation rows for any supervised model (GBDT now, TabNet in Chapter 7),
not only from evaluation. Keeping them as negatives teaches the model that
malicious activity is benign. Unsupervised models see them, label-blind.

## N14. Chapter 6 is PARTIALLY IMPLEMENTED until real runs exist  (from Chapter 6)

RETIRED (chapter 6, mid and full runs verified; see `docs/audits/chapter_6_audit.md`).

The code is tested on synthetic data only. Chapter 6 becomes IMPLEMENTED
when `experiments/runlog.jsonl` has `chapter6_baseline` lines for all five
detectors at mid and full (user split; time split at least at mid). Until
then no baseline number is quoted anywhere. Each of those runs must also
pass `scripts/verify_chapter6.py` with 0 FAIL (the mid user-split run with
`--reload-models --permutation-test`), with every WARN explained in the write-up. Report LOF numbers with
`lof_fit_rows`, `pca_components` and `pca_retained_variance`, and say which
profile every number came from (mid has ~28% insider users, full ~7%).

## N15. Headline numbers are mostly scenario 2  (from Chapter 6 runs)

Scenario 2 supplies 170 of the 190 test positives in the user split (157 of
168 in the time split); scenario 3 has 4 test days. A single PR-AUC is
therefore mostly a scenario-2 number.

- Every model comparison, TabNet included, reports recall per scenario and
  insiders caught per scenario next to the headline.
- Do not claim anything about scenario 3 from 4 test days.

## N16. Time-split results need the seen/new insider breakdown  (from Chapter 6 runs)

In the time split the same people are in train and test, so a supervised
model could be recognising insiders it has already seen. Any time-split
result for a supervised model (TabNet included) is reported with the
seen/new breakdown from `scripts/inspect_scores.py`. The user split stays
the headline for insiders never seen in training.

- Chapter 6 outcome: 12 of 14 time-split test insiders were new, and
  XGBoost scored PR-AUC 0.994 on them, so recognition did not explain its
  0.991 there. Why the time split scores above the user split (0.991 vs
  0.843 at mid) is not established; do not state a reason without evidence.

## N17. The daily budget means different things per profile  (from Chapter 6 runs)

Test users: 44 at mid, 183 at full; the same 14 insiders in both. Top-5 per
day at mid alerts on over 10% of users and saturates per-user detection
(even the rules catch 14/14). Use top-1 when reading mid results; top-5 is
informative at full. Precision@k is capped by the base rate; quote it with
the ceiling printed by `inspect_scores.py`.

## N18. Compare against the recorded baseline runs  (from Chapter 6)

The reported baseline scores are the run ids in the "Reported runs" table of
`docs/audits/chapter_6_audit.md`: rule, Isolation Forest, LOF and XGBoost
from the first run of each profile/split, the LSTM autoencoder from its
re-run after the resume fix. Chapter 7 (TabNet) and Chapter 16 compare
against those score files on the same split file and the same budgets,
rather than re-running the baselines with different code. If a baseline is
ever re-run, record the new run id there and say why.

- The LSTM's ranking moved noticeably with training order alone (full
  ROC-AUC 0.862 vs 0.767 across the fix). Chapter 16 should use several
  seeds before ranking it against models near it.

## N19. Chapter 7 is PARTIALLY IMPLEMENTED until real runs exist  (from Chapter 7)

RETIRED (chapter 7, mid and full runs verified; see `docs/audits/chapter_7_audit.md`).

The TabNet code is tested on synthetic data only. Chapter 7 becomes
IMPLEMENTED when `experiments/runlog.jsonl` has `chapter7_tabnet` lines for:

- mid, user split, passing `scripts/verify_chapter7.py --reload-models
  --permutation-test --baselines` with 0 FAIL;
- mid, time split, passing `--baselines` with 0 FAIL;
- full, user split, passing `--reload-models --permutation-test --baselines`
  with 0 FAIL;
- a `--fresh` re-run at mid compared with `--compare-run-id`.

Every WARN is explained in `docs/audits/chapter_7_audit.md`, which also lists
the reported run ids (the Chapter 7 equivalent of N18). Until then no TabNet
number is quoted anywhere. Mark this note RETIRED when that is done.

## N20. TabNet's score is a ranking score, not a probability  (from Chapter 7)

`anomaly_score = sigmoid(logit margin)`, computed in float64, in [0, 1]. It
equals `predict_proba[:, 1]`, but the model was trained with a class-weighted
loss (positive weight = negatives / positives; with 574 training positives
that is roughly 110 at mid and 500 at full), so the number is inflated
relative to a true probability of malice.

- Chapter 9 uses it as a score input to CRI, never as "the probability this
  user is malicious", and the dashboard does not label it as one.
- If calibrated probabilities are ever needed, fit a calibrator on validation
  only and record it as a new model version.
- Scores at exactly 1.0 are counted in each run (`saturated_scores`); report
  them if non-zero.

## N21. Models are loaded through the registry  (from Chapter 7)

`models/saved_models/tabnet/` is append-only: a version directory is never
replaced, and every file has a sha256 in `registry.jsonl`.

- Chapter 8 loads with `app.tabnet.infer.load_model(ref, registry_root=...,
  verify=True)` and serves on CPU. On any load or verification failure it
  gets `ModelUnavailableError` and returns an explicit error, never a score
  (Architecture §36).
- Reported results and the served model name a pinned registry version
  (`v000N`), not "latest".
- Every stored score carries `model_version`; lineage from an alert back to
  the artifact goes model_version -> registry entry -> files.
- (Chapter 8) The same rules cover `models/saved_models/gbdt/`, where the
  behaviour-only XGBoost is registered. Serving goes through
  `app.scoring.adapters.load_adapter`, which uses the same registry class
  and sha256 check for both models.

## N22. The model's input columns are not the matrix's columns  (from Chapter 7)

The network sees `preprocessor.output_columns`: every Chapter 5 feature after
imputation, signed log1p and standardisation, followed by one
`isnull__<column>` indicator per nullable column.

- Chapter 11 maps mask and SHAP contributions by position in that list,
  sums a feature with its indicator (`app.tabnet.dataset.feature_groups`),
  and describes values from the raw matrix row, not the standardised input.
- SHAP background sets are drawn from preprocessed training rows (HCEA D-5).
- If the static-trait check (psychometrics, department size in the mask
  top 10) ever warns, Chapter 11 must not present those as behavioural
  reasons.

## N23. The supervised comparison is TabNet vs XGBoost  (from Chapter 7)

Both are trained on the same primary labels, the same split, with the same
class-weight ratio, early-stopped on validation PR-AUC.

- Chapter 16 compares them with `app.evaluation.compare` on identical rows,
  budgets and tie-break seed, per scenario, with the harness check passing.
- If TabNet does not beat XGBoost, that is the result; it is not tuned on
  test to change it. The case for TabNet then rests on its masks
  (Chapter 11), and the write-up says so.
- Manual search stays within 12 configurations per profile (HCEA §7.6), all
  logged.

## N24. Compare against the recorded TabNet runs  (from Chapter 7)

The reported TabNet runs are in `experiments/chapter7_reference_runs.json`
and in the Reported runs table of `docs/audits/chapter_7_audit.md`:

| Profile / split | Run id | Registry |
|---|---|---|
| full / user | `20260927T162456Z-full-user-s42` | v0005 |
| mid / user | `20260927T125702Z-mid-user-s42` | v0003 |
| mid / time | `20260927T161717Z-mid-time-s42` | v0004 |

- Chapter 16 compares against these score files with `app.evaluation.compare`
  on the same rows, budgets and tie-break seed, with the harness check
  passing, as for the baselines (N18). Do not retrain TabNet to get a
  comparison number.
- If TabNet is retrained for the record, add the run to the reference file
  and the audit, and say why.

## N25. The adopted TabNet is behaviour-only  (from Chapter 7)

The reported TabNet models were trained with
`--exclude-features psych_,peer_department_size`: the five psychometric
columns and `peer_department_size` are not model inputs.

- Any retrain meant to reproduce or replace a reported model passes the
  same flag; without it the config, model_version and results differ.
- The serving path needs nothing extra: the saved preprocessor picks its own
  columns by name, so full matrix rows can be scored as they are.
- Chapter 11 has no static trait to explain for TabNet. The Chapter 6
  XGBoost was trained with all features; its top 10 by gain held no static
  trait, but its explanations must still be checked for them (N22).

## N26. TabNet trails XGBoost, and its model selection is noisy  (from Chapter 7)

Test PR-AUC, primary view: full user 0.359 vs 0.828, mid user 0.220 vs
0.843, mid time 0.888 vs 0.991. XGBoost is also higher on validation. Most
of the gap is scenario 2; TabNet caught 0 of 2 scenario-3 test insiders at
top-1 on the user split.

- Chapter 8 decides which model is served and records why. The Bible names
  TabNet primary, mainly for its masks (Chapter 11); the ranking evidence
  favours XGBoost. Whatever is served is pinned by registry version (N21).
- TabNet's validation PR-AUC swings by 0.1-0.2 between epochs and early
  stopping keeps the peak, so its validation numbers are optimistic (mid
  0.734 on validation, 0.220 on test). One run per configuration cannot
  separate TabNet configurations: the static-trait ablation reversed order
  between validation and test.
- Chapter 16 runs several seeds per model and adds bootstrap intervals
  before claiming more than "XGBoost ranks higher on all three splits".
- The all-features model's mid test PR-AUC (0.509) was seen during tuning
  (C7-9). Report it as a disclosure; do not use it to change the adopted
  configuration.

## N27. Chapter 8 is PARTIALLY IMPLEMENTED until real runs exist  (from Chapter 8)

RETIRED (chapter 8, runs verified; see `docs/audits/chapter_8_audit.md`).

The scoring code is tested on synthetic data only. Chapter 8 becomes
IMPLEMENTED when all of the following hold:

- `experiments/runlog.jsonl` has `chapter8_gbdt_candidate` lines for mid /
  user, mid / time and full / user, each passing
  `scripts/verify_chapter8.py --candidate-run-id <run> --permutation-test
  --no-decision` with 0 FAIL;
- `experiments/chapter8_serving_decision.json` is written by
  `python -m app.scoring.select` and committed;
- `experiments/chapter8_test_readout.json` is written once;
- a full batch run passes `scripts/verify_chapter8.py --profile full` with
  0 FAIL, and `/health` shows the decided model on the development machine;
- `docs/audits/chapter_8_audit.md` explains every WARN.

Until then no model is served and no Chapter 8 number is quoted. Mark this
note RETIRED when that is done.

## N28. The served model is decided once, by a rule fixed in advance  (from Chapter 8)

Rule `c8-serving-rule-v1` (`app/scoring/select.py`,
`docs/chapters/chapter_8_scoring.md`): serve the behaviour-only XGBoost only
if its validation PR-AUC beats TabNet's by more than 0.10 on full / user
and it is also ahead on mid / user and mid / time; otherwise serve TabNet.
Both must pass the gates (registered with sha256, reportable, full profile,
behaviour-only).

- The decision file is the only source of the served pin. Rolling back
  with `CIRA_SERVED_MODEL` is allowed and is visible in `/health` and the
  batch runlog, but it is not a new decision.
- Changing the served model needs `select --supersede "<reason>"` and a
  line in the audit. Never change it because of a test number.
- If XGBoost is served, the write-up says TabNet was built, evaluated and
  kept in shadow, and that the served detector is XGBoost (deviation C8-1).

## N29. CRI thresholds belong to one served model_version  (from Chapter 8)

TabNet's and XGBoost's scores have different distributions, although both
are in [0, 1] and both are ranking scores (N20). Chapter 9 records the
served `model_version` next to its weights and severity thresholds. A
change of served model means re-deriving them, not reusing them.

## N30. Explanations come from the served model only  (from Chapter 8)

Chapter 11 explains the model whose score produced the alert. If TabNet is
served, its masks are primary and KernelSHAP corroborates, as planned. If
XGBoost is served, TreeSHAP on XGBoost is the model-side explanation, and
TabNet's masks must not be presented as the reason for an XGBoost score.
They can appear only as a clearly labelled second model's view, if at all.

## N31. Scores on training rows are in-sample  (from Chapter 8)

The batch file tags every row with `model_split` from the served model's own
split file. Rows tagged `train` were scored by a model that saw their labels.

- Never quote detection, precision or insiders caught from them.
- Chapter 12's demo sample and the dashboard's example alerts come from
  `validation` or `test` users. Test users are preferred, since validation
  chose the model.
- `python -m app.scoring.batch --rows evaluation` writes a file without
  `train` rows.

## N32. Shadow scores are for comparison only  (from Chapter 8)

The candidate not served is the shadow (`role = "shadow"` in the batch
file, `status()["shadow"]` in the API). Shadow scores go to Chapter 16 and
to monitoring of disagreement between the two models. They never feed CRI,
alerts, explanations or the analyst's queue, and there is no ensemble of the
two (C8-4).

## N33. CRI rarity is calibrated per served model_version  (from Chapter 9)

Every CRI component is a rarity against a label-free reference: the served
model's validation user-days from its Chapter 8 batch (`app/cri/calibration.py`).
The calibration is pinned in `experiments/chapter9_cri_calibration.json` with
sha256 and names the model_version it was fitted for.

- The engine refuses scores from any other model_version, and shadow rows.
  A change of served model (including a `CIRA_SERVED_MODEL` rollback to
  TabNet) needs `python -m app.cri.calibrate --supersede "<reason>"` and a new
  validation readout. This is how N29 is met: the band numbers stay, the
  reference behind them is refitted.
- Never fit a reference on train rows (in-sample, N31) or test rows (N11).
- `CRI_RARITY_DECADES` is part of the definition; changing it means refitting.
- Chapter 10 must deliver `mitre_context` in [0, 1] (0 = no mapped
  technique, null = not evaluated). Adding it changes the effective weights
  and the config hash, so the result is a new CRI configuration whose
  validation effect belongs to Chapter 16's ablation D.

## N34. The CRI and the anomaly score stay separate values  (from Chapter 9)

Risk rows carry `anomaly_score` unchanged next to `cri_score`, with
`model_version`, `calibration_id`, `cri_config_hash` and `source_batch_run_id`
(Architecture §14, §37).

- Chapter 12 persists both (`AnomalyScore` and `RiskScore`) and never
  derives one from the other.
- Chapter 11 explains the CRI from `points_<component>`,
  `historical_top_feature`, `peer_top_feature` and `role`, and the model side
  from the served model only (N30). A CRI point is not a model reason.
- The dashboard never labels either number a probability (N20).

## N35. Unavailable components are excluded, never imputed  (from Chapter 9)

CERT r4.2 has no asset criticality (N9), and MITRE is Chapter 10. A component
the deployment cannot provide is removed from the formula and the weights
are renormalised over the rest; the reason is written into every risk run's
meta. A per-row null of an available component contributes 0 and does not
inflate the other weights.

- `assets.criticality` is never filled from CERT. A criticality must carry
  its source (check constraint).
- A report that compares CRI runs states which components were available.

## N36. user_context lifts scenario 3 by construction  (from Chapter 9)

The default privileged role is `ITAdmin`, chosen from the role name. r4.2
scenario 3 is a system administrator, so this component raises scenario-3
insiders because of how the dataset was built.

- Never cite a scenario-3 improvement from user_context as evidence; report
  the `no_user_context` ablation next to it.
- The calibration report states how many users and what share of user-days
  the role covers; quote it when discussing false positives among admins.

## N37. CRI weights are fixed a priori; its test readout is Chapter 16  (from Chapter 9)

The default weights (0.60 / 0.15 / 0.10 / 0.05 / 0.10, asset 0.00) were
written before any CRI number existed. Chapter 9 reads the CRI on validation
only, once (`experiments/chapter9_validation_readout.json`).

- Guard `c9-cri-guard-v1` WARNs on any validation loss against the anomaly
  score. A WARN is explained in the audit; it is not a reason to retune.
- Any later weight change is a new configuration with its own hash, recorded
  with the reason it was made and whether validation numbers informed it.
- The Chapter 9 sign-off stops at preflight if any `CRI_*` value in `.env`
  or the environment differs from the code defaults; a deliberate change is
  made in `backend/app/cri/config.py` with a reason, never through `.env`.
- The CRI is first read on test in Chapter 16 (ablation C), once.

## N38. Chapter 9 is PARTIALLY IMPLEMENTED until real runs exist  (from Chapter 9)

RETIRED (chapter 9, runs verified; see `docs/audits/chapter_9_audit.md`).

The CRI code is tested on synthetic data only. Chapter 9 becomes IMPLEMENTED
when `python ../scripts/signoff_chapter9.py` runs green on the full profile
without the tests-only flags, and `docs/audits/chapter_9_audit.md` explains
every WARN; `--finalize` then marks this note RETIRED. Until then no CRI
number is quoted anywhere.

## N39. Severity bands are global; the analyst budget is per day  (from Chapter 9)

A band is a fixed CRI threshold on every day; the Chapter 6-8 budget is the
top-k user-days of each day. They answer different questions and can
disagree on quiet or busy days.

- Chapter 12's alert policy says which it uses (band, per-day top-k, or
  both) and reports alerts per day for it.
- Chapter 16 reports both views for every CRI variant.

## N40. The default CRI ranks below the anomaly score on validation  (from Chapter 9 runs)

Full / user validation, primary view (`experiments/chapter9_validation_readout.json`):
PR-AUC 0.915 for the served anomaly score against 0.694 for the default CRI.
Leave-one-out: without peer deviation 0.824, without user context 0.822,
without historical deviation 0.653. Insiders caught at top-1 went from 9/14
to 11/14; scenario-1 days at top-1 from 7/19 to 9/19; scenario-2 days from
125/179 to 110/179.

- Peer deviation and user context are what lower the ranking; removing
  either recovers most of the loss. Historical deviation is the one
  component whose removal makes the CRI worse.
- The scenario-1 gain is consistent with the Chapter 9 hypothesis (the
  historical component recovers some of what XGBoost misses and TabNet
  finds), but it is two days and two insiders out of six; descriptive only.
  TabNet's anomaly score still does better on scenario 1 (14/19, 6/6).
- user_context produced no scenario-3 gain on validation (N36 still holds
  for any future claim).
- The weights stay as fixed (N37). A configuration without peer deviation
  and user context looks better here, but it was found by looking at
  validation; if it is ever adopted it is recorded as validation-informed,
  and only the Chapter 16 test readout can say whether it holds.
- Chapter 12 must choose the analyst-queue ordering explicitly (anomaly
  score, CRI, or anomaly score with the CRI band as context) and must not
  assume the CRI improves detection. It reports the choice and both views.
- Chapter 16 ablation C reads, on test and once: the anomaly score, the
  default CRI and every leave-one-out variant.

