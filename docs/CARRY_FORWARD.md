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
| N41 MITRE rules touch public scenario behaviour | 11, 16, 19 (reporting) |
| N42 the MITRE layer is model-free | 11, 12, 13, 14, 16 |
| N43 MITRE rules fixed a priori; its test readout is Chapter 16 | 16, 19 (reporting) |
| N44 Chapter 10 status (RETIRED) | - |
| N45 a technique is context, not a model reason | 11, 12, 14 |
| N46 MITRE lifts scenario 1 and costs scenario 2 (validation) | 11, 12, 14, 16, 19 (reporting) |
| N47 explanations add up to the served margin | 12, 13, 14, 16 |
| N48 KernelSHAP corroborates, it never explains | 12, 14, 16, 19 (reporting) |
| N49 Chapter 11 status (RETIRED) | - |
| N50 Chapter 12 persists explanations; one explanation per score | 12, 13, 14 |
| N51 the TabNet mask view is a readout, not a reason | 14, 16, 19 (reporting) |
| N52 USB disconnects lead the false alarms (validation) | 12, 14, 16, 19 (reporting) |
| N53 TabNet and XGBoost explain the same days differently (validation) | 16, 19 (reporting) |
| N54 Chapter 12 status (RETIRED) | - |
| N55 the alert queue is ordered by the anomaly score (validation-informed) | 13, 14, 16, 19 (reporting) |
| N56 an idle user-day never takes a top-k slot | 13, 14, 16 |
| N57 suppressed alerts are kept, and what they hide is reported | 13, 14, 16, 19 (reporting) |
| N58 a load is one transaction; the audit row is the claim | 13, 15, 17 |
| N59 the demo sample is validation and test users only | 14, 15, 16, 19 (reporting) |
| N60 deduplication folds continuing scenario-2 activity; most missed days are in no alert | 14, 16, 19 (reporting) |
| N61 the alert queue and the earlier daily top-k readouts rank different populations | 16, 19 (reporting) |
| N62 Chapter 13 status (RETIRED) | - |
| N63 the API serves PostgreSQL only; coverage is the D-6 rows | 14, 15, 16, 19 (reporting) |
| N64 scores computed over HTTP are never stored | 14, 15, 17 |
| N65 analysts are created by CLI; every login is audited | 14, 15, 18 |
| N66 every list is paginated with a hard cap of 200 | 14, 17, 18 |
| N67 a route is one return of a service call | 14, 17, 18 |
| N68 /health's routes block is the readiness signal | 14, 15, 18 |

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

## N41. The MITRE rules touch behaviour the public scenarios describe  (from Chapter 10)

The four rules (`app/mitre/mapping_rules.py`) were written from the ATT&CK
19.2 definitions and the Chapter 5 column definitions, never from answer
files or from which users a rule fires on. But the public r4.2 scenario
descriptions are known, and three rules touch behaviour they name:
removable-media copies (R01), a leak site (R02), a keylogger site (R04).

- A scenario gain from `mitre_context` is partly by construction of the
  dataset, like user_context and scenario 3 (N36). Never cite it on its own;
  report it next to the `no_mitre_context` ablation.
- The readout carries this disclosure in its `disclosure` field; the audit
  and the Chapter 19 write-up repeat it.
- Any new rule follows N7's provenance rule: added by technique and by
  column meaning, reviewed label-blind, with a ruleset version bump.

## N42. The MITRE layer is model-free  (from Chapter 10)

The enrichment reads only Chapter 5 behaviour columns, never an anomaly
score. Its rarity reference is fitted on the validation users of the shared
split file (N11), not on a model's batch. The served XGBoost and the shadow
TabNet rank user-days very differently (validation Spearman 0.285); a
technique on a user-day must not change with the served model.

- A `CIRA_SERVED_MODEL` rollback needs no MITRE refit. The CRI that consumes
  `mitre_context` still needs its own recalibration (N29, N33).
- No module under `app/mitre/` except `evaluate.py` may read a score. The
  verifier FAILs a run or reference holding a model column.
- `evaluate.py` reads the shadow's scores for the disagreement view only
  (N32 monitoring). Nothing is ensembled.

## N43. MITRE rules are fixed a priori; its test readout is Chapter 16  (from Chapter 10)

The ruleset `c10-rules-v1` (hash in every run) and the MITRE weight (0.10,
unchanged since Chapter 9) were fixed before any MITRE number existed.
Chapter 10 reads MITRE context on validation only, once
(`experiments/chapter10_validation_readout.json`).

- Guard `c10-mitre-guard-v1` WARNs on any validation loss of the CRI with
  MITRE against the CRI without it. A WARN is explained in the audit; it is
  never a reason to change a rule, a grade or the weight.
- A later rule change is a new ruleset version, refit with
  `python -m app.mitre.calibrate --supersede "<reason>"`, recorded with
  whether validation numbers informed it.
- The test readout is Chapter 16's ablation D, once.
- The benign mapped share (how many ordinary user-days carry a technique)
  is quoted next to any MITRE detection number. It is the analyst's cost.

## N44. Chapter 10 is PARTIALLY IMPLEMENTED until real runs exist  (from Chapter 10)

RETIRED (chapter 10, runs verified; see `docs/audits/chapter_10_audit.md`).

The MITRE code is tested on synthetic data only. The technique table is
real: it was generated from the pinned ATT&CK 19.2 bundle (sha256
`dc1639ca...`). Chapter 10 becomes IMPLEMENTED when all of the following
hold on the full profile:

- `experiments/chapter10_mitre_reference.json` is pinned by
  `python -m app.mitre.calibrate --profile full` and committed;
- a full enrichment run and a `cri.batch --with-mitre` run pass
  `scripts/verify_chapter10.py --no-readout` with 0 FAIL, and
  `scripts/verify_chapter9.py --cri-run-id <mitre run> --no-readout`
  with 0 FAIL;
- the validation readout is written once and the verifier passes again
  with it;
- `/health` shows the `mitre` block loaded on the development machine;
- `docs/audits/chapter_10_audit.md` records those runs and explains every
  WARN.

Until then no MITRE number on CERT is quoted anywhere. Mark this note
RETIRED when that is done.

## N45. A technique is context, not a model reason  (from Chapter 10)

A mapped technique says what ATT&CK calls the observed behaviour. It does
not say why the model scored the user-day (N30).

- Chapter 11 lists MITRE matches in their own section, with the rule, the
  triggering column and value, and the evidence grade. It never presents
  them as model factors.
- An `indicated` match is shown as indicated: "visited a leak site", never
  "exfiltrated data". r4.2 records no upload, bytes or method (N9).
- An `unmapped` user-day is shown as unmapped, with its
  `mitre_unmapped_behaviours` tags. Job search is shown as "no ATT&CK
  technique", not left blank.
- The dashboard never shows the MITRE points of a benign-looking day as an
  accusation. Most mapped days are ordinary (N43, benign mapped share).

## N46. MITRE lifts scenario 1 and costs scenario 2 on validation  (from Chapter 10 runs)

Full / user validation, primary view (`experiments/chapter10_validation_readout.json`), served
gbdt v0003:

| Ranking | PR-AUC | Caught@1 | s1 days@1 | s2 days@1 | s3 days@1 |
|---|---|---|---|---|---|
| anomaly score | 0.915 | 9/14 | 7/19 | 125/179 | 2/4 |
| CRI without MITRE | 0.694 | 11/14 | 9/19 | 110/179 | 1/4 |
| CRI with MITRE | 0.557 | 13/14 | 13/19 | 93/179 | 1/4 |
| TabNet anomaly score (reference) | 0.749 | 12/14 | 14/19 | 97/179 | 0/4 |

Of the 8 scenario-1 days TabNet caught and XGBoost missed at top-1, all 8 are mapped and the CRI with
MITRE puts 6 at top-1 (2 without). MITRE context alone reaches 12/19 scenario-1 days and 0/179
scenario-2 days. 27% of benign validation user-days carry a mapped technique.

- The scenario-1 gain is partly by construction (N41), from six insiders and one seed. Never quote it
  without the `no_mitre_context` row, the benign mapped share and that caveat.
- The scenario-2 loss (110 to 93 days) drives the PR-AUC drop (0.694 to 0.557). Its mechanism is not
  established; the likely one is weakly graded common matches losing daily top-1 slots to rarer ones.
  Do not state it as shown.
- Rules, grades and the MITRE weight stay as fixed (N43). A configuration found by looking at this
  readout is validation-informed and is recorded as such.
- Chapter 12 must choose the analyst-queue ordering explicitly (N40). No ordering dominates on
  validation: the anomaly score ranks best overall, the CRI with MITRE catches the most insiders at
  top-1. The choice and both views are reported.
- The severity bands shifted when MITRE joined (HIGH 245 to 151, CRITICAL 2 to 0 over all rows)
  because renormalisation lowered the anomaly weight to 0.600. Chapter 12's band policy uses the
  with-MITRE run's volumes, not Chapter 9's.
- Chapter 16 ablation D reads the anomaly score, the CRI with and without MITRE, and MITRE alone on
  test, once, per scenario, with seeds and bootstrap intervals, before anything beyond "on validation"
  is claimed.

## N47. Explanations add up to the served margin  (from Chapter 11)

The model-side explanation of an XGBoost score is XGBoost's own TreeSHAP with
`iteration_range = (0, best_iteration + 1)`. Its contributions plus the
expected value must equal the margin the served model produces (1e-3), and
that margin must equal the Chapter 8 batch's `raw_score` (1e-4). A row that
does not add up is refused, never explained.

- An explain run belongs to one served model_version and one Chapter 8
  batch. A new served model, a rollback or a new batch means a new explain
  run; the batch refuses a batch scored by another model (N30).
- Contributions are in log-odds of the margin. They are written as "raised /
  lowered the score by x log-odds", never as a change in probability (N20).
- Any later code that computes TreeSHAP (the dashboard, Chapter 16) goes
  through `app.explainability.shap_explainer.TreeShapExplainer`, so the
  iteration range and the additivity check come with it.

## N48. KernelSHAP corroborates, it never explains  (from Chapter 11)

KernelSHAP runs on a bounded, label-free set (`c11-selection-v1`), against a
background of 50 training user-days of the served model, with
`nsamples = 2 * M + 2048` (C11-2, C11-3). It estimates interventional SHAP;
TreeSHAP computes the path-dependent value. They are expected to differ.

- KernelSHAP values are never shown to an analyst as a reason. They are an
  agreement statistic next to the explanation.
- Low agreement or a weak deletion check is a verifier WARN, explained in
  the audit. It is never a reason to change the model or the explainer.
- Agreement is not evidence that an explanation is correct, and it is not a
  detection metric. Report it as "two estimators agree on N of M rows".

## N49. Chapter 11 is PARTIALLY IMPLEMENTED until real runs exist  (from Chapter 11)

RETIRED (chapter 11, runs verified; see `docs/audits/chapter_11_audit.md`).

The explainability code is tested on the synthetic tree only, with real
XGBoost and TabNet models trained there. Chapter 11 becomes IMPLEMENTED when
all of the following hold on the full profile:

- a full explain run (`python -m app.explainability.batch --profile full`)
  passes `scripts/verify_chapter11.py --profile full --no-readout` with 0 FAIL;
- the validation readout is written once
  (`python -m app.explainability.evaluate --profile full`) and the verifier
  passes again with it;
- `/health` shows the `explainability` block loaded on the development
  machine;
- `docs/audits/chapter_11_audit.md` records the run ids, the wall-clock and
  peak RSS of the batch, and explains every WARN (including KernelSHAP
  agreement and any guard warning).

Until then no explanation statistic on CERT is quoted anywhere. Mark this
note RETIRED when that is done.

## N50. Chapter 12 persists explanations; one explanation per score  (from Chapter 11)

HCEA D-5 caches explanations in `AlertReason`. Chapter 11 writes them to
Parquet and `reasons.jsonl` (C11-5).

- Chapter 12 creates `AlertReason` rows from `build_explanation` output for
  its alert rows, keyed by user-day, model_version and explain_run_id. Every
  row keeps its section (`model`, `cri` or `mitre`) and its `source`, so a
  reason can be traced back through the §37 lineage chain.
- Alert rows that are not in the bounded set are explained on demand
  through the same builder; TreeSHAP for every row is already in the explain
  run. An alert whose explanation cannot be built is still persisted, with
  status `model_explanation_deferred` and the reason (§36).
- The risk row and the attributions of one explanation must come from the
  same score: the builder refuses a mismatch, and Chapter 12 must not work
  around it by mixing runs.
- The dashboard (Chapter 14) shows the three sections separately, with their
  headings, and never presents a CRI point or an ATT&CK match as a model
  factor (N34, N45).

## N51. The TabNet mask view is a readout, not a reason  (from Chapter 11)

With XGBoost served, TabNet's masks exist only in the validation readout's
"second model's view", computed on the shadow model (N30, N32).

- The dashboard does not show masks for an alert. If a mask panel is ever
  added, it is labelled as the shadow model's view and appears apart from
  the explanation.
- The Chapter 19 write-up can cite the mask view as the evidence for or
  against "the case for TabNet rests on its masks" (N23, N26), with its
  caveats: validation only, one seed, per scenario, six scenario-1 insiders
  (N15), and partly by construction where a feature matches a public
  scenario description (N41).
- If TabNet is ever served, its masks become the model-side explanation
  automatically (`explainer_for`), and they are worded as attention, never
  as "raised the score".

## N52. USB disconnects lead the false alarms  (from Chapter 11 runs)

Full / user validation, primary view (`experiments/chapter11_validation_readout.json`), served gbdt
v0003: on the 366 benign validation days in the served model's daily top-1, the top raising factor is
`usb_disconnect_count` on 192 (52%), and the device domain supplies half of their top-three factors.
The same feature leads 38 of 179 scenario-2 malicious days.

- It is the explanation an analyst would read most often on a wrong alert. Chapter 12's alert policy
  reports how many alerts it leads, and Chapter 14 shows the value next to it (a count of
  disconnects, not a claim about data).
- Why the model weights it this way is not established. One seed, validation only.
- Nothing is retuned on this. A model or feature change motivated by it is validation-informed and is
  recorded as such; only Chapter 16's test readout can say whether it holds.

## N53. TabNet and XGBoost explain the same days differently  (from Chapter 11 runs)

On the same malicious validation days, the shadow TabNet's top-five mask features and the served
XGBoost's top-five TreeSHAP features overlap by a mean Jaccard of 0.053 (scenario 1), 0.065
(scenario 2) and 0.156 (scenario 3, four days). TabNet's top mask feature is `usb_off_hours_events`
on 15 of 19 scenario-1 days and 112 of 179 scenario-2 days, and `is_weekend` on 31 scenario-2 days.
XGBoost's top factor is `http_leak_paste_count` on 15 of 19 scenario-1 days and
`peer_dev_http_request_count` on 114 of 179 scenario-2 days.

- The write-up can say the two models rely on different evidence. It cannot say either is right for
  the right reasons: both leading features match public scenario descriptions (N41), and a mask is
  attention, not direction (N51).
- TabNet's calendar-led days (31 of 179 in scenario 2) are reported next to any claim that its masks
  make TabNet the more interpretable model (N23, N26).
- Chapter 16 repeats the comparison on test, per scenario, with seeds, before anything beyond "on
  validation" is claimed.

## N54. Chapter 12 is PARTIALLY IMPLEMENTED until real runs exist  (from Chapter 12)

RETIRED (chapter 12, runs verified and loaded, `/health` alerts block loaded; see
`docs/audits/chapter_12_audit.md`).

The alert code, the migration (`9f3b2c7d4e81`), the verifier and the tests
pass on the synthetic chain and on a local PostgreSQL 16. No alert run exists
on CERT r4.2 full. Chapter 12 becomes IMPLEMENTED when all of the following
hold on the full profile, against the served gbdt model and the explain run
the alert run names:

- `alembic upgrade head` runs on the development machine's PostgreSQL;
- a full alert batch (`python -m app.alerts.batch --profile full`) passes
  `scripts/verify_chapter12.py --profile full --no-readout` with 0 FAIL;
- the load (`python -m app.alerts.load --profile full`) reports STORED and
  the verifier passes again with `--database-url`;
- the validation readout is written once (`python -m app.alerts.evaluate
  --profile full`) and the verifier passes with it;
- `/health` shows `alerts` loaded and `database` reachable;
- `docs/audits/chapter_12_audit.md` records the run ids, the policy hash, the
  wall-clock and peak RSS of the batch and the load, the events read, and
  explains every WARN.

Progress (1 October 2026): run `20261001T062628Z-full-alerts` is verified,
loaded and read, and `docs/audits/chapter_12_audit.md` is written. The first
`/health` check showed `alerts` unavailable because the runtime looked for a
`dev` run (C12-13); after the fix it shows the run loaded.

CERT alert numbers are quoted from the audit only, with the run id and the
policy hash. The synthetic numbers in the chapter document show the plumbing
works and nothing else.

## N55. The alert queue is ordered by the anomaly score  (from Chapter 12)

`c12-alert-policy-v1` orders the analyst queue, and picks the daily top-k, by
the served anomaly score. The CRI band is shown beside it as context and is
the second trigger. This choice was made after N40 and N46 were known (on
validation the anomaly score ranks above the default CRI), so it is
validation-informed and recorded as such in `alert_meta.json`
(`queue.validation_informed`, `queue.why`).

- Every alert readout reports both views: the policy as built and the same
  policy with `--ordering cri_score`, recomputed from the same risk run.
  Neither is quoted without the other.
- The dashboard (Chapter 14) sorts by the anomaly score by default and shows
  the CRI and its band on every row. It does not re-sort by CRI silently, and
  a CRI sort, if offered, is labelled as the other view.
- Chapter 13's alert routes return both values and say which one ordered the
  queue. They never recompute either (N34).
- Chapter 16 decides on test whether the ordering holds, per scenario
  (N15). If the policy changes after that, it gets a new version and a new
  hash; the old runs stay as they are.

## N56. An idle user-day never takes a top-k slot  (from Chapter 12)

With `require_activity` on (the default), a user-day whose
`total_event_count` is 0 cannot be in the daily top-k. It can still trigger
through the CRI band. The rule was added while building on the synthetic
chain, after the daily top-1 picked an idle weekend day; no CERT number
informed it (C12-4).

- Chapter 13's scoring and alert routes apply the same rule through
  `app.alerts.policy`, not a copy of it.
- Chapter 16 reports how many top-k slots the rule changed on the full
  profile (`activity_rule_view` in the batch summary) before calling it
  neutral. On run `20261001T062628Z-full-alerts` it changed the top-1 on 38
  of 501 dates (76 user-days, two per changed date); see N61.
- Turning it off (`--allow-inactive-top-k`) is an override: recorded in the
  run's meta and a WARN in the verifier.

## N57. Suppressed alerts are kept, and what they hide is reported  (from Chapter 12)

Deduplication does not delete. A suppressed alert is stored with status
`suppressed` and `duplicate_of` pointing at the open alert whose pattern it
repeats (same user, inside the cooldown, signature covered, signature not
empty). Suppressed alerts leave the queue but stay in Parquet and
PostgreSQL (C12-9).

- Every alert count quoted anywhere sits next to the suppressed count.
- The validation readout lists malicious days that sit only in suppressed
  alerts and insiders whose only alerts were suppressed. Guard
  `c12-alert-guard-v1` WARNs on either, and the audit explains each one.
- The dashboard (Chapter 14) lets an analyst open the suppressed alerts of an
  open one. It never shows a suppressed alert as resolved or benign.
- Chapter 16 reports alert precision and insiders caught with and without
  deduplication.

## N58. A load is one transaction; the audit row is the claim  (from Chapter 12)

`python -m app.alerts.load` writes one alert run, its lineage rows and an
`audit_logs` row with action `alert_run_loaded` in one PostgreSQL
transaction. Either all of it is stored or none of it is. A failure prints
NOT STORED and exits 3; a run already loaded is refused (exit 2). The load
verifies the model artifacts by sha256 before writing (N21).

- "This alert run is in the database" means the audit row exists. Code that
  needs to know (Chapter 13's routes, `/health`, the verifier) checks that
  row, not row counts.
- Nothing writes alert rows outside this path. Chapter 13's write routes, if
  any, and Chapter 17's workers (Celery, Kafka consumers) call
  `app.alerts.persistence.persist` or the same transaction shape, and keep the
  audit row in the same transaction.
- A database outage stays visible (§36): a failed write is reported as not
  stored, and `/health`'s `database` block says unavailable. No retry loop
  hides it.
- Chapter 15 repeats the outage tests (refused connection, error mid-load)
  end to end.

## N59. The demo sample is validation and test users only  (from Chapter 12)

`c12-demo-sample-v1` (HCEA D-6) picks a 30-day window and up to 20 users from
the served model's validation and test users, test first, label-free. The
rule is recorded in `configurations` and reproduced by the verifier.

- Screens, screenshots and walkthroughs in Chapters 14 and 19 use this sample
  or alert-linked rows. No training user-day is shown as an example (N31).
- The sample shows test users' alerts. Looking at them is fine; changing the
  policy, a feature or the model because of what they show is test-informed
  and is recorded as such, the same as any other look at test (N15).
- A demo built on a different window or set of users is a new version of the
  rule, with its own hash, not an edit of v1.

## N60. Deduplication folds continuing scenario-2 activity; most missed days are in no alert  (from Chapter 12)

On validation (run `20261001T062628Z-full-alerts`, one seed), 89 of 179
scenario-2 malicious days fall in some alert, and 35 of those sit only in
suppressed alerts. Every such day belongs to an insider who already has an
open alert, so no insider is lost; the analyst loses the sign that the
activity continued. Another 90 scenario-2 days are in no alert at all,
because the queue takes one user-day per date. Guard `c12-alert-guard-v1`
WARNs on the first effect, and the Chapter 12 audit explains it.

- The dashboard (Chapter 14) shows, on every open alert, how many suppressed
  alerts point at it and their date range, and lets the analyst open them
  (N57). "One alert" for a scenario-2 insider can mean weeks of activity.
- Chapter 16 reports per scenario: malicious days in an open alert, only in
  suppressed alerts, and in no alert; with and without deduplication; under
  both orderings (N55). Insiders caught is never quoted alone.
- `usb_disconnect_count` leads 44 of 90 false-alarm validation alerts (49%)
  under the policy, close to the 52% of benign top-1 days in Chapter 11. N52
  holds at alert level.
- 54 of 232 open alerts (23%) never rise above LOW on the CRI; they are in the
  queue on the anomaly score alone. The band is shown on every row (N55).
- Nothing in `c12-alert-policy-v1` changes because of these validation
  numbers.

## N61. The alert queue and the earlier daily top-k readouts rank different populations  (from Chapter 12)

The daily top-k readouts of Chapters 8 to 10 apply no activity rule. The
Chapter 12 queue applies `require_activity` (N56): on the full run, an idle
user-day had the top anomaly score on 38 of 501 dates, and the queue gives
that slot to the next active user-day. The queue also ranks validation and
test users together, as an analyst would see them, so its population need not
match the one a readout ranked.

- A daily top-k figure from Chapters 8 to 10 is not an alert-queue figure.
  When Chapter 16 or the report puts them side by side, it says which
  population each one ranks and whether idle days could take a slot.
- The ordering trade-off on validation (alert precision 0.211 with 114 open
  alerts under the anomaly score; 0.190 with 153 under the CRI; scenario 2
  caught 5 of 6 against 6 of 6) is quoted with both columns or not at all
  (N55). Chapter 16 reads it on test.
- That the anomaly score rates idle days so high on 38 dates is a property of
  the served model, not established as a cause of anything. Chapter 16 may
  look at it; it is not a reason to change the model now.

## N62. Chapter 13 is PARTIALLY IMPLEMENTED until the API serves CERT full  (from Chapter 13)

RETIRED (chapter 13, API verified on CERT full with 28 PASS / 0 FAIL and the integration tests
passing through testcontainers; see `docs/audits/chapter_13_audit.md`).

The API, the verifier and the tests pass on the synthetic chain, against a
local PostgreSQL 16 (`CIRA_TEST_DATABASE_URL`) and against SQLite: 459
passed, 1 skipped for the whole suite. Chapter 13 becomes IMPLEMENTED when
all of the following hold on the development machine:

- `SECRET_KEY` is a real secret in `.env` and an analyst exists
  (`python -m app.services.accounts create`);
- the API (`uvicorn app.main:app`) serves alert run
  `20261001T062628Z-full-alerts` and `/health` shows every route group ready;
- `scripts/verify_chapter13.py --database-url` runs with 0 FAIL against it;
- `python -m pytest backend/tests/integration/test_ch13_api.py` runs with
  Docker available and no `CIRA_TEST_DATABASE_URL`, so the testcontainers
  branch is exercised (the Bible's acceptance item), and
  `test_database_is_postgres` passes;
- `docs/audits/chapter_13_audit.md` records the verifier output, the
  re-scoring differences, the latency and explains every WARN.

Until then no API number on CERT is quoted anywhere. Mark this note RETIRED
when that is done.

## N63. The API serves PostgreSQL only; coverage is the D-6 rows  (from Chapter 13)

Routes read the loaded alert run's rows: alert member days and the
c12-demo-sample-v1 window (HCEA D-6). A user's risk history and event
timeline cover those days only; every coverage block says so (C13-5).

- The dashboard (Chapter 14) shows the coverage note next to every history
  chart and timeline, and never draws a gap between persisted days as
  "no risk".
- A wider history needs a larger D-6 sample (a new demo rule version, N59),
  not a Parquet reader in the API: that would tie the API to the dataset
  mount and could put training users' days on screen (N31).
- The run served is chosen by audit row and served model (N28, N58), never
  by row count or by `CIRA_PROFILE`.

## N64. Scores computed over HTTP are never stored  (from Chapter 13)

`POST /api/v1/anomaly/score` and `POST /api/v1/risk/score` compute and
return; they write nothing (HCEA §8, N58). Their purpose is reproducing a
stored decision and explaining a user-day that has no stored explanation.

- `by_top_k` is always null there: a single user-day cannot be ranked
  against its day. A route that claims a top-k result for one day is wrong.
- Chapter 15 can use the re-scoring check (stored vector -> same anomaly
  score and CRI) as its end-to-end lineage test.
- Chapter 17 workers that persist scores go through the batch and
  `app.alerts.persistence`, not through these routes.

## N65. Analysts are created by CLI; every login is audited  (from Chapter 13)

There is no registration route. `python -m app.services.accounts` creates and
deactivates analysts, and every account change and login attempt writes an
`audit_logs` row (`analyst_*`). Tokens are HS256, signed with `SECRET_KEY`,
which must be a real secret of at least 32 characters.

- The dashboard (Chapter 14) signs in through `POST /api/v1/auth/token` and
  sends the bearer token; it never stores a password.
- Role checks, refresh tokens, lockout and rate limiting are Chapter 18. Until
  then `analyst` and `admin` read the same data.
- Any new audit action keeps a name other than `alert_run_loaded` (N58).

## N66. Every list is paginated with a hard cap of 200  (from Chapter 13)

`/alerts`, `/events` and `/investigations` take `limit` (default 50, maximum
200, a 422 above it) and `offset`, and return `page.total` and
`page.max_limit` (HCEA §13). `/events` requires a `user_id`. Charts get
server-side aggregates (`/risk/overview`, `/risk/users/{user}/history`).

- Chapter 14 pages through lists and never asks for "all".
- Any new list route follows the same shape; the OpenAPI unit test fails
  otherwise.

## N67. A route is one return of a service call  (from Chapter 13)

Routers in `app/api/v1/` contain one `return` per handler and import only
FastAPI, the dependencies, schemas and services. Services never import
FastAPI. API, services and schemas never import label or offline code (N5).
`backend/tests/unit/test_ch13_api_rules.py` enforces all three statically.

- Chapters 17 and 18 (SSE, auth hardening) add routes under the same rule.

## N68. /health's routes block is the readiness signal  (from Chapter 13)

The top-level `status` still means "an anomaly model is loaded" (C8-7). The
`routes` block says, per route group, whether it can answer now and why
not; the alert/risk/investigation group names the run it would serve.

- The dashboard (Chapter 14) reads `routes` to show a precise "not ready"
  message instead of a generic error.
- Chapter 15's outage tests check `routes` as well as `database`.
- Chapter 18's container healthcheck can keep calling `/health` at the root.

