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
| N14 Chapter 6 status | 16, 19 |

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

The code is tested on synthetic data only. Chapter 6 becomes IMPLEMENTED
when `experiments/runlog.jsonl` has `chapter6_baseline` lines for all five
detectors at mid and full (user split; time split at least at mid). Until
then no baseline number is quoted anywhere. Each of those runs must also
pass `scripts/verify_chapter6.py` with 0 FAIL (the mid user-split run with
`--reload-models --permutation-test`), with every WARN explained in the write-up. Report LOF numbers with
`lof_fit_rows`, `pca_components` and `pca_retained_variance`, and say which
profile every number came from (mid has ~28% insider users, full ~7%).
