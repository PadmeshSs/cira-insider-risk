# Chapter 6: baseline models

Bible Chapter 6 / Architecture Phase 4, executed under HCEA v1.0 §6.

Status: PARTIALLY IMPLEMENTED. The code runs and its 45 tests pass on
synthetic CERT-shaped data (full suite: 129 passed, 1 skipped). No mid or
full run has been done yet, so this document contains no results. It moves
to IMPLEMENTED once the mid and full runs below are in
`experiments/runlog.jsonl` (see N14).

## What was built

| Path | Purpose |
|---|---|
| `backend/app/baselines/base.py` | Shared detector contract, score calibrator, persistence, label-blind user-stratified sampling |
| `backend/app/baselines/preprocess.py` | Train-only median imputation with schema-driven missing indicators (N4); reusable by TabNet in Chapter 7 |
| `backend/app/baselines/rule_based.py` | Rule floor: fraction of 8 fixed presence rules that fire |
| `backend/app/baselines/isolation_forest.py` | Isolation Forest with the HCEA settings |
| `backend/app/baselines/lof.py` | LOF with the HCEA D-2 approximation |
| `backend/app/baselines/lstm_autoencoder.py` | LSTM autoencoder with the HCEA D-3 adjustments and causal scoring |
| `backend/app/baselines/gbdt.py` | Supervised XGBoost baseline |
| `backend/app/baselines/run.py` | Runner: split, fit, score, evaluate, persist, log |
| `backend/app/evaluation/labels.py` | Evaluation-only label loading and in-memory join (N1, N5) |
| `backend/app/evaluation/splitting.py` | User split (saved) and time split (N3) |
| `backend/app/evaluation/metrics.py` | PR-AUC, daily top-k budget metrics, per-scenario recall, per-user detection and latency (N2) |
| `backend/tests/unit/test_ch6_*.py`, `backend/tests/integration/test_ch6_runner.py` | 45 tests |
| `scripts/verify_chapter6.py` | Post-run verification: every acceptance check as PASS / WARN / FAIL |
| `backend/tests/fixtures/synthetic_ch6.py`, `synthetic_matrix.py` | Test fixtures only |

`app/evaluation/labels.py` is not in the Bible §2 tree. It exists so that
exactly one module reads `<processed>/labels/`, which makes N5 checkable.
`app/evaluation/ablation.py` is Chapter 16 work and was not created.

`xgboost` was added to `backend/requirements.txt`. It is already in the
Bible's tech-stack table, so this is not an addition requiring approval.

## The detector contract

Every detector takes a DataFrame with `user_id`, `date` and the Chapter 5
feature columns.

```text
fit(train, y=None, *, validation=None, y_validation=None) -> self
raw_score(frame)  -> native anomaly measure, higher = more anomalous
score(frame)      -> [0, 1], higher = more anomalous
save(dir) / load(dir)
```

Unsupervised detectors raise if they are handed labels. The supervised one
raises if it is not.

`score` applies `sigmoid(asinh((raw - median) / scale))`, with median and
robust scale taken from training scores only. The map is strictly monotone,
so PR-AUC and top-k results are the same on raw and calibrated scores. The
`asinh` step keeps float64 scores distinct even for LOF values far above the
median; a plain sigmoid saturates to exactly 1.0 and creates ties at the top
of the alert queue. The rule baseline (a fraction) and GBDT (a probability)
are already in [0, 1] and skip calibration.

Each saved model has a `meta.json` holding model version, config, seed,
profile, split mode, run id, feature fingerprint, fit and score wall-clock,
and process peak RSS (HCEA §6.3). Peak RSS is the process high-water mark at
that point, so in a multi-model run it is cumulative, not per model.

## The five baselines

Rule-based. Eight fixed rules, each "count > 0" on one or two columns:
off-hours logon, weekend logon, off-hours USB, logon to a new PC, job-search
hosts, cloud-storage or leak/paste hosts, hacking-tool hosts, zip/exe file
activity. Thresholds were not tuned on labels. The rules are generic
insider-risk indicators, but they overlap with the published CERT scenario
descriptions, so treat this floor as optimistic. Scores are heavily tied;
the metrics break ties at the daily budget with a seeded random key rather
than by user id.

Isolation Forest. `n_estimators=100`, `max_samples=256`, fixed
`random_state`, `n_jobs` from `CIRA_MAX_WORKERS`. Input is the imputed
matrix plus missing indicators, unscaled.

LOF (HCEA D-2). Imputation and indicators, then signed `log1p`, then
`StandardScaler`, then PCA to 20 components; scaler and PCA are fitted on
the whole training split. `LocalOutlierFactor(n_neighbors=20, novelty=True)`
is fitted on at most 50,000 training rows sampled in proportion per user
(label-blind). Scoring runs in 50,000-row chunks. The calibrator is fitted
on a second sample of training rows LOF was not fitted on, because scoring
the fit points of a novelty LOF is biased. `lof_fit_rows`,
`pca_components` and `pca_retained_variance` are in the metadata and have
to be reported next to every LOF number.

LSTM autoencoder (HCEA D-3). 36 core count/volume columns
(`CORE_COLUMNS`), all with the Chapter 5 "zero" null policy; a null there
raises. `log1p` then train mean/std. Window 30 days, training stride 7,
windows cut lazily from one float32 array. Encoder and decoder LSTM, hidden
64, one layer, batch 128, `num_workers=0`, AMP only on CUDA, Adam 1e-3, up to
20 epochs with patience 3 on validation reconstruction loss (validation
users' windows, no labels). A checkpoint is written every epoch and a re-run
resumes from the latest one. The checkpoint key includes a fingerprint of
the feature file and split, so weights from an older matrix are never
reused.

GBDT. XGBoost, `tree_method="hist"`, native null handling, 600 trees at
learning rate 0.05 with early stopping on validation PR-AUC (`aucpr`),
`scale_pos_weight` = negatives / positives on the training split. Labels
come from the primary view. Masquerade account-days are removed from
training and validation, not only from evaluation. CatBoost is not
implemented.

## Splits

User split (default). Insiders are allocated per scenario by largest
remainder over a seeded-hash order: 18/6/6, 18/6/6 and 6/2/2 users at
60/20/20. Benign users go by a seeded-hash threshold. Neither rule depends
on who else is in the population, so every user lands in the same split in
mid and in full, which a test checks. The assignment is written to
`experiments/splits/user_split_<profile>_seed<seed>.json` with aggregate
counts and nothing label-like per user. Later runs load that file. If it no
longer matches the population or seed, the runner stops and asks for
`--rebuild-split` instead of overwriting it.

Time split (`--split time`). Defaults: train before 2011-01-01, validation
January 2011, test from 2011-02-01. The data starts 2010-01-02, so that is
roughly the 13-month / 4-month split from HCEA §7.5. The LSTM scores
validation and test days with the earlier rows as history; nothing later
than the scored day is ever inside its window.

## Metrics

Computed per split (validation and test) for each detector, written to
`experiments/results/chapter6/<run_id>/metrics.json`:

* primary view: rows, excluded rows, positives, positive rate, PR-AUC,
  ROC-AUC (labelled secondary), and for each daily budget k (default 1, 5,
  10): alerts, TP, FP, precision, recall, recall per scenario, insiders
  caught per scenario, and detection latency in days for caught insiders;
* the same block once for the account view;
* the count of rows whose label differs between the two views.

Masquerade account-days are ranked with everyone else, since a real queue
would contain them, but an alert on one counts as neither TP nor FP.
Accuracy is not computed anywhere.

`experiments/results/` is gitignored. The committed evidence is the
`experiments/runlog.jsonl` line per detector, which carries the test
headline numbers, row counts, wall-clock, peak RSS and feature fingerprint.

## How to run

From `backend/`, with `.env` pointing at `D:/CIRA_dataset/...`:

```bash
python ../scripts/build_labels.py                      # if labels are not built yet
python -m app.baselines.run --profile dev              # debugging only, never reported
python -m app.baselines.run --profile mid              # user split, all five detectors
python -m app.baselines.run --profile mid --split time
python -m app.baselines.run --profile full             # after the full Chapter 5 run
python -m app.baselines.run --profile full --split time
```

Useful flags: `--models isolation_forest,lof`, `--budgets 1,5,10`,
`--device cpu`, `--lstm-max-epochs 20`, `--no-save-models`.

The runner stops if a label day inside a user's feature date range has no
feature row, if mid/full has any label day outside that range (dev is
exempt because it cuts the calendar to Jun-Aug 2010), if a split
is empty, or if the saved split does not match. Wall-clock and memory on
your machine have not been measured; the first mid run is where to get
them. Do not run the frontend dev server alongside a full run (HCEA §13).

## Verification

After each run, from `backend/`:

```bash
python ../scripts/verify_chapter6.py --profile mid                      # newest mid user-split run
python ../scripts/verify_chapter6.py --profile mid --reload-models --permutation-test
python ../scripts/verify_chapter6.py --profile mid --compare-run-id <earlier run id>
python ../scripts/verify_chapter6.py --profile mid --split time
```

It checks the run record, feature file, label coverage and published
counts, the split (reproducible from the seed, stratified, disjoint, stable
between mid and full), masquerade exclusion, every score file, runlog lines,
peak RSS against the HCEA budget, required metadata, and LOF / LSTM / GBDT
specifics. The options add a reload test (saved models must reproduce the
stored scores), a label-permutation test (GBDT on shuffled training labels
must stay near chance; if it does not, labels are leaking), and a
determinism comparison between two runs. Output goes to
`experiments/results/chapter6/<run_id>/verification.json` and one
`chapter6_verification` line in the runlog. Exit code 1 on any FAIL.

Fixed after first delivery: the label-coverage check counted a dev
insider's malicious days outside the Jun-Aug 2010 window as missing, which
would have stopped every dev run. Coverage now only requires label days
inside each user's feature date range, and the runner additionally refuses
out-of-range label days under mid/full. Two regression tests cover this.

## Carry-forward compliance

| Note | How Chapter 6 satisfies it |
|---|---|
| N1 masquerade | Primary view for headlines; masquerade account-days excluded from primary negatives and from GBDT training; account view reported once with the differing-row count; recall per scenario always reported |
| N2 imbalance | PR-AUC and daily top-k budget metrics as headline, per-user detection, ROC-AUC secondary, no accuracy; `scale_pos_weight` from train only; no resampling |
| N3 user split | Each user in one split, insiders stratified by scenario, fixed seed, assignment saved under `experiments/splits/`; time split available; LSTM scoring is causal |
| N4 imputation | Medians fitted on train only; indicators for every column whose schema null policy is "null..."; XGBoost uses native nulls on the same split |
| N5 labels | Only `app/evaluation/labels.py` reads `labels/`; joins happen in memory in a separate frame; score Parquet files hold no labels; a test checks that no baseline module imports label code |
| N6 profiles | dev runs are marked `reportable: false` and flagged on the console; every run appends to the runlog |
| N7 hosts | Not touched |
| N8 resources | `apply_thread_caps()` runs before numpy/torch in `run.py`; `n_jobs` from `CIRA_MAX_WORKERS`; LOF and LSTM follow HCEA budgets; LSTM checkpoints per epoch |
| N9 signals | Rules and LSTM columns use only r4.2 signals; the cloud-storage rule says "visits", not uploads |

## Deviation register additions

| Id | What | Status |
|---|---|---|
| D-2 (HCEA) | LOF via PCA-20 and a 50k user-stratified subsample, as specified. Added: calibrator fitted on a separate held-out training sample | MANDATORY, applied |
| D-3 (HCEA) | LSTM core subset, window 30, stride 7, lazy windows, as specified. Added: scoring uses the window ending on each scored day (stride 1, forward pass only) so no future data is used | MANDATORY, applied |
| C6-1 | CatBoost not implemented; XGBoost is the only GBDT | Scope decision |
| C6-2 | Bootstrap confidence intervals and significance tests left to Chapter 16 | Deferred |
| C6-3 | Unsupervised detectors train on every training row, insiders included; a benign-only variant would need labels and is not done | Scope decision |

## Before reporting any number

* Mid picks the alphabetically first 180 benign users, so about 28% of mid
  users are insiders against about 7% in full. Mid and full numbers are not
  directly comparable; say which profile each number is from.
* The test split holds 14 insiders under the user split, 2 of them from
  scenario 3. Per-user detection moves in steps of about 7 percentage points.
* Report `lof_fit_rows`, `pca_components` and `pca_retained_variance` with
  every LOF result.
* Pick nothing on the test split. Hyperparameters here are fixed; GBDT early
  stopping uses validation only.

## Acceptance checklist

- [x] All four mandatory baselines plus GBDT run end to end on one matrix and produce scores (synthetic data)
- [ ] The same, on the mid profile (user split and time split)
- [ ] The same, on the full profile
- [x] Scores share TabNet's convention: [0, 1], higher = more anomalous, `model_version` on every row
- [x] Each baseline persists model, config, profile, seed, wall-clock, peak RSS (HCEA §6.3)
- [x] No baseline result appears in any document without a run behind it
- [ ] `scripts/verify_chapter6.py` shows 0 FAIL for mid (user and time) and full (user)
