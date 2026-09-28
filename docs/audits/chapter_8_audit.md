# Chapter 8 audit (28 September 2026)

Scope: Chapter 8 (anomaly scoring and serving), checked against the Bible Chapter 8 acceptance
list, HCEA v1.0 §8 and CARRY_FORWARD N1-N32.
Evidence: `experiments/runlog.jsonl`, `experiments/chapter8_serving_decision.json`,
`experiments/chapter8_test_readout.json`, `experiments/chapter8_reference_runs.json`, and the
`scripts/verify_chapter8.py` output of each run (logs under `experiments/results/chapter8/signoff_logs/`,
gitignored). Every number below is copied from those files by `scripts/signoff_chapter8.py`.

Result: every verification finished with 0 FAIL. The served model is **gbdt v0003** (`gbdt-chapter8-v1-077a3dae6cee`), chosen by rule `c8-serving-rule-v1` on validation.
Deviation C8-1: applies (XGBoost is served instead of the Bible's TabNet).

## Candidate runs (behaviour-only XGBoost)

| Profile / split | Run id | Registry | model_version | scale_pos_weight | Best iteration | Fit (s) | Peak RSS (MB) |
|---|---|---|---|---|---|---|---|
| mid/user | `20260928T194650Z-mid-user-s42` | v0001 | `gbdt-chapter8-v1-077a3dae6cee` | 117.577 | 312 | 6.67 | 732.5 |
| mid/time | `20260928T194701Z-mid-time-s42` | v0002 | `gbdt-chapter8-v1-077a3dae6cee` | 114.445 | 320 | 4.12 | 739.8 |
| full/user | `20260928T194711Z-full-user-s42` | v0003 | `gbdt-chapter8-v1-077a3dae6cee` | 506.228 | 590 | 42.73 | 1594.6 |

## Verification record

| What | Verifier |
|---|---|
| candidate mid/user (`20260928T194650Z-mid-user-s42`) with permutation test | 17 PASS, 0 WARN, 0 FAIL |
| candidate mid/time (`20260928T194701Z-mid-time-s42`) with permutation test | 15 PASS, 0 WARN, 0 FAIL |
| candidate full/user (`20260928T194711Z-full-user-s42`) with permutation test | 17 PASS, 0 WARN, 0 FAIL |
| decision, served model, batch `20260928T194858Z-full-batch` | 49 PASS, 0 WARN, 0 FAIL |
| test suite | 221 passed, 615 warnings in 118.06s (0:01:58) |

WARNs and why they are acceptable:

- none.

## Permutation test (C7-8 rule, three shuffles)

- mid/user: `PASS leakage    XGBoost on shuffled labels stays near chance (3 shuffles, C7-8 rule)  -- worst shuffled PR-AUC 0.0063; chance 0.0100; 3x-chance bar 0.0300; all [0.0058, 0.0062, 0.0063]`
- mid/time: `PASS leakage    XGBoost on shuffled labels stays near chance (3 shuffles, C7-8 rule)  -- worst shuffled PR-AUC 0.0060; chance 0.0094; 3x-chance bar 0.0294; all [0.0055, 0.006, 0.0058]`
- full/user: `PASS leakage    XGBoost on shuffled labels stays near chance (3 shuffles, C7-8 rule)  -- worst shuffled PR-AUC 0.0014; chance 0.0022; 3x-chance bar 0.0222; all [0.0013, 0.0014, 0.0013]`

## Serving decision (validation, primary view)

Rule `c8-serving-rule-v1`: Serve XGBoost only if its validation PR-AUC exceeds TabNet's by more than 0.10 on full/user and it is also ahead on mid/user and mid/time; otherwise serve TabNet. A candidate that fails a gate (registered + sha256, reportable, full profile, behaviour-only) cannot be served.

Decided 2026-09-28T19:48:48+00:00. Served: gbdt v0003. Shadow: tabnet v0005.

Reason recorded by `select`: XGBoost leads by 0.166 on full/user validation PR-AUC (> 0.1) and is ahead on mid/user (+0.198), mid/time (+0.039)

Difference on full/user (XGBoost minus TabNet): 0.166; mid/user: 0.198, mid/time: 0.039.

Gates: tabnet passed; gbdt passed.

### full/user validation (89018 rows, 202 malicious user-days, chance 0.0023)

| Model | PR-AUC | ROC-AUC (secondary) | Recall@1 | Caught@1 | Days at top-1 by scenario | Insiders caught at top-1 by scenario |
|---|---|---|---|---|---|---|
| TabNet (Ch7 reference) | 0.749 | 0.974 | 0.550 | 12/14 | s1 14/19, s2 97/179, s3 0/4 | s1 6/6, s2 6/6, s3 0/2 |
| XGBoost, behaviour-only (Ch8) | 0.915 | 0.999 | 0.663 | 9/14 | s1 7/19, s2 125/179, s3 2/4 | s1 3/6, s2 5/6, s3 1/2 |
| XGBoost, all features (Ch6 reference) | 0.939 | 1.000 | 0.678 | 9/14 | s1 6/19, s2 129/179, s3 2/4 | s1 3/6, s2 5/6, s3 1/2 |

### mid/user validation (19809 rows, 202 malicious user-days, chance 0.0102)

| Model | PR-AUC | ROC-AUC (secondary) | Recall@1 | Caught@1 | Days at top-1 by scenario | Insiders caught at top-1 by scenario |
|---|---|---|---|---|---|---|
| TabNet (Ch7 reference) | 0.734 | 0.970 | 0.619 | 12/14 | s1 11/19, s2 113/179, s3 1/4 | s1 5/6, s2 6/6, s3 1/2 |
| XGBoost, behaviour-only (Ch8) | 0.932 | 0.998 | 0.668 | 10/14 | s1 7/19, s2 126/179, s3 2/4 | s1 3/6, s2 6/6, s3 1/2 |
| XGBoost, all features (Ch6 reference) | 0.923 | 0.998 | 0.668 | 10/14 | s1 7/19, s2 126/179, s3 2/4 | s1 3/6, s2 6/6, s3 1/2 |

### mid/time validation (5677 rows, 76 malicious user-days, chance 0.0134)

| Model | PR-AUC | ROC-AUC (secondary) | Recall@1 | Caught@1 | Days at top-1 by scenario | Insiders caught at top-1 by scenario |
|---|---|---|---|---|---|---|
| TabNet (Ch7 reference) | 0.947 | 0.982 | 0.276 | 2/8 | s1 0/7, s2 21/69 | s1 0/2, s2 2/6 |
| XGBoost, behaviour-only (Ch8) | 0.986 | 1.000 | 0.276 | 3/8 | s1 0/7, s2 21/69 | s1 0/2, s2 3/6 |
| XGBoost, all features (Ch6 reference) | 0.989 | 1.000 | 0.276 | 4/8 | s1 0/7, s2 21/69 | s1 0/2, s2 4/6 |

## Test readout (read once, after the decision)

Read 2026-09-28T19:48:54+00:00; decision sha256 at that time `8ff92939fb89`. Harness check: every recomputed test PR-AUC matches the logged value.

### full/user test (84516 rows, 190 malicious user-days, chance 0.0022)

| Model | PR-AUC | ROC-AUC (secondary) | Recall@1 | Caught@1 | Days at top-1 by scenario | Insiders caught at top-1 by scenario |
|---|---|---|---|---|---|---|
| TabNet (Ch7 reference) | 0.359 | 0.982 | 0.516 | 11/14 | s1 12/16, s2 86/170, s3 0/4 | s1 6/6, s2 5/6, s3 0/2 |
| XGBoost, behaviour-only (Ch8) | 0.827 | 0.998 | 0.721 | 12/14 | s1 9/16, s2 126/170, s3 2/4 | s1 5/6, s2 6/6, s3 1/2 |
| XGBoost, all features (Ch6 reference) | 0.828 | 0.998 | 0.716 | 12/14 | s1 9/16, s2 125/170, s3 2/4 | s1 5/6, s2 6/6, s3 1/2 |

### mid/user test (19042 rows, 190 malicious user-days, chance 0.0100)

| Model | PR-AUC | ROC-AUC (secondary) | Recall@1 | Caught@1 | Days at top-1 by scenario | Insiders caught at top-1 by scenario |
|---|---|---|---|---|---|---|
| TabNet (Ch7 reference) | 0.220 | 0.969 | 0.437 | 9/14 | s1 8/16, s2 75/170, s3 0/4 | s1 3/6, s2 6/6, s3 0/2 |
| XGBoost, behaviour-only (Ch8) | 0.848 | 0.993 | 0.711 | 12/14 | s1 9/16, s2 125/170, s3 1/4 | s1 5/6, s2 6/6, s3 1/2 |
| XGBoost, all features (Ch6 reference) | 0.843 | 0.993 | 0.711 | 13/14 | s1 10/16, s2 123/170, s3 2/4 | s1 5/6, s2 6/6, s3 2/2 |

### mid/time test (17886 rows, 168 malicious user-days, chance 0.0094)

| Model | PR-AUC | ROC-AUC (secondary) | Recall@1 | Caught@1 | Days at top-1 by scenario | Insiders caught at top-1 by scenario |
|---|---|---|---|---|---|---|
| TabNet (Ch7 reference) | 0.888 | 0.993 | 0.268 | 8/14 | s1 1/9, s2 43/157, s3 1/2 | s1 1/5, s2 6/8, s3 1/1 |
| XGBoost, behaviour-only (Ch8) | 0.990 | 1.000 | 0.298 | 9/14 | s1 3/9, s2 45/157, s3 2/2 | s1 2/5, s2 6/8, s3 1/1 |
| XGBoost, all features (Ch6 reference) | 0.991 | 1.000 | 0.298 | 10/14 | s1 4/9, s2 44/157, s3 2/2 | s1 2/5, s2 7/8, s3 1/1 |

## Batch scoring and serving

Batch `20260928T194858Z-full-batch`: 464687 user-days scored by gbdt v0003 on CPU, shadow rows 464687, model_split {"test": 84516, "train": 291153, "validation": 89018}. Saturated served scores: 0. Scoring took 11.03 s; peak RSS 1245.7 MB. Same feature file as training: True.

Served score quantiles: {"0.5": 8.359586229901963e-08, "0.9": 3.545684808121434e-06, "0.99": 0.0005007798893684603, "0.999": 0.9999875442088478}. Rows tagged `train` are in-sample (N31).

`/health` on this machine: healthy, source decision_file, serving gbdt v0003 on cpu.

## Notes

- Every number comes from one seed per model. Chapter 16 adds seeds and bootstrap intervals (C6-2, C7-7).
- The served model's CRI thresholds are tied to its model_version (N29); explanations come from it (N30).
