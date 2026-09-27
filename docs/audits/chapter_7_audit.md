# Chapter 7 audit (27 September 2026)

Scope: Chapter 7 (TabNet), checked against the Bible Chapter 7 acceptance
list, HCEA v1.0 §7 and CARRY_FORWARD N1-N23.
Evidence: `experiments/runlog.jsonl` (committed), the split files under
`experiments/splits/`, `models/saved_models/tabnet/registry.jsonl`, and
`scripts/verify_chapter7.py` and `app.evaluation.compare` output per run.
`experiments/results/` and `models/` are gitignored, so per-run
`metrics.json`, `verification.json`, `comparison_*.json` and the registry
artifacts stay on the development machine; the runlog lines are the
committed record.

Result: Chapter 7 is IMPLEMENTED. The adopted TabNet configuration passes
the verifier with 0 FAIL at mid (user and time split) and full (user
split), including reload, label permutation and the comparability checks
against the Chapter 6 reference runs; a from-scratch re-run and an
interrupted-and-resumed run both reproduce its scores exactly. TabNet ranks
insiders far better than every unsupervised baseline and clearly worse than
XGBoost, on validation and on test. That is the result (N23).

## Adopted configuration

HCEA §7.2 settings (n_d = n_a = 16, n_steps = 4, gamma 1.3, sparsemax, Adam
2e-2, StepLR 10/0.9, batch 4096, virtual batch 256, max 100 epochs,
patience 15), class-weighted cross-entropy, early stopping on validation
PR-AUC, CPU, seed 42, and the six static per-user columns removed from the
model input:

```text
--exclude-features psych_,peer_department_size
  -> peer_department_size, psych_agreeableness, psych_conscientiousness,
     psych_extraversion, psych_neuroticism, psych_openness
```

Why they were removed is under "Static-trait ablation" below. The model
sees 166 input columns (the remaining features after preprocessing, plus
missing-value indicators).

## Reported runs

| Profile / split | Run id | Registry | model_version |
|---|---|---|---|
| full / user | `20260927T162456Z-full-user-s42` | v0005 | `tabnet-chapter7-v1-e03b3d0d3360` |
| mid / user | `20260927T125702Z-mid-user-s42` | v0003 | `tabnet-chapter7-v1-5231a85c1c6f` |
| mid / time | `20260927T161717Z-mid-time-s42` | v0004 | `tabnet-chapter7-v1-02d79aff8e79` |

The same ids are in `experiments/chapter7_reference_runs.json`. Chapter 8
and Chapter 16 use these (N24). There is no full / time run; Chapter 6 has
no full time-split baseline to compare with either.

## Verification record

| Run id | What | Verifier |
|---|---|---|
| `20260927T114008Z-dev-user-s42`, `20260927T125632Z-dev-user-s42` | dev smoke runs, never reported | not verified |
| `20260927T114021Z-mid-user-s42` | first mid run, all features (v0001); reload + permutation + baselines | 79 PASS, 1 WARN, 1 FAIL; superseded, not adopted |
| `20260927T121708Z-mid-user-s42` | static-trait ablation (v0002): the adopted configuration, trained from scratch (29 epochs, best epoch 13) | not verified separately; `125702Z` completed from its checkpoints, so v0002 and v0003 hold the same weights, and their registry entries carry identical validation and test metrics |
| `20260927T125702Z-mid-user-s42` | adopted, mid user (v0003); reload + permutation + baselines | 81 PASS, 0 WARN, 0 FAIL |
| `20260927T160614Z-mid-user-s42` | `--fresh` determinism re-run, not registered; compared with `125702Z` | 61 PASS, 2 WARN, 0 FAIL; max score difference 0 |
| `20260927T160956Z-mid-user-s42` | resume test: `--fresh`, killed during epoch 4, resumed after epoch 3; compared with `125702Z` | 61 PASS, 2 WARN, 0 FAIL; max score difference 0 |
| `20260927T161717Z-mid-time-s42` | adopted, mid time (v0004); reload + permutation + baselines | 73 PASS, 0 WARN, 0 FAIL |
| `20260927T162456Z-full-user-s42` | adopted, full user (v0005); reload + permutation + baselines | 81 PASS, 0 WARN, 0 FAIL |

WARNs and why they are acceptable:

- **"Model registered"** on `160614Z` and `160956Z`: both used `--no-register` on purpose; they exist only to be compared.
- **"Both runs trained from scratch"** on the same two runs: the verifier flags it because `125702Z` did not train any epoch itself; it completed from the checkpoints of the ablation run `121708Z`, which trained from scratch (`resumed_from_epoch: null` in its registry entry). So `160614Z` compares two from-scratch trainings, and `160956Z` compares a resumed training with a from-scratch one. Both match exactly. The resumed run also printed the same loss, validation ROC-AUC, validation PR-AUC and learning rate as the fresh run for every epoch from 4 to 29.
- **`114021Z`**: the static-trait WARN led to the ablation. Its FAIL was the permutation test (0.0388 against a bar of 0.0300, one shuffle), which led to deviation C7-8. The run was not re-verified under C7-8 because its configuration was not adopted; its runlog lines stay as they are.

Checks that hold in every reported run:

- **Label coverage:** 966 of 966 malicious user-days matched, 70 of 70 insiders, none outside the feature window.
- **Split (N3, N11):** the Chapter 6 split files were loaded, not created; sha256 unchanged; scenario strata 18/6/6, 18/6/6, 6/2/2; no user in two splits. Row counts equal the Chapter 6 runs: 68,063 / 19,809 / 19,042 (mid user), 83,351 / 5,677 / 17,886 (mid time), 291,153 / 89,018 / 84,516 (full user).
- **Masquerade (N13):** at full, 4 masquerade account-days fell in training and were dropped, 0 in validation; the remainder are in test, where evaluation excludes them (N1). Mid holds neither supervisor account.
- **Imbalance (N2):** effective positive weight equals negatives / positives on the training rows: 117.577 (mid user, 574 positives), 114.445 (mid time, 722), 506.228 (full, 574).
- **Comparability (N18):** TabNet scored exactly the validation and test rows of the reference baselines, on the same feature matrix (`db650c3c1dca` mid, `4f09afb11a8f` full), and the harness reproduced all 15 logged baseline test PR-AUCs to the last digit.
- **Scores (N10):** in [0, 1], equal to sigmoid(raw margin), one model_version per file, no score saturated at 1.0.
- **Reload:** each registered artifact reproduces its stored test scores exactly (max difference 0) on CPU.
- **Registry:** every entry has the Bible Ch7 fields and matching sha256 for every artifact file; v0005 loads through `load_model` on CPU, and an unknown version is refused with `ModelUnavailableError` (covered by a unit test as well).
- **Static traits:** none in the mask top 10 of any adopted run.

## Permutation test (C7-8)

Test PR-AUC of TabNet trained for 10 epochs on shuffled training labels,
and of an untrained TabNet, against the chance level (positive rate).

| Run | Chance | Shuffle 12345 | Shuffle 12346 | Shuffle 12347 | Untrained | Bar | Verdict |
|---|---|---|---|---|---|---|---|
| mid user `125702Z` | 0.0100 | 0.0227 | 0.0151 | 0.0065 | 0.0087 | 0.0300 | PASS |
| mid time `161717Z` | 0.0094 | 0.0119 | 0.0136 | 0.0142 | 0.0085 | 0.0294 | PASS |
| full user `162456Z` | 0.0022 | 0.0030 | 0.0015 | 0.0184 | 0.0028 | 0.0222 | PASS |

The best label-free Chapter 6 baseline on the same rows (LSTM autoencoder)
reaches 0.0896, 0.0774 and 0.0784 respectively; every shuffle is far below
it. All three verdicts are PASS under the original Chapter 6 bar
(max(3 x chance, chance + 0.02)); the WARN tier added by C7-8 was not needed
for any reported run.

What this shows, and what it does not:

- The untrained network sits at chance in all three runs. So the hypothesis
  written into C7-8, that the architecture ranks unusual rows highly before
  seeing any label, is not supported by these runs.
- Eight of nine shuffles are within 2.3 x chance. The ninth (full, seed
  12347) is 0.0184, about 8 x chance, and 0.0215 on active days against
  0.0032. It passes only because of the absolute + 0.02 floor. A label leak
  would not depend on the shuffle seed, and the other two full shuffles are
  at chance (0.0030, 0.0015); the most likely reading is that fitting noise
  with a positive weight of about 506 occasionally lands on unusual days.
  It is recorded here rather than explained away.
- The superseded all-features run scored 0.0388 on one shuffle (seed 12345)
  under the old single-shuffle test. The adopted configuration scores
  0.0227 on the same seed. Whether static traits made that difference was
  not tested.

## Static-trait ablation

The first mid run had `psych_conscientiousness` in the mask top 10; the
Chapter 6 XGBoost had no static trait in its top 10. The decision rule was
written into `docs/chapters/chapter_7_tabnet.md` before the ablation ran:
adopt the behaviour-only model unless its validation PR-AUC is more than
0.10 lower.

| Configuration (mid, user split) | Validation PR-AUC | Best epoch | Static trait in mask top 10 |
|---|---|---|---|
| all features (`114021Z`, v0001) | 0.639 | 50 | `psych_conscientiousness` |
| behaviour-only (`121708Z` v0002; adopted as `125702Z` v0003) | 0.734 | 13 | none |

Behaviour-only was 0.095 higher, so it was adopted.

Disclosure (C7-9): the runner printed test metrics for `114021Z` before
that was changed, so the all-features model's mid test PR-AUC (0.509) has
been seen. The adopted model's mid test PR-AUC is 0.220. On test the order
is reversed. The decision was made on validation under a rule fixed in
advance and is not revisited (N11). The reversal says that one run per
configuration, with 14 validation insiders, cannot separate these two
configurations reliably; see "What the results say".

## Results (test split, primary view, read once)

Chance level equals the positive rate. ROC-AUC is secondary (N2).
"Caught" is insiders with at least one malicious day inside the daily
top-k. The baseline rows are the Chapter 6 reference runs, recomputed by
the same harness.

Full, user split (84,516 rows, 190 malicious user-days, chance 0.0022;
precision ceiling top-1 0.313):

| Model | PR-AUC | ROC-AUC | Recall@1 | Recall@5 | Caught@1 | Caught@5 |
|---|---|---|---|---|---|---|
| Rule-based | 0.015 | 0.786 | 0.063 | 0.163 | 9/14 | 11/14 |
| Isolation Forest | 0.016 | 0.870 | 0.058 | 0.184 | 7/14 | 13/14 |
| LOF (D-2) | 0.007 | 0.568 | 0.079 | 0.116 | 8/14 | 11/14 |
| LSTM autoencoder | 0.078 | 0.767 | 0.079 | 0.121 | 9/14 | 11/14 |
| XGBoost | 0.828 | 0.998 | 0.716 | 0.974 | 12/14 | 14/14 |
| TabNet | 0.359 | 0.982 | 0.516 | 0.863 | 11/14 | 14/14 |

Mid, user split (19,042 rows, 190 positives, chance 0.0100):

| Model | PR-AUC | ROC-AUC | Recall@1 | Recall@5 | Caught@1 | Caught@5 |
|---|---|---|---|---|---|---|
| Rule-based | 0.034 | 0.776 | 0.132 | 0.358 | 12/14 | 14/14 |
| Isolation Forest | 0.035 | 0.802 | 0.079 | 0.321 | 10/14 | 13/14 |
| LOF (D-2) | 0.006 | 0.291 | 0.037 | 0.042 | 1/14 | 2/14 |
| LSTM autoencoder | 0.090 | 0.691 | 0.084 | 0.332 | 9/14 | 14/14 |
| XGBoost | 0.843 | 0.993 | 0.711 | 0.995 | 13/14 | 14/14 |
| TabNet | 0.220 | 0.969 | 0.437 | 0.911 | 9/14 | 14/14 |

Mid, time split (17,886 rows, 168 positives, chance 0.0094):

| Model | PR-AUC | ROC-AUC | Recall@1 | Recall@5 | Caught@1 | Caught@5 |
|---|---|---|---|---|---|---|
| Rule-based | 0.024 | 0.761 | 0.012 | 0.089 | 2/14 | 7/14 |
| Isolation Forest | 0.037 | 0.819 | 0.018 | 0.196 | 3/14 | 12/14 |
| LOF (D-2) | 0.012 | 0.616 | 0.018 | 0.030 | 3/14 | 5/14 |
| LSTM autoencoder | 0.077 | 0.774 | 0.054 | 0.089 | 6/14 | 9/14 |
| XGBoost | 0.991 | 1.000 | 0.298 | 0.946 | 10/14 | 13/14 |
| TabNet | 0.888 | 0.993 | 0.268 | 0.899 | 8/14 | 14/14 |

Per scenario at top-1, test (malicious days in the top-1; insiders caught), N15:

| Split | Model | Scenario 1 | Scenario 2 | Scenario 3 |
|---|---|---|---|---|
| full user | XGBoost | 9/16; 5/6 | 125/170; 6/6 | 2/4; 1/2 |
| full user | TabNet | 12/16; 6/6 | 86/170; 5/6 | 0/4; 0/2 |
| mid user | XGBoost | 10/16; 5/6 | 123/170; 6/6 | 2/4; 2/2 |
| mid user | TabNet | 8/16; 3/6 | 75/170; 6/6 | 0/4; 0/2 |
| mid time | XGBoost | 4/9; 2/5 | 44/157; 7/8 | 2/2; 1/1 |
| mid time | TabNet | 1/9; 1/5 | 43/157; 6/8 | 1/2; 1/1 |

Time split, insiders never seen in training (N16): 12 of the 14 test
insiders are new. On those 12 plus all benign users (chance 0.0085), TabNet
scores PR-AUC 0.899 and XGBoost 0.994.

Validation, for reference (the numbers every decision was made on):

| Split | TabNet | XGBoost |
|---|---|---|
| mid user | 0.734 | 0.923 |
| mid time | 0.947 | 0.989 |

Full user validation: TabNet 0.749 (the full-profile XGBoost validation
value was not part of this review).

## What the results say

- **TabNet learned the task.** At full it reaches PR-AUC 0.359, about 160 x chance and 4.6 x the best unsupervised baseline (LSTM, 0.078), and catches 11 of 14 test insiders at one alert a day. On the time split it scores 0.899 on insiders it never saw.
- **XGBoost is better on every split, on validation and on test.** 0.828 vs 0.359 at full, 0.843 vs 0.220 at mid, 0.991 vs 0.888 on the time split. Per N23 this is reported as it stands; nothing was tuned on test to change it.
- **Most of the gap is scenario 2.** At full top-1 TabNet ranks 86 of 170 scenario-2 days in the daily top alert against 125 for XGBoost. On scenario 1 it does as well or better at full (12/16 days, 6/6 insiders, against 9/16 and 5/6).
- **Scenario 3 is missed on the user split.** 0 of 4 days and 0 of 2 insiders at top-1, at mid and at full. Four test days are too few to measure, but XGBoost finds 2 of them.
- **TabNet's model selection is noisy.** Validation PR-AUC swings by 0.1 to 0.2 between neighbouring epochs, and early stopping keeps the peak: for the adopted mid model the kept epoch scored 0.734 while the epochs on either side scored 0.545 and 0.551. The gap from validation to test is correspondingly large (0.734 to 0.220 at mid, 0.749 to 0.359 at full; XGBoost goes from 0.923 to 0.843). With 14 validation insiders, one run per configuration is not enough to compare TabNet configurations: the static-trait ablation reversed its order between validation and test.
- **It learns behaviour.** On mid validation the aggregate mask puts deviation from the user's own baseline in USB connections (`hist_z_usb_connect_count`) and in distinct logon PCs (`hist_z_distinct_auth_pcs`) first, then peer deviation in web and USB activity, USB events, file activity, job-search browsing, off-hours logon and executable files. Median validation score is 0.942 for malicious days, 0.005 for benign active days and 0.001 for benign inactive days; active-days-only PR-AUC equals the all-rows value (0.734).
- **Precision is close to the ceiling at mid.** Validation precision at top-1 is 0.250 against a maximum possible 0.280 (N17).

## Resources (HCEA §7.6)

| Run | Device | Time per epoch | Epochs | Peak RSS |
|---|---|---|---|---|
| mid user (`160614Z`, from scratch) | CPU | 2.5-2.9 s | 29 (best 13) | 1,415 MB |
| mid time (`161717Z`) | CPU | 2.9-3.3 s | 75 (best 59) | 1,556 MB |
| full user (`162456Z`) | CPU | 12.0-13.6 s | 41 (best 25) | 2,363 MB |

All far inside the 10 GB target; no GPU was used, so the 3 GB VRAM budget
does not apply. The longest fit (full, about 9 minutes) is well under the
45-minute checkpoint rule, and every epoch was checkpointed anyway. The full
permutation test adds about 5 minutes. Hyperparameter configurations logged:
3 at mid (counting split variants), 1 at full; well inside the budget of 12.

## Defects found during verification and fixed

| # | Defect | Found by | Fix and proof |
|---|---|---|---|
| 1 | The permutation test used one shuffle and a bar copied from Chapter 6, with no reference for what label-free structure gives on the same rows | First mid verification (`114021Z`, 0.0388 vs 0.0300) | C7-8: three shuffles, an untrained-network control and the best label-free baseline; the Chapter 6 bar still decides PASS. Unit test that a leak-sized score (0.20 at chance 0.01) still FAILs. All reported runs PASS the original bar |
| 2 | The runner printed test metrics on every run, which turns tuning into test-peeking | Review of the first mid run | C7-9: console shows validation only; test goes to `metrics.json`, the registry and the runlog. Integration test. The one test number seen is disclosed above |

## Outside Chapter 7: still open

- **Which model Chapter 8 serves.** The Bible names TabNet the primary model, mainly for its attention masks (Chapter 11). The evidence here, validation included, ranks XGBoost higher. Chapter 8 must make and record that choice; if TabNet is served, pin v0005 (N21, N26).
- **Seed variance.** Every number above comes from one seed. Chapter 16 needs several seeds per configuration and bootstrap intervals (C6-2, C7-7) before any finer ranking claim.
- **`114021Z` under C7-8.** Optional, since that configuration is not used: `python ../scripts/verify_chapter7.py --profile mid --run-id 20260927T114021Z-mid-user-s42 --permutation-test`.
- **Optional HCEA ablations not run:** balanced sampler (§7.3) and pretraining (§7.4).
- **N8 (Chapter 5):** the http-stage interrupt test is still open, as in the Chapter 6 audit.
