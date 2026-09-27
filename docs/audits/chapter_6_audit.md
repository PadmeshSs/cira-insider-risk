# Chapter 6 audit (26-27 September 2026)

Scope: Chapter 6 baselines, checked against the Bible Chapter 6 acceptance
list, HCEA v1.0 §6 and CARRY_FORWARD N1-N14.
Evidence: `experiments/runlog.jsonl` (committed), the split files under
`experiments/splits/`, and `scripts/verify_chapter6.py` output per run.
`experiments/results/` is gitignored, so per-run `metrics.json`,
`verification.json` and `inspection_*.json` stay on the development
machine; the runlog lines are the committed record.

Result: Chapter 6 is IMPLEMENTED. Every reported run passes the verifier
with 0 FAIL at mid (user and time split) and full (user split). The one
item not done, the Chapter 5 interrupt test (N8), belongs to Chapter 5 and
is listed at the end.

## Reported runs

The headline set combines runs. The LSTM autoencoder was re-run after the
resume fix (defect 4); every other model comes from the first run of its
profile and split. Chapter 7 and Chapter 16 compare against these score
files (N18).

| Profile / split | Rule, Isolation Forest, LOF, XGBoost | LSTM autoencoder |
|---|---|---|
| full / user | `20260926T134214Z-full-user-s42` | `20260927T094717Z-full-user-s42` |
| mid / user | `20260926T124335Z-mid-user-s42` | `20260927T094513Z-mid-user-s42` |
| mid / time | `20260926T125859Z-mid-time-s42` | `20260927T094626Z-mid-time-s42` |

## Verification record

| Run id | What | Verifier (final) |
|---|---|---|
| `20260926T123936Z-dev-user-s42` | dev smoke run, never reported | 148 PASS, 1 WARN, 0 FAIL |
| `20260926T124335Z-mid-user-s42` | mid, all five models; reload + permutation | 161 PASS, 3 WARN, 0 FAIL |
| `20260926T125725Z-mid-user-s42` | determinism re-run vs `124335Z` | 157 PASS, 2 WARN, 0 FAIL; identical scores, all five models |
| `20260926T125859Z-mid-time-s42` | mid time split; permutation | 143 PASS, 1 WARN, 0 FAIL |
| `20260926T134214Z-full-user-s42` | full, all five models; reload, then permutation | 161 PASS, 1 WARN, 0 FAIL; then 153 PASS, 0 WARN, 0 FAIL |
| `20260926T134637Z-mid-user-s42` | mid re-run after full, for the mid/full split check | 152 PASS, 1 WARN, 0 FAIL |
| `20260927T094513Z-mid-user-s42` | LSTM re-run after resume fix; reload | 55 PASS, 1 WARN, 0 FAIL |
| `20260927T094626Z-mid-time-s42` | LSTM re-run after resume fix; reload | 46 PASS, 1 WARN, 0 FAIL |
| `20260927T094717Z-full-user-s42` | LSTM re-run after resume fix; reload | 55 PASS, 1 WARN, 0 FAIL |
| `20260927T095024Z-mid-user-s42` | LSTM interrupted during epoch 6, resumed; compared with `094513Z` | 55 PASS, 1 WARN, 0 FAIL; resumed after epoch 5, max score difference 0 |

WARNs and why they are acceptable:

- **"All five detectors ran"** on the LSTM-only runs: only one model was run, by design.
- **"Supervised PR-AUC not suspiciously perfect"** for XGBoost on the time split (0.991): explained by the permutation test and the seen/new breakdown below.
- **Cross-profile split check** before the full split existed: it passed once the full run was done (250 shared users, 0 moved).
- **"Label table matches published counts"** only warned on synthetic data; it passes on real data (966 user-days, 70 insiders).

The first verification of `124335Z` recorded 1 FAIL (defect 2). That line
stays in the runlog and is superseded by the later 0-FAIL line for the
same run id. Runs `125345Z`, `125528Z` and `125636Z` are the first resume
test, which exposed defect 4.

Checks that hold in every reported run:

- **Label coverage:** 966 of 966 malicious user-days matched, 70 of 70 insiders, 0 outside the feature window.
- **Split:** scenario strata of 18/6/6, 18/6/6 and 6/2/2; no user appears in two splits. Mid and full agree on all 250 shared users, so the same 14 insiders form the test set in both profiles.
- **Masquerade (N1):** exercised at full. Both supervisor accounts (`faw0032`, `fba0348`) are in the full matrix, and all 20 masquerade account-days are excluded from primary evaluation and from XGBoost training. Mid holds neither account.
- **Reload:** reloaded models reproduce their stored test scores exactly.
- **Permutation test:** XGBoost trained on shuffled labels stays at chance: 0.0059 vs 0.0100 (mid user split), 0.0057 vs 0.0094 (mid time split), 0.0015 vs 0.0022 (full). No labels leak through the features or the split.

## Results (test split, primary view)

Chance level for PR-AUC equals the positive rate: 190 / 84,516 = 0.22% at
full, 190 / 19,042 = 1.0% at mid, 168 / 17,886 = 0.94% for the mid time
split. ROC-AUC is secondary (N2). "Caught" is insiders with at least one
malicious day inside the daily top-k.

Full, user split (the profile to report):

| Model | PR-AUC | ROC-AUC | Recall@1 | Recall@5 | Caught@1 | Caught@5 |
|---|---|---|---|---|---|---|
| Rule-based | 0.015 | 0.786 | 0.063 | 0.163 | 9/14 | 11/14 |
| Isolation Forest | 0.016 | 0.870 | 0.058 | 0.184 | 7/14 | 13/14 |
| LOF (D-2) | 0.007 | 0.568 | 0.079 | 0.116 | 8/14 | 11/14 |
| LSTM autoencoder | 0.078 | 0.767 | 0.079 | 0.121 | 9/14 | 11/14 |
| XGBoost | 0.828 | 0.998 | 0.716 | 0.974 | 12/14 | 14/14 |

Mid, user split:

| Model | PR-AUC | ROC-AUC | Recall@1 | Recall@5 | Caught@1 | Caught@5 |
|---|---|---|---|---|---|---|
| Rule-based | 0.034 | 0.776 | 0.132 | 0.358 | 12/14 | 14/14 |
| Isolation Forest | 0.035 | 0.802 | 0.079 | 0.321 | 10/14 | 13/14 |
| LOF (D-2) | 0.006 | 0.291 | 0.037 | 0.042 | 1/14 | 2/14 |
| LSTM autoencoder | 0.090 | 0.691 | 0.084 | 0.332 | 9/14 | 14/14 |
| XGBoost | 0.843 | 0.993 | 0.711 | 0.995 | 13/14 | 14/14 |

Mid, time split (train before 2011-01-01, validation January 2011, test
from 2011-02-01):

| Model | PR-AUC | ROC-AUC | Recall@1 | Recall@5 | Caught@1 | Caught@5 |
|---|---|---|---|---|---|---|
| Rule-based | 0.024 | 0.761 | 0.012 | 0.089 | 2/14 | 7/14 |
| Isolation Forest | 0.037 | 0.819 | 0.018 | 0.196 | 3/14 | 12/14 |
| LOF (D-2) | 0.012 | 0.616 | 0.018 | 0.030 | 3/14 | 5/14 |
| LSTM autoencoder | 0.077 | 0.774 | 0.054 | 0.089 | 6/14 | 9/14 |
| XGBoost | 0.991 | 1.000 | 0.298 | 0.946 | 10/14 | 13/14 |

LOF setup: 50,000 fit rows, 20 PCA components, retained variance 0.818
(mid user split), 0.816 (full), and 49,973 rows / 0.814 (mid time split).

The LSTM re-run moved PR-AUC from 0.088 to 0.090 at mid and from 0.083 to
0.078 at full; ROC-AUC at full moved from 0.862 to 0.767. The time-split
LSTM is unchanged at 0.077: early stopping kept the epoch-1 weights in both
versions, and epoch 1 shuffles identically before and after the fix. That
the full-profile ROC-AUC moves this much with only the training order
changed says the LSTM baseline is sensitive to training noise; one seed is
not enough to rank it finely against models close to it.

## What the results say

- **Supervised versus unsupervised.** XGBoost is far ahead of every unsupervised baseline, at 0.83 PR-AUC on insiders it never saw (full user split). The best unsupervised model is the LSTM autoencoder at 0.078, about 35× chance. Isolation Forest and the rules sit at about 7× chance, LOF at about 3×.
- **XGBoost learns behaviour, not identity.** On mid validation its top features by gain are USB activity (`usb_disconnect_count`, `usb_event_count`) and deviation from the user's own baseline (`hist_z_usb_event_count`, `hist_z_distinct_auth_pcs`), followed by deviation from peers in web activity and job-search browsing. No psychometric or other static per-user feature is in the top 10.
- **The time-split result is not recognition.** 12 of the 14 test insiders in the time split had no malicious days in training; on those 12 plus benign users, XGBoost scores PR-AUC 0.994 against a chance level of 0.0085. The earlier suggestion that the 0.991 came from recognising seen insiders was wrong. Why the time split scores higher than the user split (0.991 vs 0.843 at mid) is not established. Candidates are more training positives (722 vs 574), and a test window where 157 of 168 positives are scenario 2, whose USB pattern the model has learned well.
- **Scenario 2 dominates every headline.** It supplies 170 of 190 test positives in the user split and 157 of 168 in the time split, so per-scenario recall goes next to every headline (N15). The LSTM at full shows why this matters: at top-5 it catches 15 of 16 scenario-1 days but 4 of 170 scenario-2 days.
- **Scenario 3 can't be judged.** It has 4 test days, too few to confirm or refute N1's expectation that it is the weakest.
- **LOF carries no usable signal under the D-2 approximation.** On mid validation, benign inactive days get the highest LOF scores (median 0.94, against 0.67 for benign active days and 0.66 for malicious days), which is why its overall ranking is inverted. Restricted to active days only, its ROC-AUC is 0.50, exactly chance. So LOF is not just distracted by quiet days; it has nothing to offer on active days either. It is reported as it stands. Its direction was not flipped and nothing was tuned, since both would use labels.
- **XGBoost sits at the precision ceiling.** On mid validation its precision is 0.270 at top-1, against a maximum possible of 0.280, and 0.081 at top-5, against a maximum of 0.081. Low precision@k values here are a property of the base rate, not of the model.
- **The weekend share is structural.** About 29% of alerts land on weekends for every model, because a daily budget alerts k rows on every calendar day and 2 of 7 days are weekends. That column says nothing about a model; `inspect_scores.py` now prints this caveat.
- **Top-5 per-user detection is saturated at mid.** With 5 alerts a day across 44 test users, even the rules catch 14/14 at mid. At full, with 183 test users, top-5 separates the models (N17).

## Resources (HCEA)

| Run | Peak RSS | Wall-clock |
|---|---|---|
| Chapter 5 full pipeline | 2,160 MB | 330 s |
| Chapter 6 mid, all five models | 871 MB | under a minute |
| Chapter 6 full, all five models | 1,863 MB | LSTM fit 89 s, XGBoost fit 47 s, others under 6 s |
| Chapter 6 full, LSTM re-run | 1,387 MB | fit 102 s, scoring 7 s |

Every run is far inside the 12 GB target, and no single fit comes near the
45-minute thermal checkpoint rule. The LSTM ran on CPU throughout.

## Defects found during verification and fixed

| # | Defect | Found by | Fix and proof |
|---|---|---|---|
| 1 | Label coverage treated dev insiders' malicious days outside the Jun-Aug 2010 dev window as missing, so every dev run would have stopped | Dry run before any real run | Coverage only requires label days inside each user's feature date range; mid/full refuse out-of-range days. Two regression tests |
| 2 | Verifier reload check compared a 5-user subset with scores from the full test batch; LOF differed by 4.2e-4 because of batch-size-dependent kNN arithmetic on Windows, reported as FAIL | First mid verification | Reload check re-scores the whole test split and requires an exact match; the subset comparison is an informational WARN |
| 3 | Verifier crashed on a time-split run when `--split time` was not passed | Mid time-split verification | Split mode is read from the run itself |
| 4 | A resumed LSTM did not match an uninterrupted one (mid PR-AUC 0.0901 vs 0.0881): the checkpoint did not carry the shuffle position | First resume test (`125636Z`) | Shuffle re-seeded per epoch from (seed, epoch); new config key changes the model version and checkpoint key. Regression test, plus run `095024Z`: interrupted during epoch 6, resumed after epoch 5, scores identical to `094513Z` |
| 5 | `inspect_scores.py` wrote one file per split, so inspecting a second model overwrote the first | Final inspection | Output named `inspection_<part>_<model>.json` |

## Outside Chapter 6: still open

- **N8 (Chapter 5):** the full Chapter 5 run has not been interrupted during the http stage to confirm it resumes (HCEA R7). The full matrix itself is verified (464,687 rows, 1,000 users, every malicious day matched), so no Chapter 6 result depends on this. It stays open under N8 until done: `python -m app.feature_engineering.pipeline --profile full`, Ctrl+C while processing http, run again, confirm it continues and ends at 464,687 rows.
