# Chapter 16 audit (10 October 2026)

Scope: Chapter 16 (evaluation protocol and ablation studies), checked against the Bible Chapter 16 checklist and
CARRY_FORWARD N1-N80.

Evidence, from the development machine (Windows, `backend\venv`, Docker PostgreSQL 17 on port 5433): the console
output of `python -m app.evaluation.ablation` for the validation rehearsal and the test readout, the console output of
the readout inspection scripts over `experiments/chapter16_test_readout.json`, the seed manifest
`experiments/chapter16_seed_runs.json`, and the console output of `scripts/verify_chapter16.py --recompute`. Every CERT
number below is copied from that output.

Result: **29 PASS, 0 WARN, 0 FAIL** (verifier run `20261010T075805Z`). Chapter 16 is IMPLEMENTED.

## What was run

| Step | Run id | Result |
|---|---|---|
| Seed runs, `python -m app.evaluation.seeds --profile full` | `experiments/chapter16_seed_runs.json` | 4 groups x 6 seeds (42-47), no errors |
| Validation rehearsal, `--part validation` | `20261010T055423Z-full-validation-c16` | 89,018 rows, 202 malicious user-days, harness PASS, 2 WARN |
| Test readout, `--part test` | `20261010T055945Z-full-test-c16` | 84,516 rows, 190 malicious user-days, 1 harness FAIL (below), 2 WARN |
| Test readout, superseded | `20261010T072243Z-full-test-c16` | same rows, every harness check PASS, 2 WARN |
| Report, `python -m app.evaluation.report` | `experiments/chapter16_evaluation_report.md` | regenerated; the verifier confirms it equals the readout's regeneration byte for byte |
| Verification, `python scripts/verify_chapter16.py --recompute` | `20261010T075805Z` | 29 PASS, 0 WARN, 0 FAIL |

The best baseline on validation was the Chapter 6 XGBoost (all features). The alert run read for E1 is
`20261001T062628Z-full-alerts` (policy hash `21cd9391fd48`) on risk run `20260929T184445Z-full-cri-default-mitre`.

## What the verifier ran

| Layer | Result |
|---|---|
| backend unit | 391 passed, 43 s |
| backend integration | 93 passed, 2 skipped, 211 s (the two expected skips: CERT Chapter 4 raw files live on `D:`; the Chapter 12 test that needs `CIRA_TEST_DATABASE_URL`) |
| backend e2e (regression gate, N70) | 30 passed, 0 skipped, 39 s; under a minute (36.5 s) |
| `test_ch16_evaluation.py` | 15 of 15 |
| `test_ch16_pipeline.py` | 8 of 8 |
| readout checks | pinned test readout, full profile, `c16-readout-v1`; every chain stage present; experiments C, D, E1, E2 and A/B/E3 present; no harness check failed (13 checks, 0 n/a); six seeds in every model and configuration; bootstrap 1000 replicates; no accuracy metric anywhere (N2); best baseline chosen on validation; the readout's served model is the Chapter 8 decision (`gbdt-chapter8-v1-077a3dae6cee`); 2 guard warnings listed |
| recompute | all 14 rankings' PR-AUCs equal the readout's, worst difference 0; the risk run's file hash is the one the readout recorded |
| notes | N75-N80 and their table rows present; audit and chapter documents exist; README status not PLANNED and consistent with the evidence |

## The harness failure and its fix

The first test readout reported `FAIL: cri:anomaly_only ranks like the anomaly score (3.28e-03)`. On validation the same
check had passed with a difference of exactly 0.

Cause. The check required `anomaly_only` to give the same PR-AUC as the served anomaly score, which assumes a strictly
order-preserving map. The anomaly component is a rarity against the validation reference (`app/cri/calibration.py`,
counted with `searchsorted`), so it is monotone but not strict: test scores that fall between the same two reference
points get the same value. A diagnostic on test confirmed it: the map never reverses the served score's order, the
number of distinct values fell from 63,824 to 32,866, and no score reached 1.0 (so it was not saturation or rounding).
On validation the reference is fitted on the same rows, so nothing merged.

Fix. The check now requires that `anomaly_only` never reverses the served score's order, and prints the distinct-value
counts and the PR-AUC shift from ties. It is a change to a check. No model, weight, rule or policy changed (N80). The
readout was superseded with the reason "harness check for cri:anomaly_only changed from equal PR-AUC to order
preservation; no model, weight, rule or policy changed". Every PR-AUC in the superseding readout equals the one it
replaced, and the previous readout is kept inside it. Chapters 9 and 10 run the older check on validation only, where it
holds, and were left alone.

## Harness (test, superseding readout)

All PASS:

- every ranking covers exactly the served model's 84,516 test rows (14 rankings)
- recombining the stored CRI components reproduces the stored `cri_score`
- `cri:anomaly_only` never reverses the anomaly score's order (63,824 distinct values become 32,866; PR-AUC shift from
  ties 3.28e-03)
- the risk run's anomaly score equals the Chapter 8 batch's served score (max difference 0)
- the five Chapter 6 baselines: recomputed test PR-AUC equals what each run logged (XGBoost 0.827690579579137,
  rule-based 0.014882924593174284, isolation forest 0.015525253249517323, LOF 0.007337273745975112, LSTM autoencoder
  0.078362011058405)
- served XGBoost test PR-AUC equals the Chapter 8 readout: 0.8265240869827831
- TabNet test PR-AUC equals the Chapter 8 readout: 0.3589115124971715
- Chapter 6 XGBoost equals the Chapter 8 readout's `gbdt_ch6_all_feat`: 0.827690579579137
- a fresh load of every stored ranking gives identical metrics (14 of 14)

## Test results (primary view, one fixed user split, tie-break seed 42)

Chance PR-AUC is 0.0022. Intervals are 95% user-clustered bootstrap, 1000 replicates. "Caught" is insiders with at
least one day in the daily top-1, out of 14.

| Ranking | PR-AUC | 95% CI | Recall@1 | Caught@1 |
|---|---|---|---|---|
| baseline:rule_based | 0.015 | 0.007-0.047 | 0.063 | 9/14 |
| baseline:isolation_forest | 0.016 | 0.007-0.061 | 0.058 | 7/14 |
| baseline:lof | 0.007 | 0.003-0.025 | 0.079 | 8/14 |
| baseline:lstm_autoencoder | 0.078 | 0.028-0.246 | 0.079 | 9/14 |
| baseline:gbdt_all_features | 0.828 | 0.618-0.973 | 0.716 | 12/14 |
| tabnet (shadow) | 0.359 | 0.189-0.795 | 0.516 | 11/14 |
| xgboost_served | 0.827 | 0.607-0.973 | 0.721 | 12/14 |
| cri:default (with MITRE) | 0.632 | 0.390-0.827 | 0.621 | 14/14 |
| cri:no_mitre_context | 0.655 | 0.386-0.850 | 0.658 | 13/14 |
| cri:no_historical_deviation | 0.731 | 0.372-0.936 | 0.674 | 11/14 |
| cri:no_peer_deviation | 0.715 | 0.462-0.890 | 0.674 | 14/14 |
| cri:no_user_context | 0.658 | 0.386-0.855 | 0.663 | 13/14 |
| cri:no_peer_deviation+no_user_context | 0.715 | 0.464-0.891 | 0.674 | 14/14 |
| mitre_context (alone) | 0.074 | 0.027-0.222 | 0.074 | 8/14 |

Comparison chain on test: best baseline 0.828, TabNet 0.359, XGBoost 0.827, XGBoost + CRI 0.655, XGBoost + CRI + MITRE
0.632. The chain ends in the served XGBoost (C16-1). On validation the same ordering holds (XGBoost 0.915, Chapter 6
XGBoost 0.939, TabNet 0.749, `cri:default` 0.557, `cri:no_mitre_context` 0.694).

### Paired differences (first minus second, test, 95% user-clustered bootstrap)

| Pair | PR-AUC difference | Recall@1 difference |
|---|---|---|
| TabNet - best baseline | -0.469 (-0.665 to -0.117), p 0.002 | -0.200 (-0.322 to -0.067), p 0.012 |
| XGBoost served - best baseline | -0.001 (-0.033 to 0.020), p 0.684 | 0.005 (-0.016 to 0.033), p 0.966 |
| TabNet - XGBoost served | -0.468 (-0.657 to -0.111), p 0.002 | -0.205 (-0.317 to -0.081), p 0.004 |
| CRI without MITRE - XGBoost served | -0.172 (-0.322 to -0.085), p 0.002 | -0.063 (-0.150 to 0.034), p 0.252 |
| CRI with MITRE - XGBoost served | -0.194 (-0.325 to -0.096), p 0.002 | -0.100 (-0.177 to 0.048), p 0.150 |
| CRI with MITRE - CRI without MITRE | -0.023 (-0.053 to 0.033), p 0.334 | -0.037 (-0.100 to 0.044), p 0.374 |
| no_historical_deviation - CRI without MITRE | 0.076 (-0.031 to 0.191), p 0.108 | 0.016 (-0.102 to 0.080), p 0.748 |
| no_peer_deviation - CRI without MITRE | 0.060 (0.016 to 0.120), p 0.004 | 0.016 (-0.041 to 0.069), p 0.570 |
| no_user_context - CRI without MITRE | 0.003 (0.000 to 0.010), p 0.046 | 0.005 (0.000 to 0.017), p 0.768 |
| no_peer_deviation+no_user_context - CRI without MITRE | 0.060 (0.017 to 0.122), p 0.004 | 0.016 (-0.041 to 0.069), p 0.570 |

What the table supports:

- TabNet is clearly behind the Chapter 6 XGBoost on test, on PR-AUC and on recall at top-1.
- The served XGBoost and the Chapter 6 XGBoost cannot be told apart.
- The CRI loses to the anomaly score on PR-AUC with intervals that exclude zero. Its top-1 recall is not clearly lower
  (both recall intervals include zero), and it catches more insiders at top-1 (14/14 with MITRE against 12/14), but the
  caught count is a count, not a tested difference. The two views disagree and are always quoted together (N39, N40).
- MITRE has no detectable effect on test, in either direction, on PR-AUC or on recall.
- Removing peer deviation raises PR-AUC by 0.060 with an interval above zero. This agrees with what validation showed
  (N40). The best variant still sits at 0.715, well below XGBoost at 0.827. The variant was found by looking at
  validation, so it stays validation-informed and not adopted. Adopting it now would be a design decision made after
  seeing test, and test cannot validate it again (N11).
- `no_user_context` adds 0.003 with an interval touching zero. `no_historical_deviation` adds 0.076 with an interval
  spanning zero. Neither is a finding.
- Twenty intervals are quoted in this table with no correction for multiple comparisons. The p = 0.046 is not evidence of
  an effect. Only the clear results above (TabNet, CRI vs XGBoost, peer deviation) should be quoted.
- Scenario 3 has 4 test days. No claim is made about it (N15).

## Seed runs: experiments A, B and the supervised comparison

One fixed split (split seed 42), model seeds 42-47, all four model-and-configuration groups. The seed-42 behaviour-only
cells are the reported runs, not retrained (TabNet 0.3589, XGBoost 0.8265). Test PR-AUC per seed:

| Group | 42 | 43 | 44 | 45 | 46 | 47 | median | min-max | std |
|---|---|---|---|---|---|---|---|---|---|
| tabnet / behaviour (A) | 0.359 | 0.490 | 0.216 | 0.578 | 0.193 | 0.426 | 0.393 | 0.193-0.578 | 0.152 |
| tabnet / all features (B) | 0.268 | 0.235 | 0.469 | 0.380 | 0.261 | 0.367 | 0.317 | 0.235-0.469 | 0.091 |
| xgboost / behaviour (A) | 0.827 | 0.816 | 0.810 | 0.807 | 0.812 | 0.812 | 0.812 | 0.807-0.827 | 0.007 |
| xgboost / all features (B) | 0.828 | 0.818 | 0.821 | 0.810 | 0.826 | 0.825 | 0.823 | 0.810-0.828 | 0.007 |

Paired Wilcoxon signed-rank tests over the six seeds (two-sided; the smallest p six pairs can give is 0.03125):

| Comparison | Mean difference | Wins / losses | p |
|---|---|---|---|
| TabNet minus XGBoost, behaviour-only (N23) | -0.437 | 0 / 6 | 0.031 |
| TabNet behaviour-only minus XGBoost all features (headline vs closest seeded Chapter 6 baseline) | -0.444 | 0 / 6 | 0.031 |
| B vs A, TabNet (all features minus behaviour) | -0.047 | 2 / 4 | 0.563 |
| B vs A, XGBoost (all features minus behaviour) | +0.007 | 6 / 0 | 0.031 |

Findings:

- XGBoost beats TabNet on all six seeds, by a margin far larger than either model's seed spread. "XGBoost ranks higher"
  is now supported by seeds and not by a single run (N26).
- TabNet's test PR-AUC depends heavily on the seed: 0.193 to 0.578, standard deviation 0.152, against 0.007 for
  XGBoost. TabNet is reported as a median and range. The reported run (0.359) is near the middle of the spread.
- Excluding the static traits costs XGBoost about 0.007 PR-AUC (all features win on 6 of 6 seeds, by roughly one seed
  standard deviation) and TabNet nothing measurable (mean -0.047, p = 0.563). This is the cost of the interpretability
  constraint that keeps explanations behavioural (N22, N25), experiment E3.

Limits:

- The three p = 0.031 results sit at the floor for six pairs and are unadjusted. Four paired tests were run, and with a
  correction for that none would be below 0.05. The direction is consistent across seeds; the audit does not call it
  significant.
- Seeds vary the model on one split. The user bootstrap, not the seeds, covers which users are in test. Neither covers
  both.
- XGBoost on all features is the closest seeded reproduction of the Chapter 6 baseline, not that baseline's own run.
- The seed tests do not explain why TabNet fell from 0.749 on validation to 0.359 on test. Per-seed validation scores
  were not compared, so no cause is stated.

## E1: the alert queue on test

Policy `c12-alert-policy-v1`: HIGH and CRITICAL bands plus daily top-1, anomaly-score ordering, activity required,
correlation gap 3 days, cooldown 7 days. The queue ranks validation and test users together (N61), so these figures are
not comparable to the top-1 counts above (12/14 and 14/14 rank test users among themselves). The test part spans 501
dates and 84,516 user-days.

| View | Open alerts | Suppressed | Open alerts with a malicious day | Alert precision |
|---|---|---|---|---|
| anomaly ordering, as built | 118 | 17 | 26 | 0.220 |
| anomaly ordering, without deduplication | 135 | 0 | 36 | 0.267 |
| CRI ordering, with deduplication | 140 | 15 | 34 | 0.243 |
| CRI ordering, without deduplication | 155 | 0 | 40 | 0.258 |

Insiders caught are the same in all four views: 13 of 14 (scenario 1 6/6, scenario 2 6/6, scenario 3 1/2). No insider's
only alerts were suppressed.

Malicious days (190) in an open alert / only in a suppressed alert / in no alert:

| View | Scenario 1 (16 days) | Scenario 2 (170 days) | Scenario 3 (4 days) | All |
|---|---|---|---|---|
| anomaly ordering, as built | 6 / 1 / 9 | 63 / 19 / 88 | 2 / 0 / 2 | 71 / 20 / 99 |
| anomaly ordering, no dedup | 7 / 0 / 9 | 82 / 0 / 88 | 2 / 0 / 2 | 91 / 0 / 99 |
| CRI ordering, as built | 8 / 1 / 7 | 44 / 9 / 117 | 2 / 0 / 2 | 54 / 10 / 126 |
| CRI ordering, no dedup | 9 / 0 / 7 | 53 / 0 / 117 | 2 / 0 / 2 | 64 / 0 / 126 |

What this shows:

- About half of the malicious days (99 of 190 under anomaly ordering, 126 under CRI ordering) are in no alert at all.
  The queue finds the insiders, not their days.
- Deduplication lowers alert precision (0.267 to 0.220). It removed 17 alerts, 10 of which contained a malicious day,
  so the suppressed alerts were more often malicious than the kept ones. It costs 20 malicious days that are visible
  only in suppressed alerts. It is meant to collapse repeats on an ongoing case, and no insider lost all alerts to it.
  Both facts are stated together (N57).
- The two orderings trade off. CRI ordering has slightly higher alert precision (0.243 against 0.220) and leaves more
  malicious days in no alert (126 against 99), with 140 open alerts against 118. Neither is quoted without the other
  (N55). The precision difference is 34 of 140 against 26 of 118 alerts and has no interval.
- Of 118 open alerts, 27 never rise above LOW on the CRI (N60).
- Top-1 alone supplies almost all the alerted days: 268 member-days with 66 malicious (25%). The band alone supplies 3
  member-days (3 malicious) and band plus top-1 supplies 2 (2 malicious). Those five days are too few to say the band
  is precise.
- Latency: median 0 days, maximum 32. Open alerts per day: median 0, 95th percentile 1, maximum 1.
- Activity rule (N56): on 30 of 501 dates, 38 user-days changed slot when the rule is off. None of the 38 is malicious,
  and 17 would be idle user-days taking a slot. The rule is neutral on test for malicious days, on 38 days of evidence.
- False-alarm alerts: 92, led by USB factors: `hist_z_usb_connect_count` 46, `usb_disconnect_count` 10 and
  `usb_last_hour` 7, 63 of 92 together (N52).

## E2: explanations on test

Explain run integrity: 84,516 rows explained, no warnings, no row with a static trait in its top five, no row without a
raising factor, maximum additivity error 3.04e-05.

Top factor on malicious days, served model (TreeSHAP):

| Scenario | Days | Most frequent top factors |
|---|---|---|
| 1 | 16 | `http_leak_paste_count` 12, `logoff_count` 2, `peer_dev_http_request_count` 1, `hist_z_usb_connect_count` 1 |
| 2 | 170 | `peer_dev_http_request_count` 100, `usb_disconnect_count` 37, `hist_z_emails_sent` 15, `hist_z_usb_connect_count` 9 |
| 3 | 4 | one day each: `hist_z_emails_sent`, `logoff_count`, `usb_last_hour`, `hist_abs_z_file_event_count` |

A top factor that matches a public scenario description (the leak-site factor for scenario 1) is partly by
construction (N41).

Benign days in the served model's daily top-1: 364 days, 37 with no raising factor. The top factors are
`peer_abs_dev_login_count` 115, `hist_z_usb_connect_count` 92 and `usb_disconnect_count` 50. Calendar factors lead none
of them (0.0). By domain, the top three factors come from the historical baseline (0.410), the peer group (0.307) and
the device (0.249).

Shadow TabNet masks on the same malicious days (labelled the second model's view, never shown to an analyst, N30, N32).
Mean top-5 Jaccard with TreeSHAP: scenario 1 0.099, scenario 2 0.036, scenario 3 0.118 (4 days). The two models explain
the same days almost entirely differently (N53). TabNet masks lead with `usb_off_hours_events` (12 of 16 days in
scenario 1, 113 of 170 in scenario 2) and `is_weekend` (31 days in scenario 2). A mask is attention, not direction
(N51), so low agreement does not say either model is right.

## D: MITRE context

- 29.1% of benign user-days are mapped to a rule (0.2906 of 84,310 benign user-days). Mapping is common on benign days
  and is not selective by itself.
- Rule coverage of malicious days, with each rule's share of benign days:

| Rule | Technique | Benign share | Scenario 1 | Scenario 2 | Scenario 3 |
|---|---|---|---|---|---|
| R01 removable media copy | T1052.001 | 8.1% | 2/16 | 116/170 | 3/4 |
| R02 leak site access | T1567 | 0.0% | 12/16 | 0/170 | 0/4 |
| R03 cloud storage access | T1567.002 | 22.9% | 2/16 | 79/170 | 3/4 |
| R04 attack tool site access | T1588.002 | 0.0% | 0/16 | 0/170 | 2/4 |

- `mitre_context` alone ranks at 0.074 PR-AUC, 8/14 insiders at top-1. It is a context component, not a detector (N42).
- MITRE has no detectable effect on the CRI on test (paired table above). The gain would be partly by construction of
  the dataset, since the rules were written against the scenario descriptions (N36, N41), so a null result here is
  not a reason to remove the component or to defend it.

The served-versus-shadow disagreement cells and the HIGH/CRITICAL band views are in the readout and are not quoted here.

## Guard warnings (c16-evaluation-guard-v1)

Both appeared on validation and on test. Neither changes a model, a weight or a policy (N37, N80).

1. `cri:default` PR-AUC is below the anomaly score: 0.6323 against 0.8265 on test (0.5572 against 0.9155 on
   validation). Explained above: the CRI trades PR-AUC for insiders caught at top-1. The rarity map's ties may account
   for part of the gap; that was not tested and is not claimed as a cause.
2. Scenario 3 has 4 test days. No claim is made about it (N15). The warning text prints "aboutit" without a space;
   the message is cosmetic.

## Deviations and disclosures

C16-1 (the chain ends in the served XGBoost, not TabNet), C16-2 (C and D vary tie-break seeds and resample users; they
are not retrained per seed), C16-3 (risk coverage is defined in `app/evaluation/operating.py`) and C16-4 (the
contextual features of B are the static traits) are in `docs/chapters/chapter_16_evaluation.md` and in the readout.

Disclosures, all in the readout: Chapter 8 already read test once for each model (`chapter8_test_readout.json`), and
this is the designated Chapter 16 read; the all-features TabNet's mid test PR-AUC was seen during Chapter 7 tuning
(C7-9); `cri:no_peer_deviation+no_user_context` is validation-informed; MITRE and user-context gains are partly by
construction of the dataset (N36, N41); scenario 2 supplies most positives (N15).

The readout was written twice. The second write superseded the first for a harness-check fix only (N76).

## Not recorded

These were not read from a file and carry no number here. None blocks the chapter.

- Wall-clock and peak memory of the seed runs.
- The KernelSHAP agreement figure carried in the explain run's meta (it is label-free and was recorded by Chapter 11).
- Secondary splits (mid/user, mid/time with the seen/new breakdown): the test readout was run without `--secondary`,
  so `secondary_splits` is empty. The verifier does not require them. The time-split result from Chapter 6 stands as
  reported there (N16).

## Result

Chapter 16 is IMPLEMENTED: 29 PASS, 0 WARN, 0 FAIL on `scripts/verify_chapter16.py --recompute`, with the pinned test
readout `20261010T072243Z-full-test-c16`.
