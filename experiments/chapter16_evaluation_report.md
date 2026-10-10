# Chapter 16 evaluation report (test, profile full)

Generated from `experiments/chapter16_test_readout.json` (sha256 `8edbbc88b169ad0826fff1cbd754f682db7b52ed867d36d94f08d8bd0d28c762`), run `20261010T072243Z-full-test-c16`, written 2026-10-10T07:26:19+00:00. Every number below is read from that file; none is typed in.

Population: 84516 user-days of 183 users, 190 malicious user-days (chance PR-AUC 0.0022), scenario days s1 16, s2 170, s3 4. Scores are ranking scores, not probabilities of malice (N20). The headline is mostly scenario 2 (N15).

Lineage: risk run `20260929T184445Z-full-cri-default-mitre`, alert run `20261001T062628Z-full-alerts` (policy `21cd9391fd48`), explain run `20260930T190519Z-full-explain`, calibration `20260929T095921Z-full-cri`, CRI config `297bbbe7add7`, MITRE run `20260929T184439Z-full-mitre`.

## Comparison chain

Best baseline, chosen on validation before test was read: `gbdt`.

| Stage | Ranking | PR-AUC | 95% interval | Recall@1 | Insiders caught@1 |
|---|---|---|---|---|---|
| baseline (best on validation) | `baseline:gbdt_all_features` | 0.828 | 0.618 to 0.973 | 0.716 | 12/14 |
| TabNet (shadow, behaviour-only) | `tabnet` | 0.359 | 0.189 to 0.795 | 0.516 | 11/14 |
| XGBoost (served, behaviour-only) | `xgboost_served` | 0.827 | 0.607 to 0.973 | 0.721 | 12/14 |
| XGBoost + CRI | `cri:no_mitre_context` | 0.655 | 0.386 to 0.850 | 0.658 | 13/14 |
| XGBoost + CRI + MITRE | `cri:default` | 0.632 | 0.390 to 0.827 | 0.621 | 14/14 |

## All rankings

| Ranking | PR-AUC | 95% interval | ROC-AUC (secondary) | P@1 | R@1 | F1@1 | FPR@1 | Risk coverage@1 | Review load@1 | Caught@1 | Caught@5 | Days@1 by scenario |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `baseline:rule_based` | 0.015 | 0.007 to 0.047 | 0.786 | 0.024 | 0.063 | 0.035 | 0.00580 | 0.063 | 0.00593 | 9/14 | 11/14 | s1 8/16, s2 2/170, s3 2/4 |
| `baseline:isolation_forest` | 0.016 | 0.007 to 0.061 | 0.870 | 0.022 | 0.058 | 0.032 | 0.00581 | 0.058 | 0.00593 | 7/14 | 13/14 | s1 3/16, s2 4/170, s3 4/4 |
| `baseline:lof` | 0.007 | 0.003 to 0.025 | 0.568 | 0.030 | 0.079 | 0.043 | 0.00575 | 0.079 | 0.00592 | 8/14 | 11/14 | s1 10/16, s2 1/170, s3 4/4 |
| `baseline:lstm_autoencoder` | 0.078 | 0.028 to 0.246 | 0.767 | 0.030 | 0.079 | 0.043 | 0.00576 | 0.079 | 0.00593 | 9/14 | 11/14 | s1 12/16, s2 1/170, s3 2/4 |
| `baseline:gbdt_all_features` | 0.828 | 0.618 to 0.973 | 0.998 | 0.271 | 0.716 | 0.394 | 0.00433 | 0.716 | 0.00593 | 12/14 | 14/14 | s1 9/16, s2 125/170, s3 2/4 |
| `tabnet` | 0.359 | 0.189 to 0.795 | 0.982 | 0.196 | 0.516 | 0.284 | 0.00478 | 0.516 | 0.00593 | 11/14 | 14/14 | s1 12/16, s2 86/170, s3 0/4 |
| `xgboost_served` | 0.827 | 0.607 to 0.973 | 0.998 | 0.273 | 0.721 | 0.397 | 0.00432 | 0.721 | 0.00593 | 12/14 | 14/14 | s1 9/16, s2 126/170, s3 2/4 |
| `cri:default` | 0.632 | 0.390 to 0.827 | 0.996 | 0.236 | 0.621 | 0.342 | 0.00454 | 0.621 | 0.00593 | 14/14 | 14/14 | s1 12/16, s2 103/170, s3 3/4 |
| `cri:no_mitre_context` | 0.655 | 0.386 to 0.850 | 0.997 | 0.250 | 0.658 | 0.362 | 0.00446 | 0.658 | 0.00593 | 13/14 | 14/14 | s1 11/16, s2 112/170, s3 2/4 |
| `cri:no_historical_deviation` | 0.731 | 0.372 to 0.936 | 0.997 | 0.255 | 0.674 | 0.370 | 0.00442 | 0.674 | 0.00593 | 11/14 | 14/14 | s1 8/16, s2 120/170, s3 0/4 |
| `cri:no_peer_deviation` | 0.715 | 0.462 to 0.890 | 0.997 | 0.255 | 0.674 | 0.370 | 0.00442 | 0.674 | 0.00593 | 14/14 | 14/14 | s1 11/16, s2 114/170, s3 3/4 |
| `cri:no_user_context` | 0.658 | 0.386 to 0.855 | 0.997 | 0.251 | 0.663 | 0.365 | 0.00445 | 0.663 | 0.00593 | 13/14 | 14/14 | s1 11/16, s2 113/170, s3 2/4 |
| `cri:no_peer_deviation+no_user_context` (validation-informed) | 0.715 | 0.464 to 0.891 | 0.997 | 0.255 | 0.674 | 0.370 | 0.00442 | 0.674 | 0.00593 | 14/14 | 14/14 | s1 11/16, s2 114/170, s3 3/4 |
| `mitre_context` | 0.074 | 0.027 to 0.222 | 0.812 | 0.028 | 0.074 | 0.041 | 0.00578 | 0.074 | 0.00593 | 8/14 | 10/14 | s1 12/16, s2 0/170, s3 2/4 |

Risk coverage is defined in `app/evaluation/operating.py` (deviation C16-3) and printed with the review load.

## Paired comparisons (user-clustered bootstrap)

1000 replicates, seed 42; user-clustered bootstrap, fixed scores and fixed alert masks (module docstring).

| A | B | Metric | A - B | 95% interval | p (approx.) |
|---|---|---|---|---|---|
| `tabnet` | `baseline:gbdt_all_features` | pr_auc | -0.469 | -0.665 to -0.117 | 0.0020 |
| `tabnet` | `baseline:gbdt_all_features` | recall | -0.200 | -0.322 to -0.067 | 0.0120 |
| `tabnet` | `baseline:gbdt_all_features` | insiders_caught_share | -0.071 | -0.333 to 0.182 | 0.7720 |
| `xgboost_served` | `baseline:gbdt_all_features` | pr_auc | -0.001 | -0.033 to 0.020 | 0.6840 |
| `xgboost_served` | `baseline:gbdt_all_features` | recall | 0.005 | -0.016 to 0.033 | 0.9660 |
| `xgboost_served` | `baseline:gbdt_all_features` | insiders_caught_share | 0.000 | 0.000 to 0.000 | 1.0000 |
| `tabnet` | `xgboost_served` | pr_auc | -0.468 | -0.657 to -0.111 | 0.0020 |
| `tabnet` | `xgboost_served` | recall | -0.205 | -0.317 to -0.081 | 0.0040 |
| `tabnet` | `xgboost_served` | insiders_caught_share | -0.071 | -0.333 to 0.182 | 0.7720 |
| `cri:no_mitre_context` | `xgboost_served` | pr_auc | -0.172 | -0.322 to -0.085 | 0.0020 |
| `cri:no_mitre_context` | `xgboost_served` | recall | -0.063 | -0.150 to 0.034 | 0.2520 |
| `cri:no_mitre_context` | `xgboost_served` | insiders_caught_share | 0.071 | 0.000 to 0.250 | 0.7760 |
| `cri:default` | `cri:no_mitre_context` | pr_auc | -0.023 | -0.053 to 0.033 | 0.3340 |
| `cri:default` | `cri:no_mitre_context` | recall | -0.037 | -0.100 to 0.044 | 0.3740 |
| `cri:default` | `cri:no_mitre_context` | insiders_caught_share | 0.071 | 0.000 to 0.250 | 0.7500 |
| `cri:default` | `xgboost_served` | pr_auc | -0.194 | -0.325 to -0.096 | 0.0020 |
| `cri:default` | `xgboost_served` | recall | -0.100 | -0.177 to 0.048 | 0.1500 |
| `cri:default` | `xgboost_served` | insiders_caught_share | 0.143 | 0.000 to 0.375 | 0.3000 |
| `cri:no_historical_deviation` | `cri:no_mitre_context` | pr_auc | 0.076 | -0.031 to 0.191 | 0.1080 |
| `cri:no_historical_deviation` | `cri:no_mitre_context` | recall | 0.016 | -0.101 to 0.080 | 0.7480 |
| `cri:no_historical_deviation` | `cri:no_mitre_context` | insiders_caught_share | -0.143 | -0.375 to 0.000 | 0.2800 |
| `cri:no_peer_deviation` | `cri:no_mitre_context` | pr_auc | 0.060 | 0.016 to 0.120 | 0.0040 |
| `cri:no_peer_deviation` | `cri:no_mitre_context` | recall | 0.016 | -0.041 to 0.069 | 0.5700 |
| `cri:no_peer_deviation` | `cri:no_mitre_context` | insiders_caught_share | 0.071 | 0.000 to 0.250 | 0.7500 |
| `cri:no_user_context` | `cri:no_mitre_context` | pr_auc | 0.003 | 0.000 to 0.010 | 0.0460 |
| `cri:no_user_context` | `cri:no_mitre_context` | recall | 0.005 | 0.000 to 0.017 | 0.7680 |
| `cri:no_user_context` | `cri:no_mitre_context` | insiders_caught_share | 0.000 | 0.000 to 0.000 | 1.0000 |
| `cri:no_peer_deviation+no_user_context` | `cri:no_mitre_context` | pr_auc | 0.060 | 0.017 to 0.122 | 0.0040 |
| `cri:no_peer_deviation+no_user_context` | `cri:no_mitre_context` | recall | 0.016 | -0.041 to 0.069 | 0.5700 |
| `cri:no_peer_deviation+no_user_context` | `cri:no_mitre_context` | insiders_caught_share | 0.071 | 0.000 to 0.250 | 0.7500 |

## Experiments A and B: training seeds

| Model / configuration | Seeds | Min | Median | Max | Mean | Std |
|---|---|---|---|---|---|---|
| tabnet/behaviour | 6 | 0.193 | 0.393 | 0.578 | 0.377 | 0.152 |
| tabnet/all_features | 6 | 0.235 | 0.317 | 0.469 | 0.330 | 0.091 |
| gbdt/behaviour | 6 | 0.807 | 0.812 | 0.827 | 0.814 | 0.007 |
| gbdt/all_features | 6 | 0.810 | 0.823 | 0.828 | 0.821 | 0.007 |

| Paired test | Pairs | Mean difference | Wins / losses / ties | p (Wilcoxon) | Smallest attainable p |
|---|---|---|---|---|---|
| A_tabnet_vs_xgboost_behaviour_n23 | 6 | -0.437 | 0/6/0 | 0.0312 | 0.0312 |
| B_tabnet_all_features_minus_behaviour | 6 | -0.047 | 2/4/0 | 0.5625 | 0.0312 |
| B_xgboost_all_features_minus_behaviour | 6 | 0.007 | 6/0/0 | 0.0312 | 0.0312 |
| headline_tabnet_vs_xgboost_all_features | 6 | -0.444 | 0/6/0 | 0.0312 | 0.0312 |

- headline_tabnet_vs_xgboost_all_features: XGBoost on all features is the closest seeded reproduction of the Chapter 6 XGBoost baseline; it is not that baseline's own run

Experiment E3 (cost of the interpretability constraint, all features minus behaviour-only, mean PR-AUC over seeds): TabNet -0.047, XGBoost 0.007.

## Experiment C: the CRI and its leave-one-out variants

| Ranking | PR-AUC | Caught@1 | Band HIGH or above |
|---|---|---|---|
| `xgboost_served` | 0.827 | 12/14 | - |
| `cri:no_mitre_context` | 0.655 | 13/14 | 14 alerts, precision 0.929, recall 0.068, caught 6/14 |
| `cri:no_historical_deviation` | 0.731 | 11/14 | 42 alerts, precision 0.976, recall 0.216, caught 7/14 |
| `cri:no_peer_deviation` | 0.715 | 14/14 | 48 alerts, precision 0.938, recall 0.237, caught 14/14 |
| `cri:no_user_context` | 0.658 | 13/14 | 33 alerts, precision 0.970, recall 0.168, caught 13/14 |
| `cri:no_peer_deviation+no_user_context` | 0.715 | 14/14 | 121 alerts, precision 0.843, recall 0.537, caught 14/14 |

## Experiment D: MITRE context

a scenario gain from MITRE is partly by construction (N41); read it beside cri:no_mitre_context and the benign mapped share (N43).

Share of benign test user-days carrying a mapped technique: 0.291 of 84310.

| Scenario | Cell | Days | Mapped | CRI default @1 | CRI without MITRE @1 |
|---|---|---|---|---|---|
| 1 | both | 9 | 9 | 9 | 9 |
| 1 | served_only | 0 | 0 | 0 | 0 |
| 1 | shadow_only | 3 | 3 | 3 | 2 |
| 1 | neither | 4 | 0 | 0 | 0 |
| 2 | both | 84 | 70 | 64 | 71 |
| 2 | served_only | 42 | 38 | 31 | 35 |
| 2 | shadow_only | 2 | 1 | 0 | 0 |
| 2 | neither | 42 | 36 | 8 | 6 |
| 3 | both | 0 | 0 | 0 | 0 |
| 3 | served_only | 2 | 2 | 2 | 2 |
| 3 | shadow_only | 0 | 0 | 0 | 0 |
| 3 | neither | 2 | 1 | 1 | 0 |

## Experiment E1: the alert queue

the queue ranks validation and test users together (N61); a test alert depends on validation users' scores that day.

| View | Ordering | Open | Suppressed | Alert precision | Insiders caught | Malicious days |
|---|---|---|---|---|---|---|
| policy_as_built | anomaly_score | 118 | 17 | 0.220 | s1 6/6, s2 6/6, s3 1/2 | s1 6 open, 1 suppressed only, 9 none of 16, s2 63 open, 19 suppressed only, 88 none of 170, s3 2 open, 0 suppressed only, 2 none of 4 |
| policy_without_deduplication | anomaly_score | 135 | 0 | 0.267 | s1 6/6, s2 6/6, s3 1/2 | s1 7 open, 0 suppressed only, 9 none of 16, s2 82 open, 0 suppressed only, 88 none of 170, s3 2 open, 0 suppressed only, 2 none of 4 |
| other_ordering | cri_score | 140 | 15 | 0.243 | s1 6/6, s2 6/6, s3 1/2 | s1 8 open, 1 suppressed only, 7 none of 16, s2 44 open, 9 suppressed only, 117 none of 170, s3 2 open, 0 suppressed only, 2 none of 4 |
| other_ordering_without_deduplication | cri_score | 155 | 0 | 0.258 | s1 6/6, s2 6/6, s3 1/2 | s1 9 open, 0 suppressed only, 7 none of 16, s2 53 open, 0 suppressed only, 117 none of 170, s3 2 open, 0 suppressed only, 2 none of 4 |

Activity rule: 30 of 501 dates had a changed top-1 slot (38 user-days, 0 malicious). Open alerts never above LOW on the CRI: 27 of 118.

## Experiment E2: explanations

| Scenario | Days | Top factors | Calendar-led share |
|---|---|---|---|
| 1 | 16 | http_leak_paste_count 12, logoff_count 2, peer_dev_http_request_count 1, hist_z_usb_connect_count 1 | 0.000 |
| 2 | 170 | peer_dev_http_request_count 100, usb_disconnect_count 37, hist_z_emails_sent 15, hist_z_usb_connect_count 9 | 0.000 |
| 3 | 4 | hist_z_emails_sent 1, logoff_count 1, usb_last_hour 1, hist_abs_z_file_event_count 1 | 0.000 |

False alarms at top-1: 364 days; leading factors peer_abs_dev_login_count 115, hist_z_usb_connect_count 92, usb_disconnect_count 50, hist_abs_z_http_request_count 25. Integrity: 84516 rows, max additivity error 0.000030, 0 with a static trait in the top five.

SECOND MODEL'S VIEW (shadow TabNet masks); never shown to an analyst (N30, N32).

| Scenario | Days | Mean top-5 Jaccard with TreeSHAP | Top mask factors |
|---|---|---|---|
| 1 | 16 | 0.099 | usb_off_hours_events 12, peer_median_http_distinct_hosts 2, hist_z_http_distinct_hosts 2 |
| 2 | 170 | 0.036 | usb_off_hours_events 113, is_weekend 31, hist_z_usb_connect_count 13 |
| 3 | 4 | 0.118 | peer_median_http_distinct_hosts 2, hist_z_usb_connect_count 1, hist_abs_z_usb_connect_count 1 |

## Harness checks

| Check | Result | Detail |
|---|---|---|
| every ranking covers exactly the served model's rows | PASS | 84516 test rows, 14 rankings |
| recombining the stored components reproduces the stored cri_score | PASS | cri_variant_outputs raises otherwise |
| cri:anomaly_only never reverses the anomaly score's order (ties allowed) | PASS | distinct values 63824 -> 32866; PR-AUC shift from ties 3.28e-03 |
| the risk run's anomaly score equals the Chapter 8 batch's served score | PASS | max difference 0.00e+00 |
| baseline:rule_based: recomputed test PR-AUC equals the one its Chapter 6 run logged | PASS | logged 0.014882924593174284, recomputed 0.014882924593174284 |
| baseline:isolation_forest: recomputed test PR-AUC equals the one its Chapter 6 run logged | PASS | logged 0.015525253249517323, recomputed 0.015525253249517323 |
| baseline:lof: recomputed test PR-AUC equals the one its Chapter 6 run logged | PASS | logged 0.007337273745975112, recomputed 0.007337273745975112 |
| baseline:lstm_autoencoder: recomputed test PR-AUC equals the one its Chapter 6 run logged | PASS | logged 0.078362011058405, recomputed 0.078362011058405 |
| baseline:gbdt_all_features: recomputed test PR-AUC equals the one its Chapter 6 run logged | PASS | logged 0.827690579579137, recomputed 0.827690579579137 |
| xgboost_served test PR-AUC equals the Chapter 8 test readout (gbdt) | PASS | Chapter 8 0.8265240869827831, here 0.8265240869827831 |
| tabnet test PR-AUC equals the Chapter 8 test readout (tabnet) | PASS | Chapter 8 0.3589115124971715, here 0.3589115124971715 |
| baseline:gbdt_all_features test PR-AUC equals the Chapter 8 test readout (gbdt_ch6_all_feat) | PASS | Chapter 8 0.827690579579137, here 0.827690579579137 |
| a fresh load of every stored ranking is identical (metrics are reproducible) | PASS | 14/14 rankings identical |

## Guard c16-evaluation-guard-v1

- WARN: cri:default PR-AUC 0.6323 < anomaly score 0.8265
- WARN: scenario 3 has 4 test days: no claim is made about it (N15)

## Deviations

- C16-1: The Bible's chain ends 'TabNet + CRI + MITRE'. The served model is XGBoost (C8-1) and the CRI is calibrated to it (N33); shadow scores never feed a CRI (N32). The chain therefore ends in XGBoost + CRI + MITRE, and TabNet is compared as the supervised alternative (N23).
- C16-2: Experiments C and D run on the one served model_version, because the CRI calibration is pinned to it (N33). Their 'seeds' are tie-break seeds for the daily top-k plus a user-clustered bootstrap. Training seeds belong to experiments A and B.
- C16-3: Risk coverage is defined in app/evaluation/operating.py; the Architecture text that names it was not available. It is always printed with the review load.

## Disclosures

- Test was read once per model in Chapter 8 (experiments/chapter8_test_readout.json). This is the designated Chapter 16 readout; nothing about design may change after it.
- The mid all-features TabNet test PR-AUC was seen during tuning (C7-9, N26). Experiment B uses new seeds on full.
- The variant 'cri:no_peer_deviation+no_user_context' was found by looking at validation (N40). It is reported, not adopted.
- The alert queue ordering and the MITRE / user_context rules touch behaviour the public scenarios describe (N41, N36). A scenario gain from them is partly by construction.
- The headline is mostly scenario 2 (N15). Scenario 3 has too few test days for any claim.

## Caveats

- one trained model per ranking except experiments A and B (seeds, N26)
- a bootstrap interval is about which users the test set holds, not about training noise
- scenario 2 supplies most positives (N15); six scenario-1 insiders cannot settle a scenario claim
- nothing here is a probability of malice (N20)
