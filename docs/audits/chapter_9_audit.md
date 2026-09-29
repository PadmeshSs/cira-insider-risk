# Chapter 9 audit (29 September 2026)

Scope: Chapter 9 (Contextual Risk Intelligence), checked against the Bible Chapter 9 acceptance
list, HCEA v1.0 §9 and CARRY_FORWARD N1-N39.
Evidence: `experiments/chapter9_cri_calibration.json`, `experiments/chapter9_validation_readout.json`,
`experiments/chapter9_reference_runs.json`, `experiments/runlog.jsonl` and the verifier output (logs
under `experiments/results/chapter9/signoff_logs/`, gitignored). Every number below is copied from those
files by `scripts/signoff_chapter9.py`.

Served model: gbdt v0003 (`gbdt-chapter8-v1-077a3dae6cee`), from the Chapter 8 decision. Calibration `20260929T095921Z-full-cri`; risk run `20260929T095927Z-full-cri-default`.

## Verification record

| What | Verifier |
|---|---|
| calibration + risk run, before labels | 32 PASS, 0 WARN, 0 FAIL |
| including the readout | 36 PASS, 3 WARN, 0 FAIL |
| test suite | 261 passed, 615 warnings in 112.73s (0:01:52) |
| /health | healthy, CRI loaded |

WARNs and why they are acceptable:

- `WARN readout     c9-cri-guard-v1  -- PR-AUC 0.6937 < anomaly score 0.9155`: Recorded as the result, not accepted as an improvement. The default weights were fixed before this readout (N37). The leave-one-out variants locate the loss in peer deviation (0.824 without it) and user context (0.822 without it); historical deviation is the only component whose removal lowers PR-AUC further (0.653). Weights are not changed on validation. Chapter 12 chooses the queue ordering explicitly, and Chapter 16 reads every variant on test (N40).
- `WARN readout     c9-cri-guard-v1  -- scenario 2 malicious days at top-1: 110/179 < anomaly score 125/179`: Same cause as the PR-AUC loss. Scenario 2 supplies 179 of the 202 validation positives (N15), so the headline drop is mostly this. Removing peer deviation or user context brings it back to 116 or 117; neither variant reaches the anomaly score's 125. Recorded, not tuned (N37, N40).
- `WARN readout     c9-cri-guard-v1  -- scenario 3 malicious days at top-1: 1/4 < anomaly score 2/4`: One day out of four; nothing can be concluded from four days (N15). The drop happens with and without user context (1/4 in both), so the privileged-role component did not cause it. Recorded.

## Calibration (label-free)

Reference: 89018 validation user-days (194 users, 500 days) of Chapter 8 batch `20260928T194858Z-full-batch`. Maximum reachable rarity 0.990 (D = 5.0).

| model_split | rows | q0.5 | q0.9 | q0.99 | q0.999 | max |
|---|---|---|---|---|---|---|
| test | 84516 | 7.37e-08 | 2.55e-06 | 0.00534 | 1 | 1 |
| train | 291153 | 8.82e-08 | 3.65e-06 | 0.000308 | 1 | 1 |
| validation | 89018 | 7.95e-08 | 4.08e-06 | 0.000448 | 1 | 1 |

Context on the reference: historical null share 0.015, peer null share 0.033, no LDAP row 0.005, privileged user-days 0.0190 (5 users).

### Served vs shadow on the same validation user-days (N32 monitoring)

Shadow tabnet:v0005, 89018 rows. Spearman 0.285; top-1% overlap 0.465; share of shadow scores at or above the served model's 99th percentile 0.1810, and the reverse 0.0018; mean daily top-1 Jaccard 0.356, top-5 0.210.

## Risk run (label-free)

464687 user-days. Severity: LOW 448106, MEDIUM 16334, HIGH 245, CRITICAL 2.
Effective weights: anomaly 0.667, historical_deviation 0.167, peer_deviation 0.111, user_context 0.056.
Unavailable: asset_criticality (CERT r4.2 has no asset inventory or criticality source (N9); no user-day-to-asset criticality was supplied, so the component is excluded, never invented); mitre_context (MITRE ATT&CK enrichment is Chapter 10; not wired yet).

- validation: HIGH or above per day median 0.0, p95 1.0, max 2; CRITICAL per day median 0.0, max 0
- test: HIGH or above per day median 0.0, p95 0.0, max 1; CRITICAL per day median 0.0, max 0

## Validation readout (89018 rows, 202 malicious user-days, chance 0.0023)

| Ranking | PR-AUC | ROC-AUC (secondary) | Recall@1 | Caught@1 | Caught@5 | Days at top-1 by scenario | Insiders at top-1 by scenario |
|---|---|---|---|---|---|---|---|
| anomaly_score | 0.915 | 0.999 | 0.663 | 9/14 | 14/14 | s1 7/19, s2 125/179, s3 2/4 | s1 3/6, s2 5/6, s3 1/2 |
| cri:anomaly_only | 0.915 | 0.999 | 0.663 | 9/14 | 14/14 | s1 7/19, s2 125/179, s3 2/4 | s1 3/6, s2 5/6, s3 1/2 |
| cri:default | 0.694 | 0.998 | 0.594 | 11/14 | 14/14 | s1 9/19, s2 110/179, s3 1/4 | s1 4/6, s2 6/6, s3 1/2 |
| cri:no_historical_deviation | 0.653 | 0.999 | 0.579 | 9/14 | 14/14 | s1 7/19, s2 109/179, s3 1/4 | s1 3/6, s2 5/6, s3 1/2 |
| cri:no_peer_deviation | 0.824 | 0.999 | 0.614 | 10/14 | 14/14 | s1 7/19, s2 116/179, s3 1/4 | s1 3/6, s2 6/6, s3 1/2 |
| cri:no_user_context | 0.822 | 0.999 | 0.629 | 11/14 | 14/14 | s1 9/19, s2 117/179, s3 1/4 | s1 4/6, s2 6/6, s3 1/2 |
| tabnet anomaly score (Ch8 evidence, not a CRI) | 0.749 | | | 12/14 | | s1 14/19, s2 97/179, s3 0/4 | s1 6/6, s2 6/6, s3 0/2 |
| gbdt_ch6_all_feat anomaly score (Ch8 evidence, not a CRI) | 0.939 | | | 9/14 | | s1 6/19, s2 129/179, s3 2/4 | s1 3/6, s2 5/6, s3 1/2 |

Default CRI as a band alert (primary view):

- HIGH_or_above: 54 alerts, precision 0.833, recall 0.223, insiders caught 8/14, alerts per day median 0.0, max 2
- CRITICAL: 0 alerts, precision n/a, recall 0.000, insiders caught 0/14, alerts per day median 0.0, max 0

Harness: cri:anomaly_only ranks like the anomaly score (same PR-AUC): PASS; anomaly score PR-AUC equals the Chapter 8 decision evidence: PASS.

Guard c9-cri-guard-v1: 3 warning(s), listed with the WARNs above.

## Notes

- One seed per model; no confidence intervals yet. Chapter 16 adds seeds and bootstrap intervals (C6-2, C7-7).
- The CRI was not read on test. Its test readout is Chapter 16's ablation C (N37).
- Any scenario-3 difference from user_context is expected by construction and is not evidence (N36).
- Rows tagged `train` are in-sample; nothing above quotes detection from them (N31).
