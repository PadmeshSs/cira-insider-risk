# Chapter 10 audit (29 September 2026)

Scope: Chapter 10 (MITRE ATT&CK enrichment), checked against the Bible Chapter 10 acceptance list,
HCEA v1.0 §10 and D-4, and CARRY_FORWARD N1-N45.
Evidence: `experiments/chapter10_mitre_reference.json`, `experiments/chapter10_validation_readout.json`,
`experiments/chapter10_reference_runs.json`, `experiments/runlog.jsonl`, and the verifier reports under
`experiments/results/chapter10/` and `experiments/results/chapter9/` (gitignored). Every number below is
copied from the console output of those runs on the development machine. Chapter 10 has no sign-off
script, so this audit was written by hand from that output.

Served model: gbdt v0003 (`gbdt-chapter8-v1-077a3dae6cee`), from the Chapter 8 decision, with
tabnet v0005 in shadow. ATT&CK 19.2 (bundle sha256 `dc1639ca…`, table sha256 `f33bc9d4…`), ruleset
`c10-rules-v1` (`d58ec9c75bc6`).

## Reported runs

| What | Id |
|---|---|
| MITRE reference | `20260929T184428Z-full-mitre` |
| Enrichment run | `20260929T184439Z-full-mitre` |
| CRI run with MITRE | `20260929T184445Z-full-cri-default-mitre` (formula_hash `3bea2eac4884`, config_hash `297bbbe7add7`) |
| CRI calibration (Chapter 9, reused) | `20260929T095921Z-full-cri` |
| CRI run without MITRE (Chapter 9) | `20260929T095927Z-full-cri-default` |
| Chapter 8 batch | `20260928T194858Z-full-batch` |
| Chapter 5 matrix fingerprint | `4f09afb11a8f` |

## Verification record

| What | Verifier |
|---|---|
| table + reference + enrichment + CRI join, before labels (`verify_chapter10.py --no-readout`) | 39 PASS, 0 WARN, 0 FAIL |
| the CRI run with MITRE under the Chapter 9 verifier (`verify_chapter9.py --cri-run-id … --no-readout`) | 31 PASS, 0 WARN, 0 FAIL |
| including the readout (`verify_chapter10.py`) | 45 PASS, 2 WARN, 0 FAIL |
| test suite (Windows, Python 3.13.3) | 292 passed, 1 skipped (pre-existing) |
| /health | healthy; anomaly model gbdt v0003 loaded; CRI loaded with `20260929T095921Z-full-cri`; MITRE loaded with ATT&CK 19.2 and reference `20260929T184428Z-full-mitre` |

The readout was written once. The verifier was run twice after it (reports `…184836Z` and `…184920Z`),
with identical results.

In both readout runs, the "disagreement view present" check printed its WARN message ("no shadow rows
in the source batch") beside a PASS. The check passed and the view is in the readout; only the message
was wrong. It is fixed in `scripts/verify_chapter10.py`, which now prints the shadow model and budget.
No result changes.

WARNs and why they are acceptable:

- `WARN readout  c10-mitre-guard-v1  -- PR-AUC 0.5572 < cri:no_mitre_context 0.6937`: Recorded as the
  result, not accepted as an improvement. The ruleset and the MITRE weight (0.10, set in Chapter 9) were
  fixed before this readout (N43). The loss is in scenario 2, which supplies 179 of the 202 validation
  positives (N15). Over the same rows, insiders caught at top-1 rose from 11/14 to 13/14 and scenario-1
  days at top-1 from 9/19 to 13/19. Those gains are partly by construction of the dataset (N41). Nothing
  is changed on validation. Chapter 16 reads ablation D on test, once (N46).
- `WARN readout  c10-mitre-guard-v1  -- scenario 2 malicious days at top-1: 93/179 < cri:no_mitre_context 110/179`:
  Same cause. In the four-cell view the losses fall where the served model was already right: "both"
  from 77 to 70 at top-1, "served only" from 30 to 21. Scenario-2 days carry a mapped technique more
  often than benign days (134/179 against 27%), but mostly the common, weakly graded kind
  (removable-media copies, cloud storage). The likely mechanism is that rarer matches on other rows
  (scenario-1 leak-site days, a few benign days) take the daily top-1 slot. That is not yet shown; it
  would need a look at which rows took the lost slots. Recorded, not tuned (N43).

## Technique table and rules

ATT&CK 19.2 enterprise bundle, published 2026-08-05, 697 active techniques and 15 tactics, generated
offline by `app.mitre.stix_loader` and committed. Every rule names an active technique under the
tactic it claims, and every rule column exists in the full matrix:

| Rule | Technique | Tactic | Evidence |
|---|---|---|---|
| R01_removable_media_copy | T1052.001 Exfiltration Over Physical Medium: Exfiltration over USB | exfiltration | observed |
| R02_leak_site_access | T1567 Exfiltration Over Web Service | exfiltration | indicated |
| R03_cloud_storage_access | T1567.002 Exfiltration Over Web Service: Exfiltration to Cloud Storage | exfiltration | indicated |
| R04_attack_tool_site_access | T1588.002 Obtain Capabilities: Tool | resource-development | indicated |

Eight behaviours are recorded as deliberately unmapped, with reasons (`docs/chapters/chapter_10_mitre.md`).

## Reference (label-free)

89,018 validation user-days of the shared user split (N11), the same rows as the Chapter 9
calibration. No label, no model column. Rarity scale D = 5.

| Rule | Fires on share of reference days | Strength of one triggering event |
|---|---|---|
| R01_removable_media_copy | 0.0873 | 0.212 |
| R02_leak_site_access | 0.0002 | 0.749 |
| R03_cloud_storage_access | 0.2139 | 0.134 |
| R04_attack_tool_site_access | 0.0000 (about 2 days, from the strength) | 0.894 |

Mapped share of the reference: 0.2736.

## Enrichment run (label-free)

464,687 user-days: mapped 127,835, unmapped 336,852, not evaluated 0. 141,358 matches.

| Rule | User-days | Users |
|---|---|---|
| R01_removable_media_copy | 45,907 | 264 |
| R02_leak_site_access | 68 | 30 |
| R03_cloud_storage_access | 95,375 | 812 |
| R04_attack_tool_site_access | 8 | 8 |

A from-scratch recomputation reproduced every row. Peak RSS 862.5 MB.

## CRI run with MITRE (label-free)

Effective weights: anomaly 0.600, historical_deviation 0.150, peer_deviation 0.100, user_context 0.050,
mitre_context 0.100. Asset criticality unavailable (N9, N35).

| Severity | Chapter 9 run (no MITRE) | Chapter 10 run (with MITRE) |
|---|---|---|
| LOW | 448,106 | 450,017 |
| MEDIUM | 16,334 | 14,519 |
| HIGH | 245 | 151 |
| CRITICAL | 2 | 0 |

Highest CRI 69.638. HIGH or above per day: validation median 0, p95 1, max 2; test median 0, p95 0,
max 1 (the same as Chapter 9). The drop in HIGH follows from renormalisation: with MITRE in, the
anomaly score's effective weight falls from 0.667 to 0.600, so the anomaly score alone needs about
1-in-14,700 rarity to reach HIGH instead of 1-in-5,600, and a MITRE match adds at most 10 points.
Peak RSS 1,056 MB.

## Validation readout (89,018 rows, 202 malicious user-days, chance 0.0023)

| Ranking | PR-AUC | Caught@1 | Caught@5 | Days at top-1 by scenario |
|---|---|---|---|---|
| anomaly_score (gbdt v0003) | 0.915 | 9/14 | 14/14 | s1 7/19, s2 125/179, s3 2/4 |
| cri:anomaly_only | 0.915 | 9/14 | 14/14 | s1 7/19, s2 125/179, s3 2/4 |
| cri:no_mitre_context (the Chapter 9 formula) | 0.694 | 11/14 | 14/14 | s1 9/19, s2 110/179, s3 1/4 |
| cri:default (with MITRE) | 0.557 | 13/14 | 14/14 | s1 13/19, s2 93/179, s3 1/4 |
| mitre_context alone | 0.039 | 7/14 | 9/14 | s1 12/19, s2 0/179, s3 2/4 |
| tabnet v0005 anomaly score (Chapter 8 evidence, not a CRI) | 0.749 | 12/14 | | s1 14/19, s2 97/179, s3 0/4 |

Benign validation user-days with a mapped technique: 0.2725.

Harness: recombining stored components reproduces the stored cri_score (max diff 0): PASS;
cri:anomaly_only ranks like the anomaly score: PASS; cri:no_mitre_context equals the Chapter 9
readout's cri:default (0.693657 both): PASS.

### Served vs shadow at daily top-1 (N32 monitoring)

Malicious validation days per cell: days / MITRE-mapped / at top-1 with MITRE / at top-1 without MITRE.

| Scenario | both | served only | shadow only | neither |
|---|---|---|---|---|
| 1 | 6 / 6 / 6 / 6 | 1 / 0 / 0 / 1 | 8 / 8 / 6 / 2 | 4 / 2 / 1 / 0 |
| 2 | 86 / 58 / 70 / 77 | 39 / 31 / 21 / 30 | 11 / 10 / 1 / 1 | 43 / 35 / 1 / 2 |
| 3 | 0 / 0 / 0 / 0 | 2 / 1 / 1 / 1 | 0 / 0 / 0 / 0 | 2 / 2 / 0 / 0 |

Read against the interpretations written in the chapter doc before any number existed:

- **Scenario 1.** Every one of the 8 days TabNet caught and XGBoost missed carries a mapped technique.
  The CRI with MITRE puts 6 of them at top-1, against 2 without. With MITRE, the served XGBoost reaches
  13/19 scenario-1 days (TabNet 14/19) and 13/14 insiders at top-1 (TabNet 12/14). This is the outcome
  the doc described as "recovers part of TabNet's scenario-1 advantage". MITRE context alone gets 12/19
  scenario-1 days and 0/179 scenario-2 days, which shows how closely the rules match scenario 1's
  design. Partly by construction (N41), six validation insiders (N15), one seed: a reason for Chapter
  16 to test it, nothing more.
- **Scenario 2.** The CRI with MITRE loses days, as the doc allowed for. The guard WARNed and the WARN
  is explained above. No rule or weight was changed (N43).
- **Scenario 3.** Four days, nothing can be concluded (N15).

## Notes

- One seed per model; no confidence intervals yet. Chapter 16 adds seeds and bootstrap intervals and
  reads ablation D on test, once.
- MITRE context was not read on test.
- Any scenario difference from MITRE context is partly by construction (N41) and is quoted next to
  `no_mitre_context` and the benign mapped share (N43).
- Rows tagged `train` are in-sample; nothing above quotes detection from them (N31).
