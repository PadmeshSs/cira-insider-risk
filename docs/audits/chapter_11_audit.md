# Chapter 11 audit (30 September 2026)

Scope: Chapter 11 (explainability), checked against the Bible Chapter 11 acceptance list, HCEA v1.0
§11 and D-5, and CARRY_FORWARD N1-N48.
Evidence: `experiments/chapter11_validation_readout.json`, `experiments/chapter11_reference_runs.json`,
`experiments/runlog.jsonl`, the explain run's `explain_meta.json` under
`<CERT_PROCESSED_DIR>/explanations/chapter11/`, and the verifier reports under
`experiments/results/chapter11/` (gitignored). Every number below is copied from the console output
of those runs on the development machine, or from the readout and meta files printed there. Chapter 11
has no sign-off script, so this audit was written by hand from that output.

Served model: gbdt v0003 (`gbdt-chapter8-v1-077a3dae6cee`), best iteration 590 (TreeSHAP iteration
range 0-591), 106 inputs, no static input. Shadow: tabnet v0005 (`tabnet-chapter7-v1-e03b3d0d3360`),
used only in the readout's second model's view.

## Reported runs

| What | Id |
|---|---|
| Explain run | `20260930T190519Z-full-explain` |
| Verifier before the readout | `verification_20260930T191005Z` |
| Verifier after the readout | `verification_20260930T191038Z` |
| Validation readout | `experiments/chapter11_validation_readout.json` (written once) |
| Chapter 8 batch, CRI run and enrichment run it explains | as recorded in the run's `explain_meta.json` (`source_batch`, `risk_run`, `mitre`); the batch selects the newest default CRI run with MITRE of the served batch |
| Chapter 5 matrix fingerprint | `4f09afb11a8f` |

## Verification record

| What | Result |
|---|---|
| explain run, before labels (`verify_chapter11.py --no-readout`) | 41 PASS, 2 WARN, 0 FAIL |
| including the readout (`verify_chapter11.py`) | 45 PASS, 2 WARN, 0 FAIL |
| /health | anomaly model, CRI, MITRE and explainability all `loaded`; explainability: TreeSHAP on gbdt v0003, role served, iteration range 0-591 |
| test suite | 326 passed, 1 skipped (pre-existing), on Linux, Python 3.12; not yet run on the development machine |

The readout was written once. The same two WARNs appear in both verifier runs, and nothing else differs
between them apart from the four readout checks, which all passed.

WARNs and why they are acceptable:

- `WARN selection  nothing cut by --max-bounded-rows  -- 465 cut`: 765 user-days met the selection rule
  (6 by severity, 244 by daily top-1 anomaly score, 156 by daily top-1 CRI, with overlap) and the cap is
  300 (D-5 keeps KernelSHAP bounded). The ordering keeps test users first (N31), so all 300 selected
  rows are test users. The 465 cut rows are still explained by TreeSHAP in the run; they have no
  KernelSHAP row and no written reason. Chapter 12 explains its alert rows on demand through the same
  builder (N50), so no alert depends on the cap. The cap is not raised.
- `WARN kernel  median top-5 overlap with the primary explanation >= 0.4  -- 0.250`: KernelSHAP and
  TreeSHAP share a median of one feature in five, and their rank correlation over the union of the two
  top-10s has a median of -0.07. On the same 300 rows, the signs of TreeSHAP's top five agree with
  KernelSHAP's (median 1.0, 10th percentile 0.8), and the deletion check is decisive: removing the top
  raising features by TreeSHAP lowered the margin by a median of 10.5 log-odds, against 0.55 for as many
  random features, on 300 of 300 rows. The explanation names features the model relies on; the two
  estimators divide the credit among them differently. That difference was expected: KernelSHAP
  estimates interventional SHAP against a 50-row background, TreeSHAP the path-dependent value (N48). A
  likely further cause is the near-duplicate input pairs (`hist_z_x` / `hist_abs_z_x`, `peer_dev_x` /
  `peer_abs_dev_x`, USB connect / disconnect), which can trade credit with each other. That is a
  hypothesis; testing it would mean comparing the two top-5s after grouping each pair. Nothing is
  changed (N48).

## TreeSHAP over every user-day

| | |
|---|---|
| user-days explained | 464,687 (train 291,153, validation 89,018, test 84,516) |
| attribution rows kept (top 10 per user-day) | 4,646,870 |
| additivity error against the served margin | median 5.4e-06, 90th percentile 1.2e-05, max 3.9e-05 log-odds (tolerance 1e-3) |
| stored margin against the Chapter 8 batch `raw_score` | max difference 0 |
| TreeSHAP against `shap.TreeExplainer` (500 rows, shap 0.52.0) | max difference 0 |
| recomputation of the stored top-10 (2,000 sampled rows) | identical |
| static trait in any top five | 0 rows |
| out-of-sample rows led by a calendar column | 0.7% |
| out-of-sample rows with no raising factor | 0 |
| wall-clock | 88.5 s TreeSHAP, 137.8 s KernelSHAP on 300 rows, 242.9 s in total |
| peak RSS | 2,575 MB (limit 10,240 MB) |

The served model stopped at iteration 590 of 600, so the iteration range covers 591 trees. Here the
range changes less than it did on the 4.56-log-odds probe in the chapter document, but the additivity
check on every row is what shows it was applied.

Most frequent top raising factor over all 173,534 validation and test user-days, benign or not:
`peer_abs_dev_login_count` 71,168 (41%), `hist_z_http_distinct_hosts` 28,863, `hist_z_usb_connect_count`
15,297, `file_doc_count` 9,361, `email_bcc_count` 8,704. Most of those days score low, so this
describes what nudges ordinary days up, not what drives alerts.

## Written explanations (bounded set)

300 explanations, all complete, all from test users. Every model factor, CRI point and ATT&CK match
was re-checked against the stored attributions, the risk run and the enrichment run with no problem
found. No generic statement, no static trait, nothing from the shadow model, no CRI or ATT&CK item
listed as a model factor, and every `indicated` ATT&CK match worded as a visit.

## First real readout (full / user validation, primary view)

One seed, validation only. Top raising factor on each malicious validation day, and the domain mix of
the top three factors:

| Scenario | Days | Most frequent top factor | Top-3 domain mix |
|---|---|---|---|
| 1 | 19 | `http_leak_paste_count` 15, `hist_z_usb_connect_count` 2, `usb_disconnect_count` 1, `logoff_count` 1 | device 0.32, http 0.26, historical 0.19, peer 0.16, logon 0.05, email 0.02 |
| 2 | 179 | `peer_dev_http_request_count` 114, `usb_disconnect_count` 38, `hist_z_emails_sent` 19, `hist_z_usb_connect_count` 4, `usb_connect_count` 3, `peer_abs_dev_login_count` 1 | peer 0.42, historical 0.31, device 0.24, http 0.02, email 0.004 |
| 3 | 4 | four different factors, one day each | too few days to read (N15) |
| false alarms (benign days in the served model's daily top-1) | 366 | `usb_disconnect_count` 192, `peer_dev_http_request_count` 45, `hist_z_usb_connect_count` 35, `peer_abs_dev_login_count` 22, `hist_abs_z_http_request_count` 16 | device 0.51, historical 0.28, peer 0.18, email 0.01, logon 0.01, file 0.005, http 0.004 |

Guard `c11-explain-guard-v1`: no warning. No served explanation has a static trait in its top five, and
no scenario is led by a calendar column.

What this shows and does not show:

- **Scenario 1.** Leak-site visits lead 15 of 19 malicious days. That behaviour is in the public
  scenario description, so the match is partly by construction of the dataset (N41). It also sits
  beside N46: the served model ranks only 7 of these 19 days at the daily top-1. The model's own
  explanation points at the right behaviour on most scenario-1 days, and the day still loses the top
  slot to other users' days. Why is not established here.
- **Scenario 2.** Web volume above the peer median leads 114 of 179 days, and job-search visits
  (`http_job_search_count`) never lead a malicious day. The model explains scenario 2 mostly through
  volume against peers and the user's own history, not through the job-search host class. This is a
  description of the explanation, not of intent.
- **False alarms.** `usb_disconnect_count` leads 192 of 366 benign top-1 days (52%), and the device
  domain supplies half of their top-three factors. The same feature leads 38 of 179 scenario-2 days. It
  is the reason an analyst would read most often on a wrong alert. Recorded as N52 for Chapters 12, 14
  and 16. Nothing is changed on validation.

### Second model's view (shadow TabNet masks, never shown to an analyst)

| Scenario | Days | Most frequent top mask feature | Mean top-5 Jaccard with TreeSHAP |
|---|---|---|---|
| 1 | 19 | `usb_off_hours_events` 15, `hist_z_http_distinct_hosts` 2, `weekend_login_ratio` 1, `is_weekend` 1 | 0.053 |
| 2 | 179 | `usb_off_hours_events` 112, `is_weekend` 31, `hist_z_usb_connect_count` 17, `file_archive_or_executable_count` 10 | 0.065 |
| 3 | 4 | `file_archive_or_executable_count` 2, two others | 0.156 |

The two models explain the same malicious days with almost disjoint features. TabNet attends to
off-hours USB activity on 15 of 19 scenario-1 days and 112 of 179 scenario-2 days. That matches the
scenario descriptions, so it is partly by construction too (N41). On 31 scenario-2 days TabNet's top
feature is `is_weekend`, a calendar column. The guard covers the served model only, so this did not
WARN, but it matters for the case for TabNet (N23, N51): its masks look at behaviour the scenarios
describe, and on one day in six of scenario 2 they look at the calendar. A mask is attention, not
direction; this does not say those features raised TabNet's score. Recorded as N53.

## Checklist

Bible Chapter 11:

- [x] A sample alert produces a reason list traceable to real model attributions, CRI factors and
  ATT&CK matches (300 on CERT full, all re-checked by the verifier)
- [x] No generic explanation strings
- [x] SHAP failure degrades gracefully (tested on the synthetic chain; no failure on CERT)

HCEA §11 / D-5:

- [x] TreeSHAP in 50,000-row chunks, top 10 persisted, never the dense matrix
- [x] KernelSHAP bounded (300 rows), 50-row training background, nsamples 2,260 (C11-2, C11-3)

N49:

- [x] full explain run verified with 0 FAIL before the readout
- [x] validation readout written once, verifier 0 FAIL again
- [x] `/health` shows the explainability block loaded
- [x] this audit, every WARN explained

## Still open

- The test suite has not been run on the development machine for Chapter 11. Run `pytest` from the
  repository root and add the result to the verification record.
- The KernelSHAP disagreement hypothesis (near-duplicate inputs) is untested.
- Everything above is one seed on validation. Test-set explanation statistics belong to Chapter 16.
