# Chapter 12 audit (1 October 2026)

Scope: Chapter 12 (alert correlation and persistence), checked against the Bible Chapter 12 acceptance
list, Architecture §17, §20, §36 and §37, HCEA v1.0 §12 and D-6, and CARRY_FORWARD N1-N59.
Evidence: the alert run's `alert_meta.json` and load record `loads/load_20261001T063107Z.json` under
`<CERT_PROCESSED_DIR>/alerts/chapter12/20261001T062628Z-full-alerts/`,
`experiments/chapter12_validation_readout.json`, the verifier reports under
`experiments/results/chapter12/` (gitignored), a `/health` response saved on the development machine,
and the console output of every step. Every number below is copied from those. Chapter 12 has no
sign-off script, so this audit was written by hand from that output.

Served model: gbdt v0003 (`gbdt-chapter8-v1-077a3dae6cee`), 106 inputs, no static input. The shadow
tabnet v0005 is never read by the alert batch (N32).

## Reported runs

| What | Id |
|---|---|
| Alert run | `20261001T062628Z-full-alerts` (profile full, `--rows evaluation`) |
| Policy | `c12-alert-policy-v1`, hash `21cd9391fd48`, no override |
| Explain run it uses | `20260930T190519Z-full-explain` (TreeSHAP) |
| Chapter 8 batch | `20260928T194858Z-full-batch` |
| CRI run | `20260929T184445Z-full-cri-default-mitre` (formula `3bea2eac4884`, config `297bbbe7add7`, calibration `20260929T095921Z-full-cri`) |
| Enrichment run | `20260929T184439Z-full-mitre` (rules `c10-rules-v1` / `d58ec9c75bc6`, ATT&CK 19.2, reference `20260929T184428Z-full-mitre`) |
| Chapter 5 matrix fingerprint | `4f09afb11a8f` |
| Load | `20261001T063107Z` into `insider_threat_db` at Alembic `9f3b2c7d4e81` |
| Verifier before the load | `verification_20261001T063009Z` |
| Verifier after the load | `verification_20261001T063327Z` |
| Verifier with the readout | `verification_20261001T063605Z` |
| Validation readout | `experiments/chapter12_validation_readout.json`, written once at 2026-10-01T06:33:35Z |

## Verification record

| What | Result |
|---|---|
| `alembic upgrade head` | `7c1e4a9d2b60 -> 9f3b2c7d4e81` on the development machine's PostgreSQL (Docker, port 5433) |
| alert run, before the load (`--no-readout`) | 36 PASS, 0 WARN, 0 FAIL |
| after the load (`--no-readout --database-url`) | 50 PASS, 0 WARN, 0 FAIL |
| with the readout (`--database-url`) | 53 PASS, 2 WARN, 0 FAIL |
| `/health`, first check | anomaly model, CRI, MITRE and explainability `loaded`; `database` reachable, revision `9f3b2c7d4e81`, 1 alert run loaded; `alerts` **unavailable** (see below) |
| `/health`, after the C12-13 fix | `alerts` `loaded`: run `20261001T062628Z-full-alerts`, policy hash `21cd9391fd48`, no override, 232 open and 33 suppressed alerts, explanations 519 complete, explain run `20260930T190519Z-full-explain`, CRI run `20260929T184445Z-full-cri-default-mitre`, loaded into the database at `20261001T063107Z` |
| test suite | 352 passed, 1 skipped (the CERT sample test) on Linux, Python 3.12, with the PostgreSQL test against a database at head; not yet run on the development machine |

The database section of the verifier traced all 519 member days through alert, risk score, anomaly
score, feature vector and model version to their source events (§37), found the audit row of the
load, and matched every stored row count to the run.

### The `/health` alerts block

The first `/health` check reported `alerts` unavailable because it looked for an alert run under
profile `dev`. The API took the profile from `CIRA_PROFILE` in `.env`. That variable is the batch
execution budget, and on the development machine it is `dev`. Nothing else in the API reads it, which
is why every other block loaded. This was a bug in `app.alerts.runtime`. The runtime now follows the
profile of the model it serves, which is the only profile an alert run can match (N28, N30), and keeps
`CIRA_PROFILE` as the fallback. The integration test now sets `CIRA_PROFILE=dev` and expects the full
run to load. Recorded as C12-13. The alert run, the load and the readout do not depend on this code,
so nothing was rerun; only the `/health` check was repeated, and it shows the run loaded.

The first attempt at `/health` reached the `cira-insider-risk-backend-1` container on port 8000, which
runs the image built before Chapter 12 and answered with the Chapter 1 body. The check above was made
against `uvicorn` on port 8010 from the current code. See "Still open".

### WARNs and why they are acceptable

Both WARNs come from guard `c12-alert-guard-v1`, which flags malicious validation days that sit only
in suppressed alerts.

- `scenario 1: 2 malicious days only in suppressed alerts`
- `scenario 2: 35 malicious days only in suppressed alerts`

A suppressed alert always points at an open alert of the same user inside the 7-day cooldown, so no
insider leaves the queue through deduplication. The readout confirms it: insiders whose only alerts
were suppressed is empty under both orderings. What suppression hides is continuation. For scenario
2, 89 malicious days fall in some alert, and 35 of those (39%) are only in suppressed alerts. These
insiders exfiltrate over weeks with the same pattern, so their later days repeat the signature of an
alert already open. An analyst who reads only the open alert sees when it started, not that it
continued. Nothing in the policy is changed on validation. The dashboard has to show the suppressed
alerts of an open one (N57), and Chapter 16 reports scenario 2 with and without deduplication (N60).

Suppression is not the larger gap. 90 of the 179 scenario-2 malicious days are in no alert at all,
because the queue takes one user-day per day and scenario 2 shares those days with every other user.

## The full alert run

The batch ranked 173,534 user-days of the served model's validation (89,018) and test (84,516)
users. Training users are not ranked (N31).

| Quantity | Value |
|---|---|
| Triggered user-days | 519: 41 by the HIGH/CRITICAL band, 501 by the daily top-1, 23 by both |
| Triggered days with no recorded activity | 0 |
| Alerts | 265: 232 open, 33 suppressed (89 member days in suppressed alerts) |
| Open alerts by split | validation 114, test 118 |
| Open alert length | 186 of 232 are one day (80%); the longest are 10 days (6 alerts) |
| Highest CRI band in an open alert | LOW 54, MEDIUM 156, HIGH 22, CRITICAL 0 |
| New open alerts per date (501 dates) | mean 0.46, median 0, p95 1, max 2; 271 dates have none |
| Top factor of open alerts | `usb_disconnect_count` 68 (29%, N52), `hist_z_usb_connect_count` 58, `peer_dev_http_request_count` 37, `http_leak_paste_count` 13 |
| Explanations | 519 complete, 0 deferred; 4,710 reason rows (model 1,951, CRI 1,415, model_lowering 863, ATT&CK 481) |
| Demo sample | 2011-04-19 to 2011-05-18, 20 users of which 9 alerting, 561 user-days |

On 271 dates no new open alert appears. On those dates the top-1 user-day joined an alert that was
already open for the same user, or opened an alert that was suppressed.

54 open alerts (23%) never rise above LOW on the CRI. They are in the queue only because their day
had the highest anomaly score that day. That is the N40 disagreement between the two scores, now
visible in the queue. It is why the queue shows the band next to every alert (N55).

Two label-free views from the same risk run:

- **Other ordering.** Ordered by the CRI, the daily top-1 would be the same user-day on 260 of 501
  dates and a different one on 241.
- **Activity rule.** With `require_activity` off, 76 user-days change top-1 status. Every date had an
  active top-1 under the policy (no date without a top-1 trigger), so each changed date counts twice,
  once for the day that loses the slot and once for the day that takes it. Without the rule, an idle
  user-day would have taken the top-1 on 38 of 501 dates (7.6%). This rule came from the synthetic
  chain (C12-4), and this is its first CERT number. It also means the alert queue's top-1 differs on
  38 dates from the daily top-1 that Chapters 8 to 10 evaluated, which applied no such rule (N61).

### Cost (HCEA §12, D-6)

| Step | Wall-clock | Peak RSS |
|---|---|---|
| Alert batch | 99.9 s (explanations 96.3 s, correlation 0.6 s) | 1,574 MB |
| Load | 15.8 s | 2,962 MB |

The load wrote 107,098 events and 1,051 user-days (519 member days plus 561 demo days, 29 in both),
together with their feature vectors, anomaly scores and risk scores. On top of that it wrote 265 alerts,
519 members, 4,710 reasons, 1,181 ATT&CK rows and 2 configuration rows, all in one transaction. The
event count is well under the `--max-events` guard. Both steps stay far below the 20 GB budget. The
load's higher RSS comes from reading the Stage 0 event Parquet month by month to pick out member and
demo days.

## First real readout (full / user validation, primary view)

One seed, validation only. Masquerade account-days are neither a hit nor a false alarm (N1). Both
orderings are recomputed from the same risk run.

| | Policy (anomaly score) | Other ordering (CRI) |
|---|---|---|
| Open validation alerts | 114 | 153 |
| Suppressed validation alerts | 16 | 15 |
| Open alerts with a malicious day | 24 | 29 |
| Alert precision | 0.211 | 0.190 |
| False-alarm alerts | 90 | 124 |
| ... led by `usb_disconnect_count` | 44 (49%) | 27 (22%) |
| Latency, first malicious day to alert (days) | median 0, max 25 | median 0, max 17 |

| Scenario | Malicious days | In an open alert | Only in suppressed alerts | In no alert | Insiders caught |
|---|---|---|---|---|---|
| 1, policy | 19 | 7 | 2 | 10 | 5 of 6 |
| 1, CRI | 19 | 10 | 3 | 6 | 5 of 6 |
| 2, policy | 179 | 54 | 35 | 90 | 5 of 6 |
| 2, CRI | 179 | 42 | 28 | 109 | 6 of 6 |
| 3, policy | 4 | 2 | 0 | 2 | 1 of 2 |
| 3, CRI | 4 | 1 | 0 | 3 | 1 of 2 |

Member days of open validation alerts by trigger, under the policy: band only 13 (6 malicious), top-1
only 132 (46 malicious), both 12 (11 malicious).

What this shows and does not show:

- **Ordering.** Neither ordering dominates, which is what N40 found at day level. The anomaly-score
  queue is more precise (0.211 against 0.190) with 39 fewer alerts, and it puts more scenario-2 days in
  open alerts (54 against 42). The CRI queue catches the sixth scenario-2 insider (6 of 6 against 5 of
  6), puts more scenario-1 days in open alerts (10 against 7), and has a shorter worst-case latency.
  The policy is not changed. The ordering was chosen before this readout and is already
  validation-informed (N55). Switching now would be tuning on validation after seeing the alert
  result. Chapter 16 reads both on test.
- **Why the CRI queue has more alerts** is not established. Both take one user-day per date. A likely
  cause is that the CRI's top-1 moves between users more often, so fewer days merge into an alert that
  is already open. Counting distinct users per alert under each ordering would test it.
- **The band trigger** fired on 25 member days of open validation alerts, and 17 of them are malicious.
  The top-1 trigger supplies the volume at a lower rate (46 of 132 days that only it triggered). These
  are small counts on one seed, and they do not justify changing the band or k.
- **False alarms.** `usb_disconnect_count` leads 44 of 90 false-alarm alerts (49%). Chapter 11 found
  the same feature leading 52% of benign top-1 days, so N52 carries over from days to alerts. Under the
  CRI ordering it leads 27 of 124 (22%). The other CRI components may push USB-led days down, but that
  is not established here.
- **Scenario 3** has 4 malicious days and 2 insiders. Nothing is read from it (N15).
- A factor matching a public scenario description is partly by construction (N41). A validation alert
  also depends on test users' scores on the same date, because the queue ranks both together.

## Checklist

Bible Chapter 12:

- [x] A cluster of related events produces exactly one correlated `Alert`, not four separate ones
  (unit test; on CERT, 46 open alerts span more than one day)
- [x] Every persisted `Alert` traces back through the full lineage chain to its source events (519 of
  519 member days on the development machine's PostgreSQL)
- [x] A simulated DB outage during alert write fails safely and visibly (refused connection and
  mid-load error in the tests, and both checked by hand on PostgreSQL 16 while building: NOT STORED,
  exit 3, nothing committed). Not repeated on the development machine; Chapter 15 repeats it end to
  end (N58)

HCEA §12 / D-6:

- [x] EventLog, FeatureVector, AnomalyScore and RiskScore hold alert-linked rows plus the demo sample
  only (1,051 user-days, 107,098 events); the full set stays in Parquet
- [x] The demo sample's selection rule is recorded in configuration (`c12-demo-sample-v1`)

N54:

- [x] `alembic upgrade head` on the development machine's PostgreSQL
- [x] full alert batch verified with 0 FAIL before the readout
- [x] load stored, verifier 0 FAIL with `--database-url`
- [x] validation readout written once, verifier 0 FAIL again
- [x] `/health` shows `alerts` loaded and `database` reachable (alerts after the C12-13 fix)
- [x] this audit, every WARN explained

## Still open

- The test suite has not been run on the development machine for Chapter 12.
- The Docker backend image predates Chapter 12, and its container does not mount
  `D:\CIRA_dataset`. Rebuild it and add the mount before any later chapter relies on the container
  (Chapters 13 and 18).
- The CRI queue's higher alert count has a hypothesis but no test.
- Everything above is one seed on validation. Test-set alert numbers belong to Chapter 16.
