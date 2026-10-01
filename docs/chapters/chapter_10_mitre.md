# Chapter 10: MITRE ATT&CK enrichment

Bible Chapter 10 / Architecture Phase 7 (§16), executed under HCEA v1.0 §10 (deviation D-4).

Status: IMPLEMENTED (29 September 2026). Verified on CERT r4.2 full with 0 FAIL; the runs, the
validation readout and both WARNs are in `docs/audits/chapter_10_audit.md`. ATT&CK 19.2, ruleset
`c10-rules-v1`, reference `20260929T184428Z-full-mitre`, enrichment run `20260929T184439Z-full-mitre`,
CRI run `20260929T184445Z-full-cri-default-mitre`. Reported runs: `experiments/chapter10_reference_runs.json`.

## Why the XGBoost / TabNet result shapes this chapter

Chapter 8 serves the behaviour-only XGBoost (gbdt v0003) and keeps TabNet v0005 in shadow (C8-1).
The two models do not just differ in quality. They find different insiders. Full / user validation,
primary view, from `docs/audits/chapter_9_audit.md`:

| | PR-AUC | Scenario 1 days at top-1 | Scenario 1 insiders | Scenario 2 days at top-1 | Scenario 3 days at top-1 |
|---|---|---|---|---|---|
| XGBoost v0003 (served) | 0.915 | 7/19 | 3/6 | 125/179 | 2/4 |
| TabNet v0005 (shadow) | 0.749 | 14/19 | 6/6 | 97/179 | 0/4 |

On the same 89,018 validation user-days the rank correlation between them is 0.285, and their daily
top-1 picks overlap by a mean Jaccard of 0.356. XGBoost wins overall because scenario 2 supplies 179
of the 202 validation positives (N15). TabNet does better on scenario 1, the user who starts working
after hours, copying to removable media and visiting a leak site.

Three design decisions follow.

**The enrichment never reads a score.** If techniques were attached to "the user-days the model
ranked highly", the technique picture would change whenever the served model changed, because the
two models disagree about which days those are. So `app/mitre/` reads Chapter 5 behaviour columns
only. A user-day gets the same techniques under XGBoost and TabNet, and a rollback through
`CIRA_SERVED_MODEL` needs no MITRE refit (N42). The CRI that consumes the result is still tied to one
model_version (N29, N33).

**The rarity reference is model-free too.** Chapter 9's calibration is the served model's validation
rows from its Chapter 8 batch. Chapter 10's reference is the validation users of the shared split
file (N11), which both models were validated on. It reads no model output at all.

**The readout asks the scenario-1 question directly.** For each scenario, the malicious validation
days are split by daily top-1 into four cells: caught by both models, by the served model only, by
the shadow only, by neither. Each cell reports how many days carry a mapped technique and how many
the CRI puts at top-1 with and without MITRE. The `shadow_only` cell of scenario 1 is where the
question lives: does MITRE context bring back days TabNet finds and XGBoost misses, while XGBoost
stays served? Shadow scores are read for that comparison only (N32). Nothing is ensembled.

What the answer could and could not show, written before any number exists:

- If `shadow_only` scenario-1 days carry mapped techniques and the CRI with MITRE puts some of them
  at top-1 where the CRI without MITRE did not, MITRE context recovers part of TabNet's scenario-1
  advantage. That is still partly by construction (N41), and six validation insiders cannot settle
  it (N15). It would be a reason for Chapter 16 to test it with seeds and intervals, nothing more.
- If those days carry no mapped technique, MITRE cannot help there, and the scenario-1 gap stays a
  model question for Chapter 16.
- If the CRI with MITRE loses days in scenario 2, the guard WARNs and the audit explains it. No rule
  or weight changes (N43).

## What ATT&CK can say about CERT r4.2

ATT&CK describes adversary techniques. CERT r4.2 records logons, removable-device connects, file
copies to removable media, email metadata and HTTP hosts. It has no failed logins, source IPs, byte
volumes, upload flags or process logs (N9). Most insider behaviour in r4.2 is therefore either
outside ATT&CK's scope or not observable in enough detail to name a technique. The map is kept
small for that reason.

### The rules (`c10-rules-v1`)

Each rule fires when one existing Chapter 5 column is above 0. Every technique and tactic below was
checked against the 19.2 bundle when the table was generated, and is checked again on every load.

| Rule | Technique | Tactic | Fires on | Evidence | What CERT cannot show |
|---|---|---|---|---|---|
| R01_removable_media_copy | T1052.001 Exfiltration over USB | exfiltration | `file_event_count` | observed | whether the files mattered, or where the device went |
| R02_leak_site_access | T1567 Exfiltration Over Web Service | exfiltration | `http_leak_paste_count` | indicated | an upload; r4.2 http has no method or bytes |
| R03_cloud_storage_access | T1567.002 Exfiltration to Cloud Storage | exfiltration | `http_cloud_storage_count` | indicated | direction and volume |
| R04_attack_tool_site_access | T1588.002 Obtain Capabilities: Tool | resource-development | `http_hacking_tools_count` | indicated | a download, an install, any use |

`observed` means CERT records the technique's action itself: r4.2 `file.csv` logs copies to
removable media. `indicated` means CERT records access to a destination whose purpose fits the
technique, but not the action. The grade is stored and shown. It does not scale the number, because
any factor would be one more constant nobody has validated.

### Considered and deliberately left unmapped

"Unmapped" is a recorded decision, not an omission (Architecture §16). Three of these are tagged on
the user-day when they occur (`mitre_unmapped_behaviours`), so an analyst can see they were
considered and have no technique. The others happen on most days and would only be noise as tags.

| Behaviour | Considered | Why not |
|---|---|---|
| job-search browsing (tagged) | none | a departure precursor, not an adversary technique |
| logon from a first-seen PC (tagged) | T1078 | no failed logins or IPs; can't separate misuse from hot-desking; masqueraded activity lands on the victim's row (N1) |
| archive or executable among the USB copies (tagged) | T1560, T1537 | the archiving step isn't recorded, and the copy is already R01; T1537 needs cloud telemetry (C10-3) |
| keylogger install or use | T1056.001 | needs process logs (N9) |
| mass internal email | T1534 | defined by message content, which is not used (§10.3) |
| external email with attachments | T1048.003, T1567 | no Enterprise technique covers a user mailing data from their own mailbox |
| USB connect without a copy | T1200, T1091 | a connect shows neither |
| off-hours activity | none | timing is a heuristic; the CRI's historical term carries it |

### Provenance, and what it means for any result

The rules were written from technique definitions and column definitions, label-blind, by the same
rule as the host list (N7). The public r4.2 scenario descriptions are known to anyone who has read
the dataset documentation, though, and three rules touch behaviour they name. A scenario gain from
MITRE context is partly by construction, like user_context and scenario 3 (N36), and is always
reported next to the `no_mitre_context` ablation (N41).

## From matches to `mitre_context`

On CERT, removable-media copies and cloud-storage visits are ordinary. A flat "technique matched = 1"
would add the same points to thousands of benign user-days and tell the analyst nothing. So a match
is graded by how unusual its triggering activity is, on the CRI's own rarity scale (D = 5):

```text
stage 1   strength_r    = rarity(value of the rule's column)       against the reference values of that column
                          0 if the rule did not fire, null if the column is null
stage 2   mitre_context = rarity(max_r strength_r)                 against the reference distribution of that maximum
```

Stage 2 exists for the reason the peer component has it: a maximum over several rules is larger than
any one of them by construction. Per user-day:

| Status | Meaning | `mitre_context` |
|---|---|---|
| mapped | at least one rule fired | in (0, 1] |
| unmapped | rules evaluated, none fired | 0 exactly |
| not_evaluated | every rule column null | null |

That is the contract N33 set for Chapter 10. On the synthetic tree, one cloud-storage visit (a rule
that fires on 59% of reference days) gets strength 0.045, while one keylogger-site visit (0.5% of
days) gets 0.436. Those are synthetic numbers that show the grading works, not results.

## Joining the CRI

`python -m app.cri.batch --profile full --with-mitre` joins `mitre_context` from an enrichment run of
the same matrix (fingerprint checked). Without the flag, the CRI is exactly Chapter 9's formula, so
the verified Chapter 9 runs stay reproducible. With it:

| | anomaly | historical | peer | user context | MITRE |
|---|---|---|---|---|---|
| Chapter 9 (MITRE unavailable) | 0.667 | 0.167 | 0.111 | 0.056 | - |
| Chapter 10 (MITRE joined) | 0.600 | 0.150 | 0.100 | 0.050 | 0.100 |

The configured weights did not change (0.10 for MITRE was set in Chapter 9, N37); only availability
did. `config_hash` therefore stays the same. `formula_hash` (configuration, available components,
ruleset hash, reference id) is new and is what distinguishes the two runs (N33). Run ids end in
`-mitre`.

What this does to the bands, from the formula alone:

- the anomaly score by itself now tops out at 100 × 0.60 × 0.99 = 59.4, still HIGH;
- to reach MEDIUM alone a user-day must be rarer than about 1 in 121 validation user-days (was 1 in
  75);
- to reach HIGH alone, rarer than about 1 in 14,700 (was 1 in 5,600);
- a mapped technique adds at most 10 points.

So adding MITRE makes the anomaly-only route to HIGH stricter. That is a consequence of
renormalisation, not a choice, and Chapter 12's alert policy has to know it.

## What was built

| Path | Purpose |
|---|---|
| `backend/app/mitre/techniques.py` | Loads the committed table; version and bundle sha256 pinned; refuses an old `MITRE_ATTACK_VERSION` |
| `backend/app/mitre/stix_loader.py` | Offline, run once: pinned bundle → table. The only importer of mitreattack-python (HCEA D-4) |
| `backend/app/mitre/data/enterprise_attack_v19.2.json` | 697 active techniques, 15 tactics, one-sentence descriptions, URLs (committed) |
| `backend/app/mitre/mapping_rules.py` | Rules, unmapped behaviours with reasons, ruleset hash, validation |
| `backend/app/mitre/reference.py` | Two-stage rarity maps, pin with sha256, refuses another ruleset or table |
| `backend/app/mitre/calibrate.py` | `python -m app.mitre.calibrate`: fit and pin on validation users of the shared split; label-free report |
| `backend/app/mitre/enrich.py` | `MitreEnricher`: vectorised context + matches; `enrich_event` for Chapter 13 |
| `backend/app/mitre/batch.py` | `python -m app.mitre.batch`: enrichment run to Parquet with lineage |
| `backend/app/mitre/sources.py`, `runtime.py` | Run discovery and alignment; what the API holds |
| `backend/app/mitre/evaluate.py` | Offline validation readout, the disagreement view, guard `c10-mitre-guard-v1` |
| `backend/app/database/models/mitre_mapping.py`, `alembic/versions/7c1e4a9d2b60_...py` | `MITREMapping` entity |
| `backend/app/cri/batch.py` | `--with-mitre` / `--mitre-run-id`, `formula_hash`, the `mitre` block in the meta |
| `backend/app/main.py` | Lifespan loads the MITRE runtime; `/health` gains a `mitre` block |
| `scripts/verify_chapter10.py` | PASS / WARN / FAIL over table, reference, run, CRI join and readout |
| `scripts/verify_chapter9.py` | Recomputes a MITRE-enabled risk run with the same enrichment run |
| `backend/tests/unit/test_ch10_mitre.py`, `backend/tests/integration/test_ch10_pipeline.py` | 32 tests |

The Bible names `stix_loader.py`, `mapping_rules.py` and `enrich.py`. The others split label-free
serving code, the offline readout and the CLI runners apart, the same split Chapters 8 and 9 used
(C10-4). No dependency was added: `mitreattack-python` and `stix2` were already in
`requirements.txt`.

## The `MITREMapping` entity

One row is either a mapped technique for a user-day or the explicit record that a user-day was
evaluated and nothing mapped. Check constraints make a forced mapping impossible to store:

- a `mapped` row must name its technique, tactic, rule, triggering column and evidence grade;
- an `unmapped` row must not name a technique;
- the evidence grade is `observed` or `indicated`;
- `mitre_context` is in [0, 1].

Rows carry `ruleset_version`, `ruleset_hash`, `attack_version`, `reference_id` and `mitre_run_id`.
Lineage runs mapping → run meta → ruleset and reference, next to the Architecture §37 chain.
Persistence is Chapter 12's job, for alert-linked user-days and the demo sample only (HCEA D-6). The
foreign key to `Alert` arrives with that entity (C10-6). The migration is tested on SQLite: upgrade
leaves nothing for autogenerate to add, and downgrade removes the table.

## Failure modes (Architecture §36)

| Situation | Behaviour |
|---|---|
| No table, a table of another release, or a bundle sha256 that differs from the pin | `TechniqueTableError`; runtime unavailable with the reason |
| `MITRE_ATTACK_VERSION` set and different from the pin (an old `.env` saying 15.1) | Refused, naming both versions |
| A rule naming a retired technique or the wrong tactic | Calibrate and batch refuse before fitting anything; the loader reports it |
| No reference pin, a modified reference, or one fitted for another ruleset or table | `MitreReferenceUnavailableError` |
| Matrix differs from the one the reference was fitted on, or host categories changed (N7) | Batch refuses (fingerprint) |
| Enrichment run from another matrix joined into the CRI | CRI batch refuses |
| MITRE unavailable in the API | `/health` shows `mitre.status = unavailable` with the reason; no `mitre_context` is invented (N35) |
| Served model rolled back | MITRE stays loaded (N42); the CRI refuses until recalibrated (N29) |

## The validation readout and the guard

`python -m app.mitre.evaluate` reads the default `--with-mitre` risk run's validation rows, joins
labels in memory and reports:

- `anomaly_score`, `cri:anomaly_only`, `cri:no_mitre_context` (Chapter 9's formula), `cri:default`
  (with MITRE) and `mitre_context` alone as a ranking;
- PR-AUC (primary view), ROC-AUC as a secondary number, insiders caught at top-1 and top-5, days per
  scenario (N15);
- the four-cell disagreement view per scenario (above);
- per rule, how often it fires on malicious days by scenario against benign days, and the share of
  benign validation user-days that carry any mapped technique. That share is the analyst's cost and
  is quoted next to any MITRE detection number (N43).

Harness checks: recombining the stored components reproduces the stored CRI; `cri:anomaly_only` ranks
like the anomaly score; `cri:no_mitre_context` equals the Chapter 9 readout's `cri:default` PR-AUC on
the same calibration and rows.

Guard `c10-mitre-guard-v1` WARNs if the CRI with MITRE has lower validation PR-AUC than without it,
catches fewer insiders at top-1 or top-5, or has fewer malicious days at top-1 in any scenario. There
is no margin. A WARN is explained in the audit and never changes a rule or the weight (N43).
Validation only (`--part test` is refused); written once. The test readout is Chapter 16's
ablation D.

## How to run, step by step

From `backend/`, with `.env` updated from `.env.example` (`MITRE_ATTACK_VERSION=19.2`) and the
Chapter 9 calibration in place:

```bash
python -m app.mitre.calibrate --profile full          # label-free; pins experiments/chapter10_mitre_reference.json
python -m app.mitre.batch --profile full              # <CERT_PROCESSED_DIR>/mitre/chapter10/<run id>/
python -m app.cri.batch --profile full --with-mitre   # risk run ending in -mitre
python ../scripts/verify_chapter10.py --profile full --no-readout
python ../scripts/verify_chapter9.py --profile full --cri-run-id <the -mitre run> --no-readout
python -m app.mitre.evaluate --profile full           # validation readout, once (reads labels)
python ../scripts/verify_chapter10.py --profile full
alembic upgrade head                                  # mitre_mappings table
```

The technique table is committed, so `stix_loader` is only needed if the pin changes:
`python -m app.mitre.stix_loader --download` fetches the pinned bundle into `datasets/raw/mitre/`,
checks its sha256 and rewrites the table.

Only full is reportable. A mid reference can be fitted for debugging; its numbers are not reported.

## Verification

`scripts/verify_chapter10.py` sections:

- **table:** loads under the pin; every rule names an active technique under its tactic; every rule
  column is in the matrix.
- **reference:** pin and sha256; the current ruleset and table; no label column and no model column;
  rows are exactly the validation users of the shared split; both stages monotone and in [0, 1]; a
  user-day with no fired rule maps to exactly 0.
- **run:** contract columns; no label or model column; one row per matrix user-day; made from the
  matrix that exists now; statuses and values agree; matches agree with context rows; every match is
  an active technique under its tactic; a from-scratch recomputation reproduces every row; runlog
  line; peak RSS.
- **cri:** the risk run names this enrichment run; MITRE is an available component; weights sum to
  1; `formula_hash` recorded; the stored component equals the enrichment run; MITRE points only on
  mapped user-days.
- **readout:** validation only; of that risk run; harness checks; disagreement view present; every
  guard warning shown as a WARN.

On the synthetic chain: 45 PASS, 1 WARN (no Chapter 9 readout exists for the synthetic rows), 0 FAIL.
On CERT full: 45 PASS, 2 WARN (the guard, explained in the audit), 0 FAIL. `verify_chapter9.py` on the
MITRE-enabled run: 31 PASS, 0 WARN, 0 FAIL, on both.

## Carry-forward compliance

| Note | How Chapter 10 satisfies it |
|---|---|
| N5 labels | Serving modules statically checked label-free; only `evaluate.py` reads labels, in memory |
| N6 profiles | Only full is reportable; every run logs `reportable` |
| N7 host list | Rules read host classes, never hosts; the batch refuses if `host_categories_version` changed |
| N8 resources | Thread caps first in every entry point; only the rule columns are read; the STIX graph stays out of the API |
| N9 signals | Nothing is claimed that CERT lacks; `indicated` marks every rule whose action is not recorded |
| N11 split | The reference uses the saved split file; test rows are not read |
| N15 per scenario | Readout by scenario, and the four-cell view per scenario |
| N29, N33 | The CRI still refuses another model_version; `mitre_context` in [0, 1], 0 = none, null = not evaluated; `formula_hash` |
| N30, N34 | MITRE is a CRI component with its own points; the anomaly score is carried unchanged |
| N32 shadow | Shadow scores only in the offline disagreement view |
| N35 unavailable | Without an enrichment run the component is excluded with its reason; never imputed |
| N36, N41 | Scenario gains disclosed as partly by construction; always next to `no_mitre_context` |
| N37, N43 | Rules and weight fixed before the readout; guard WARNs, never retunes |

## Deviation register additions

| Id | What | Status |
|---|---|---|
| C10-1 | ATT&CK pinned at 19.2 (newest release, 2026-08-05) instead of the Chapter 1 placeholder 15.1 in `.env.example` | Applied |
| C10-2 | `MITRE_MAPPING_CONFIDENCE_THRESHOLD=0.6` removed; rules fire on observed behaviour, strength is rarity, evidence is a stored grade | Applied |
| C10-3 | The Bible's example (archive then external transfer → T1560 + T1537) not implemented: archiving is not recorded and T1537 needs cloud telemetry | Recorded as not mapped |
| C10-4 | Modules beyond the Bible's three (see "What was built") | Applied, explained above |
| C10-5 | MITRE joins the CRI by flag; Chapter 9 runs stay unchanged; `formula_hash` distinguishes the formulas | Applied |
| C10-6 | `MITREMapping` rows persisted in Chapter 12 (bounded, D-6); the `Alert` foreign key comes with that entity | Done in Chapter 12 (`mitre_mappings.alert_id`, migration `9f3b2c7d4e81`) |
| C10-7 | The MITRE reference is fitted on the shared split's validation users, not a model batch (N42) | Applied |
| C10-8 | `/health` gains a `mitre` block; top-level status keeps its Chapter 8 meaning | Applied |
| C10-9 | Chapter 9's migration test now checks that its revision is on the single head's chain, not that it is the head | Applied |
| C10-10 | Tactics follow the 19.2 bundle as it is (for example, Valid Accounts under `stealth`) | Informational |

## First real readout (full / user validation)

From `experiments/chapter10_validation_readout.json`; the audit has the full record, including the
four-cell table.

| Ranking | PR-AUC | Caught at top-1 | Scenario 1 days | Scenario 2 days | Scenario 3 days |
|---|---|---|---|---|---|
| anomaly score (gbdt v0003) | 0.915 | 9/14 | 7/19 | 125/179 | 2/4 |
| CRI without MITRE | 0.694 | 11/14 | 9/19 | 110/179 | 1/4 |
| CRI with MITRE | 0.557 | 13/14 | 13/19 | 93/179 | 1/4 |
| MITRE context alone | 0.039 | 7/14 | 12/19 | 0/179 | 2/4 |
| TabNet v0005 anomaly score (Chapter 8) | 0.749 | 12/14 | 14/19 | 97/179 | 0/4 |

Both outcomes the doc allowed for happened. Of the 8 scenario-1 days TabNet caught and XGBoost missed,
all 8 are mapped and the CRI with MITRE puts 6 at top-1 (2 without): MITRE context recovers most of
TabNet's scenario-1 advantage while XGBoost stays served. Scenario 2 pays for it (110 to 93 days),
and that drives the PR-AUC drop. MITRE alone ranking 12/19 scenario-1 days and 0/179 scenario-2 days
shows how closely the rules match scenario 1's design, so the gain is partly by construction (N41).
What this does and does not show is in N46. Nothing was changed on validation (N43).

## Before reporting anything

- Chapter 10's numbers are validation numbers, one seed, per N46.
- Report MITRE context with the served model named, on full, on validation, per scenario, next to
  `no_mitre_context`, with the benign mapped share and the N41 disclosure.
- One seed per model. Chapter 16 adds seeds and bootstrap intervals, and reads ablation D on test.

## Acceptance checklist

Bible Chapter 10:

- [x] Technique table loads from a pinned STIX version (19.2, sha256-checked) and is queryable offline
- [x] Every emitted mapping is traceable to the behavioural pattern, column and value that triggered it
- [x] Ambiguous cases are marked unmapped, never force-mapped (eight recorded, three tagged per row; entity constraints)
- [x] CRI's `mitre_context` input is live-wired (`cri.batch --with-mitre`; synthetic)
- [x] `MITREMapping` entity created now, with its migration

HCEA §10 / D-4:

- [x] The STIX bundle is read once, offline; the API and the enrichment path read only the table

Real runs (N44):

- [x] reference fitted and pinned on full
- [x] full enrichment run and `--with-mitre` risk run verified with 0 FAIL (both verifiers)
- [x] validation readout written once
- [x] `/health` shows the MITRE block loaded on the development machine
- [x] `docs/audits/chapter_10_audit.md` written from those runs, every WARN explained
