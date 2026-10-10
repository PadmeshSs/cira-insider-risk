# Chapter 16: Evaluation protocol and ablation studies

Bible Chapter 16 / Architecture §39-40, executed under HCEA v1.0 §14.

Status: IMPLEMENTED. `scripts/verify_chapter16.py --recompute` on the development machine: 29 PASS, 0 WARN, 0 FAIL
(run 20261010T075805Z), with the CERT seed runs and the pinned test readout `20261010T072243Z-full-test-c16`.
The results, the harness failure found on test and its fix, and the guard warnings are in
`docs/audits/chapter_16_audit.md`.

## What this chapter does

It reads the runs earlier chapters stored and answers, once and on test, the questions the carry-forward notes
postponed: does the CRI help, does MITRE context help, how do TabNet and XGBoost compare across seeds, and what
does the alert queue do on data nobody tuned on. Nothing is trained for the readout itself. The only training is
the seed runs, which exist to measure training noise (N26).

## The pieces

| Module | Job |
|---|---|
| `app/evaluation/operating.py` | F1, false positive rate, risk coverage (the Bible's metric list; precision, recall, AUCs, top-k and latency already live in `metrics.py`) |
| `app/evaluation/bootstrap.py` | user-clustered bootstrap intervals, paired differences, Wilcoxon over seeds |
| `app/evaluation/rankings.py` | loads every ranking from stored runs, aligned on one set of user-days; chooses the best baseline on validation |
| `app/evaluation/alert_views.py` | experiment E1: the Chapter 12 alert run read on test, with and without deduplication, both orderings, the activity rule |
| `app/evaluation/explain_view.py` | experiment E2: the Chapter 11 explanation readout repeated on test |
| `app/evaluation/seeds.py` | resumable seed runs for experiments A and B, on the saved split (N78) |
| `app/evaluation/ablation.py` | the readout: chain, experiments A-E, harness checks, pinned test readout |
| `app/evaluation/report.py` | the Markdown report, generated from the readout only (N79) |
| `scripts/verify_chapter16.py` | the final verification |

Two existing entry points gained one option, `--split-seed` (default: `--seed`, so no earlier run changes):
`app.tabnet.train`, `app.scoring.gbdt_candidate`, `app.baselines.run`.

## The comparison chain and its deviation (C16-1)

The Bible writes Baseline, TabNet, TabNet + CRI, TabNet + CRI + MITRE. The served model is XGBoost (C8-1), the
CRI is calibrated to it (N33) and shadow scores never feed a CRI (N32). The chain here is:

```text
best baseline (chosen on validation) -> TabNet (shadow) -> XGBoost (served) -> XGBoost + CRI -> XGBoost + CRI + MITRE
```

TabNet stays in the table as the supervised alternative (N23). The report says "XGBoost + CRI", never "TabNet + CRI".

## Experiments

| Id | Question | Source |
|---|---|---|
| A | behaviour-only TabNet and XGBoost over six seeds | seed manifest; seed 42 are the reported runs |
| B | the same with the static / contextual columns (psychometrics, department size) | seed runs, all-features configuration |
| C | anomaly score vs the Chapter 9 CRI and its leave-one-out variants; top-k and band views (N39, N40) | risk run, recombined from stored components |
| D | anomaly score, CRI with and without MITRE, MITRE alone, per scenario, benign mapped share, served/shadow cells (N43, N46) | risk run, MITRE run |
| E1 | alert queue: deduplication on/off, both orderings, activity rule, three-way coverage per scenario (N55-N57, N60, N61) | Chapter 12 alert run |
| E2 | explanations on test: leading factors, false alarms, mask view, integrity (N52, N53) | Chapter 11 explain run |
| E3 | the cost of the interpretability constraint: all features minus behaviour-only (B - A) | seed runs |

The Bible defines B as "TabNet + contextual features". In this repository the model-level contextual inputs are the
static traits Chapter 7 excluded (N25). The CRI's own context components (user context, peer and historical deviation)
are experiment C.

Experiments C and D run on one served model_version (C16-2): their variation is five tie-break seeds plus the bootstrap.

## Statistics

- Intervals: 95% percentile, user-clustered bootstrap (1000 replicates by default). Scores and alert masks are held
  fixed, so an interval is about which users the test set holds, not about training noise.
- Paired differences use the same replicates for both rankings. The p-value is the bootstrap sign proportion, floored
  at 2 / (B + 1); the interval is the evidence.
- Seeds: Wilcoxon signed-rank over per-seed PR-AUC. With n pairs the smallest attainable two-sided p is 2 / 2^n, so
  five seeds can never go below 0.0625. The readout prints that limit. Six seeds are planned.
- The headline "TabNet vs best baseline": the paired bootstrap on the reference runs, and a Wilcoxon over seeds against
  the all-features XGBoost (the closest seeded reproduction of the Chapter 6 baseline, not its own run).

## Metrics

Precision, recall, F1, ROC-AUC (secondary), PR-AUC, false positive rate, detection latency, top-k precision, risk
coverage. Never accuracy (N2). Masquerade account-days are neither hits nor false alarms nor true negatives (N1).

Risk coverage (C16-3): the share of the part's malicious user-days that sit in an alert of the stated kind, always
printed with the share of all user-days those alerts occupy. The Architecture text that names the metric was not
available when this was written; change the definition in `operating.py` and the report together if it differs.

## Rules that shape the run

- Test is written to the pinned readout once; a rewrite needs `--supersede` (N76).
- Seed runs load the saved split and register nothing (N78).
- The report is generated from the readout only, and the verifier regenerates it (N79).
- Run ids come from `app.core.run_stamp` (N74).
- Label tables are read in memory through `app.evaluation.labels` only (N5).

## How to run, on the development machine

From `backend/`, with `CERT_PROCESSED_DIR` and the pins in `.env`:

```bash
python -m app.evaluation.seeds --profile full                      # about two hours; resumable
python -m app.evaluation.ablation --profile full --part validation # rehearsal, writes nothing pinned
python -m app.evaluation.ablation --profile full --part test --secondary mid/user,mid/time
python -m app.evaluation.report
cd .. && python scripts/verify_chapter16.py --recompute
```

`--secondary` also runs the Chapter 7 harness on mid/user and mid/time, with the seen/new insider breakdown on the time
split (N16) and the budget caveat for mid (N17).

## What the synthetic tests prove

`backend/tests/integration/test_ch16_pipeline.py` builds the Chapter 15 synthetic world, runs the Chapter 6 baselines,
the seed runner on two seeds, a validation rehearsal and a test readout, refuses a second write, supersedes it, and
renders the report. It proves the plumbing and the rules. Its numbers are never results (N72).
