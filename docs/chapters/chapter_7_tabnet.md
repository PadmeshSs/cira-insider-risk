# Chapter 7: TabNet

Bible Chapter 7 / Architecture Phase 5, executed under HCEA v1.0 §7.

Status: IMPLEMENTED (27 September 2026). Verified at mid (user and time
split) and full (user split) with 0 FAIL; results, the verification record
and every WARN are in `docs/audits/chapter_7_audit.md`. Reported runs:
`experiments/chapter7_reference_runs.json` (N24). Full suite: 176 passed,
1 skipped.

The adopted model is behaviour-only (`--exclude-features
psych_,peer_department_size`, N25). It ranks insiders far better than every
unsupervised baseline and worse than XGBoost on every split (N26).

## What was built

| Path | Purpose |
|---|---|
| `backend/app/tabnet/dataset.py` | Loads the Chapter 5 matrix like the Chapter 6 runner, reuses the saved split (N11), train-only preprocessing (N4), feature fingerprints identical to Chapter 6, value/indicator grouping for Chapter 11 |
| `backend/app/tabnet/train.py` | `TabNetDetector` on the Chapter 6 detector contract; per-epoch checkpoint and exact resume; class-weighted loss; the `python -m app.tabnet.train` runner |
| `backend/app/tabnet/infer.py` | Label-free loading and scoring for Chapter 8: `load_model(...)`, `TabNetScorer.score(frame) -> [0, 1]`, `ModelUnavailableError` |
| `backend/app/tabnet/model_registry.py` | Append-only versioned registry with sha256 per artifact file |
| `backend/app/evaluation/compare.py` | Same-harness comparison of TabNet with the reference Chapter 6 runs (N18) |
| `experiments/chapter6_reference_runs.json` | The N18 run ids in machine-readable form |
| `scripts/verify_chapter7.py` | Post-run verification, PASS / WARN / FAIL per check |
| `scripts/inspect_scores.py` | One change: reads a Chapter 7 run and prints mask importances instead of gain |
| `backend/tests/unit/test_ch7_tabnet.py`, `test_ch7_registry.py`, `backend/tests/integration/test_ch7_runner.py` | 42 tests |

`compare.py` and the reference-run file are not in the Bible §2 tree. The
Bible's Chapter 7 acceptance list asks for "the plumbing to compare" with
the baselines through the same harness, and N18 says to compare against the
recorded score files rather than re-run the baselines; these two files are
that plumbing. `app/evaluation/ablation.py` stays Chapter 16 work.

No new dependency. `pytorch-tabnet` and `torch` were already in
`backend/requirements.txt`. Tested with pytorch-tabnet 4.1.0 and a CPU build
of torch; the versions used are written into every model's metadata.

## Data, split and preprocessing

The runner reads `features/user_day_<profile>.parquet`, normalises and sorts
the keys exactly like the Chapter 6 runner, and loads the user split from
`experiments/splits/user_split_<profile>_seed<seed>.json` through
`load_or_create_split`, which refuses a file that no longer matches (N11). A
run records the split file's sha256 and whether it was created during the
run; on mid and full it should always be loaded. The time split uses the
Chapter 6 defaults (train before 2011-01-01, validation January 2011, test
from 2011-02-01). The feature fingerprint and the data fingerprint use the
Chapter 6 formulas, so a TabNet run and a baseline run on the same matrix
and split carry identical fingerprints, which the verifier and `compare.py`
check.

TabNet cannot take NaN. Preprocessing, fitted on the training rows only:

1. Chapter 6's `TrainFittedImputer`: training medians, plus a 0/1 indicator
   for each column whose schema null policy starts with "null" (N4);
2. signed log1p;
3. standardisation with the training mean and standard deviation.

Each step is per column and monotone, so output column `c` still describes
input column `c`. The fitted preprocessor is saved beside the network as
`preprocessor.json`; a model cannot be scored without it.

Masquerade account-days are removed from the training and validation rows
(N13). They stay in the scored validation and test rows, where the metrics
treat them as neither positive nor negative (N1).

## Model and settings

`TabNetClassifier` with the HCEA §7.2 settings as defaults: `n_d = n_a = 16`,
`n_steps = 4`, `gamma = 1.3`, `n_independent = n_shared = 2`, sparsemax,
Adam at 2e-2, StepLR (step 10, gamma 0.9), up to 100 epochs, patience 15,
batch 4096, virtual batch 256 (the detector refuses more than 512),
`num_workers = 0`, `drop_last = False`, seed from `CIRA_SEED`. Every value
can be changed from the command line and every run logs its full config and
a config hash. HCEA §7.6 caps the manual search at 12 configurations per
profile; the runner warns past that and the verifier reports the count.

Class imbalance (HCEA §7.3, D-7). The default is class-weighted
cross-entropy with weight 1 for benign rows and negatives / positives for
malicious rows, computed on the training rows. That is the ratio XGBoost
used as `scale_pos_weight`, so both supervised models get the same
correction. Nothing is resampled. pytorch-tabnet's own `weights=1` is not a
weighted loss: it is a `WeightedRandomSampler` that draws both classes
equally often, with replacement. It is available as `--imbalance
balanced_sampler` for the one-off mid ablation HCEA §7.3 suggests. The
method, effective weight and training positive rate go into the metadata,
the registry entry and the runlog. SMOTE is not implemented.

Early stopping is on validation PR-AUC (average precision), with ROC-AUC
logged per epoch beside it (deviation C7-1). If a validation split has no
positives the run trains for the fixed number of epochs and says so.

## Score convention

```text
raw_score(frame) -> z = logit(malicious) - logit(benign)
score(frame)     -> sigmoid(z) in [0, 1], higher = more anomalous
```

`sigmoid(z)` equals `predict_proba(X)[:, 1]`, but it is computed in float64
from the margin. A float32 probability becomes exactly 1.0 once z passes
about 17, which would create ties at the top of the alert queue; in float64
that happens only past about 37. The runner and the verifier count scores
at exactly 1.0. The map is monotone, so ranking metrics are the same on raw
and calibrated scores (N10). Under the class-weighted loss this is a
ranking score, not a probability of malice (N20).

Scoring is causal (N12): day t is scored from its own row, whose historical
and peer columns use only past and same-day data. Eval-mode batch norm uses
running statistics, so a row's score does not depend on the other rows in
its batch; a unit test checks this.

## Checkpoints and resume (HCEA R7)

Every epoch writes network, optimiser, LR scheduler, early-stopping state
(best score, patience counter, best weights) and history to
`models/checkpoints/chapter7/<profile>/<split>/tabnet-<key>/epoch_NNN.pt`,
atomically. The key is a hash of the config, seed and data fingerprint, so
weights from another matrix or split are never reused. The newest three
checkpoints are kept.

A re-run with the same key resumes after the last finished epoch. Each epoch
shuffles with `seed + epoch`, so a resumed run makes the same batches as an
uninterrupted one. A unit test interrupts training during epoch 3, resumes,
and gets the same validation curve, best epoch and scores (within 1e-6) as
an uninterrupted run. If the last checkpoint marks training as finished, a
re-run trains zero epochs and just rebuilds the model; the metadata says
`completed_from_checkpoint`. A determinism re-run must therefore use
`--fresh`, which deletes that config's checkpoints first.

## Registry (Bible Ch7 step 4)

`<MODEL_PATH>/tabnet/` holds `registry.jsonl` and one directory per version
(`v0001`, `v0002`, ...) with `tabnet_model.zip`, `preprocessor.json`,
`global_importance.json`, `meta.json` and `registry_entry.json`. Artifacts
are written to a temporary directory and renamed into place; an existing
version directory is never replaced, and every retrain gets the next number.
Each file's sha256 is recorded, and `load_model(..., verify=True)` refuses a
modified artifact. A lock file keeps two runs from registering at once; a
stale lock is reported, not deleted.

An entry records the model name and version, registry version, run id,
profile and reportability, split file and hash, seed, training timestamp,
training data (feature file, fingerprints, rows used, masquerade rows
dropped, feature count), feature-schema version, the config, the imbalance
method with its weight and positive rate, training facts (device, epochs,
best epoch, early stopping, resume, pretraining) and the validation and test
headline metrics with per-scenario recall. `models/saved_models/` is
gitignored; the committed record is the runlog line.

## Pretraining (HCEA §7.4)

`--pretrain` runs `TabNetPretrainer` on the training features (no labels),
at most 20 epochs, then fine-tunes. Try it at mid only, against the same
config without it, and keep it only if validation PR-AUC improves.
Pretraining is not checkpointed. When a run resumes, pretraining is skipped
because the checkpoint already holds the fine-tuned weights.

## Global importance

After training, TabNet's aggregate mask is summed over the training rows in
chunks of 50,000 (HCEA §11.1), normalised, and saved per input column and
per base feature (value plus missing indicator). The top 20 by base feature
go into the metadata. If a static per-user trait (psychometrics, department
size) is in the top 10, the runner prints a note and the verifier warns:
that would mean the model learned who insiders resemble, not what they did.
This is the same check Chapter 6 applied to XGBoost.

## How to run

From `backend/`, with `.env` pointing at `D:/CIRA_dataset/...`:

```bash
python -m app.tabnet.train --profile dev                   # debugging only, never reported
python -m app.tabnet.train --profile mid  --exclude-features psych_,peer_department_size
python -m app.tabnet.train --profile mid  --exclude-features psych_,peer_department_size --split time
python -m app.tabnet.train --profile full --exclude-features psych_,peer_department_size
```

These reproduce the reported models (N25). Without `--exclude-features` the
runner trains the all-features configuration, which was not adopted.
Re-running an existing configuration completes from its checkpoints and
registers a new version with the same weights; add `--fresh` to retrain.

Optional, mid only, one run each:

```bash
python -m app.tabnet.train --profile mid --imbalance balanced_sampler --tag "ablation: sampler vs weighted loss"
python -m app.tabnet.train --profile mid --pretrain --tag "pretraining trial"
python -m app.tabnet.train --profile mid --fresh --no-register --tag "determinism re-run"
```

The console shows validation only. Test metrics are in `metrics.json`; read
them once, for the write-up, with `compare --part test`.

Useful flags: `--device cpu`, `--exclude-features`, `--max-epochs`, `--patience`, `--batch-size`
(halve this first if VRAM errors appear, HCEA §7.2), `--n-d`, `--n-a`,
`--n-steps`, `--lambda-sparse`, `--mask-type entmax` (only if sparsemax
underperforms), `--tag`.

Do not run the frontend dev server alongside a full run (HCEA §13).
Wall-clock and memory on the development machine have not been measured
yet; the first mid run is where to get them. HCEA §7.6 budgets: peak RSS
under 10 GB, VRAM under 3 GB, minutes at mid, tens of minutes at full.

## Verification and comparison

After each run, from `backend/`:

```bash
python ../scripts/verify_chapter7.py --profile mid --reload-models --permutation-test --baselines
python ../scripts/verify_chapter7.py --profile mid --split time --baselines
python ../scripts/verify_chapter7.py --profile full --reload-models --permutation-test --baselines
python ../scripts/verify_chapter7.py --profile mid --run-id <fresh re-run> --compare-run-id <first run>
```

The verifier checks the run record, the feature file, label coverage, the
split (same file and hash as at run time, reproducible, stratified,
disjoint), masquerade rows dropped from training and validation, the class
weight against the training counts, early stopping, checkpoints, the score
file (columns, range, `sigmoid(raw)`, model version, rows, saturation), the
metrics blocks, the registry entry and its file hashes, the runlog line and
the HCEA budgets. Options add a reload test (the registered artifact must
reproduce the stored test scores), a label-permutation test (TabNet on
shuffled training labels must stay near chance), a determinism comparison,
and `--baselines`: same validation and test rows as the reference Chapter 6
runs, same feature matrix, and the harness must reproduce every logged
baseline test PR-AUC exactly. `--baselines` never prints a TabNet test
number.

The comparison table:

```bash
python -m app.evaluation.compare --profile mid --split user --run-id <id>              # validation
python -m app.evaluation.compare --profile full --split user --run-id <id> --part test # write-up, once
```

It prints PR-AUC, ROC-AUC (secondary), recall and insiders caught per daily
budget for every model, recall and insiders caught per scenario (N15), the
chance level and the precision ceiling per budget (N17), and for the time
split the PR-AUC on insiders never seen in training plus benign users
(N16). It writes `experiments/results/chapter7/<run_id>/comparison_<part>.json`
and one runlog line. There is no reference Chapter 6 run for full/time, so a
full time-split TabNet run has nothing to be compared with.

## Carry-forward compliance

| Note | How Chapter 7 satisfies it |
|---|---|
| N1 masquerade | Primary view for headlines; masquerade days out of the primary negatives; account view reported once; recall per scenario always reported |
| N2 imbalance | PR-AUC and daily top-k as headline; ROC-AUC secondary; no accuracy; class weight from the training rows only; test never resampled |
| N3 user split | Saved Chapter 6 split, users disjoint; time split available; no look-ahead feature added |
| N4 imputation | Train-only medians, schema-driven indicators, fitted once and saved with the model |
| N5 labels | Only `train.py` imports label code; `dataset.py`, `infer.py`, `model_registry.py` are statically checked to never do so; score files hold no labels |
| N6 profiles | dev runs are `reportable: false`; every run appends to the runlog |
| N7 hosts | Not touched |
| N8 resources | `apply_thread_caps()` before numpy/torch in `train.py`, `compare.py` and the verifier; checkpoint every epoch |
| N9 signals | Uses only the Chapter 5 matrix; nothing new is claimed |
| N10 score convention | `score = sigmoid(margin)` in [0, 1]; monotone; `model_version` on every row |
| N11 saved split | Loaded, hash recorded, created-now flagged; model selection on validation only |
| N12 causal scoring | Per-row model on past/same-day features |
| N13 masquerade in training | Dropped from training and early-stopping rows; counts recorded and verified |
| N15 per scenario | Per-scenario recall and caught counts in metrics, runlog, registry and comparison |
| N16 time split | Seen/new breakdown per model in `compare.py` |
| N17 budgets | Precision ceiling printed; top-1 note for mid |
| N18 reference runs | Compared from the stored score files listed in `experiments/chapter6_reference_runs.json`; harness reproduction checked |

## Deviation register additions

| Id | What | Status |
|---|---|---|
| D-7 (HCEA) | Class-weighted loss, recorded with weight and positive rate. Implemented as an explicit weighted cross-entropy because pytorch-tabnet's `weights=1` is a sampler | Within specification, applied |
| C7-1 | Early stopping on validation PR-AUC instead of the `"auc"` in HCEA §7.2, to match N2 and the XGBoost baseline | Applied |
| C7-2 | `drop_last=True` only when the training rows leave a one-row final batch, which batch norm cannot train on; recorded with the reason | Applied, conditional |
| C7-3 | Score is `sigmoid(margin)` in float64 rather than the float32 `predict_proba`, to avoid artificial ties at the top | Applied |
| C7-4 | Global importance computed in 50,000-row chunks instead of pytorch-tabnet's `compute_importance`, which stacks per-step masks for the whole training split | Applied |
| C7-5 | `grouped_features` not used in training; value and missing indicator are grouped after the fact for reporting, and Chapter 11 does the same | Scope decision |
| C7-6 | Pretraining is not checkpointed (at most 20 epochs, mid only) | Scope decision |
| C7-7 | Bootstrap intervals and significance tests stay in Chapter 16, as in C6-2 | Deferred |
| C7-8 | Permutation test changed after the first mid run failed it (see below). Three shuffles instead of one, an untrained-TabNet control, and a label-free reference; the Chapter 6 bar (3 x chance) still decides PASS | Applied; the original FAIL stays in the runlog |
| C7-9 | The runner no longer prints test metrics; they go to `metrics.json`, the registry and the runlog only. The first mid run (`20260927T114021Z-mid-user-s42`) printed them, so that test number has been seen | Applied; no decision may cite that number |

## Permutation test (C7-8)

The first mid user-split run failed the permutation test as copied from
Chapter 6: TabNet trained on shuffled labels scored test PR-AUC 0.0388
against a bar of 0.03 (3 x chance 0.0100). XGBoost on shuffled labels
scored 0.0059 in Chapter 6.

A model trained on shuffled labels knows nothing about who the insiders are,
but it can still rank above chance if its output follows how unusual a row
is, because malicious days are unusual days. The label-free baselines show
how far that goes on the same test rows: rule-based 0.034, Isolation Forest
0.035, LSTM autoencoder 0.090, none of which ever saw a label. A 3 x chance
bar sits below that, so for a model that maps unusual rows to extreme
outputs it cannot tell leakage from structure.

The verifier now fits three shuffled-label models and one untrained TabNet
(0 epochs: no label has touched its weights) and reads the best label-free
Chapter 6 baseline from the reference runs:

* PASS: worst shuffled PR-AUC at or under the Chapter 6 bar;
* WARN: above the bar but not above the best label-free baseline. The audit
  must explain it with the printed diagnostics;
* FAIL: above every label-free reference. A model with no label information
  beats every method that never sees labels: investigate.

How to read the diagnostics. If the untrained network already ranks near the
shuffled models, the lift exists before any label is seen: it comes from the
preprocessing and architecture, not from leakage. If the shuffled models sit
well above the untrained one, the lift was learned, and it came from fitting
noise; look at the active-days-only numbers and inspect before accepting it.
A unit test checks that a leak-sized score (0.20 at chance 0.01) still FAILs.

Outcome: every reported run PASSes the original Chapter 6 bar on its worst
of three shuffles, so the WARN tier was never used. The untrained network
sat at chance in all three runs, which does not support the idea that the
architecture ranks unusual rows before seeing labels. One full-profile
shuffle reached about 8 x chance and passed only on the absolute floor; the
audit records it.

## Static-trait ablation

The first mid run had `psych_conscientiousness` in the mask top 10. XGBoost
had no static trait in its top 10 (Chapter 6 audit). A static trait cannot
describe what someone did on a given day, so Chapter 11 could not use it as
a reason (N22), and it may reflect how the CERT generator assigns
psychometrics rather than insider behaviour.

```bash
python -m app.tabnet.train --profile mid --exclude-features psych_,peer_department_size --tag "ablation: no static traits"
```

Decision rule, fixed before the ablation is run: adopt the behaviour-only
model unless its validation PR-AUC is more than 0.10 below the model with
static traits. 0.10 is about the epoch-to-epoch swing of validation PR-AUC
in the first mid run, so a smaller gap cannot be told apart from noise.
Either way, record both validation numbers and the decision in the audit.
Excluding features changes the config, so it is a new model version and
counts toward the 12-configuration budget.

Outcome: validation PR-AUC 0.734 without static traits against 0.639 with
them, so the behaviour-only model was adopted for every reported run. On
test the order was reversed (0.220 against 0.509, the latter seen through
C7-9); the decision stands and the audit discloses it.

## Before reporting any number

* Mid has about 28% insider users and full about 7%. Say which profile each
  number is from.
* The user-split test set holds 14 insiders, 2 from scenario 3, and most
  test positives are scenario 2 (N15). A single PR-AUC is mostly a
  scenario-2 number.
* TabNet and XGBoost are both supervised on the same labels and split. The
  comparison that matters is between those two; the unsupervised baselines
  answer a different question.
* Pick nothing on test. Hyperparameters, the imbalance method and
  pretraining are chosen on validation only.
* Nothing in this document has been measured on the development machine:
  CUDA training, Windows behaviour and full-profile wall-clock are untested
  here. The first mid run is the first real evidence.

## Acceptance checklist

- [x] TabNet trains on a Chapter 5 matrix and produces a saved, versioned artifact (synthetic)
- [x] Leakage-safe split, by user (saved Chapter 6 file) or by time, documented
- [x] Class-imbalance handling implemented and recorded
- [x] Plumbing to benchmark against the Chapter 6 baselines with the same harness (synthetic, harness reproduction checked)
- [x] Registry never overwrites; entries hold model, data, schema, timestamp and metrics
- [x] Per-epoch checkpoints; interrupted and uninterrupted training give the same model (unit test)
- [x] mid user-split run, verifier 0 FAIL with `--reload-models --permutation-test --baselines` (`20260927T125702Z-mid-user-s42`)
- [x] mid time-split run, verifier 0 FAIL with `--baselines` (`20260927T161717Z-mid-time-s42`, also reload and permutation)
- [x] full user-split run, verifier 0 FAIL with `--reload-models --permutation-test --baselines` (`20260927T162456Z-full-user-s42`)
- [x] `--fresh` determinism re-run at mid, compared with `--compare-run-id` (`20260927T160614Z`, max difference 0)
- [x] interrupted-and-resumed run at mid, compared with `--compare-run-id` (`20260927T160956Z`, max difference 0)
- [x] static-trait ablation decided on validation under the rule fixed in advance
- [x] `docs/audits/chapter_7_audit.md` written from those runs
