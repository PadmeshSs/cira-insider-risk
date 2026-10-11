# Chapter 19: repository finalization and submission

Bible Chapter 19, run with Chapters 17-18 deliberately scoped out (the Bible's prerequisite allows "1-16 if
production extensions were deliberately scoped out"). Nothing in this chapter touches the detection path: no
model, weight, rule, policy or feature changes, so nothing here is test-informed (N80) and the Chapter 16
readout stands as written.

## What the chapter does

| Bible step | Done by |
|---|---|
| 1. Re-run the full Chapter 15 e2e validation one final time | `scripts/verify_chapter19.py` runs `scripts/verify_chapter15.py --browser` with the CERT API and dashboard checks, then `scripts/verify_chapter16.py --no-tests --recompute`, and records both stamps |
| 2. Fill in the README | Setup, run steps for Chapters 3-4 and 14 (missing before), the fresh-clone limits, the Chapter 19 commands; the opening now names the served XGBoost and the shadow TabNet (N71) |
| 3. Component status table | `docs/COMPONENT_STATUS.md`, Appendix B with an evidence column (N83) |
| 4. Structure matches §2, no orphans | `docs/STRUCTURE.md` lists every difference with its reason; the scratch script `scripts/show_ch16_open.py` is removed; `scripts/chapter4_smoke.py` now runs from the root as its docstring says |
| 5. No secrets in history; `.env.example` complete | The verifier scans `git log -p --all`; `.env.example` gains `POSTGRES_USER`, `POSTGRES_DB` and the test and tooling variables the code reads |
| 6. Tag a release commit | Annotated `v1.0.0`, checked by `--release` (N84) |

Two things the Bible's list does not name were added because the submission depends on them:

- The governing documents are back in the repository (N85). `CIRA_FINAL_ARCHITECTURE.md` and `CLAUDE.md` were
  removed in commit `5585ff7` and are restored from `7550961`; `CIRA_IMPLEMENTATION_BIBLE.md` and the HCEA PDF
  were never committed. The README and every audit cite them.
- `backend/requirements.lock.txt` (N87). `requirements.txt` has no versions, and the registry's models, the
  TreeSHAP additivity tolerance and the pinned readouts depend on the versions that produced them.

## What the verifier checks

`scripts/verify_chapter19.py` prints PASS, WARN or FAIL per check and exits 1 on any FAIL. Sections:
governance, readme, status, structure, secrets, lockfile, regression and notes, described in the script's
docstring. Three behaviours worth knowing:

- Status follows evidence. README row 19 may say IMPLEMENTED only when the audit names a passing verifier run,
  and a production extension row may not say IMPLEMENTED unless the repository holds code for it (a dependency,
  a workflow folder, a compose overlay).
- The structure check reads git, not the disk. `datasets/` and `models/` exist on the development machine but are
  gitignored, so they count as not tracked and must be explained in `docs/STRUCTURE.md`.
- `--finalize <stamp>` writes a passing run into the audit, README row 19 and N82, and lists each WARN with an
  `EXPLAIN:` marker. `--release` fails while any marker is left.

## Design choices: fixed before test, or not

N80 asks the write-up to say, with the readout (`20261010T072243Z-full-test-c16`), which choices were fixed
before test was read and which were not. Every row cites the note or audit that records it.

| Choice | When it was fixed | Source |
|---|---|---|
| User split, seed 42, users stratified by scenario | Before any model was trained; one saved file reused by every chapter | N3, N11 |
| HTTP host categories | Label-blind review by host category | N7, `experiments/http_host_category_review.txt` |
| TabNet behaviour-only configuration | Chosen on validation under a rule fixed in advance; the all-features model's mid test PR-AUC was seen during tuning (disclosed) | N25, N26, C7-9 |
| Served model (XGBoost) | Rule `c8-serving-rule-v1` written before it was applied, on validation; test read once per model after the decision | N28, C8-1, `experiments/chapter8_test_readout.json` |
| CRI weights and bands | A priori, before any CRI number | N37 |
| CRI calibration | Label-free, on the served model's validation user-days | N33 |
| MITRE rules and weight | A priori, from ATT&CK definitions and column meaning; the public scenario descriptions were known, so gains are partly by construction | N41, N43 |
| KernelSHAP selection | Label-free bounded set | N48 |
| Alert queue ordered by the anomaly score | Validation-informed: chosen after the validation readouts of Chapters 9 and 10 | N55 |
| Idle days never take a top-k slot | Added on the synthetic chain; no CERT number informed it | N56 |
| Alert policy (bands, cooldown, deduplication) | Not changed for any validation number | N60 |
| Demo sample rule | Label-free | N59 |
| Best baseline for the chain | Chosen on validation before test was read | N76 |
| `cri:no_peer_deviation+no_user_context` | Validation-informed; reported, not adopted | N40, N80 |
| Chapter 16 harness check on `cri:anomaly_only` | Changed after the first test readout; it changed a check, not a model, weight, rule or policy; the readout was superseded once | N81 |

## What stays out

Chapters 17 and 18 (Kafka, Redis, Celery, SSE, OpenSearch, Prometheus and Grafana, RBAC hardening, production
images, Kubernetes, CI/CD) are PRODUCTION EXTENSION and not implemented. TWOS stays PLANNED.
