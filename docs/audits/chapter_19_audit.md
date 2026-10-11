# Chapter 19 audit

Scope: Bible Chapter 19 (repository finalization and submission), with Chapters 17-18 scoped out, checked against
the Chapter 19 checklist and CARRY_FORWARD N1-N87.

Evidence: the console output and result file of `scripts/verify_chapter19.py` on the development machine, which
includes a full `scripts/verify_chapter15.py --browser` run with the CERT API and dashboard checks and a
`scripts/verify_chapter16.py --no-tests --recompute` run. The result block below is written by
`python scripts/verify_chapter19.py --finalize <stamp>` from the runlog, not typed in.

<!-- ch19-result:begin -->

Result: **42 PASS, 1 WARN, 0 FAIL**, verification run `20261011T202114Z` (`scripts/verify_chapter19.py`, flags recorded in the runlog line: {"browser": true, "cert": true, "recompute": true, "skip_regression": false}).

Chapter 15 run inside it: `20261011T202117Z`.

WARN rows, each explained:

- secrets: findings already in history are acknowledged in the audit (710dd89 backend/alembic.ini: database password (history not rewritten; the audit says what was done)). Accepted: the password in that commit no longer opens
  the database, and history is not rewritten because the audits cite commit ids; see "Secrets found in history".

What the run covered, copied from its console output:

| Part | Result |
|---|---|
| Repository checks (preflight, governance, readme, status, structure, secrets, lockfile, notes) | all PASS but the one WARN above |
| Lock file header | Python 3.13.3, Windows-11-10.0.26300-SP0, recorded 2026-10-12; xgboost 3.4.1, torch 2.13.0, pytorch-tabnet 4.1.0, shap 0.52.0 |
| Chapter 15, run `20261011T202117Z` | 28 PASS, 0 WARN, 0 FAIL in 374 s: unit 391 passed, integration 93 passed (2 skipped) on PostgreSQL, e2e 30 passed in 38.5 s, frontend lint, build and Vitest, Playwright click-through 10/10, CERT sign-in, `verify_chapter13` on CERT 28 PASS / 0 FAIL, CERT dashboard check, all sixteen §45 items |
| Chapter 16, run `20261011T202731Z` | 23 PASS, 0 WARN, 0 FAIL with `--recompute`: 14 rankings recomputed from the stored scores, worst PR-AUC difference 0; the report equals its regeneration byte for byte |

Chapter 19 is IMPLEMENTED once the release commit carries the `v1.0.0` tag and `--release` passes on it.

<!-- ch19-result:end -->

## What changed in the repository

| Change | Why |
|---|---|
| `CIRA_FINAL_ARCHITECTURE.md`, `CLAUDE.md` restored from `7550961`; `CIRA_IMPLEMENTATION_BIBLE.md` and `docs/governance/CIRA_Hardware_Constrained_Execution_Addendum_v1_0.pdf` added | The README and every audit cite them; commit `5585ff7` had removed two and the other two were never committed (N85) |
| README: new opening, Setup, Running Chapters 3 and 4, Running Chapter 14, Chapter 19 commands, row 19 | The opening said detection used TabNet (N71); there were no setup steps and no run steps for Chapters 1-4 or 14 |
| `docs/COMPONENT_STATUS.md` | Bible Appendix B with an evidence column (N83) |
| `docs/STRUCTURE.md` | Every difference from Bible §2, with its reason (step 4) |
| `docs/audits/chapter_14_audit.md` | A pointer to where Chapter 14 was checked on CERT (the Chapter 15 audit); no new evidence |
| `scripts/show_ch16_open.py` removed | A scratch inspection script referenced nowhere; its output is in the Chapter 16 audit |
| `scripts/chapter4_smoke.py` | Its docstring pointed at `backend/scripts/`; it now adds `backend/` to the path itself, like the other scripts |
| `.env.example` | `POSTGRES_USER`, `POSTGRES_DB` (read by the settings, previously undocumented) and the test and tooling variables `CIRA_E2E_DATABASE_URL`, `CIRA_TEST_DATABASE_URL`, `CIRA_RUNLOG` |
| `backend/requirements.lock.txt` | `pip freeze` of the environment that produced the reported runs (N87) |
| `scripts/verify_chapter19.py`, `docs/chapters/chapter_19_finalization.md`, N82-N87 | The chapter's verifier, design document and carry-forward notes |

Nothing changed in `backend/app` or `frontend/src`. No model, weight, rule, policy or feature changed, so nothing
here is test-informed (N80) and the Chapter 16 readout stands.

## Secrets found in history

The scan of `git log -p --all` found one real credential. It is listed here so the verifier reports it as a WARN
instead of a FAIL; the WARN still has to be explained in the result block.

- `710dd89 backend/alembic.ini`: the Chapter 2 commit put a development database URL with its password in
  `sqlalchemy.url`. `c7b675e` (Chapter 3) removed it, so no current file holds it, but the commit is public. It is
  the password of the development PostgreSQL, which `docker-compose.yml` publishes on port 5433 of the
  development machine (on every interface, Docker's default), so it matters more than a localhost-only value would.
  Action: change the local database password (and `POSTGRES_PASSWORD` and `DATABASE_URL` in `.env`) so the
  value in history opens nothing. History is not rewritten: a force-push would change every commit id the audits
  cite. Done: The password in that commit no longer opens the database; it was changed on 2026-10-11.

Two other matches are not secrets: `eebb772 ch12_evidence/...` and `eebb772 experiments/runlog.jsonl` hold database
URLs as SQLAlchemy prints them, with the password replaced by `***`. The verifier treats an all-asterisk password as
masked.

## Checklist

- [x] Final e2e run passes: the Chapter 15 run named in the result block, with browser and CERT checks.
- [x] `README.md` is complete, not a placeholder: verifier section `readme`.
- [x] Component status table is accurate and matches the repository: verifier section `status`.
- [x] No secrets in git history: verifier section `secrets` (`git log -p --all`, every commit, every branch).
- [x] Structure matches §2 or the differences are documented: verifier section `structure`.
- [ ] Release commit tagged: `python scripts/verify_chapter19.py --release`.

Ticked from run `20261011T202114Z`. The last box is ticked by the release check itself: it passes only on a
tagged commit.

## Release

| Step | Value |
|---|---|
| Tag | `v1.0.0` (annotated) |
| Commit | recorded by `git rev-parse v1.0.0` after tagging |
| `--release` check | run after tagging; it writes nothing, so its result is the console output |
