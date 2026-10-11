# Chapter 19 audit

Scope: Bible Chapter 19 (repository finalization and submission), with Chapters 17-18 scoped out, checked against
the Chapter 19 checklist and CARRY_FORWARD N1-N87.

Evidence: the console output and result file of `scripts/verify_chapter19.py` on the development machine, which
includes a full `scripts/verify_chapter15.py --browser` run with the CERT API and dashboard checks and a
`scripts/verify_chapter16.py --no-tests --recompute` run. The result block below is written by
`python scripts/verify_chapter19.py --finalize <stamp>` from the runlog, not typed in.

<!-- ch19-result:begin -->

Not run yet. Chapter 19 is PARTIALLY IMPLEMENTED (N82).

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
  cite. EXPLAIN: The password in that commit no longer opens the database; it was changed on 2026-10-11.

Two other matches are not secrets: `eebb772 ch12_evidence/...` and `eebb772 experiments/runlog.jsonl` hold database
URLs as SQLAlchemy prints them, with the password replaced by `***`. The verifier treats an all-asterisk password as
masked.

## Checklist

- [ ] Final e2e run passes: the Chapter 15 run named in the result block, with browser and CERT checks.
- [ ] `README.md` is complete, not a placeholder: verifier section `readme`.
- [ ] Component status table is accurate and matches the repository: verifier section `status`.
- [ ] No secrets in git history: verifier section `secrets` (`git log -p --all`, every commit, every branch).
- [ ] Structure matches §2 or the differences are documented: verifier section `structure`.
- [ ] Release commit tagged: `python scripts/verify_chapter19.py --release`.

Tick each box only after the run in the result block shows it.

## Release

| Step | Value |
|---|---|
| Tag | `v1.0.0` (annotated) |
| Commit | recorded by `git rev-parse v1.0.0` after tagging |
| `--release` check | run after tagging; it writes nothing, so its result is the console output |
