# Chapter 1-5 audit (24 September 2026)

Scope: repository state at commit `d3bb41f` checked against the
Implementation Bible (Chapters 1-5) and HCEA v1.0 (§2 standing rules, §3-5).
Evidence: code reading, the existing test suite, and an end-to-end run of the
Chapter 5 pipeline on a synthetic CERT-shaped tree with small chunk sizes,
compared column by column against brute-force values computed from the raw
CSVs.

## Result before fixes

Chapters 1-4: pass. Chapter 5: not accepted. Existing tests passed (58/58)
but only exercised single-chunk inputs, which is where the defects hide.

## Defects found and fixed

| # | Defect | Evidence | Fix |
|---|---|---|---|
| 1 | `usb_distinct_pcs`, `file_distinct_pcs` summed across Parquet parts (the HCEA §5.3 chunk-safety bug) | 213 of 2,563 user-days wrong on synthetic run; max 5 vs true max 3 | Exact counts from globally deduplicated (user, day, item) triples |
| 2 | `usb_first_hour` / `usb_last_hour` summed across parts | Values up to 42 (not a clock hour) | Per-column combine rules: min/max for hours, max for flags, sum only for additive columns |
| 3 | Inactive days treated as a midnight logon: `first_auth_hour` filled with 0, so `first_auth_off_hours` = 1 on every no-login day | 1,423 of 1,423 idle days flagged off-hours | Hour columns stay null; off-hours flags null when there was no logon |
| 4 | Ratios zero-filled on days with no denominator; schema recorded "zero" | `off_hours_login_ratio` = 0 on idle days | Ratios null (undefined); schema null_policy states this |
| 5 | Peer median pooled over the whole month (includes peers' future days) and ran a per-row Python loop | ~3-4 ms/row measured, tens of minutes at full scale | Same-day peer groups (functional_unit + department), exact leave-one-out median, vectorised: 450k rows in 0.15 s, verified against brute force |
| 6 | No HTTP host-class features; `DEFAULT_HOST_CATEGORIES` empty (HCEA §5.2 requires a committed expert list) | No host-class columns | `network_domains.py` draft list (job search, cloud storage, leak/paste, hacking tools) + label-blind `scripts/http_host_inventory.py` for review |
| 7 | Stage 0 CLI crashed (`run_stage0()` missing `profile`) | TypeError on the documented command | CLI fixed, profile/env aware |
| 8 | Stage 0 resumable only per whole domain, not per part (HCEA R7, §5.2) | A crash mid-http restarts http from zero | Per-chunk `.done` markers; config fingerprint invalidates stale outputs; tested by a simulated kill |
| 9 | One malformed timestamp aborted the run (`errors="raise"`); no rejected sink in Stage 0 (Bible Ch4 rule) | Code | Malformed rows go to `processed/rejected/` with a reason code |
| 10 | Dev profile window Jan-Apr 2010 precedes all r4.2 insider activity (earliest answer-file events seen: June 2010) | Answer-file dates | Dev window Jun-Aug 2010; dev insiders chosen from those active in the window; fails loudly if fewer than 10 |
| 11 | No evaluation label tables (`labels/insider_user_days.parquet`, HCEA §3.4) | Missing | `build_insider_label_tables()` in the ground-truth module (event-level answer files) + `scripts/build_labels.py`; feature package statically barred from importing it |
| 12 | Email size/attachments zero-filled when missing | Code | Kept null |
| 13 | HCEA §17 variables absent from config and `.env.example`; `.env` path depended on CWD | Code | Added; path resolved from the repo root |
| 14 | No thread caps (R6), runlog lacked rows/config hash (R8) | Code | `app/core/runtime.py`; `experiments/runlog.jsonl` summary per run |
| 15 | Four duplicated `* copy.py` test files; empty README; no tests for file_activity, temporal, application, stage0, pipeline | Repo | Removed / written / added (80 tests pass) |

Added features along the way: `email_distinct_external_domains`, temporal
rolling 7-day activity and active-day counts, `auth_active_span_hours`,
`total_event_count`, static psychometric (OCEAN) context columns.

## Documented deviations (not silent)

- Stage 0 applies the Chapter 4 policy vectorised per chunk rather than
  calling the per-event Pydantic path, which would be too slow at 3.2x10^7
  rows. Duplicate ids are rejected within a chunk; CERT ids are unique per
  domain, so a multi-GB global id set is not built.
- CERT r4.2 has no failed logins, source IPs, byte counts, file
  create/modify/delete, or application/process logs. Those Architecture §10
  sub-features are omitted, not fabricated; `application.py` emits no columns.
- The feature matrix contains nulls by design. Chapter 6 must impute with a
  policy fitted on the training split only.

## Still required on the real dataset (cannot be verified in review)

1. Review `network_domains.py` against `scripts/http_host_inventory.py`
   output, by host category only, never by who visited a host.
2. Run `scripts/build_labels.py`; confirm 7,323 events and 70 users.
3. Run the pipeline at dev, then mid; record wall-clock and peak RSS.
   HCEA §5.5 targets: dev under ~2 minutes, full-pipeline peak RSS under 12 GB.
4. Kill the http stage mid-run once at mid and confirm it resumes (HCEA §5.5).
5. Save `experiments/dataset_inventory.txt` (HCEA §3.2) and commit it.

## Follow-up review (commit 9f69389, real-data runs)

Fixes applied exactly as tested; 80/80 tests pass on the committed code.
`experiments/runlog.jsonl` shows:

| Profile | Users | Events in | Rejected | User-days out | Features | Wall-clock |
|---|---|---|---|---|---|---|
| dev | 49 | 254,850 | 0 | 4,258 | 112 | 267 s |
| mid | 250 | 7,180,298 | 0 | 106,914 | 112 | 277 s (2 s cached re-run) |

Defect 16 found in this review: on Windows `memory_rss_mb()` returned
`WorkingSetSize` (current memory), and the summary is logged at the end of a
run, so the logged 331 MB / 550 MB are end-of-run snapshots, not peaks.
Fixed to `PeakWorkingSetSize`; the HCEA §5.5 peak-RSS item must be re-measured.

Notes:
- dev selects 50 users but only 49 have activity in Jun-Aug 2010; one user
  contributes no rows. Acceptable for a dev profile; worth knowing.
- dev takes ~4.5 min, above the ~2 min HCEA target, because Stage 0 must scan
  every raw CSV once regardless of profile size. Cached re-runs are seconds.
- The 2 s mid re-run proves stage caching, not crash-resume. The kill-and-resume
  check (HCEA §5.5) is still to be demonstrated on real data.
