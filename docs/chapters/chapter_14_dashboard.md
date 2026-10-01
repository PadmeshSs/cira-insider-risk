# Chapter 14: React + TypeScript SOC dashboard

Bible Chapter 14 / Architecture Phase 11 (§27), over the Chapter 13 API.

Status: IMPLEMENTED against the Chapter 13 synthetic chain; PARTIALLY IMPLEMENTED for CERT full until the
dashboard has been opened against the API serving `20261001T062628Z-full-alerts` on the development
machine and the checks below are repeated there (N62 pattern).

## What it is for

The dashboard answers the six §27 questions from the decisions Chapters 8 to 12 stored and Chapter 13
serves. It computes no score. Every number on screen is read from an API response, and the one route that
computes (`POST /risk/score`) is used only to reproduce a stored decision, never stored (N64).

## Views

| View | Route | §27 question | API |
|---|---|---|---|
| Login | `/login` | | `POST /auth/token`, `GET /users/me`, `GET /health` (readiness list) |
| Overview | `/` | Who is risky? | `GET /risk/overview`, `GET /alerts?limit=8` |
| Alerts | `/alerts` | What happened? | `GET /alerts` with status, band, user, sort and paging |
| Alert details | `/alerts/:id` | How risky is it? | `GET /alerts/{id}`, `/risk/users/{u}/days/{d}`, `/anomaly/users/{u}/days/{d}`, `/features/users/{u}/days/{d}`, `POST /risk/score` |
| Explainability | `/alerts/:id/explain` | Why is it risky? | `GET /explanations/alerts/{id}` |
| ATT&CK context | `/alerts/:id/mitre` | What contextual evidence supports the risk? | `GET /mitre/alerts/{id}`, `GET /mitre/techniques/{id}` |
| User investigation | `/users/:id` | What should the analyst investigate? | `GET /investigations/{u}`, `GET /risk/users/{u}/history`, `GET /events` |
| Risk history | `/users/:id/history` | | `GET /risk/users/{u}/history?bucket=day\|week` |

Two supporting views: `/users` (`GET /investigations?scope=`) and `/system` (`GET /health`, `GET /models`).

## Design

`DESIGN.md` ("Tactical Threat Surface") sets the palette: permanent dark mode, planar panels with 1px
borders, Inter for text, JetBrains Mono for identifiers and scores, and severity colours that always come
with a word and a value (`MEDIUM 31`). After the first review the density was relaxed for readability:
56px table rows, 24px gaps between sections, 32px page padding, 14px body text, sentence-case labels
instead of tracked capitals, and plain names on screen ("Model score" for the queue score, "Repeats" for
suppressed alerts, "When" for the alert window), each with a hover note carrying the exact meaning.

- Labelled sidebar (Overview, Alerts, Users, System status), each item with a one-line hint.
- Top bar: one status line from `/health` ("All services ready", or the first route that is not, with
  its reason) and a user search available on every page.
- Three provenance hues, used wherever a value appears: cyan = served model, indigo = CRI context,
  fuchsia = ATT&CK. They never mark severity (N34, N45, N50).
- Run ids sit behind a "Where these numbers come from" toggle on Overview, Alerts and alert pages.

Elements specific to CIRA:

- How the scores were made (alert details). The anomaly score and the CRI on two instruments and two
  scales. The CRI is drawn as its component points laid end to end; the points sum to the stored CRI
  exactly and the table says so or names the difference. A component without a value is shown as
  excluded (N35). Band limits on the scale come from `/health` `cri.config.severity_maxima`.
- Days in this alert. Each member day with both scores as separate bars, the trigger that admitted it
  and the peak; gaps between member days are labelled with their length.
- Explanation sections. Model factors (TreeSHAP, log-odds, raising and lowering on one diverging axis),
  CRI context points and ATT&CK matches, each in its own section and colour. KernelSHAP only as the
  agreement statistic (N48). Stored `alert_reasons` counts shown beside the sections.
- Factors across days. A feature x member-day grid of the stored TreeSHAP contributions.
- Check the decision. The day's stored feature vector and LDAP role go back through `POST /risk/score`;
  stored and recomputed anomaly score, CRI and band are set side by side (§37).
- Day timeline. One lane per CERT domain on a 24-hour axis, off-hours hatched. Clock times are read from
  the recorded timestamp, so the browser's time zone never moves an event.

## Where every value on screen comes from

Every number, date, id and label of data comes from one of these responses. The views were checked by
stopping the API: no view renders a value without it.

| View | Element | Source |
|---|---|---|
| Top bar | status line, model, alert run | `GET /health`: `routes`, `anomaly_model.served`, `routes.alerts_risk_investigations.alert_run_id` |
| Overview | open alerts, repeats | `GET /risk/overview`: `counts.open`, `counts.suppressed` |
| | severity card | `open_by_severity` |
| | raised by the model alone | `open_never_above_low` (percentage = it divided by `counts.open`) |
| | ordering in the subtitle | `queue.ordered_by`, `queue.policy_version` |
| | riskiest users | `top_users[]`: `user_id`, `max_severity`, `max_queue_score`, `open_alerts`, `suppressed_alerts`, `in_sample` |
| | what is driving alerts, USB warning | `top_features[]`, `open_led_by_usb_disconnect_count` |
| | new alerts per week | `new_open_alerts[]` |
| | next to review | `GET /alerts?status=open&sort=queue&limit=6` |
| Alerts | every row | `GET /alerts` `items[]`: `id`, `status`, `duplicate_of_id`, `in_sample`, `user_id`, `max_severity`, `max_cri_score`, `queue_score`, `ordering`, `top_feature`, `techniques`, `first_date`, `last_date`, `peak_date`, `n_days`, `suppressed` |
| | header counts, pager | `counts`, `page` |
| Alert details | header | `GET /alerts/{id}`: `alert.*`, `triggers`, `duplicate_of` |
| | days in this alert | `members[]`: `anomaly_score`, `cri_score`, `severity`, `is_peak`, `by_band`, `by_top_k` |
| | how the scores were made | `GET /risk/users/{u}/days/{d}`: `anomaly_score`, `cri_score`, `severity`, `components`, `points`, `missing_components`, `historical_top_feature`, `peer_top_feature`, `ldap_role`, `cri_version`, `cri_variant`, `calibration_id`, `cri_config_hash`; `GET /anomaly/users/{u}/days/{d}`: `model_name`, `registry_version`, `raw_score`, `batch_run_id`; band limits from `/health` |
| | activity measured that day | `GET /features/users/{u}/days/{d}` `values[]`: `label`, `column`, `value`, `value_text`, `domain`, `static`, `model_input`; highlighted contributions from `GET /explanations/alerts/{id}` |
| | check the decision | `POST /risk/score` with the stored `values[]` and `ldap_role`; shows `anomaly.anomaly_score`, `risk.cri_score`, `risk.severity`, `alert_trigger`, `unavailable_components`, `persisted` |
| | repeats of this alert | `suppressed_alerts[]` |
| Explainability | everything | `GET /explanations/alerts/{id}` `members[]`: `headline`, `status`, `model_unavailable_reason`, `sections.model`, `sections.model_lowering`, `sections.cri`, `sections.mitre`, `corroboration`, `unavailable`, `reason_rows`, `text`, `explain_run_id` |
| ATT&CK context | grid, day detail | `GET /mitre/alerts/{id}`: `note`, `days[]`, `techniques[]` |
| | technique drawer | `GET /mitre/techniques/{id}` |
| User investigation | header, alerts | `GET /investigations/{u}`: `subject`, `alerts`, `coverage` |
| | risk chart | `GET /risk/users/{u}/history?bucket=day` |
| | day timeline, event table | `GET /events?user_id=&date_from=&date_to=&limit=200`: `items[]`, `page.total` |
| Risk history | charts, table, coverage | `GET /risk/users/{u}/history?bucket=day\|week` |
| Users | table, demo window | `GET /investigations?scope=` |
| System | components, readiness, models | `GET /health`, `GET /models` |

### What the frontend adds itself

Nothing below is a score, rank or new data point; each item is wording, layout, or arithmetic on values
the API returned, listed so it can be checked.

- Wording: titles, help text, the CRI component names (`constants/cri.ts`) and CERT domain names
  (`constants/events.ts`).
- Column names shown in sentence case where the API sends no described label (`top_feature`,
  `top_features[].feature`).
- Off-hours shading at 07:00 and 19:00, copied from the Chapter 5 definition
  (`app/explainability/features.py` `OFF_HOURS`), which the API does not expose.
- Band limits 24 / 49 / 74 as a fallback only until `/health` answers.
- The USB caveat quotes note N52 (Chapter 11 validation readout); the count beside it is from the API.
- Arithmetic: percentages of API counts; the sum of CRI points as a check; stored minus recomputed
  difference; days per band and alert member days on the risk history page, counted from the returned
  buckets; zero-count weeks between the first and last returned week; breaks between non-adjacent
  persisted days.
- Formatting: dates as "19 Jan 2010", event clock times read from `event_time`, and one-line event
  summaries built only from `details` (`activity`, `file_extension`, recipients, `size`, `attachments`,
  `host`).

### Endpoints and parameters not used by a view

`GET /explanations/users/{user}/days/{day}` (the alert route returns every member day already),
`POST /anomaly/score` (`POST /risk/score` returns the same anomaly part), the `alert_run_id` query
parameter (the dashboard always reads the served run) and the `source_type` filter of `/events`.

### Synthetic data

There is none in the application. The only hand-made values are in `src/test/units.test.tsx`, which
the app never imports. `grep -rn "src/test" frontend/src --include=*.tsx` finds no import outside the
test folder.

## Carry-forward compliance

| Note | How the dashboard satisfies it |
|---|---|
| N9 | Event wording uses only what r4.2 records per domain; web events read "Visited host", never a transfer |
| N20, N34 | Anomaly score and CRI are separate instruments everywhere; the anomaly score is described as a ranking score, not a probability |
| N25 | `/features` static traits marked; "not an input" shown for columns the served model does not read |
| N31, N59 | `in_sample` flagged on alerts, users and members; demo-sample users tagged |
| N35 | Missing CRI components shown as excluded, never as zero contribution |
| N45 | Techniques in their own section; `indicated` shown as a visit; unmapped and not-evaluated days shown as such |
| N48, N51 | KernelSHAP only as corroboration; no TabNet mask panel |
| N50 | Three explanation sections apart, with reason-row counts |
| N52 | Overview shows how many open alerts `usb_disconnect_count` leads, with the caveat |
| N55 | Queue in policy order by default; "Newest first" is the only other sort; no CRI sort |
| N57, N60 | Open and suppressed counts together; suppressed count and span on every open alert; suppressed alerts openable, never shown as resolved |
| N63 | Coverage note beside every history chart and timeline; history lines break where the database holds no day |
| N64 | Re-score results labelled as computed on demand, `persisted: false` shown |
| N65 | Sign-in through `POST /auth/token`; only the token and expiry are kept (sessionStorage); 401 ends the session |
| N66 | Every list paged within the 200 cap; events of a day loaded 200 at a time |
| N68 | Login and error panels read `/health` `routes` for a precise "not ready" reason |

## Verification

On the development container, against the Chapter 13 integration world (synthetic chain, SQLite,
alert run with 36 open and 5 suppressed alerts), API started with its real lifespan:

- `npm run build`, `npm run lint`: clean. `npm test`: 8 Vitest tests pass.
- Every view opened in headless Chromium after a real sign-in; no page errors.
- Re-scoring the peak day of an alert through the dashboard reproduced the stored anomaly score and CRI
  with difference 0 and the same band.

These are synthetic numbers and say nothing about CERT. The synthetic run has no HIGH or CRITICAL day, so
those badge colours were checked only in unit tests.

## Checking it yourself

1. API off: stop uvicorn and reload every view. Each shows "API not reachable" or a "Not ready" panel
   and no number. Any value still on screen would be a fixture.
2. Network tab: on each view, pick a few values and find them in a response (DevTools, Network, the
   request, Preview, Ctrl+F).
3. `grep -rniE "mock|fixture|faker|sample data" frontend/src` matches only the test file.

## Still open

- Repeat the checks against the CERT full run on the development machine and record them in an audit.
- Chapter 15: end-to-end tests (Playwright click-through) can reuse the reproduce check as the lineage test.
- Chapter 17: SSE live alerts will need a live-update path in the queue.
