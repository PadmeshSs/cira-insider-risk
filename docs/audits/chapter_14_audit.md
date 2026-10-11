# Chapter 14 audit (pointer, written at Chapter 19)

Chapter 14 has no audit of its own because its last open item, checking the dashboard against the CERT full
run, could only be closed once the Chapter 15 harness existed. That check is recorded in
`docs/audits/chapter_15_audit.md` (the CERT dashboard row and the section on the CERT browser run):
`frontend/e2e/cert.spec.ts` signed in through the login form and checked every view against alert run
`20261001T062628Z-full-alerts`, including "Re-score this day" and the API-unreachable case.

Design, the views and what the frontend adds itself: `docs/chapters/chapter_14_dashboard.md`. Run steps and
the frontend test files: `frontend/README.md`. The rule every later change keeps: the dashboard computes
nothing it displays (N69).

Nothing in this file is new evidence. It exists so that every chapter from 1 to 16 has an audit to point at
from `docs/COMPONENT_STATUS.md`.
