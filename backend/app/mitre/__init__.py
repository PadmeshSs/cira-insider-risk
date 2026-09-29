"""Chapter 10: MITRE ATT&CK enrichment.

Bible Chapter 10 / Architecture Phase 7 (§16), executed under HCEA v1.0 §10
(deviation D-4).

The enrichment maps behaviour that CERT r4.2 actually records to candidate
ATT&CK techniques, per user-day, and turns the strongest candidate into the
CRI's ``mitre_context`` input in [0, 1]. It is threat context, not a
detector: it never produces an anomaly score and never replaces one.

It reads behaviour only (the Chapter 5 matrix), never a model output. The
served XGBoost and the shadow TabNet disagree on which user-days are risky
(validation Spearman 0.285, docs/audits/chapter_9_audit.md), so a technique
attached to a user-day must not depend on which of them is served. The same
user-day gets the same techniques under either model, and a rollback needs
no MITRE refit. The CRI that consumes ``mitre_context`` is still tied to one
model_version (N29, N33).

Serving modules (label-free, model-free, statically checked, N5)
    techniques.py     the committed technique table (no mitreattack import)
    mapping_rules.py  the expert map: rules, the behaviours considered and
                      deliberately left unmapped, the ruleset hash
    reference.py      rarity reference for rule strength, pinned with sha256
    enrich.py         MitreEnricher: user-day rows -> matches, context, status
    runtime.py        what the API holds (/health ``mitre`` block)
    sources.py        where enrichment runs live
    calibrate.py      ``python -m app.mitre.calibrate``: fit and pin the reference
    batch.py          ``python -m app.mitre.batch``: enrichment run to Parquet

Offline modules
    stix_loader.py    ``python -m app.mitre.stix_loader``: run once against the
                      pinned bundle; the only module that imports mitreattack
    evaluate.py       validation readout (reads labels in memory), including
                      the XGBoost / TabNet disagreement view

The serving modules must never import ``evaluate``, ``stix_loader``, label
code or scoring code.

This init stays import-light (no numpy) so entry points can apply thread
caps first (N8, HCEA R6).
"""

MITRE_VERSION = "chapter10-v1"
