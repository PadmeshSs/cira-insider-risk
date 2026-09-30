"""Chapter 11: explainability.

Bible Chapter 11 / Architecture Phase 8 (§18), executed under HCEA v1.0 §11
(deviation D-5) and the Chapter 8 serving decision (C8-1).

Why this chapter does not look like the Bible's plan
    The Bible assumed TabNet is served, so its masks would be the primary
    explanation and KernelSHAP would corroborate them. Chapter 8 serves the
    behaviour-only XGBoost (gbdt v0003) and keeps TabNet in shadow. N30 then
    decides the model side: an explanation comes from the model whose score
    produced the alert. For XGBoost that is exact TreeSHAP. TabNet masks are
    never shown as the reason for an XGBoost score, and shadow output never
    feeds an analyst-facing explanation (N32). The mask code is here and is
    used when TabNet is served (a rollback) and by the offline readout.

Serving modules (label-free, statically checked, N5)
    features.py        plain-language description of every Chapter 5 column
    attributions.py    the attribution contract; picks the explainer for the
                       served model (N30); top-k per row
    shap_explainer.py  TreeSHAP for XGBoost (every row, exact); KernelSHAP
                       corroboration and a deletion check (bounded rows, D-5)
    tabnet_masks.py    TabNet aggregate masks, chunked, grouped per feature
    reason_builder.py  the analyst explanation (§18 format): model factors,
                       CRI context, ATT&CK context, each traced to its source
    selection.py       which user-days get the bounded treatment (label-free)
    sources.py         where explain runs and their inputs live
    runtime.py         what the API holds; ``/health`` block; on-demand explain
    batch.py           ``python -m app.explainability.batch``

Offline module (reads labels in memory, like app.mitre.evaluate)
    evaluate.py        validation readout: what explains malicious days per
                       scenario, and the shadow TabNet's masks on the same days

The serving modules must never import ``evaluate``.

This init stays import-light (no numpy) so entry points can apply thread
caps first (N8, HCEA R6).
"""

EXPLAIN_VERSION = "chapter11-v1"
