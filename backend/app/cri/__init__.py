"""Chapter 9: Contextual Risk Intelligence (CRI).

Bible Chapter 9 / Architecture Phase 6 (§15), executed under HCEA v1.0 §9.

The CRI turns the served model's anomaly score into a 0-100 contextual risk
score and a severity band. It sits after Chapter 8's scoring service and
before alerts (Chapter 12). It never talks to a model (N10): it reads scores
that already carry their model_version, and it refuses scores from any model
other than the one it was calibrated for (N29).

Every component is expressed on one scale, rarity against a label-free
reference: how unusual the value is among the served model's validation
user-days, in decades, capped at 1. See ``calibration.py``. That scale is
what lets the same weights and severity thresholds mean the same thing for
XGBoost and TabNet, whose raw scores are distributed very differently.

Serving modules (label-free, statically checked, N5)
    config.py       weights, severity bands, ablation variants, config hash
    calibration.py  rarity maps and the pinned calibration (N21-style sha256)
    context.py      component statistics from the Chapter 5 matrix and LDAP
    assets.py       asset-criticality lookup over the Asset table
    engine.py       CRIEngine: combine components into cri_score + severity
    batch.py        ``python -m app.cri.batch``: risk scores to Parquet
    calibrate.py    ``python -m app.cri.calibrate``: fit the reference for
                    the served model (label-free: uses split tags, no labels)

Offline module (reads labels in memory, like app.scoring.select)
    evaluate.py     validation readout of the CRI and its ablation variants

The serving modules must never import ``evaluate``.

This init stays import-light (no numpy) so entry points can apply thread
caps first (N8, HCEA R6).
"""

CRI_VERSION = "chapter9-v1"
