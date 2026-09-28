"""Chapter 8: anomaly scoring and model serving.

Bible Chapter 8 / Architecture Phase 5, executed under HCEA v1.0 §8.

This package sits between the model packages (``app.tabnet``,
``app.baselines``) and everything downstream of a score: CRI (Chapter 9),
alerts (Chapter 12) and the API (Chapter 13). Downstream code talks to
``AnomalyScoringService`` and never to a model object (N10).

Serving modules (label-free, statically checked, N5)
    contracts.py       score contract, errors, input validation, model pins
    gbdt_model.py      behaviour-only XGBoost detector (sigmoid of the margin)
    adapters.py        load a pinned, sha256-verified registry version on CPU
    serving_config.py  which model is served: decision file or env pin
    service.py         AnomalyScoringService: score_frame, score_event, status
    batch.py           ``python -m app.scoring.batch``: scores to Parquet

Offline modules (read labels in memory, like app.tabnet.train)
    gbdt_candidate.py  trains and registers the behaviour-only XGBoost
    select.py          applies the serving rule on validation, writes the
                       decision file; reads test once, afterwards

The serving modules must never import an offline module.

This init stays import-light (no numpy, no torch) so entry points can apply
thread caps first (N8, HCEA R6).
"""

SERVING_VERSION = "chapter8-v1"
