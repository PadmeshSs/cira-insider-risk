"""Chapter 12: alert correlation and persistence.

Bible Chapter 12 / Architecture Phase 9 (§17, §20, §36, §37), executed under
HCEA v1.0 §12 (deviation D-6, bounded persistence).

What an alert is here
    CIRA scores user-days (Chapter 5-11). An alert is one incident: the
    triggered user-days of one user that lie close together in time,
    correlated into one row with its member days, instead of one alert per
    day or per event (§17). Four related events on one day are already one
    user-day; related days a few days apart become one alert.

Label-free serving modules (N5; statically checked by the tests)
    policy.py         c12-alert-policy-v1: which user-days trigger (CRI band
                      and/or daily top-k), the queue ordering, the
                      correlation gap, the span cap and the cooldown
    correlation.py    triggered user-days -> alerts and member days
    deduplication.py  suppress a repeat of the same pattern inside the cooldown
    demo.py           c12-demo-sample-v1: the bounded demo sample (D-6)
    explain.py        member-day explanations through the Chapter 11 builder (N50)
    sources.py        where alert runs live
    batch.py          ``python -m app.alerts.batch``: alerts to Parquet
    persistence.py    the bounded load into PostgreSQL, one transaction (D-6, §36, §37)
    load.py           ``python -m app.alerts.load``
    runtime.py        what the API holds; the ``alerts`` and ``database`` blocks of /health

Offline module (reads labels in memory, like app.explainability.evaluate)
    evaluate.py       validation readout of the alert policy

The serving modules must never import ``evaluate`` or label code. This init
stays import-light so entry points can apply thread caps first (N8).
"""

ALERTS_VERSION = "chapter12-v1"
