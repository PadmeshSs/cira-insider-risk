"""Experiment E1: what the Chapter 12 alert queue does on test (N55, N56, N57, N60, N61).

The Chapter 12 readout read the queue on validation. This module reads the SAME alert run on another
part, and answers the questions the carry-forward notes left for Chapter 16:

    * N57  alert precision and insiders caught with and without deduplication
    * N55  the policy as built (anomaly-score ordering) and the same policy with ``cri_score`` ordering,
           recomputed from the same risk run; neither is quoted without the other
    * N56  how many daily top-k slots the ``require_activity`` rule changed on this part
    * N60  per scenario: malicious days in an open alert, only in suppressed alerts, in no alert;
           open alerts that never rise above LOW on the CRI
    * N61  which population each figure ranks (the queue ranks validation and test users together)

The alert code is not copied: ``app.alerts.evaluate.read_view`` does the label read, ``app.alerts.policy``
the triggers, ``correlate`` and ``deduplicate`` the grouping. Alerts of the run as built are read from its
Parquet; the other variants are recomputed from the same risk run, label-free, then read.

Offline, reads labels in memory (N5).
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from pathlib import Path

from app.alerts.correlation import correlate
from app.alerts.deduplication import deduplicate
from app.alerts.evaluate import SCENARIOS, read_view
from app.alerts.policy import ACTIVITY_COLUMN, AlertPolicy, triggers
from app.alerts.sources import ALERTS_OUTPUT, MEMBERS_OUTPUT, alert_run_dir, read_meta
from app.cri.sources import RISK_OUTPUT
from app.evaluation.labels import attach_labels, load_label_views
from app.explainability.sources import aligned
from app.tabnet.dataset import load_feature_matrix


def _key(u, d) -> tuple[str, str]:
    return str(u), str(d)


def _coverage(view: dict) -> dict:
    """Per scenario: malicious days in an open alert / only in suppressed alerts / in no alert (N60)."""
    out = {}
    for s, b in (view.get("malicious_days_by_scenario") or {}).items():
        in_open, only_sup = b["in_open_alert"], b["only_in_suppressed_alert"]
        out[s] = {"malicious_days": b["malicious_days"], "in_open_alert": in_open,
                  "only_in_suppressed_alert": only_sup, "in_no_alert": b["malicious_days"] - in_open - only_sup}
    return out


def _summarise(view: dict) -> dict:
    return {**view, "coverage_by_scenario": _coverage(view)}


def _other_policy(policy: AlertPolicy, **changes) -> AlertPolicy:
    return AlertPolicy.from_dict({**policy.to_dict(), **changes})


def _replay(risk: pd.DataFrame, activity: np.ndarray, members: pd.DataFrame, policy: AlertPolicy, *, dedup: bool):
    trig = triggers(risk, policy, activity)
    days = risk.assign(by_band=trig["by_band"].to_numpy(), by_top_k=trig["by_top_k"].to_numpy())[trig["triggered"].to_numpy()]
    top = dict(zip(zip(members["user_id"], members["date"]), members["top_feature"]))
    days = days.assign(top_feature=[top.get((u, d)) for u, d in zip(days["user_id"], days["date"])], techniques=None)
    alerts, mem = correlate(days.reset_index(drop=True), policy)
    alerts = deduplicate(alerts, policy) if dedup else alerts.assign(status="open", duplicate_of=None)
    return alerts, mem, trig


def operational_views(processed: str | Path, profile: str, part: str, *, alert_run_id: str | None = None) -> dict:
    processed = Path(processed)
    run_dir = alert_run_dir(processed, alert_run_id, profile)
    meta = read_meta(run_dir)
    alerts = pd.read_parquet(run_dir / ALERTS_OUTPUT)
    members = pd.read_parquet(run_dir / MEMBERS_OUTPUT)
    policy = AlertPolicy.from_dict(meta["policy"])

    rdir = processed / "risk" / "chapter9" / meta["risk_run"]["cri_run_id"]
    risk = pd.read_parquet(rdir / RISK_OUTPUT, columns=["user_id", "date", "model_split", "anomaly_score", "cri_score", "severity"])
    risk["user_id"] = risk["user_id"].astype("string").str.strip().str.casefold()
    risk["date"] = risk["date"].astype("string")
    if meta.get("rows_option") == "evaluation":
        risk = risk[risk["model_split"].astype(str) != "train"]
    risk = risk.sort_values(["user_id", "date"], kind="mergesort").reset_index(drop=True)
    rows = risk[risk["model_split"].astype(str) == part].reset_index(drop=True)
    if rows.empty:
        raise RuntimeError(f"alert run {run_dir.name} covers no {part} rows")
    labels = attach_labels(rows[["user_id", "date"]], load_label_views(processed))
    lab = {_key(u, d): (int(y), int(s), bool(e)) for u, d, y, s, e in zip(
        rows["user_id"], rows["date"], labels["y_primary"], labels["scenario_primary"], labels["exclude_primary"])}

    fm = load_feature_matrix(processed, profile)
    activity = aligned(fm.matrix[["user_id", "date", ACTIVITY_COLUMN]], risk[["user_id", "date"]],
                       "the feature matrix")[ACTIVITY_COLUMN].to_numpy(dtype="float64")

    views: dict[str, dict] = {}
    views["policy_as_built"] = _summarise(read_view(alerts, members, lab, rows["date"]))
    views["policy_without_deduplication"] = _summarise(
        read_view(alerts.assign(status="open"), members, lab, rows["date"]))
    other = _other_policy(policy, ordering="cri_score" if policy.ordering == "anomaly_score" else "anomaly_score")
    for name, dedup in (("other_ordering", True), ("other_ordering_without_deduplication", False)):
        a, m, _ = _replay(risk, activity, members, other, dedup=dedup)
        v = _summarise(read_view(a, m, lab, rows["date"]))
        v["ordering"] = other.ordering
        v["note"] = ("recomputed from the same risk run with the other ordering; ATT&CK techniques are left out of the "
                     "deduplication signature, so suppression can differ slightly from a stored run")
        views[name] = v
    views["policy_as_built"]["ordering"] = policy.ordering
    views["policy_without_deduplication"]["ordering"] = policy.ordering

    # N56: how many daily top-k slots the activity rule changed on this part (the rule is label-free)
    off = _other_policy(policy, require_activity=False)
    t_on = triggers(risk, policy, activity)["by_top_k"].to_numpy()
    t_off = triggers(risk, off, activity)["by_top_k"].to_numpy()
    in_part = (risk["model_split"].astype(str) == part).to_numpy()
    changed = (t_on != t_off) & in_part
    changed_rows = risk.loc[changed, ["user_id", "date"]]
    lab_changed = [lab.get(_key(u, d), (0, 0, False)) for u, d in zip(changed_rows["user_id"], changed_rows["date"])]
    views["activity_rule"] = {
        "require_activity": bool(policy.require_activity),
        "top_k_per_day": int(policy.top_k_per_day),
        "dates_in_part": int(rows["date"].nunique()),
        "dates_with_a_changed_slot": int(changed_rows["date"].nunique()),
        "user_days_whose_slot_changed": int(changed.sum()),
        "of_which_malicious": int(sum(1 for y, _s, e in lab_changed if y == 1 and not e)),
        "of_which_idle_user_days_taking_a_slot_without_the_rule": int((t_off & ~t_on & in_part).sum()),
        "meaning": "slots that change when the rule is off; the rule is neutral only if few of them are malicious",
    }

    open_alerts = alerts[(alerts["status"] == "open") & alerts["user_id"].astype(str).isin({u for u, _ in lab})]
    never_above_low = int((open_alerts["max_severity"].astype(str) == "LOW").sum())
    return {
        "alert_run_id": run_dir.name, "policy_hash": meta.get("policy_hash"), "policy": meta.get("policy"),
        "risk_run_id": rdir.name, "part": part,
        "population": {"rows_option": meta.get("rows_option"), "ranked_rows": int(len(risk)), "part_rows": int(len(rows)),
                       "note": "the queue ranks validation and test users together (N61); a test alert depends on "
                               "validation users' scores that day"},
        "open_alerts_never_above_low": {"count": never_above_low, "of_open_alerts": int(len(open_alerts))},
        "views": views,
        "scenarios": list(SCENARIOS),
    }
