"""Validation readout of the alert policy (Chapter 12; N1, N2, N15, N39, N40, N46, N52).

Offline module: joins labels in memory through app.evaluation, like
app.explainability.evaluate. Never imported by a serving module (N5).

What it answers, on the served model's validation users only
    1. The policy as built (queue ordered by the anomaly score): open alerts,
       alerts per day, how many open alerts contain a malicious day (alert
       precision), malicious days covered per scenario, insiders caught per
       scenario with latency, and which trigger (band, top-k, both) the
       covered days came from (N39).
    2. The same policy with the other ordering (CRI score), recomputed
       label-free from the same risk run and read the same way (N40: both
       views reported).
    3. What false alarms look like: open alerts with no malicious day, by
       top factor; how many are led by usb_disconnect_count (N52).
    4. What deduplication costs: malicious days that sit only in suppressed
       alerts, and insiders whose only alert was suppressed.

Masquerade account-days (N1) are neither a hit nor a false alarm: an alert
whose member days are all benign except excluded ones is counted as
``excluded``.

Guard c12-alert-guard-v1 (WARN only; explained in the audit, never a reason
to change the policy)
    * a malicious validation day is in a suppressed alert and in no open one;
    * the band trigger never fires on validation (the policy is then top-k only
      in practice);
    * an open alert's peak day has its model explanation deferred.

Rules
    * Validation only; ``--part test`` is refused. The test readout is
      Chapter 16's, once.
    * Written once; ``--supersede "<reason>"`` keeps the old readout inside.

Usage, from backend/:

    python -m app.alerts.evaluate --profile full
"""
from __future__ import annotations

from app.core.runtime import apply_thread_caps

apply_thread_caps()

import argparse  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import sys  # noqa: E402
from collections import Counter  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
from pathlib import Path  # noqa: E402

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from app.cri.sources import RISK_OUTPUT  # noqa: E402
from app.evaluation.labels import attach_labels, load_label_views  # noqa: E402
from app.explainability.sources import aligned  # noqa: E402
from app.feature_engineering.common import append_experiment_runlog, repo_root  # noqa: E402
from app.tabnet.dataset import PROFILE_OUTPUT, load_feature_matrix  # noqa: E402

from .batch import USB_FACTOR  # noqa: E402
from .correlation import correlate  # noqa: E402
from .deduplication import deduplicate  # noqa: E402
from .policy import ACTIVITY_COLUMN, AlertPolicy, triggers  # noqa: E402
from .sources import ALERTS_OUTPUT, MEMBERS_OUTPUT, AlertSourceError, alert_run_dir, read_meta  # noqa: E402

READOUT_FILE = "chapter12_validation_readout.json"
GUARD = {
    "version": "c12-alert-guard-v1",
    "warn_if": ["a malicious validation day is only in suppressed alerts",
                "the band trigger never fires on validation",
                "an open alert's peak day has its model explanation deferred"],
    "effect": "WARN to be explained in docs/audits/chapter_12_audit.md; never changes the policy",
}
SCENARIOS = (1, 2, 3)


class ReadoutRefused(RuntimeError):
    """Nothing was written."""


def _key(u, d) -> tuple[str, str]:
    return str(u), str(d)


def read_view(alerts: pd.DataFrame, members: pd.DataFrame, lab: dict, val_days: pd.Series) -> dict:
    """Label-read statistics of one set of alerts, validation users only. ``lab``: key -> (y, scenario, excluded)."""
    val_users = {u for u, _ in lab}
    a = alerts[alerts["user_id"].astype(str).isin(val_users)]
    m = members[members["user_id"].astype(str).isin(val_users)].copy()
    y = np.array([lab.get(_key(u, d), (0, 0, False))[0] for u, d in zip(m["user_id"], m["date"])], dtype=int)
    sc = np.array([lab.get(_key(u, d), (0, 0, False))[1] for u, d in zip(m["user_id"], m["date"])], dtype=int)
    ex = np.array([lab.get(_key(u, d), (0, 0, False))[2] for u, d in zip(m["user_id"], m["date"])], dtype=bool)
    m["y"], m["s"], m["ex"] = y, sc, ex
    status = dict(zip(a["alert_key"], a["status"]))
    m["status"] = m["alert_key"].map(status)
    mo = m[m["status"] == "open"]

    per_alert = mo.groupby("alert_key").agg(pos=("y", "max"), ex=("ex", "max"))
    open_a = a[a["status"] == "open"].set_index("alert_key")
    kind = np.where(per_alert["pos"] == 1, "malicious", np.where(per_alert["ex"], "excluded", "benign"))
    kinds = pd.Series(kind, index=per_alert.index)

    positives = {_key(u, d): (s, e) for (u, d), (yy, s, e) in lab.items() if yy == 1 and not e}
    covered_open = set(zip(mo.loc[mo["y"] == 1, "user_id"].astype(str), mo.loc[mo["y"] == 1, "date"].astype(str)))
    covered_any = set(zip(m.loc[m["y"] == 1, "user_id"].astype(str), m.loc[m["y"] == 1, "date"].astype(str)))
    by_scen = {}
    for s in SCENARIOS:
        keys = [k for k, (ss, _) in positives.items() if ss == s]
        if keys:
            by_scen[str(s)] = {"malicious_days": len(keys), "in_open_alert": sum(k in covered_open for k in keys),
                               "only_in_suppressed_alert": sum(k in covered_any and k not in covered_open for k in keys)}
    first_mal = {}
    for (u, d), (s, _) in positives.items():
        first_mal[u] = min(first_mal.get(u, d), d)
    scen_of = {}
    for (u, _d), (s, _) in positives.items():
        scen_of[u] = s
    first_hit = {}
    for u, d in sorted(covered_open):
        first_hit[u] = min(first_hit.get(u, d), d)
    caught = {}
    for s in SCENARIOS:
        users = [u for u, ss in scen_of.items() if ss == s]
        if users:
            caught[str(s)] = {"insiders": len(users), "caught": sum(u in first_hit for u in users)}
    lat = [(pd.Timestamp(first_hit[u]) - pd.Timestamp(first_mal[u])).days for u in first_hit]
    trig = {}
    for name, mask in (("band_only", mo["by_band"] & ~mo["by_top_k"]), ("top_k_only", ~mo["by_band"] & mo["by_top_k"]),
                       ("both", mo["by_band"] & mo["by_top_k"])):
        g = mo[mask.to_numpy()]
        trig[name] = {"member_days": int(len(g)), "malicious": int(((g["y"] == 1) & ~g["ex"]).sum()),
                      "excluded": int(g["ex"].sum())}
    fa = open_a.loc[kinds[kinds == "benign"].index]
    fa_top = Counter(x for x in fa["top_feature"] if isinstance(x, str) and x)
    per_day = pd.Series(0, index=sorted(set(val_days.astype(str))), dtype="int64")
    if len(open_a):
        per_day = per_day.add(open_a["peak_date"].astype(str).value_counts(), fill_value=0).astype("int64")
    n_open = int(len(open_a))
    n_mal = int((kinds == "malicious").sum())
    n_ex = int((kinds == "excluded").sum())
    return {
        "open_alerts": n_open, "suppressed_alerts": int((a["status"] == "suppressed").sum()),
        "open_alerts_containing_a_malicious_day": n_mal, "open_alerts_excluded_masquerade_only": n_ex,
        "alert_precision": (n_mal / (n_open - n_ex)) if (n_open - n_ex) else None,
        "open_alerts_per_day": {"median": float(per_day.median()), "p95": float(per_day.quantile(0.95)),
                                "max": int(per_day.max()), "days": int(len(per_day))} if len(per_day) else {},
        "malicious_days_by_scenario": by_scen,
        "insiders_caught_by_scenario": caught,
        "latency_days": {"median": float(np.median(lat)), "max": int(max(lat))} if lat else None,
        "member_days_by_trigger": trig,
        "false_alarm_alerts": {"count": int(len(fa)), "top_factor_counts": dict(fa_top.most_common(8)),
                               "led_by_usb_disconnect_count": int(fa_top.get(USB_FACTOR, 0))},
        "insiders_whose_only_alerts_were_suppressed": sorted(
            {u for u, d in covered_any if u not in first_hit and positives.get((u, d)) is not None}),
    }


def _parse_args(argv):
    root = repo_root()
    p = argparse.ArgumentParser(description="CIRA Chapter 12 validation readout (reads labels)")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "full"), choices=tuple(PROFILE_OUTPUT))
    p.add_argument("--alert-run-id", default=None)
    p.add_argument("--part", default="validation")
    p.add_argument("--readout-path", default=str(root / "experiments" / READOUT_FILE))
    p.add_argument("--supersede", default=None, metavar="REASON")
    return p.parse_args(argv)


def run(args) -> dict:
    if args.part != "validation":
        raise ReadoutRefused("validation only; the alert policy is read on test in Chapter 16, once")
    path = Path(args.readout_path)
    previous = None
    if path.exists():
        if not args.supersede:
            raise ReadoutRefused(f"{path} exists: the readout is written once (use --supersede \"<reason>\")")
        previous = json.loads(path.read_text(encoding="utf-8"))
    processed = Path(args.processed_dir)
    run_dir = alert_run_dir(processed, args.alert_run_id, args.profile)
    meta = read_meta(run_dir)
    alerts = pd.read_parquet(run_dir / ALERTS_OUTPUT)
    members = pd.read_parquet(run_dir / MEMBERS_OUTPUT)
    policy = AlertPolicy.from_dict(meta["policy"])

    # the population the batch ranked, read again from the same risk run
    rdir = processed / "risk" / "chapter9" / meta["risk_run"]["cri_run_id"]
    risk = pd.read_parquet(rdir / RISK_OUTPUT, columns=["user_id", "date", "model_split", "anomaly_score", "cri_score",
                                                        "severity"])
    risk["user_id"] = risk["user_id"].astype("string").str.strip().str.casefold()
    risk["date"] = risk["date"].astype("string")
    if meta.get("rows_option") == "evaluation":
        risk = risk[risk["model_split"].astype(str) != "train"]
    risk = risk.sort_values(["user_id", "date"], kind="mergesort").reset_index(drop=True)
    val = risk[risk["model_split"].astype(str) == "validation"].reset_index(drop=True)
    if val.empty:
        raise ReadoutRefused(f"alert run {run_dir.name} covers no validation rows")
    labels = attach_labels(val[["user_id", "date"]], load_label_views(processed))
    lab = {_key(u, d): (int(y), int(s), bool(e)) for u, d, y, s, e in zip(
        val["user_id"], val["date"], labels["y_primary"], labels["scenario_primary"], labels["exclude_primary"])}

    policy_view = read_view(alerts, members, lab, val["date"])

    # the other ordering, recomputed label-free on the same population (N40)
    fm = load_feature_matrix(processed, args.profile)
    activity = aligned(fm.matrix[["user_id", "date", ACTIVITY_COLUMN]], risk[["user_id", "date"]],
                       "the feature matrix")[ACTIVITY_COLUMN].to_numpy(dtype="float64")
    other = AlertPolicy.from_dict({**policy.to_dict(),
                                   "ordering": "cri_score" if policy.ordering == "anomaly_score" else "anomaly_score"})
    trig = triggers(risk, other, activity)
    days = risk.assign(by_band=trig["by_band"].to_numpy(), by_top_k=trig["by_top_k"].to_numpy())[trig["triggered"].to_numpy()]
    top = dict(zip(zip(members["user_id"], members["date"]), members["top_feature"]))
    days = days.assign(top_feature=[top.get((u, d)) for u, d in zip(days["user_id"], days["date"])], techniques=None)
    oa, om = correlate(days.reset_index(drop=True), other)
    oa = deduplicate(oa, other)
    other_view = read_view(oa, om, lab, val["date"])
    other_view["note"] = ("recomputed from the same risk run with the other ordering; ATT&CK techniques are left out of the "
                          "deduplication signature here, so suppression can differ slightly")

    warnings = []
    for s, b in policy_view["malicious_days_by_scenario"].items():
        if b["only_in_suppressed_alert"]:
            warnings.append(f"scenario {s}: {b['only_in_suppressed_alert']} malicious days only in suppressed alerts")
    band_days = sum(v["member_days"] for k, v in policy_view["member_days_by_trigger"].items() if k in ("band_only", "both"))
    if band_days == 0:
        warnings.append("the band trigger never fired on validation; the policy is top-k only in practice")
    val_users = set(val["user_id"].astype(str))
    deferred = alerts[(alerts["status"] == "open") & alerts["user_id"].astype(str).isin(val_users)
                      & (alerts["explanation_status"] != "complete")]
    if len(deferred):
        warnings.append(f"{len(deferred)} open validation alerts have their peak explanation deferred")

    readout = {
        "chapter": 12, "part": "validation", "view": "primary (N1); masquerade account-days neither hit nor false alarm",
        "alert_run_id": run_dir.name, "policy": meta["policy"], "policy_hash": meta["policy_hash"],
        "served": meta.get("served"), "population": {"rows_option": meta.get("rows_option"),
                                                     "ranked_rows": int(len(risk)), "validation_rows": int(len(val))},
        "policy_view": {"ordering": policy.ordering, **policy_view},
        "other_ordering_view": {"ordering": other.ordering, **other_view},
        "guard": {**GUARD, "warnings": warnings},
        "caveats": ["validation only, one seed (N26); the daily top-k ranks validation and test users together, so a "
                    "validation alert depends on test users' scores that day",
                    "scenario 2 dominates day counts (N15); six scenario-1 insiders cannot settle a scenario claim",
                    "the queue ordering was chosen after the Chapter 9 and 10 validation readouts (validation-informed)",
                    "a factor or technique matching a public scenario description is partly by construction (N41)"],
        "written_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if previous is not None:
        readout["supersedes"] = {"reason": args.supersede, "previous": previous}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(readout, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)
    append_experiment_runlog({"stage": "chapter12_validation_readout", "alert_run_id": run_dir.name,
                              "profile": args.profile, "guard_warnings": len(warnings), "output": str(path)})
    for name, v in (("policy", policy_view), ("other ordering", other_view)):
        print(f"[readout] {name}: {v['open_alerts']} open validation alerts, {v['open_alerts_containing_a_malicious_day']} "
              f"with a malicious day; caught {v['insiders_caught_by_scenario']}", flush=True)
    for w in warnings:
        print(f"[readout] WARN {GUARD['version']}: {w}", flush=True)
    print(f"[readout] written: {path}", flush=True)
    return readout


def main(argv=None) -> int:
    args = _parse_args(argv)
    try:
        run(args)
    except (ReadoutRefused, AlertSourceError) as exc:
        print(f"chapter12 readout refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
