"""Alerts to Parquet (Bible Ch12 steps 1, 2 and 4; HCEA §12).

Usage, from backend/ with .env loaded, after Chapters 8-11 on the profile:

    python -m app.alerts.batch --profile full
    python -m app.alerts.batch --profile full --rows all        # include in-sample rows (never as examples, N31)

What it does
    1. Thread caps before numpy (N8).
    2. Lineage before anything is computed. The explain run (default: newest
       for the profile) names the Chapter 8 batch and the CRI run it
       explained; alerts are built from exactly those, so the score an alert
       shows and the explanation it carries come from one run (N50). Refuses
       if the model served now is not the one that scored (N28, N30), if the
       CRI run is an ablation variant or from another batch or
       model_version (N29, N33), or if the matrix changed (fingerprint).
    3. Candidate rows: every scored user-day of the run's population
       (default ``evaluation``: the served model's validation and test users,
       because training rows are in-sample and would take the daily top-k
       slots, N31). Shadow rows never enter (N32): the CRI run holds served
       rows only, and this is checked.
    4. Triggers (policy.py), correlation (correlation.py), deduplication
       (deduplication.py).
    5. Every member day explained through the Chapter 11 builder (explain.py,
       N50) and flattened into AlertReason rows.
    6. The D-6 demo sample (demo.py).
    7. Writes ``<processed>/alerts/chapter12/<alert_run_id>/`` atomically and
       one ``chapter12_alert_batch`` runlog line (R8).

Label-free (N5). No database is touched here; ``python -m app.alerts.load``
does the bounded PostgreSQL load (D-6) from this run.
"""
from __future__ import annotations

from app.core.runtime import apply_thread_caps

apply_thread_caps()

import argparse  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402
from collections import Counter  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
from pathlib import Path  # noqa: E402

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import pyarrow.parquet as pq  # noqa: E402

from app.cri.sources import RISK_META, RISK_OUTPUT, SourceError, chapter8_batch  # noqa: E402
from app.explainability.sources import (  # noqa: E402
    ATTRIBUTIONS_OUTPUT,
    KERNEL_OUTPUT,
    SUMMARY_OUTPUT,
    ExplainSourceError,
    aligned,
    explain_run_dir,
)
from app.explainability.sources import read_meta as read_explain_meta  # noqa: E402
from app.feature_engineering.common import append_experiment_runlog, atomic_to_parquet, memory_rss_mb  # noqa: E402
from app.scoring.serving_config import resolve_serving_config  # noqa: E402
from app.tabnet.dataset import PROFILE_OUTPUT, feature_fingerprint, load_feature_matrix  # noqa: E402

from . import ALERTS_VERSION  # noqa: E402
from .correlation import correlate  # noqa: E402
from .deduplication import deduplicate  # noqa: E402
from .demo import demo_sample  # noqa: E402
from .explain import explain_members, reasons_frame  # noqa: E402
from .policy import ACTIVITY_COLUMN, SEVERITY_RANK, AlertPolicy, AlertPolicyError, triggers  # noqa: E402
from .sources import (  # noqa: E402
    ALERT_META,
    ALERTS_OUTPUT,
    DEMO_OUTPUT,
    EXPLANATIONS_OUTPUT,
    MEMBERS_OUTPUT,
    REASONS_OUTPUT,
)

RISK_READ = ("user_id", "date", "model_split", "model_name", "model_version", "registry_version", "anomaly_score",
             "cri_score", "severity", "missing_components", "historical_top_feature", "peer_top_feature", "role",
             "cri_version", "cri_config_hash", "cri_variant", "calibration_id", "cri_run_id", "source_batch_run_id")
MITRE_READ = ["mitre_status", "mitre_context", "mitre_unmapped_behaviours", "mitre_techniques"]
USB_FACTOR = "usb_disconnect_count"


class AlertBatchRefused(RuntimeError):
    """Nothing was written."""


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    d = AlertPolicy()
    p = argparse.ArgumentParser(description="CIRA Chapter 12 alert batch (label-free)")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "full"), choices=tuple(PROFILE_OUTPUT))
    p.add_argument("--explain-run-id", default=None, help="Chapter 11 explain run (default: newest for the profile)")
    p.add_argument("--rows", default="evaluation", choices=("evaluation", "all"))
    p.add_argument("--band", default=",".join(d.band_severities), help="severities that trigger ('' = no band trigger)")
    p.add_argument("--top-k-per-day", type=int, default=d.top_k_per_day, help="0 = no daily budget trigger")
    p.add_argument("--ordering", default=d.ordering, choices=("anomaly_score", "cri_score"))
    p.add_argument("--gap-days", type=int, default=d.correlation_gap_days)
    p.add_argument("--max-span-days", type=int, default=d.max_span_days)
    p.add_argument("--cooldown-days", type=int, default=d.cooldown_days)
    p.add_argument("--demo-window-days", type=int, default=30)
    p.add_argument("--demo-users", type=int, default=20)
    p.add_argument("--demo-alerting-users", type=int, default=10)
    p.add_argument("--allow-inactive-top-k", action="store_true",
                   help="let a user-day with no recorded event take a daily top-k slot (an override)")
    p.add_argument("--seed", type=int, default=int(os.getenv("CIRA_SEED", "42")))
    return p.parse_args(argv)


def policy_from_args(args) -> AlertPolicy:
    band = tuple(s.strip().upper() for s in str(args.band).split(",") if s.strip())
    return AlertPolicy(band_severities=band, top_k_per_day=args.top_k_per_day, ordering=args.ordering,
                       correlation_gap_days=args.gap_days, max_span_days=args.max_span_days,
                       cooldown_days=args.cooldown_days, tie_break_seed=args.seed,
                       require_activity=not args.allow_inactive_top_k)


def daily_counts(dates_universe: pd.Series, dates: pd.Series) -> dict:
    """Items per calendar day over every day in the universe (days with none count as 0)."""
    per = pd.Series(0, index=sorted(set(dates_universe.astype(str))), dtype="int64")
    if len(dates):
        c = dates.astype(str).value_counts()
        per = per.add(c, fill_value=0).astype("int64")
    if per.empty:
        return {"days": 0}
    return {"days": int(len(per)), "total": int(per.sum()), "mean": float(per.mean()), "median": float(per.median()),
            "p95": float(per.quantile(0.95)), "max": int(per.max()), "days_with_none": int((per == 0).sum())}


def lineage(processed: Path, args) -> dict:
    """Resolve and cross-check the runs an alert run is built from. Refuses on any mismatch."""
    try:
        edir = explain_run_dir(processed, args.explain_run_id, args.profile)
    except ExplainSourceError as exc:
        raise AlertBatchRefused(str(exc)) from exc
    em = read_explain_meta(edir)
    if em.get("profile") != args.profile:
        raise AlertBatchRefused(f"explain run {edir.name} is profile {em.get('profile')!r}, not {args.profile!r}")
    served = em.get("served") or {}
    cfg = resolve_serving_config()
    if cfg.served is None:
        raise AlertBatchRefused(f"no served model: {cfg.problem}")
    if (cfg.served.model_name, cfg.served.registry_version) != (served.get("model_name"), served.get("registry_version")):
        raise AlertBatchRefused(f"the served model is {cfg.served.model_name}:{cfg.served.registry_version}, explain run "
                                f"{edir.name} explains {served.get('model_name')}:{served.get('registry_version')}; alerts "
                                "come from the model served now and its own explanations (N28, N30)")
    batch = chapter8_batch(processed, (em.get("source_batch") or {}).get("batch_run_id"), args.profile)
    b = batch.served
    if (b.get("model_name"), b.get("model_version")) != (served.get("model_name"), served.get("model_version")):
        raise AlertBatchRefused(f"batch {batch.batch_run_id} was scored by {b.get('model_version')}, the explain run "
                                f"explains {served.get('model_version')}")
    cri_run_id = (em.get("risk_run") or {}).get("cri_run_id")
    rdir = processed / "risk" / "chapter9" / str(cri_run_id)
    if not (rdir / RISK_META).exists() or not (rdir / RISK_OUTPUT).exists():
        raise AlertBatchRefused(f"CRI run {cri_run_id} named by explain run {edir.name} is missing")
    rm = json.loads((rdir / RISK_META).read_text(encoding="utf-8"))
    if rm.get("variant") != "default" or (rm.get("config") or {}).get("disabled"):
        raise AlertBatchRefused(f"CRI run {rdir.name} is variant {rm.get('variant')!r}; alerts use the configured CRI")
    if (rm.get("source_batch") or {}).get("batch_run_id") != batch.batch_run_id:
        raise AlertBatchRefused(f"CRI run {rdir.name} was computed from another batch (N50: one explanation, one score)")
    if (rm.get("served") or {}).get("model_version") != served.get("model_version"):
        raise AlertBatchRefused(f"CRI run {rdir.name} belongs to another model_version (N29, N33)")
    fm = load_feature_matrix(processed, args.profile)
    fp = feature_fingerprint(fm.features_path)
    for what, other in (("explain run", (em.get("features") or {}).get("fingerprint")),
                        ("batch", (batch.meta.get("features") or {}).get("fingerprint")),
                        ("CRI run", (rm.get("features") or {}).get("fingerprint"))):
        if other != fp:
            raise AlertBatchRefused(f"the {what} was made from another matrix (fingerprint {other}, matrix now {fp})")
    return {"explain_dir": edir, "explain_meta": em, "served": served, "batch": batch, "risk_dir": rdir,
            "risk_meta": rm, "fm": fm, "fingerprint": fp, "serving_source": cfg.source}


def _mitre(processed: Path, risk_meta: dict, keys: pd.DataFrame):
    block = risk_meta.get("mitre")
    if not block:
        reason = (risk_meta.get("unavailable_components") or {}).get("mitre_context") or "no enrichment run joined"
        return None, None, reason, None
    from app.mitre.sources import MATCHES_OUTPUT, MitreSourceError, mitre_run_dir, read_context

    try:
        mdir = mitre_run_dir(processed, block["mitre_run_id"])
        ctx = read_context(mdir, keys, MITRE_READ)
    except MitreSourceError as exc:
        raise AlertBatchRefused(f"the CRI run names enrichment run {block.get('mitre_run_id')}: {exc}") from exc
    matches = pd.read_parquet(mdir / MATCHES_OUTPUT)
    matches["user_id"] = matches["user_id"].astype("string").str.strip().str.casefold()
    matches["date"] = matches["date"].astype("string")
    return ctx, matches, None, {"mitre_run_id": mdir.name, **{k: block.get(k) for k in (
        "ruleset_version", "ruleset_hash", "attack_version", "reference_id")}}


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("".join(json.dumps(r, sort_keys=True, default=str) + "\n" for r in rows), encoding="utf-8")
    tmp.replace(path)


def load_candidates(processed: Path, L: dict, rows_option: str) -> dict:
    """The ranked population and everything a trigger or an explanation reads, aligned to it (label-free)."""
    served, rdir, fm = L["served"], L["risk_dir"], L["fm"]
    cols = [c for c in pq.read_schema(rdir / RISK_OUTPUT).names
            if c in RISK_READ or c.startswith(("points_", "component_"))]
    risk = pd.read_parquet(rdir / RISK_OUTPUT, columns=cols)
    risk["user_id"] = risk["user_id"].astype("string").str.strip().str.casefold()
    risk["date"] = risk["date"].astype("string")
    if set(risk["model_version"].astype(str)) != {served["model_version"]}:
        raise AlertBatchRefused("the CRI run holds rows of another model_version (N32, N33)")
    if rows_option == "evaluation":
        risk = risk[risk["model_split"].astype(str) != "train"]
    risk = risk.sort_values(["user_id", "date"], kind="mergesort").reset_index(drop=True)
    if risk.empty:
        raise AlertBatchRefused("no candidate rows")
    risk["cri_run_id"] = rdir.name
    summary = pd.read_parquet(L["explain_dir"] / SUMMARY_OUTPUT,
                              columns=["user_id", "date", "top_feature", "model_version", "raw_score", "expected_value",
                                       "anomaly_score"])
    try:
        top = aligned(summary[["user_id", "date", "top_feature"]], risk[["user_id", "date"]],
                      f"explain run {L['explain_dir'].name}")
    except ExplainSourceError as exc:
        raise AlertBatchRefused(f"{exc}; re-run the explain batch with the same --rows") from exc
    if ACTIVITY_COLUMN not in fm.matrix.columns:
        raise AlertBatchRefused(f"the matrix has no {ACTIVITY_COLUMN} column; the policy needs it")
    activity = aligned(fm.matrix[["user_id", "date", ACTIVITY_COLUMN]], risk[["user_id", "date"]],
                       "the feature matrix")[ACTIVITY_COLUMN].to_numpy(dtype="float64")
    mctx, mmatch, mitre_reason, mitre_block = _mitre(processed, L["risk_meta"], risk[["user_id", "date"]])
    return {"risk": risk, "summary": summary, "top_feature": top["top_feature"].to_numpy(dtype=object),
            "activity": activity, "mitre_ctx": mctx, "mitre_matches": mmatch, "mitre_reason": mitre_reason,
            "mitre_block": mitre_block}


def build_alerts(C: dict, policy: AlertPolicy) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Triggers -> correlation -> deduplication. Returns (triggers, alerts, members)."""
    risk = C["risk"]
    trig = triggers(risk, policy, C["activity"])
    techniques = (C["mitre_ctx"]["mitre_techniques"].to_numpy(dtype=object) if C["mitre_ctx"] is not None
                  else np.full(len(risk), None, dtype=object))
    days = risk.assign(by_band=trig["by_band"].to_numpy(), by_top_k=trig["by_top_k"].to_numpy(),
                       top_feature=C["top_feature"], techniques=techniques)
    triggered = days[trig["triggered"].to_numpy()].reset_index(drop=True)
    alerts, members = correlate(triggered[["user_id", "date", "model_split", "anomaly_score", "cri_score", "severity",
                                           "by_band", "by_top_k", "top_feature", "techniques"]], policy)
    alerts = deduplicate(alerts, policy)
    members["alert_status"] = members["alert_key"].map(dict(zip(alerts["alert_key"], alerts["status"])))
    return trig, alerts, members


def build_member_explanations(L: dict, C: dict, members: pd.DataFrame) -> list[dict]:
    """Every member day through the Chapter 11 builder, from the stored attributions (N50)."""
    risk, fm, rm = C["risk"], L["fm"], L["risk_meta"]
    if members.empty:
        return []
    mkeys = members[["user_id", "date"]]
    member_risk = aligned(risk, mkeys, f"CRI run {L['risk_dir'].name}")
    detail_cols = [c for c in fm.matrix.columns if str(c).startswith(("hist_z_", "peer_dev_"))]
    detail = aligned(fm.matrix[["user_id", "date", *detail_cols]], mkeys, "the feature matrix")[detail_cols]
    mctx = None
    if C["mitre_ctx"] is not None:
        mctx = aligned(C["mitre_ctx"].assign(user_id=risk["user_id"].to_numpy(), date=risk["date"].to_numpy()), mkeys,
                       "the enrichment context")
    want = set(zip(mkeys["user_id"].astype(str), mkeys["date"].astype(str)))
    summary = C["summary"]
    msum = summary[[k in want for k in zip(summary["user_id"].astype(str), summary["date"].astype(str))]]
    import pyarrow.dataset as pads

    users = sorted({u for u, _ in want})
    mattr = pads.dataset(L["explain_dir"] / ATTRIBUTIONS_OUTPUT).to_table(filter=pads.field("user_id").isin(users)).to_pandas()
    mattr = mattr[[k in want for k in zip(mattr["user_id"].astype(str), mattr["date"].astype(str))]]
    kpath = L["explain_dir"] / KERNEL_OUTPUT
    kernel = pd.read_parquet(kpath) if kpath.exists() else None
    unavailable = dict(rm.get("unavailable_components") or {})
    unavailable.pop("mitre_context", None)
    method = (L["explain_meta"].get("explainer") or {}).get("method") or "treeshap"
    return explain_members(members, summary=msum, attributions=mattr, served=L["served"], method=method,
                           explain_run_id=L["explain_dir"].name, risk=member_risk, detail=detail, mitre_ctx=mctx,
                           mitre_matches=C["mitre_matches"], mitre_reason=C["mitre_reason"], unavailable=unavailable,
                           kernel=kernel)


def run(args: argparse.Namespace) -> dict:
    started = time.perf_counter()
    try:
        policy = policy_from_args(args)
    except AlertPolicyError as exc:
        raise AlertBatchRefused(str(exc)) from exc
    processed = Path(args.processed_dir)
    L = lineage(processed, args)
    em, served, rdir, rm, fm = L["explain_meta"], L["served"], L["risk_dir"], L["risk_meta"], L["fm"]
    explain_id = L["explain_dir"].name
    C = load_candidates(processed, L, args.rows)
    risk, activity, mitre_block, mitre_reason = C["risk"], C["activity"], C["mitre_block"], C["mitre_reason"]

    t0 = time.perf_counter()
    trig, alerts, members = build_alerts(C, policy)
    correlate_seconds = time.perf_counter() - t0

    t1 = time.perf_counter()
    explanations = build_member_explanations(L, C, members)
    reasons = reasons_frame(explanations)
    status_by = {(e["user_id"], e["date"]): e["status"] for e in explanations}
    members["explanation_status"] = [status_by.get((str(u), str(d))) for u, d in zip(members["user_id"], members["date"])]
    peak_status = members[members["is_peak"]].set_index("alert_key")["explanation_status"]
    alerts["explanation_status"] = alerts["alert_key"].map(peak_status)
    method = (em.get("explainer") or {}).get("method") or "treeshap"
    explain_seconds = time.perf_counter() - t1

    # --- demo sample (D-6) ---------------------------------------------------
    demo, demo_info = demo_sample(risk[["user_id", "date", "model_split"]], alerts, window_days=args.demo_window_days,
                                  max_users=args.demo_users, max_alerting_users=args.demo_alerting_users, seed=args.seed)

    # --- write ------------------------------------------------------------
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}-{args.profile}-alerts"
    out_dir = processed / "alerts" / "chapter12" / run_id
    lineage_cols = {"alert_run_id": run_id, "policy_version": policy.to_dict()["version"], "policy_hash": policy.policy_hash,
                    "model_version": served["model_version"], "batch_run_id": L["batch"].batch_run_id,
                    "cri_run_id": rdir.name, "explain_run_id": explain_id,
                    "mitre_run_id": None if mitre_block is None else mitre_block["mitre_run_id"]}
    atomic_to_parquet(alerts.assign(**lineage_cols), out_dir / ALERTS_OUTPUT)
    atomic_to_parquet(members.assign(alert_run_id=run_id), out_dir / MEMBERS_OUTPUT)
    atomic_to_parquet(reasons.assign(alert_run_id=run_id), out_dir / REASONS_OUTPUT)
    atomic_to_parquet(demo.assign(alert_run_id=run_id), out_dir / DEMO_OUTPUT)
    _write_jsonl(out_dir / EXPLANATIONS_OUTPUT, explanations)

    # --- summary (label-free) ----------------------------------------------
    open_a = alerts[alerts["status"] == "open"]
    universe = risk["date"]
    alt_ordering = "cri_score" if policy.ordering == "anomaly_score" else "anomaly_score"
    alt = triggers(risk, AlertPolicy.from_dict({**policy.to_dict(), "ordering": alt_ordering}), activity)
    alt_act = triggers(risk, AlertPolicy.from_dict({**policy.to_dict(), "require_activity": not policy.require_activity}),
                       activity)
    changed = (alt_act["by_top_k"] != trig["by_top_k"]).to_numpy()
    inactive = np.nan_to_num(activity, nan=0.0) <= 0
    top_counts = Counter(x for x in open_a["top_feature"] if x)
    stats = {
        "candidate_rows": int(len(risk)),
        "candidate_rows_by_model_split": {k: int(v) for k, v in risk["model_split"].astype(str).value_counts().sort_index().items()},
        "triggered_user_days": int(trig["triggered"].sum()),
        "triggered_by": {"band": int(trig["by_band"].sum()), "top_k": int(trig["by_top_k"].sum()),
                         "both": int((trig["by_band"] & trig["by_top_k"]).sum())},
        "triggered_with_no_recorded_activity": int((trig["triggered"].to_numpy() & inactive).sum()),
        "alerts": int(len(alerts)), "open_alerts": int(len(open_a)),
        "suppressed_alerts": int((alerts["status"] == "suppressed").sum()),
        "member_days": int(len(members)),
        "member_days_in_suppressed_alerts": int((members["alert_status"] == "suppressed").sum()),
        "open_alerts_by_model_split": {k: int(v) for k, v in open_a["model_split"].astype(str).value_counts().sort_index().items()},
        "open_alerts_by_max_severity": {s: int((open_a["max_severity"] == s).sum()) for s in SEVERITY_RANK},
        "open_alert_days": {k: int(v) for k, v in open_a["n_days"].value_counts().sort_index().items()},
        "daily_volume": {
            "open_alerts_by_peak_date": daily_counts(universe, open_a["peak_date"]),
            "triggered_by_band": daily_counts(universe, risk.loc[trig["by_band"].to_numpy(), "date"]),
            "triggered_by_top_k": daily_counts(universe, risk.loc[trig["by_top_k"].to_numpy(), "date"]),
        },
        "other_ordering_view": {
            "ordering": alt_ordering,
            "triggered_user_days": int(alt["triggered"].sum()),
            "top_k_user_days": int(alt["by_top_k"].sum()),
            "top_k_same_user_day": int((alt["by_top_k"] & trig["by_top_k"]).sum()),
            "top_k_only_under_other_ordering": int((alt["by_top_k"] & ~trig["by_top_k"]).sum()),
            "note": "label-free: what the other ordering would have put in the daily top-k (N40); the readout reads both",
        },
        "activity_rule_view": {
            "require_activity": not policy.require_activity,
            "top_k_user_days_changed": int(changed.sum()),
            "top_k_dates_changed": int(risk.loc[changed, "date"].nunique()),
            "note": "label-free: user-days whose top-k status differs with the require_activity rule flipped "
                    "(a changed slot counts twice: the day that loses it and the day that takes it), and the "
                    "dates on which the slot changes (N56)",
        },
        "open_alert_top_factor": dict(top_counts.most_common(10)),
        "open_alerts_led_by_usb_disconnect_count": int(top_counts.get(USB_FACTOR, 0)),
        "open_alerts_with_no_raising_factor": int(open_a["top_feature"].isna().sum()),
        "explanation_status": {k: int(v) for k, v in members["explanation_status"].value_counts().items()},
        "reason_rows_by_section": {k: int(v) for k, v in reasons["section"].value_counts().items()},
        "demo_rows": int(len(demo)),
    }
    meta = {
        "chapter": 12, "alerts_version": ALERTS_VERSION, "alert_run_id": run_id, "profile": args.profile,
        "reportable": args.profile != "dev", "rows_option": args.rows,
        "policy": policy.to_dict(), "policy_hash": policy.policy_hash, "policy_overrides": policy.overrides(),
        "queue": {"ordering": policy.ordering, "context": "CRI score and severity band shown next to the queue score (N40)",
                  "validation_informed": True,
                  "why": "highest validation PR-AUC of the three orderings (N40, N46); no ordering dominates on insiders caught"},
        "demo_sample": demo_info,
        "served": served, "serving_source": L["serving_source"],
        "explain_run": {"explain_run_id": explain_id, "method": method, "rows_option": em.get("rows_option")},
        "source_batch": {"batch_run_id": L["batch"].batch_run_id, "path": str(L["batch"].path)},
        "risk_run": {"cri_run_id": rdir.name, "formula_hash": rm.get("formula_hash"), "config_hash": rm.get("config_hash"),
                     "calibration_id": (rm.get("calibration") or {}).get("calibration_id"),
                     "with_mitre": bool(rm.get("mitre"))},
        "mitre": mitre_block, "mitre_unavailable_reason": mitre_reason,
        "unavailable_components": rm.get("unavailable_components") or {},
        "features": {"path": str(fm.features_path), "fingerprint": L["fingerprint"]},
        "summary": stats,
        "shadow": "never read: shadow scores feed no alert (N32)",
        "note": "rows tagged model_split=train are in-sample (N31); nothing here is a detection number",
        "outputs": {n: str(out_dir / n) for n in (ALERTS_OUTPUT, MEMBERS_OUTPUT, REASONS_OUTPUT, EXPLANATIONS_OUTPUT,
                                                  DEMO_OUTPUT)},
        "correlate_seconds": round(correlate_seconds, 2), "explain_seconds": round(explain_seconds, 2),
        "wall_seconds": round(time.perf_counter() - started, 2), "peak_rss_mb": round(memory_rss_mb(), 1),
    }
    tmp = out_dir / (ALERT_META + ".tmp")
    tmp.write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")
    tmp.replace(out_dir / ALERT_META)
    append_experiment_runlog({
        "stage": "chapter12_alert_batch", "alert_run_id": run_id, "profile": args.profile, "reportable": meta["reportable"],
        "policy_version": policy.to_dict()["version"], "policy_hash": policy.policy_hash,
        "policy_overrides": meta["policy_overrides"], "served_model_version": served.get("model_version"),
        "explain_run_id": explain_id, "cri_run_id": rdir.name, "rows_option": args.rows,
        "alerts": stats["alerts"], "open_alerts": stats["open_alerts"], "suppressed_alerts": stats["suppressed_alerts"],
        "member_days": stats["member_days"], "explanation_status": stats["explanation_status"],
        "demo_rows": stats["demo_rows"], "wall_seconds": meta["wall_seconds"], "peak_rss_mb": meta["peak_rss_mb"],
    })
    v = stats["daily_volume"]["open_alerts_by_peak_date"]
    print(f"[alerts] {run_id}: {stats['triggered_user_days']} triggered user-days (band {stats['triggered_by']['band']}, "
          f"top-{policy.top_k_per_day} {stats['triggered_by']['top_k']}) -> {stats['open_alerts']} open alerts, "
          f"{stats['suppressed_alerts']} suppressed", flush=True)
    print(f"[alerts] open alerts per day: median {v.get('median')}, p95 {v.get('p95')}, max {v.get('max')}; "
          f"led by {USB_FACTOR}: {stats['open_alerts_led_by_usb_disconnect_count']} (N52)", flush=True)
    print(f"[alerts] explanations: {stats['explanation_status']}; demo sample {stats['demo_rows']} user-days", flush=True)
    if meta["policy_overrides"]:
        print(f"[alerts] note: policy differs from {policy.to_dict()['version']} defaults: {meta['policy_overrides']}", flush=True)
    print(f"[alerts] written: {out_dir}", flush=True)
    return meta


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        run(args)
    except (AlertBatchRefused, ExplainSourceError, SourceError) as exc:
        print(f"chapter12 alert batch refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
