import json
r = json.load(open("experiments/chapter16_test_readout.json", encoding="utf-8"))
ex = r["experiments"]
v = ex["E1_alert_queue"]["views"]
print("E1 views:", list(v))
for n in ("policy_without_deduplication", "other_ordering", "other_ordering_without_deduplication"):
    b = v.get(n)
    if b:
        print(n, {k: b.get(k) for k in ("ordering", "open_alerts", "suppressed_alerts", "open_alerts_containing_a_malicious_day", "alert_precision")},
              "| insiders:", {s: f"{x['caught']}/{x['insiders']}" for s, x in b["insiders_caught_by_scenario"].items()},
              "| cov:", {s: (x["in_open_alert"], x["only_in_suppressed_alert"], x["in_no_alert"]) for s, x in b["coverage_by_scenario"].items()})
print("activity_rule:", v.get("activity_rule"))
e2 = ex["E2_explanations"]
print("E2 scenarios:", {s: b.get("top_factor_counts") for s, b in e2["malicious_days_by_scenario"].items()})
print("E2 false alarms top1:", e2["false_alarms_at_top1"])
print("E2 second model:", json.dumps(e2["second_model_view"], default=str)[:1500])
d = ex["D"]
print("D keys:", list(d))
print({k: d[k] for k in d if "benign" in k or "mapped" in k})