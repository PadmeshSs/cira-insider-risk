"""Build CERT r4.2 evaluation label tables (evaluation-only, HCEA §3.4).

Writes <CERT_PROCESSED_DIR>/labels/insider_events.parquet and
insider_user_days.parquet from the event-level answer files in
<CERT_GROUND_TRUTH_DIR>/r4.2-{1,2,3}/.  The feature pipeline never reads this
tree; labels are joined to features only inside the Chapter 6+ evaluation code.

Usage (from the repo root, with .env loaded or flags given):
    python scripts/build_labels.py
    python scripts/build_labels.py --ground-truth-dir D:/CIRA_dataset/datasets/ground_truth/cert_r4.2 \
                                   --processed-dir   D:/CIRA_dataset/datasets/processed
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.ingestion.ground_truth import build_insider_label_tables  # noqa: E402

EXPECTED_EVENTS = 7_323   # Bible Chapter 3 / HCEA §3.2 (released r4.2 ground truth)
EXPECTED_USERS = 70


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--ground-truth-dir", default=os.getenv("CERT_GROUND_TRUTH_DIR"), required=os.getenv("CERT_GROUND_TRUTH_DIR") is None)
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    args = p.parse_args()
    summary = build_insider_label_tables(args.ground_truth_dir, args.processed_dir)
    summary["expected_events"] = EXPECTED_EVENTS
    summary["expected_users"] = EXPECTED_USERS
    summary["matches_published_counts"] = (
        summary["malicious_events"] == EXPECTED_EVENTS and summary["insider_users"] == EXPECTED_USERS
    )
    print(json.dumps(summary, indent=2))
    if not summary["matches_published_counts"]:
        print("WARNING: counts differ from the published r4.2 figures; investigate before Chapter 6.", file=sys.stderr)


if __name__ == "__main__":
    main()
