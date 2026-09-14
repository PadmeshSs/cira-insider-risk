"""Run the Chapter 4 acceptance check against a CERT sample.

Usage:
    PYTHONPATH=backend python backend/scripts/chapter4_smoke.py \
        --cert-root datasets/raw/cert_r4.2 \
        --rows-per-domain 25
"""
from __future__ import annotations

import argparse
from pathlib import Path

from app.ingestion.cert_loader import load_cert_sample
from app.preprocessing.normalize import normalize_and_persist


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert-root", type=Path, required=True)
    parser.add_argument("--rows-per-domain", type=int, default=25)
    parser.add_argument("--source-timezone", default="UTC")
    parser.add_argument("--target-timezone", default="UTC")
    parser.add_argument(
        "--normalized-output",
        type=Path,
        default=Path("datasets/processed/normalized_events.jsonl"),
    )
    parser.add_argument(
        "--rejected-output",
        type=Path,
        default=Path("datasets/processed/rejected_records.jsonl"),
    )
    args = parser.parse_args()

    samples = load_cert_sample(
        args.cert_root,
        rows_per_domain=args.rows_per_domain,
    )

    events = [
        event
        for domain_events in samples.values()
        for event in domain_events
    ]

    report = normalize_and_persist(
        events,
        normalized_path=args.normalized_output,
        rejected_path=args.rejected_output,
        source_timezone=args.source_timezone,
        target_timezone=args.target_timezone,
    )

    print("Chapter 4 normalization report")
    print("------------------------------")
    for key, value in report.summary().items():
        print(f"{key:>10}: {value}")

    print(f"normalized: {args.normalized_output}")
    print(f"rejected:   {args.rejected_output}")

    if report.rejected:
        print("\nRejected records:")
        for rejected in report.rejected[:10]:
            print(f"- {rejected.reason_code}: {rejected.reason}")

    if report.accepted_count == 0:
        print("\nFAIL: no accepted events.")
        return 1

    if any(event.timestamp is not None and event.timestamp.tzinfo is None
           for event in report.accepted):
        print("\nFAIL: a normalized timestamp is timezone-naive.")
        return 1

    print("\nPASS: accepted events are schema-valid and timezone-aware.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
