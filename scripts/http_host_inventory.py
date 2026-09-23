"""Label-blind HTTP host inventory for reviewing network_domains.py.

Reads ONLY the Stage 0 Parquet tree (never ground truth) and writes the most
frequent hosts with request and user counts, plus the category each host
currently falls into.  Review categories against this list by what a host
*is*, never by who visited it.

Usage:
    python scripts/http_host_inventory.py --profile mid --top 500
Output: experiments/http_host_inventory_<profile>.csv
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.feature_engineering.common import host_matches  # noqa: E402
from app.feature_engineering.network_domains import HOST_CATEGORIES  # noqa: E402


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "dev"))
    p.add_argument("--top", type=int, default=500)
    args = p.parse_args()

    root = Path(args.processed_dir) / "events" / f"profile={args.profile}" / "source_type=http"
    requests: dict[str, int] = {}
    users: dict[str, set] = {}
    for path in sorted(root.rglob("*.parquet")):
        df = pd.read_parquet(path, columns=["user_id", "host"])
        for host, n in df["host"].value_counts().items():
            requests[host] = requests.get(host, 0) + int(n)
        for host, grp in df.groupby("host", observed=True)["user_id"]:
            users.setdefault(host, set()).update(grp.unique())

    table = pd.DataFrame({"host": list(requests), "requests": list(requests.values())})
    table["distinct_users"] = table["host"].map(lambda h: len(users.get(h, ())))
    table["category"] = table["host"].map(
        lambda h: ",".join(name for name, sfx in HOST_CATEGORIES.items() if host_matches(h, sfx)) or ""
    )
    table = table.sort_values("requests", ascending=False).head(args.top)
    out = ROOT / "experiments" / f"http_host_inventory_{args.profile}.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    table.to_csv(out, index=False)
    print(f"wrote {len(table)} hosts -> {out}")


if __name__ == "__main__":
    main()
