"""Run stamps that are never reused within a process (Chapter 15, C15-4).

Every pipeline entry point names its run ``<UTC second>-<suffix>``, e.g.
``20261006T093743Z-full-user-s42``, and writes into a folder of that name.
Two runs of the same kind started within one second used to get the same id
and the second silently overwrote the first's scores, metrics and runlog
identity. Chapter 15 caught it: test_ch7_runner failed whenever its second
training run (ablation or resume) started in the same second as the first.

``utc_run_stamp`` keeps the format and the ordering, and returns a stamp
strictly later than the last one it returned in this process, waiting for
the next second when needed (at most about one second per collision).
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timezone

FORMAT = "%Y%m%dT%H%M%SZ"
_lock = threading.Lock()
_last: str | None = None


def utc_run_stamp() -> str:
    """The current UTC second as ``YYYYMMDDTHHMMSSZ``, strictly later than any stamp issued before in this process."""
    global _last
    with _lock:
        while True:
            stamp = datetime.now(timezone.utc).strftime(FORMAT)
            if _last is None or stamp > _last:
                _last = stamp
                return stamp
            time.sleep(0.02)
