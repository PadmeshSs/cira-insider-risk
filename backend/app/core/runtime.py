"""Runtime resource guards (HCEA v1.0, rule R6).

Call ``apply_thread_caps()`` at the very top of every heavy entry point,
before numpy / scikit-learn / torch are imported, so BLAS and OpenMP pools
never grab every logical core on the development laptop.
"""
from __future__ import annotations

import os

_THREAD_VARS = (
    "OMP_NUM_THREADS",
    "MKL_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
    "VECLIB_MAXIMUM_THREADS",
)


def max_workers() -> int:
    """Worker/thread cap from CIRA_MAX_WORKERS (default 6, per HCEA §1.2)."""
    try:
        value = int(os.getenv("CIRA_MAX_WORKERS", "6"))
    except ValueError:
        value = 6
    return max(1, value)


def apply_thread_caps() -> int:
    """Set thread-pool environment caps. Existing explicit values win."""
    workers = max_workers()
    for name in _THREAD_VARS:
        os.environ.setdefault(name, str(workers))

    # torch is optional here; only cap it if it is already importable.
    try:  # pragma: no cover - depends on local install
        import torch

        torch.set_num_threads(workers)
    except Exception:
        pass

    return workers
