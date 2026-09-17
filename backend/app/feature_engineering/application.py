"""Application/process feature family.

CERT r4.2 contains no application/process source file.  The architecture
requires this module boundary, but the dataset context explicitly marks the
family unsupported, so it emits no fabricated columns.
"""
from __future__ import annotations
import pandas as pd

def aggregate(_: pd.DataFrame) -> pd.DataFrame:
    return pd.DataFrame(columns=["user_id", "date"])
