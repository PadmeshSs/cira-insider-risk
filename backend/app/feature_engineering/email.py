from __future__ import annotations
import re
import pandas as pd
from .common import off_hours, ratio

_ADDR_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

def _addresses(value: str) -> list[str]:
    return [x.casefold() for x in _ADDR_RE.findall(value or "")]

def aggregate(df: pd.DataFrame, directory: dict[str, str]) -> pd.DataFrame:
    x = df.copy()
    own = set(directory)
    x["to_list"] = x["to"].map(_addresses)
    x["cc_list"] = x["cc"].map(_addresses)
    x["bcc_list"] = x["bcc"].map(_addresses)
    x["all_recips"] = [a+b+c for a,b,c in zip(x["to_list"], x["cc_list"], x["bcc_list"])]
    x["recipient_count"] = x["all_recips"].map(len).astype("int16")
    x["external_recipient_count"] = x["all_recips"].map(lambda vals: sum(a not in own for a in vals)).astype("int16")
    x["external_sender"] = ~x["from"].isin(own)
    x["off"] = off_hours(x["hour"])
    g = x.groupby(["user_id", "date_day"], observed=True)
    out = g.agg(
        emails_sent=("event_id", "size"),
        email_recipient_count=("recipient_count", "sum"),
        email_external_recipient_count=("external_recipient_count", "sum"),
        email_cc_count=("cc_list", lambda s: sum(bool(v) for v in s)),
        email_bcc_count=("bcc_list", lambda s: sum(bool(v) for v in s)),
        email_attachment_count=("attachments", "sum"),
        email_total_size=("size", "sum"),
        email_external_sender_count=("external_sender", "sum"),
        email_off_hours_count=("off", "sum"),
    ).reset_index().rename(columns={"date_day": "date"})
    out["external_email_ratio"] = ratio(out["email_external_recipient_count"], out["email_recipient_count"])
    out["email_external_sender_ratio"] = ratio(out["email_external_sender_count"], out["emails_sent"])
    out["email_attachment_avg"] = ratio(out["email_attachment_count"], out["emails_sent"])
    out["email_off_hours_ratio"] = ratio(out["email_off_hours_count"], out["emails_sent"])
    return out
