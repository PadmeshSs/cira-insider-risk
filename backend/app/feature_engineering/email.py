"""Email metadata features per user-day.

No NLP and no message-content features (Architecture §10.3, §47 rule 17):
the Stage 0 Parquet tree does not even carry the content column.

"Internal" means an address present in the LDAP email directory; an
external domain is any recipient domain not used by a directory address.

Chunk safety: counts/sums are additive; ratios are recomputed after the
cross-part combine; ``email_distinct_external_domains`` is recomputed exactly
from deduplicated (user, day, domain) triples produced by
``external_domain_triples``.
"""
from __future__ import annotations

import re

import pandas as pd

from .common import off_hours, ratio

_ADDR_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _addresses(value) -> list[str]:
    if value is None or (isinstance(value, float) and value != value):
        return []
    return [x.casefold() for x in _ADDR_RE.findall(str(value))]


def internal_domains(directory: dict[str, str]) -> set[str]:
    return {addr.split("@", 1)[1] for addr in directory if "@" in addr}


def _recipients(x: pd.DataFrame) -> pd.Series:
    to_list = x["to"].map(_addresses)
    cc_list = x["cc"].map(_addresses)
    bcc_list = x["bcc"].map(_addresses)
    return pd.Series([a + b + c for a, b, c in zip(to_list, cc_list, bcc_list)], index=x.index)


def aggregate(df: pd.DataFrame, directory: dict[str, str]) -> pd.DataFrame:
    x = df.copy()
    own = set(directory)
    x["cc_list"] = x["cc"].map(_addresses)
    x["bcc_list"] = x["bcc"].map(_addresses)
    x["all_recips"] = _recipients(x)
    x["recipient_count"] = x["all_recips"].map(len).astype("int32")
    x["external_recipient_count"] = x["all_recips"].map(lambda vals: sum(a not in own for a in vals)).astype("int32")
    x["has_cc"] = x["cc_list"].map(bool).astype("int32")
    x["has_bcc"] = x["bcc_list"].map(bool).astype("int32")
    x["external_sender"] = (~x["from"].isin(own)).astype("int32")
    x["off"] = off_hours(x["hour"]).astype("int32")
    g = x.groupby(["user_id", "date_day"], observed=True)
    out = g.agg(
        emails_sent=("event_id", "size"),
        email_recipient_count=("recipient_count", "sum"),
        email_external_recipient_count=("external_recipient_count", "sum"),
        email_cc_count=("has_cc", "sum"),
        email_bcc_count=("has_bcc", "sum"),
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


def external_domain_triples(df: pd.DataFrame, directory: dict[str, str]) -> pd.DataFrame:
    """Deduplicated (user_id, date_day, domain) rows for external recipients."""
    internal = internal_domains(directory)
    recips = _recipients(df)
    rows = []
    for user, day, addrs in zip(df["user_id"], df["date_day"], recips):
        for addr in addrs:
            domain = addr.split("@", 1)[1]
            if domain not in internal:
                rows.append((user, day, domain))
    out = pd.DataFrame(rows, columns=["user_id", "date_day", "domain"])
    return out.drop_duplicates()
