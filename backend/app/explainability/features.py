"""Plain-language description of every Chapter 5 column (Architecture §18).

An explanation names a feature the way an analyst reads it: "files copied to
removable media: 14", not ``file_event_count = 14.0``. This module is the only
place those words are written, so they can be checked in one place:

* every column the served model sees must have a written description (the
  verifier FAILs on a fallback);
* no description may claim a signal CERT r4.2 does not record (N9): no failed
  logins, source IPs, network byte volumes, file create/modify/delete, process
  or application logs, and no upload. ``FORBIDDEN_PHRASES`` is checked by a
  unit test and by the verifier;
* values are described from the raw matrix row, never from a standardised
  model input (N22), and a null is described by what it means (N4), never as
  zero.

Static per-user traits (psychometrics, department size) are described so the
verifier can name them, but they are marked ``static`` and the reason builder
never presents one as a behavioural reason (N22, N25).

Label-free and model-free.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

STATIC_PREFIXES = ("psych_", "peer_department_size")
CALENDAR_COLUMNS = ("day_of_week", "is_weekend")
WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
FORBIDDEN_PHRASES = (
    "failed login", "failed logon", "source ip", "ip address", "bytes transferred", "bytes uploaded",
    "upload", "uploaded", "process", "application", "file created", "file modified", "file deleted",
    "exfiltrated", "exfiltrate", "stole", "theft",
)
OFF_HOURS = "outside 07:00-19:00"

# kind -> what a null means for that kind (Chapter 5 null policy, N4)
NULL_MEANING = {
    "hour": "no value (no such activity that day)",
    "ratio": "no value (no qualifying events that day, so the share is undefined)",
    "average": "no value (no qualifying events that day)",
    "hours": "no value (no logon that day)",
    "flag_logon": "no value (no logon that day)",
    "rolling": "no value (no earlier day for this user yet)",
    "baseline_z": "no value (fewer than 7 earlier days, or no variation in them)",
    "baseline_abs_z": "no value (fewer than 7 earlier days, or no variation in them)",
    "peer_median": "no value (no LDAP department or no peers that day)",
    "peer_dev": "no value (no LDAP department or no peers that day)",
    "peer_abs_dev": "no value (no LDAP department or no peers that day)",
    "static": "no value (no record for this user)",
}


@dataclass(frozen=True)
class FeatureText:
    column: str
    label: str
    kind: str
    domain: str
    described: bool = True
    static: bool = False
    calendar: bool = False


# column -> (label, kind, domain). Labels are noun phrases for one user-day.
BASE: dict[str, tuple[str, str, str]] = {
    # logon.csv
    "login_count": ("logons", "count", "logon"),
    "logoff_count": ("logoffs", "count", "logon"),
    "auth_event_count": ("logon and logoff events", "count", "logon"),
    "first_auth_hour": ("hour of the first logon or logoff", "hour", "logon"),
    "last_auth_hour": ("hour of the last logon or logoff", "hour", "logon"),
    "off_hours_logins": (f"logons {OFF_HOURS}", "count", "logon"),
    "weekend_logins": ("weekend logons", "count", "logon"),
    "distinct_auth_pcs": ("distinct PCs logged on to", "count", "logon"),
    "new_device_count": ("PCs logged on to for the first time", "count", "logon"),
    "new_device_flag": ("logged on to a PC for the first time", "flag", "logon"),
    "off_hours_login_ratio": (f"share of logons {OFF_HOURS}", "ratio", "logon"),
    "weekend_login_ratio": ("share of logons on a weekend", "ratio", "logon"),
    # device.csv
    "usb_connect_count": ("removable-device connects", "count", "device"),
    "usb_disconnect_count": ("removable-device disconnects", "count", "device"),
    "usb_event_count": ("removable-device connects and disconnects", "count", "device"),
    "usb_off_hours_events": (f"removable-device events {OFF_HOURS}", "count", "device"),
    "usb_first_hour": ("hour of the first removable-device event", "hour", "device"),
    "usb_last_hour": ("hour of the last removable-device event", "hour", "device"),
    "usb_distinct_pcs": ("distinct PCs with removable-device activity", "count", "device"),
    "usb_off_hours_ratio": (f"share of removable-device events {OFF_HOURS}", "ratio", "device"),
    # file.csv (in r4.2 every row is a copy to removable media)
    "file_event_count": ("files copied to removable media", "count", "file"),
    "file_off_hours_events": (f"files copied to removable media {OFF_HOURS}", "count", "file"),
    "file_doc_count": (".doc files copied to removable media", "count", "file"),
    "file_pdf_count": (".pdf files copied to removable media", "count", "file"),
    "file_txt_count": (".txt files copied to removable media", "count", "file"),
    "file_jpg_count": (".jpg files copied to removable media", "count", "file"),
    "file_zip_count": (".zip files copied to removable media", "count", "file"),
    "file_exe_count": (".exe files copied to removable media", "count", "file"),
    "file_other_ext_count": ("files of another type copied to removable media", "count", "file"),
    "file_archive_or_executable_count": (".zip or .exe files copied to removable media", "count", "file"),
    "file_distinct_pcs": ("distinct PCs files were copied from", "count", "file"),
    # email.csv (metadata only; message content is not used, §10.3)
    "emails_sent": ("emails sent", "count", "email"),
    "email_recipient_count": ("email recipients (to, cc and bcc)", "count", "email"),
    "email_external_recipient_count": ("external email recipients", "count", "email"),
    "email_cc_count": ("cc recipients", "count", "email"),
    "email_bcc_count": ("bcc recipients", "count", "email"),
    "email_attachment_count": ("email attachments sent", "count", "email"),
    "email_total_size": ("total size of emails sent, in bytes (email log size field)", "count", "email"),
    "email_external_sender_count": ("emails sent from an address outside the company directory", "count", "email"),
    "email_off_hours_count": (f"emails sent {OFF_HOURS}", "count", "email"),
    "email_distinct_external_domains": ("distinct external recipient domains", "count", "email"),
    "external_email_ratio": ("share of email recipients that are external", "ratio", "email"),
    "email_external_sender_ratio": ("share of emails sent from an address outside the directory", "ratio", "email"),
    "email_attachment_avg": ("attachments per email sent", "average", "email"),
    "email_off_hours_ratio": (f"share of emails sent {OFF_HOURS}", "ratio", "email"),
    # http.csv (host and host class only; no method, bytes or upload flag)
    "http_request_count": ("web requests", "count", "http"),
    "http_off_hours_count": (f"web requests {OFF_HOURS}", "count", "http"),
    "http_job_search_count": ("requests to job-search sites", "count", "http"),
    "http_cloud_storage_count": ("requests to cloud-storage or file-sharing sites", "count", "http"),
    "http_leak_paste_count": ("requests to leak or paste sites", "count", "http"),
    "http_hacking_tools_count": ("requests to hacking-tool or keylogger sites", "count", "http"),
    "http_distinct_hosts": ("distinct web hosts visited", "count", "http"),
    "http_new_host_count": ("web hosts visited for the first time", "count", "http"),
    # temporal
    "day_of_week": ("day of the week", "weekday", "temporal"),
    "is_weekend": ("weekend day", "flag", "temporal"),
    "total_event_count": ("events across all logs", "count", "temporal"),
    "is_active_day": ("any recorded activity that day", "flag", "temporal"),
    "first_auth_off_hours": (f"first logon of the day {OFF_HOURS}", "flag_logon", "temporal"),
    "last_auth_off_hours": (f"last logon event of the day {OFF_HOURS}", "flag_logon", "temporal"),
    "auth_active_span_hours": ("hours between the first and last logon event", "hours", "temporal"),
    "rolling_7d_event_count": ("events in the previous 7 days", "rolling", "temporal"),
    "rolling_7d_active_days": ("active days in the previous 7 days", "rolling", "temporal"),
    # static per-user traits (never a behavioural reason, N22)
    "peer_department_size": ("number of peers in the same unit and department that day", "static", "peer_group"),
    "psych_openness": ("psychometric score: openness", "static", "psychometric_context"),
    "psych_conscientiousness": ("psychometric score: conscientiousness", "static", "psychometric_context"),
    "psych_extraversion": ("psychometric score: extraversion", "static", "psychometric_context"),
    "psych_agreeableness": ("psychometric score: agreeableness", "static", "psychometric_context"),
    "psych_neuroticism": ("psychometric score: neuroticism", "static", "psychometric_context"),
}

PEER_GROUP = "peers (same functional unit and department, same day, the user left out)"


def describe(column: str) -> FeatureText:
    """Description of one column. Unknown columns get a fallback marked ``described=False``."""
    c = str(column)
    static = c.startswith(STATIC_PREFIXES)
    calendar = c in CALENDAR_COLUMNS
    if c in BASE:
        label, kind, domain = BASE[c]
        return FeatureText(c, label, kind, domain, True, static, calendar)
    for prefix, kind, template in (
        ("hist_abs_z_", "baseline_abs_z", "{b}: distance from this user's own average over the previous 30 days"),
        ("hist_z_", "baseline_z", "{b} compared with this user's own previous 30 days"),
        ("peer_abs_dev_", "peer_abs_dev", "{b}: distance from the median of " + PEER_GROUP),
        ("peer_median_", "peer_median", "{b}: median among " + PEER_GROUP),
        ("peer_dev_", "peer_dev", "{b} compared with " + PEER_GROUP),
    ):
        if c.startswith(prefix):
            base = c[len(prefix):]
            if base not in BASE:
                break
            domain = "historical_baseline" if prefix.startswith("hist") else "peer_group"
            return FeatureText(c, template.format(b=BASE[base][0]), kind, domain, True, static, calendar)
    return FeatureText(c, c, "unknown", "unknown", False, static, calendar)


def undescribed(columns) -> list[str]:
    return [c for c in columns if not describe(c).described]


def _num(v: float) -> str:
    if float(v).is_integer():
        return f"{int(v)}"
    return f"{v:.2f}"


def value_text(column: str, value) -> str:
    """The raw value of ``column`` in words. ``None``/NaN is described by what it means."""
    ft = describe(column)
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return NULL_MEANING.get(ft.kind, "no value")
    v = float(value)
    k = ft.kind
    if k == "hour":
        return f"{int(v):02d}:00"
    if k == "ratio":
        return f"{v:.0%}"
    if k in ("flag", "flag_logon"):
        return "yes" if v > 0 else "no"
    if k == "weekday":
        return WEEKDAYS[int(v)] if 0 <= int(v) < 7 else _num(v)
    if k == "hours":
        return f"{v:.1f} hours"
    if k == "baseline_z":
        if v == 0:
            return "exactly at their usual level"
        return f"{abs(v):.1f} standard deviations {'above' if v > 0 else 'below'} their usual level"
    if k == "baseline_abs_z":
        return f"{v:.1f} standard deviations"
    if k == "peer_dev":
        if v == 0:
            return "equal to the peers' median"
        return f"{_num(abs(v))} {'above' if v > 0 else 'below'} the peers' median"
    if k == "peer_abs_dev":
        return f"{_num(v)} away from the peers' median"
    return _num(v)


def describe_value(column: str, value) -> str:
    """``"<label>: <value in words>"``, the form every model factor uses."""
    return f"{describe(column).label}: {value_text(column, value)}"


def forbidden_in(text: str) -> list[str]:
    t = text.lower()
    return [p for p in FORBIDDEN_PHRASES if p in t]
