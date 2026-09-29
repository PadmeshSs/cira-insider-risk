"""The expert map from CERT r4.2 behaviour to ATT&CK techniques (Bible Ch10 step 2).

Small and explicit on purpose: four rules, each tied to one Chapter 5
column that already exists, each with the reason for its technique and what
CERT cannot show about it. Behaviours that were considered and deliberately
left unmapped are listed too, with the reason, so "unmapped" is a recorded
decision rather than an omission (Architecture §16: never force a mapping).

How the rules were written (provenance, same rule as network_domains.py, N7)
    From the ATT&CK 19.2 technique definitions and the Chapter 5 column
    definitions only. Not from answer files, insiders.csv or any label, and
    never edited by looking at which users a rule fires on.

    Disclosed limit: the public CERT r4.2 scenario descriptions are known to
    anyone who has read the dataset documentation, the author included. Some
    of these behaviours (removable-media copying, a leak site, a keylogger
    site) appear in them. A validation gain from ``mitre_context`` on a
    scenario is therefore partly by construction of the dataset, as for
    user_context (N36), and is reported next to the ``no_mitre_context``
    ablation, never as evidence on its own (N41).

Evidence grades (shown to the analyst, stored, never used as a multiplier)
    observed   CERT records the technique's action itself: a file copied to
               removable media is what r4.2 file.csv logs.
    indicated  CERT records access to a destination whose purpose fits the
               technique, but not the action: r4.2 http.csv has no method,
               bytes or upload flag (N9), so a visit to a leak site is not
               proof of an upload.

    The grade does not scale ``mitre_context``: any factor would be one more
    constant nobody has validated (N37). Rule strength comes from rarity
    alone (see ``reference.py``).

Per-row "observed, not mapped" tags
    A not-mapped behaviour with a ``flag_column`` is tagged on a user-day
    when that column is > 0, so the analyst sees that, for example, job
    search happened and was deliberately left without a technique. The
    others (email volume, any USB connect, off-hours) occur on most days and
    would only be noise as tags; they are documented here and not tagged.

Rules fire on ``column > 0``. A null column means the rule could not be
evaluated for that user-day (Chapter 5 fills daily counts with 0, so on
CERT this should not happen; it is handled anyway).

Changing anything here changes ``RULESET_VERSION``/``ruleset_hash()``; the
pinned reference and every enrichment run record the hash, and a reference
fitted for another ruleset is refused.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

RULESET_VERSION = "c10-rules-v1"
EVIDENCE_GRADES = ("observed", "indicated")


@dataclass(frozen=True)
class Rule:
    rule_id: str
    technique_id: str
    tactic: str
    pattern: str
    trigger_column: str
    intensity_column: str
    evidence: str
    source: str
    reasoning: str
    not_observable: str


@dataclass(frozen=True)
class NotMapped:
    behaviour: str
    columns: tuple[str, ...]
    techniques_considered: tuple[str, ...]
    reason: str
    flag_column: str | None = None


RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="R01_removable_media_copy",
        technique_id="T1052.001",
        tactic="exfiltration",
        pattern="files copied to removable media that day",
        trigger_column="file_event_count",
        intensity_column="file_event_count",
        evidence="observed",
        source="file.csv (r4.2 logs file copies to removable media)",
        reasoning=("T1052.001 is data moved out over a USB-attached device. In r4.2 every file.csv row is a copy "
                   "to removable media, so the action itself is recorded."),
        not_observable="Whether the files were sensitive, and whether the device left the building.",
    ),
    Rule(
        rule_id="R02_leak_site_access",
        technique_id="T1567",
        tactic="exfiltration",
        pattern="requests to public leak or paste sites (host class leak_paste)",
        trigger_column="http_leak_paste_count",
        intensity_column="http_leak_paste_count",
        evidence="indicated",
        source="http.csv host, classed by network_domains.py",
        reasoning=("T1567 is exfiltration to an existing web service. Leak and paste sites exist to publish "
                   "material, so access to one is the web-service channel the technique describes."),
        not_observable="r4.2 http.csv has no method, byte count or upload flag (N9): a visit is not an upload.",
    ),
    Rule(
        rule_id="R03_cloud_storage_access",
        technique_id="T1567.002",
        tactic="exfiltration",
        pattern="requests to consumer cloud storage or file-sharing hosts (host class cloud_storage)",
        trigger_column="http_cloud_storage_count",
        intensity_column="http_cloud_storage_count",
        evidence="indicated",
        source="http.csv host, classed by network_domains.py",
        reasoning="T1567.002 is exfiltration to a cloud storage service, which is what this host class lists.",
        not_observable="As R02: direction and volume are not recorded, so ordinary downloads look the same.",
    ),
    Rule(
        rule_id="R04_attack_tool_site_access",
        technique_id="T1588.002",
        tactic="resource-development",
        pattern="requests to keylogger, spyware or exploit distribution sites (host class hacking_tools)",
        trigger_column="http_hacking_tools_count",
        intensity_column="http_hacking_tools_count",
        evidence="indicated",
        source="http.csv host, classed by network_domains.py",
        reasoning=("T1588.002 is obtaining a tool, including keyloggers and exploit kits. These hosts distribute "
                   "such tools."),
        not_observable=("A download or an install is not recorded; use of a keylogger (T1056.001) would need "
                        "process or application logs, which r4.2 does not have (N9)."),
    ),
)


NOT_MAPPED: tuple[NotMapped, ...] = (
    NotMapped(
        behaviour="job-search browsing",
        columns=("http_job_search_count",),
        techniques_considered=(),
        reason=("Looking for another job is an insider-risk precursor, not an adversary technique; ATT&CK "
                "Enterprise has nothing for it. It stays a behavioural signal for the model and the CRI."),
        flag_column="http_job_search_count",
    ),
    NotMapped(
        behaviour="keylogger installation or use",
        columns=(),
        techniques_considered=("T1056.001",),
        reason="Needs process or application logs, which r4.2 does not contain (N9). Only a site visit is visible (R04).",
    ),
    NotMapped(
        behaviour="logon from a PC the account has not used before",
        columns=("new_device_count", "new_device_flag"),
        techniques_considered=("T1078",),
        reason=("Every CERT logon is a valid account. Without failed logins or source IPs (N9) a first-seen PC "
                "cannot separate credential misuse from ordinary hot-desking, and in r4.2 masqueraded activity "
                "lands on the victim's row, not the insider's (N1)."),
        flag_column="new_device_count",
    ),
    NotMapped(
        behaviour="email to many internal recipients",
        columns=("email_recipient_count",),
        techniques_considered=("T1534",),
        reason=("T1534 is phishing inside the organisation and is defined by message content; content is not "
                "used (Architecture §10.3), so volume alone cannot place a message under it."),
    ),
    NotMapped(
        behaviour="email with attachments to external recipients",
        columns=("email_external_recipient_count", "email_attachment_count"),
        techniques_considered=("T1048.003", "T1567"),
        reason=("No Enterprise technique describes a user mailing data from their own mailbox; T1048.003 is about "
                "non-C2 network protocols and T1567 about web services. Forcing either would be a guess."),
    ),
    NotMapped(
        behaviour="archive or executable files among the removable-media copies",
        columns=("file_zip_count", "file_exe_count", "file_archive_or_executable_count"),
        techniques_considered=("T1560", "T1537"),
        reason=("T1560 needs the archiving step, which is not recorded; the copy itself is already R01. The "
                "Bible's example pairs T1560 with T1537, which is transfer between cloud accounts and needs cloud "
                "telemetry r4.2 does not have (C10-3)."),
        flag_column="file_archive_or_executable_count",
    ),
    NotMapped(
        behaviour="removable device connected without a file copy",
        columns=("usb_connect_count",),
        techniques_considered=("T1200", "T1091"),
        reason=("T1200 is adding hardware to gain access and T1091 is malware spreading through removable media; "
                "a connect event shows neither."),
    ),
    NotMapped(
        behaviour="off-hours or weekend activity",
        columns=("off_hours_logins", "usb_off_hours_events", "file_off_hours_events", "http_off_hours_count"),
        techniques_considered=(),
        reason="Timing is a risk heuristic, not a technique. The CRI's historical-deviation term carries it.",
    ),
)


def rule_by_id(rule_id: str) -> Rule:
    for r in RULES:
        if r.rule_id == rule_id:
            return r
    raise KeyError(rule_id)


def required_columns() -> list[str]:
    cols: list[str] = []
    for r in RULES:
        for c in (r.trigger_column, r.intensity_column):
            if c not in cols:
                cols.append(c)
    return cols


def unmapped_columns() -> list[str]:
    cols: list[str] = []
    for n in NOT_MAPPED:
        for c in n.columns:
            if c not in cols:
                cols.append(c)
    return cols


def flag_columns() -> list[str]:
    return [n.flag_column for n in NOT_MAPPED if n.flag_column]


def ruleset_body() -> dict:
    return {"version": RULESET_VERSION, "rules": [asdict(r) for r in RULES],
            "not_mapped": [{**asdict(n), "columns": list(n.columns),
                            "techniques_considered": list(n.techniques_considered)} for n in NOT_MAPPED]}


def ruleset_hash() -> str:
    return hashlib.sha256(json.dumps(ruleset_body(), sort_keys=True).encode()).hexdigest()[:12]


def validate_rules(table, schema_columns=None) -> list[str]:
    """Problems with the rules against a technique table (and optionally a matrix schema).

    Empty list = every rule names an active technique under the tactic it
    claims, grades and ids are valid, and every column exists.
    """
    problems: list[str] = []
    ids = [r.rule_id for r in RULES]
    if len(ids) != len(set(ids)):
        problems.append("duplicate rule ids")
    for r in RULES:
        t = table.techniques.get(r.technique_id)
        if t is None:
            problems.append(f"{r.rule_id}: {r.technique_id} is not an active technique in ATT&CK {table.attack_version}")
        elif r.tactic not in t.tactics:
            problems.append(f"{r.rule_id}: {r.technique_id} is not under tactic {r.tactic!r} (bundle says {list(t.tactics)})")
        if r.evidence not in EVIDENCE_GRADES:
            problems.append(f"{r.rule_id}: evidence grade {r.evidence!r} not in {EVIDENCE_GRADES}")
    for n in NOT_MAPPED:
        for tid in n.techniques_considered:
            if tid not in table.techniques:
                problems.append(f"not-mapped '{n.behaviour}': considered technique {tid} is not active in "
                                f"ATT&CK {table.attack_version}")
    if schema_columns is not None:
        have = set(schema_columns)
        for c in required_columns():
            if c not in have:
                problems.append(f"rule column {c!r} is not in the Chapter 5 matrix")
    return problems
