"""Expert host-class list for HTTP features (HCEA v1.0 §5.2, deviation D-8).

STATUS: DRAFT - REQUIRES HUMAN REVIEW BEFORE ANY REPORTED (mid/full) RUN.

Provenance rule
---------------
This list was written from general knowledge of public web categories.
It was NOT derived from CERT answer files, insiders.csv, scenario files or
any other ground-truth artefact, and it must never be edited by looking at
which hosts malicious users visited. Doing so would leak labels into feature
design and invalidate every evaluation number.

To review it against the real host vocabulary without touching labels, run
``python scripts/http_host_inventory.py`` (label-blind: it only reads the
Stage 0 Parquet tree) and adjust the tuples below by category, not by user.

Matching is exact-host or subdomain suffix (``drive.google.com`` matches
``drive.google.com`` and ``x.drive.google.com``, never ``google.com``).
Every change to this file changes the feature set: bump
``HOST_CATEGORIES_VERSION`` so Stage 1 caches are rebuilt.
"""
from __future__ import annotations

HOST_CATEGORIES_VERSION = "2026-09-24-draft1"

HOST_CATEGORIES: dict[str, tuple[str, ...]] = {
    # General-purpose job boards and recruiting platforms.
    "job_search": (
        "monster.com",
        "indeed.com",
        "careerbuilder.com",
        "simplyhired.com",
        "glassdoor.com",
        "dice.com",
        "ziprecruiter.com",
        "linkedin.com",
        "jobhuntersbible.com",
        "job-hunt.org",
        "hotjobs.yahoo.com",
        "usajobs.gov",
    ),
    # Consumer cloud storage / file-sharing services (exfiltration channel).
    "cloud_storage": (
        "dropbox.com",
        "box.com",
        "drive.google.com",
        "docs.google.com",
        "onedrive.live.com",
        "skydrive.live.com",
        "mediafire.com",
        "megaupload.com",
        "rapidshare.com",
        "sendspace.com",
        "4shared.com",
        "yousendit.com",
    ),
    # Public leak / paste sites (MITRE T1567-style exfiltration to web service).
    "leak_paste": (
        "wikileaks.org",
        "pastebin.com",
        "cryptome.org",
    ),
    # Hacking-tool, keylogger and spyware distribution sites.
    "hacking_tools": (
        "keylogger.org",
        "spyrix.com",
        "refog.com",
        "spectorsoft.com",
        "hackforums.net",
        "exploit-db.com",
        "packetstormsecurity.com",
    ),
}
