"""Materialise the ATT&CK technique table from the pinned STIX bundle (Bible Ch10 step 1).

Run once, offline, when the pin changes. HCEA D-4: mitreattack-python's
object graph for the full enterprise bundle is heavy (the 19.2 bundle is
54 MB of JSON and takes seconds to index), fine for a one-off script and
wasteful inside a long-lived API process. This module is the only place in
the repository that imports mitreattack-python.

Usage, from backend/:

    python -m app.mitre.stix_loader --download             # fetch the pinned bundle, check sha256, write the table
    python -m app.mitre.stix_loader --bundle ../datasets/raw/mitre/enterprise-attack-19.2.json

What it does
    1. Checks the bundle's sha256 against ``techniques.PINNED_BUNDLE_SHA256``.
       A different file is refused: the pin is the version.
    2. Loads it with ``MitreAttackData`` and keeps active techniques only
       (``remove_revoked_deprecated=True``).
    3. Writes ``app/mitre/data/enterprise_attack_v<version>.json`` with id,
       name, tactics, parent, the first sentence of the description (citation
       markers removed) and the ATT&CK URL, sorted by id so the file is
       byte-stable across runs.
    4. Checks that every rule in ``mapping_rules.py`` names an active
       technique under the tactic the rule claims.
    5. Appends one ``chapter10_stix_table`` runlog line.

``--download`` is the only network access in Chapter 10 and happens here,
in this offline step. The bundle goes under ``datasets/raw/mitre/``
(gitignored); the table is committed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from app.feature_engineering.common import append_experiment_runlog, memory_rss_mb, repo_root

from .techniques import (
    PINNED_BUNDLE_SHA256,
    PINNED_BUNDLE_URL,
    PINNED_VERSION,
    TABLE_SCHEMA,
    load_technique_table,
    table_path,
)

_CITATION = re.compile(r"\s*\(Citation:[^)]*\)")
_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")


def default_bundle_path() -> Path:
    return repo_root() / "datasets" / "raw" / "mitre" / f"enterprise-attack-{PINNED_VERSION}.json"


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def first_sentence(text: str | None) -> str:
    """First sentence of an ATT&CK description, without citation markers or markdown links."""
    if not text:
        return ""
    t = _LINK.sub(r"\1", _CITATION.sub("", text)).replace("\n", " ").strip()
    m = re.search(r"(?<=[a-z0-9\)\]])\.\s", t)
    return (t[: m.start() + 1] if m else t).strip()


def _attack_url(obj) -> str:
    for ref in getattr(obj, "external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url", "")
    return ""


def build_table(bundle: Path, *, version: str, bundle_sha256: str) -> dict:
    from mitreattack.stix20 import MitreAttackData  # heavy, offline only

    data = MitreAttackData(str(bundle))
    tactics = {}
    for t in data.get_tactics(remove_revoked_deprecated=True):
        tactics[t.x_mitre_shortname] = {"tactic_id": data.get_attack_id(t.id), "name": t.name}
    rows = []
    modified = ""
    for t in data.get_techniques(remove_revoked_deprecated=True):
        tid = data.get_attack_id(t.id)
        if not tid:
            continue
        sub = bool(getattr(t, "x_mitre_is_subtechnique", False))
        phases = sorted({p.phase_name for p in (getattr(t, "kill_chain_phases", []) or [])
                         if p.kill_chain_name == "mitre-attack"})
        rows.append({
            "technique_id": tid,
            "name": t.name,
            "tactics": phases,
            "is_subtechnique": sub,
            "parent_id": tid.split(".")[0] if sub else None,
            "short_description": first_sentence(getattr(t, "description", "")),
            "url": _attack_url(t),
            "stix_id": t.id,
        })
    with bundle.open(encoding="utf-8") as fh:
        for obj in json.load(fh).get("objects", []):
            if obj.get("type") == "x-mitre-collection":
                modified = str(obj.get("modified", ""))
                break
    rows.sort(key=lambda r: [int(x) if x.isdigit() else x for x in re.split(r"[T.]", r["technique_id"]) if x])
    return {
        "schema": TABLE_SCHEMA,
        "attack_version": version,
        "domain": "enterprise-attack",
        "bundle_url": PINNED_BUNDLE_URL,
        "bundle_sha256": bundle_sha256,
        "bundle_modified": modified,
        "generated_by": "python -m app.mitre.stix_loader (mitreattack-python MitreAttackData, "
                        "remove_revoked_deprecated=True)",
        "tactics": dict(sorted(tactics.items())),
        "techniques": rows,
    }


def download(dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    with urllib.request.urlopen(PINNED_BUNDLE_URL, timeout=120) as resp, tmp.open("wb") as fh:  # noqa: S310
        while True:
            block = resp.read(1 << 20)
            if not block:
                break
            fh.write(block)
    tmp.replace(dest)


def _parse_args(argv):
    p = argparse.ArgumentParser(description="CIRA Chapter 10: build the ATT&CK technique table (offline, once)")
    p.add_argument("--bundle", default=str(default_bundle_path()))
    p.add_argument("--download", action="store_true", help="fetch the pinned bundle first if it is not present")
    p.add_argument("--out", default=str(table_path()))
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)
    started = time.perf_counter()
    bundle = Path(args.bundle)
    if not bundle.exists():
        if not args.download:
            print(f"stix_loader: {bundle} not found; pass --download to fetch the pinned bundle", file=sys.stderr)
            return 2
        print(f"[stix] downloading {PINNED_BUNDLE_URL}", flush=True)
        download(bundle)
    digest = file_sha256(bundle)
    if digest != PINNED_BUNDLE_SHA256:
        print(f"stix_loader: {bundle.name} has sha256 {digest[:12]}, the pin is {PINNED_BUNDLE_SHA256[:12]}; "
              "a different bundle is a different version, change the pin in techniques.py first", file=sys.stderr)
        return 2
    table = build_table(bundle, version=PINNED_VERSION, bundle_sha256=digest)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(table, indent=1, ensure_ascii=False, sort_keys=False) + "\n"
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(out)

    from .mapping_rules import validate_rules

    loaded = load_technique_table(out if Path(args.out) != table_path() else None, env={})
    problems = validate_rules(loaded)
    append_experiment_runlog({
        "stage": "chapter10_stix_table", "attack_version": PINNED_VERSION, "bundle_sha256": digest,
        "table": str(out), "table_sha256": loaded.table_sha256, "techniques": len(table["techniques"]),
        "rule_problems": problems, "wall_seconds": round(time.perf_counter() - started, 2),
        "peak_rss_mb": round(memory_rss_mb(), 1),
        "written_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })
    print(f"[stix] ATT&CK {PINNED_VERSION}: {len(table['techniques'])} active techniques, "
          f"{len(table['tactics'])} tactics -> {out} (sha256 {loaded.table_sha256[:12]})", flush=True)
    for p in problems:
        print(f"[stix] RULE PROBLEM: {p}", flush=True)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
