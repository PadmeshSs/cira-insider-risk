"""The committed ATT&CK technique table (Bible Ch10 step 1, HCEA D-4).

``stix_loader.py`` reads the pinned enterprise-attack STIX bundle once,
offline, and writes ``data/enterprise_attack_v<version>.json``: technique
id, name, tactics, parent, a one-sentence description and the ATT&CK URL,
plus the bundle's version, modified date and sha256. That file is
committed. Everything else in this package, and the API, reads only that
file. Nothing here imports mitreattack-python or stix2, and nothing touches
the network.

Why 19.2
    The newest Enterprise ATT&CK release when this chapter was written
    (published 2026-08-05), chosen before any mapping number existed. The
    Chapter 1 placeholder in ``.env.example`` said 15.1; it predates the
    chapter and is replaced (deviation C10-1). Tactics are taken from the
    bundle as they are; for example, 19.x files Valid Accounts under
    ``stealth`` rather than the older ``defense-evasion``, and the table
    follows the bundle rather than memory.

A table from another version is refused unless the caller asks for it by
path, and ``MITRE_ATTACK_VERSION`` in the environment must match the pin
when it is set, so an old ``.env`` cannot select a different table silently.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

PINNED_VERSION = "19.2"
PINNED_BUNDLE_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
                     "enterprise-attack/enterprise-attack-19.2.json")
PINNED_BUNDLE_SHA256 = "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4"
DATA_DIR = Path(__file__).resolve().parent / "data"
TABLE_SCHEMA = "cira-attack-technique-table-v1"


class TechniqueTableError(RuntimeError):
    """The technique table is missing, altered or of the wrong version."""


def table_path(version: str = PINNED_VERSION) -> Path:
    return DATA_DIR / f"enterprise_attack_v{version}.json"


def text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    tactics: tuple[str, ...]
    is_subtechnique: bool
    parent_id: str | None
    short_description: str
    url: str

    @property
    def display_name(self) -> str:
        return self.name


@dataclass
class TechniqueTable:
    attack_version: str
    bundle_sha256: str
    bundle_modified: str
    table_sha256: str
    path: Path
    techniques: dict[str, Technique]
    tactics: dict[str, dict]

    def get(self, technique_id: str) -> Technique:
        try:
            return self.techniques[technique_id]
        except KeyError as exc:
            raise TechniqueTableError(
                f"{technique_id} is not an active technique in ATT&CK {self.attack_version} "
                "(unknown, revoked or deprecated)") from exc

    def full_name(self, technique_id: str) -> str:
        """``Parent: Sub`` for a sub-technique, as ATT&CK writes it."""
        t = self.get(technique_id)
        if t.parent_id and t.parent_id in self.techniques:
            return f"{self.techniques[t.parent_id].name}: {t.name}"
        return t.name

    def describe(self) -> dict:
        return {"attack_version": self.attack_version, "bundle_sha256": self.bundle_sha256,
                "bundle_modified": self.bundle_modified, "table_sha256": self.table_sha256,
                "techniques": len(self.techniques), "path": str(self.path)}


def _check_env(version: str, env: Mapping[str, str] | None) -> None:
    env = os.environ if env is None else env
    wanted = (env.get("MITRE_ATTACK_VERSION") or "").strip()
    if wanted and wanted != version:
        raise TechniqueTableError(
            f"MITRE_ATTACK_VERSION={wanted} but the pinned table is {version}; update .env from .env.example "
            "(the Chapter 1 placeholder was 15.1) or regenerate the table with stix_loader and re-pin")


def load_technique_table(path: str | Path | None = None, *, env: Mapping[str, str] | None = None) -> TechniqueTable:
    """Load and check the committed table. Raises TechniqueTableError."""
    p = Path(path) if path else table_path()
    if not p.exists():
        raise TechniqueTableError(f"no technique table at {p}; run `python -m app.mitre.stix_loader` once, offline")
    text = p.read_text(encoding="utf-8")
    try:
        body = json.loads(text)
    except ValueError as exc:
        raise TechniqueTableError(f"unreadable technique table {p}: {exc}") from exc
    if body.get("schema") != TABLE_SCHEMA:
        raise TechniqueTableError(f"{p} has schema {body.get('schema')!r}, expected {TABLE_SCHEMA!r}")
    version = str(body.get("attack_version"))
    if path is None:
        if version != PINNED_VERSION or body.get("bundle_sha256") != PINNED_BUNDLE_SHA256:
            raise TechniqueTableError(
                f"{p} is ATT&CK {version} with bundle sha256 {str(body.get('bundle_sha256'))[:12]}, the pin is "
                f"{PINNED_VERSION} / {PINNED_BUNDLE_SHA256[:12]}")
        _check_env(version, env)
    techniques = {}
    for row in body.get("techniques", []):
        techniques[row["technique_id"]] = Technique(
            technique_id=row["technique_id"], name=row["name"], tactics=tuple(row["tactics"]),
            is_subtechnique=bool(row["is_subtechnique"]), parent_id=row.get("parent_id"),
            short_description=row.get("short_description", ""), url=row.get("url", ""))
    if not techniques:
        raise TechniqueTableError(f"{p} holds no techniques")
    return TechniqueTable(attack_version=version, bundle_sha256=body["bundle_sha256"],
                          bundle_modified=body.get("bundle_modified", ""), table_sha256=text_sha256(text), path=p,
                          techniques=techniques, tactics=body.get("tactics", {}))
