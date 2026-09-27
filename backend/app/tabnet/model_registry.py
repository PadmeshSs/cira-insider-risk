"""Versioned model registry (Bible Ch7 step 4, Architecture §37 lineage).

Layout under ``<MODEL_PATH>/<model_name>/`` (``models/saved_models/tabnet/``
by default; the directory is gitignored):

    registry.jsonl          one JSON line per registered version, append-only
    v0001/                  artifacts of version v0001
        tabnet_model.zip    pytorch-tabnet save_model output
        preprocessor.json   train-fitted preprocessing (needed to score)
        global_importance.json
        meta.json           detector metadata (config, seed, fit info)
        registry_entry.json the same entry that went into registry.jsonl
    v0002/ ...

Rules
    * A version directory is never overwritten. Artifacts are written to a
      hidden temporary directory and renamed into place; if the target
      exists the rename fails and nothing is replaced. A retrain always gets
      the next version number.
    * Every file gets a sha256 in the entry, so a later load can prove the
      artifact is the one that was evaluated.
    * One writer at a time, guarded by a lock file. A stale lock (a crashed
      run) is reported, not silently removed.

An entry records: model name and version, registry version, the run that
produced it, profile and reportability (N6), split file and its hash,
training data (feature file, fingerprint, rows), feature-schema version,
training timestamp, the imbalance method with its effective weight, and the
validation/test metrics of that run.

This module never imports label code (N5). Chapter 8 resolves a version here
("latest" or pinned) and loads it through ``app.tabnet.infer``.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

REGISTRY_INDEX = "registry.jsonl"
ENTRY_FILE = "registry_entry.json"
LOCK_FILE = ".registry.lock"
_VERSION_RE = re.compile(r"^v(\d{4,})$")


class RegistryError(RuntimeError):
    """Registry could not complete an operation; nothing was overwritten."""


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


class ModelRegistry:
    def __init__(self, root: str | Path, model_name: str = "tabnet") -> None:
        self.model_name = model_name
        self.root = Path(root) / model_name

    # --- reading ----------------------------------------------------------
    @property
    def index_path(self) -> Path:
        return self.root / REGISTRY_INDEX

    def entries(self) -> list[dict]:
        if not self.index_path.exists():
            return []
        out = []
        for line in self.index_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out

    def resolve(self, ref: str = "latest", *, profile: str | None = None, reportable_only: bool = False) -> dict:
        """Entry for ``ref``: a registry version ("v0003"), a model_version
        string, a run id, or "latest" (optionally filtered by profile)."""
        entries = self.entries()
        if profile is not None:
            entries = [e for e in entries if e.get("profile") == profile]
        if reportable_only:
            entries = [e for e in entries if e.get("reportable")]
        if not entries:
            raise RegistryError(f"no registered {self.model_name} model matches ref={ref!r} profile={profile!r}")
        if ref == "latest":
            return max(entries, key=lambda e: self._number(e["registry_version"]))
        hits = [e for e in entries if ref in (e.get("registry_version"), e.get("model_version"), e.get("run_id"))]
        if not hits:
            raise RegistryError(f"{ref!r} is not a registered {self.model_name} version, model_version or run id")
        return max(hits, key=lambda e: self._number(e["registry_version"]))

    def artifact_dir(self, entry: dict) -> Path:
        return self.root / entry["registry_version"]

    def verify(self, entry: dict) -> list[str]:
        """Problems with the stored artifacts of ``entry`` (empty = intact)."""
        problems = []
        directory = self.artifact_dir(entry)
        if not directory.is_dir():
            return [f"artifact directory missing: {directory}"]
        for name, digest in entry.get("files", {}).items():
            path = directory / name
            if not path.exists():
                problems.append(f"missing file {name}")
            elif _sha256(path) != digest:
                problems.append(f"sha256 mismatch for {name}")
        return problems

    # --- writing ----------------------------------------------------------
    @staticmethod
    def _number(version: str) -> int:
        m = _VERSION_RE.match(version)
        if not m:
            raise RegistryError(f"malformed registry version {version!r}")
        return int(m.group(1))

    def _next_version(self) -> str:
        used = {self._number(e["registry_version"]) for e in self.entries()}
        if self.root.exists():
            used |= {self._number(p.name) for p in self.root.iterdir() if p.is_dir() and _VERSION_RE.match(p.name)}
        return f"v{(max(used) + 1 if used else 1):04d}"

    def register(self, write_artifacts: Callable[[Path], object], entry: dict) -> dict:
        """Write artifacts into a new version directory and append the entry.

        ``write_artifacts(directory)`` must write every artifact file into
        ``directory``. ``entry`` is the metadata to record; the registry adds
        ``registry_version``, ``registered_at``, ``artifact_dir`` and
        ``files`` (name -> sha256).
        """
        self.root.mkdir(parents=True, exist_ok=True)
        lock = self.root / LOCK_FILE
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            raise RegistryError(
                f"{lock} exists: another registration is running, or one crashed. "
                "If no training run is active, delete the lock file and retry."
            ) from exc
        try:
            os.write(fd, str(os.getpid()).encode())
            version = self._next_version()
            final = self.root / version
            tmp = self.root / f".{version}.tmp"
            if final.exists():
                raise RegistryError(f"{final} already exists; refusing to overwrite a registered artifact")
            if tmp.exists():
                shutil.rmtree(tmp)
            tmp.mkdir()
            write_artifacts(tmp)
            files = {p.name: _sha256(p) for p in sorted(tmp.iterdir()) if p.is_file()}
            if not files:
                raise RegistryError("write_artifacts produced no files")
            record = {
                **entry,
                "model_name": self.model_name,
                "registry_version": version,
                "registered_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "artifact_dir": str(final),
                "files": files,
            }
            (tmp / ENTRY_FILE).write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
            os.rename(tmp, final)   # fails if final appeared meanwhile: nothing is replaced
            with self.index_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, default=str) + "\n")
            return record
        finally:
            os.close(fd)
            try:
                lock.unlink()
            except FileNotFoundError:
                pass
