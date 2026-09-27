"""Model registry: versions are appended, never overwritten (Bible Ch7 step 4)."""
import json

import pytest

from app.tabnet.infer import ModelUnavailableError, load_model
from app.tabnet.model_registry import LOCK_FILE, ModelRegistry, RegistryError


def _writer(payload: str):
    def write(directory):
        (directory / "a.txt").write_text(payload)
        (directory / "b.json").write_text(json.dumps({"p": payload}))
    return write


def test_versions_increment_and_record_hashes(tmp_path):
    reg = ModelRegistry(tmp_path)
    e1 = reg.register(_writer("one"), {"model_version": "m1", "run_id": "r1", "profile": "mid", "reportable": True})
    e2 = reg.register(_writer("two"), {"model_version": "m2", "run_id": "r2", "profile": "full", "reportable": True})
    assert (e1["registry_version"], e2["registry_version"]) == ("v0001", "v0002")
    assert set(e1["files"]) == {"a.txt", "b.json"}
    assert (tmp_path / "tabnet" / "v0001" / "a.txt").read_text() == "one"            # first version untouched
    assert json.loads((tmp_path / "tabnet" / "v0002" / "registry_entry.json").read_text())["run_id"] == "r2"
    assert [e["registry_version"] for e in reg.entries()] == ["v0001", "v0002"]
    assert reg.verify(e1) == [] and reg.verify(e2) == []


def test_resolve(tmp_path):
    reg = ModelRegistry(tmp_path)
    reg.register(_writer("a"), {"model_version": "m1", "run_id": "r1", "profile": "mid", "reportable": True})
    reg.register(_writer("b"), {"model_version": "m2", "run_id": "r2", "profile": "dev", "reportable": False})
    assert reg.resolve()["registry_version"] == "v0002"
    assert reg.resolve(profile="mid")["registry_version"] == "v0001"
    assert reg.resolve(reportable_only=True)["run_id"] == "r1"
    assert reg.resolve("r2")["model_version"] == "m2"
    assert reg.resolve("m1")["registry_version"] == "v0001"
    with pytest.raises(RegistryError):
        reg.resolve("nope")
    with pytest.raises(RegistryError):
        ModelRegistry(tmp_path / "empty").resolve()


def test_existing_version_directory_is_never_overwritten(tmp_path, monkeypatch):
    reg = ModelRegistry(tmp_path)
    reg.register(_writer("keep"), {"model_version": "m1", "run_id": "r1"})
    monkeypatch.setattr(ModelRegistry, "_next_version", lambda self: "v0001")
    with pytest.raises(RegistryError, match="refusing to overwrite"):
        reg.register(_writer("clobber"), {"model_version": "m2", "run_id": "r2"})
    assert (tmp_path / "tabnet" / "v0001" / "a.txt").read_text() == "keep"
    assert not (tmp_path / "tabnet" / LOCK_FILE).exists()            # lock released after the failure


def test_stray_version_directory_bumps_the_number(tmp_path):
    (tmp_path / "tabnet" / "v0004").mkdir(parents=True)
    e = ModelRegistry(tmp_path).register(_writer("x"), {"model_version": "m", "run_id": "r"})
    assert e["registry_version"] == "v0005"


def test_held_lock_blocks_registration(tmp_path):
    reg = ModelRegistry(tmp_path)
    reg.root.mkdir(parents=True)
    (reg.root / LOCK_FILE).write_text("123")
    with pytest.raises(RegistryError, match="lock"):
        reg.register(_writer("x"), {"model_version": "m", "run_id": "r"})


def test_tampered_artifact_is_detected_and_not_loaded(tmp_path):
    reg = ModelRegistry(tmp_path)
    e = reg.register(_writer("x"), {"model_version": "m", "run_id": "r"})
    (reg.artifact_dir(e) / "a.txt").write_text("changed")
    assert reg.verify(e) == ["sha256 mismatch for a.txt"]
    with pytest.raises(ModelUnavailableError, match="failed verification"):
        load_model("latest", registry_root=tmp_path)


def test_failed_writer_leaves_no_version(tmp_path):
    reg = ModelRegistry(tmp_path)

    def bad(directory):
        raise OSError("disk full")

    with pytest.raises(OSError):
        reg.register(bad, {"model_version": "m", "run_id": "r"})
    assert reg.entries() == [] and not (tmp_path / "tabnet" / "v0001").exists()
    assert reg.register(_writer("ok"), {"model_version": "m", "run_id": "r"})["registry_version"] == "v0001"


def test_unknown_version_is_refused_by_the_loader(tmp_path):
    """Stage 8 check: an unregistered version never yields a model (N21)."""
    ModelRegistry(tmp_path).register(_writer("x"), {"model_version": "m", "run_id": "r"})
    with pytest.raises(ModelUnavailableError, match="v9999"):
        load_model("v9999", registry_root=tmp_path)
