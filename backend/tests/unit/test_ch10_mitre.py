"""Chapter 10 unit tests: technique table, rules, rarity reference, enricher, entity, isolation."""
import ast
import importlib.util
import json
from dataclasses import replace
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
import sqlalchemy as sa
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy.orm import Session

from app.cri.config import CRIConfig
from app.database.base import Base
from app.database.models import MITREMapping
from app.mitre import mapping_rules
from app.mitre.enrich import CONTEXT_COLUMNS, MATCH_COLUMNS, MitreEnricher, MitreInputError, MitreUnavailableError
from app.mitre.mapping_rules import NOT_MAPPED, RULES, required_columns, ruleset_hash, validate_rules
from app.mitre.reference import (
    DEFINITION_VERSION,
    LoadedReference,
    MitreReferenceUnavailableError,
    fit_maps,
    load_reference,
    save_reference,
)
from app.mitre.runtime import MitreRuntime
from app.mitre.techniques import (
    PINNED_BUNDLE_SHA256,
    PINNED_VERSION,
    TechniqueTableError,
    load_technique_table,
    table_path,
)

VERSIONS = Path(__file__).resolve().parents[2] / "alembic" / "versions"
CH10_REVISION = "7c1e4a9d2b60"
SERVING = ("techniques", "mapping_rules", "reference", "enrich", "runtime", "sources", "calibrate", "batch")


@pytest.fixture(scope="module")
def table():
    return load_technique_table(env={})


def _frame(n=400, seed=0):
    """A synthetic reference: R01 common, R03 occasional, R02/R04 rare."""
    rng = np.random.default_rng(seed)
    return pd.DataFrame({
        "user_id": [f"u{i % 40:03d}" for i in range(n)],
        "date": [f"2010-{1 + (i // 40) % 12:02d}-{1 + i % 28:02d}" for i in range(n)],
        "file_event_count": rng.poisson(0.8, n).astype("float64"),
        "http_cloud_storage_count": (rng.random(n) < 0.1) * rng.integers(1, 5, n).astype("float64"),
        "http_leak_paste_count": (rng.random(n) < 0.005).astype("float64"),
        "http_hacking_tools_count": (rng.random(n) < 0.005).astype("float64"),
        "http_job_search_count": (rng.random(n) < 0.05).astype("float64"),
        "new_device_count": (rng.random(n) < 0.1).astype("float64"),
        "file_archive_or_executable_count": (rng.random(n) < 0.1).astype("float64"),
    })


def _reference(table, frame, decades=5.0) -> LoadedReference:
    meta = {"reference_id": "t-ref", "definition_version": DEFINITION_VERSION, "ruleset_hash": ruleset_hash(),
            "ruleset_version": mapping_rules.RULESET_VERSION, "attack_version": table.attack_version,
            "table_sha256": table.table_sha256, "rarity_decades": decades, "reference": {"part": "validation", "rows": len(frame)},
            "features": {"fingerprint": "x"}}
    return LoadedReference(meta=meta, maps=fit_maps(frame, decades), pin={}, reference_path=Path("."))


# --- technique table ----------------------------------------------------------

def test_table_is_the_pinned_release(table):
    assert table.attack_version == PINNED_VERSION == "19.2" and table.bundle_sha256 == PINNED_BUNDLE_SHA256
    assert table.bundle_modified.startswith("2026-08-05") and len(table.techniques) > 600
    body = json.loads(table_path().read_text(encoding="utf-8"))
    ids = [t["technique_id"] for t in body["techniques"]]
    assert len(ids) == len(set(ids))
    assert table.full_name("T1052.001") == "Exfiltration Over Physical Medium: Exfiltration over USB"
    with pytest.raises(TechniqueTableError):
        table.get("T9999")


def test_an_old_env_version_is_refused():
    with pytest.raises(TechniqueTableError, match="15.1"):
        load_technique_table(env={"MITRE_ATTACK_VERSION": "15.1"})
    assert load_technique_table(env={"MITRE_ATTACK_VERSION": PINNED_VERSION}).attack_version == PINNED_VERSION


def test_a_table_of_another_release_is_refused_under_the_pin(tmp_path, monkeypatch):
    body = json.loads(table_path().read_text(encoding="utf-8"))
    body["attack_version"] = "18.1"
    fake = tmp_path / f"enterprise_attack_v{PINNED_VERSION}.json"
    fake.write_text(json.dumps(body), encoding="utf-8")
    monkeypatch.setattr("app.mitre.techniques.DATA_DIR", tmp_path)
    with pytest.raises(TechniqueTableError, match="18.1"):
        load_technique_table(env={})


# --- rules --------------------------------------------------------------------

def test_every_rule_validates_against_the_bundle(table):
    assert validate_rules(table) == []
    for r in RULES:
        assert r.tactic in table.get(r.technique_id).tactics and r.evidence in ("observed", "indicated")
    for n in NOT_MAPPED:
        assert all(t in table.techniques for t in n.techniques_considered)


def test_a_wrong_tactic_or_retired_technique_is_caught(table, monkeypatch):
    bad = (replace(RULES[0], tactic="collection"), replace(RULES[1], technique_id="T9999"), *RULES[2:])
    monkeypatch.setattr(mapping_rules, "RULES", bad)
    problems = mapping_rules.validate_rules(table)
    assert any("not under tactic" in p for p in problems) and any("T9999" in p for p in problems)


def test_rule_columns_must_exist_in_the_matrix(table):
    assert validate_rules(table, required_columns()) == []
    assert any("file_event_count" in p for p in validate_rules(table, ["user_id", "date"]))


def test_ruleset_hash_tracks_every_rule(monkeypatch):
    h = ruleset_hash()
    monkeypatch.setattr(mapping_rules, "RULES", (replace(RULES[0], evidence="indicated"), *RULES[1:]))
    assert mapping_rules.ruleset_hash() != h


def test_things_nobody_should_map_stay_unmapped():
    mapped = {r.technique_id for r in RULES}
    assert not mapped & {"T1078", "T1056.001", "T1534", "T1048.003", "T1560", "T1537"}
    assert any(n.behaviour == "job-search browsing" and not n.techniques_considered for n in NOT_MAPPED)


# --- rarity reference -----------------------------------------------------------

def test_strength_is_rarity_and_unmapped_is_exactly_zero(table):
    frame = _frame()
    maps = fit_maps(frame, 5.0)
    r01, r02 = RULES[0], RULES[1]
    s = maps.rule_strength(r01, np.array([0.0, 1.0, 2.0, 5.0, np.nan]))
    assert s[0] == 0 and 0 < s[1] <= s[2] <= s[3] <= 1 and np.isnan(s[4])
    assert maps.rule_strength(r02, np.array([1.0]))[0] > maps.rule_strength(r01, np.array([1.0]))[0]   # rare beats common
    assert maps.context(np.array([0.0]))[0] == 0.0 and np.isnan(maps.context(np.array([np.nan]))[0])


def test_stage_two_is_monotone_and_bounded(table):
    maps = fit_maps(_frame(), 5.0)
    x = np.linspace(0, 1, 101)
    v = maps.context(x)
    assert (np.diff(v) >= 0).all() and v.min() >= 0 and v.max() <= 1


def test_reference_pin_is_sha256_checked_and_never_replaced_silently(tmp_path, table):
    frame = _frame()
    meta = {"reference_id": "20260929T000000Z-full-mitre", "created_at": "now", "definition_version": DEFINITION_VERSION,
            "ruleset_version": mapping_rules.RULESET_VERSION, "ruleset_hash": ruleset_hash(),
            "attack_version": table.attack_version, "table_sha256": table.table_sha256, "rarity_decades": 5.0,
            "reference": {"part": "validation", "rows": len(frame)}, "features": {"fingerprint": "abc"}}
    pin = tmp_path / "pin.json"
    save_reference(meta, frame[["user_id", "date", *required_columns()]], models_root=tmp_path, pin_path=pin)
    ref = load_reference(pin, tmp_path, table=table)
    assert ref.reference_id == meta["reference_id"] and ref.describe()["ruleset_hash"] == ruleset_hash()
    with pytest.raises(FileExistsError):
        save_reference({**meta, "reference_id": "other"}, frame, models_root=tmp_path, pin_path=pin)
    (tmp_path / "mitre" / meta["reference_id"] / "reference.json").write_text("{}", encoding="utf-8")
    with pytest.raises(MitreReferenceUnavailableError, match="sha256"):
        load_reference(pin, tmp_path, table=table)


def test_a_reference_for_another_ruleset_is_refused(tmp_path, table, monkeypatch):
    frame = _frame()
    meta = {"reference_id": "r1", "created_at": "now", "definition_version": DEFINITION_VERSION,
            "ruleset_version": "c10-rules-v0", "ruleset_hash": "000000000000", "attack_version": table.attack_version,
            "table_sha256": table.table_sha256, "rarity_decades": 5.0, "reference": {"part": "validation", "rows": 1},
            "features": {"fingerprint": "abc"}}
    save_reference(meta, frame[["user_id", "date", *required_columns()]], models_root=tmp_path, pin_path=tmp_path / "p.json")
    with pytest.raises(MitreReferenceUnavailableError, match="refit"):
        load_reference(tmp_path / "p.json", tmp_path, table=table)


# --- enricher -------------------------------------------------------------------

def test_enrich_statuses_matches_and_traceability(table):
    ref_frame = _frame()
    enricher = MitreEnricher(table, _reference(table, ref_frame))
    rows = pd.DataFrame({
        "user_id": ["A", "b", "c", "d"], "date": ["2010-05-03"] * 4,
        "file_event_count": [3.0, 0.0, 0.0, np.nan],
        "http_cloud_storage_count": [0.0, 0.0, 0.0, np.nan],
        "http_leak_paste_count": [1.0, 0.0, 0.0, np.nan],
        "http_hacking_tools_count": [0.0, 0.0, 0.0, np.nan],
        "http_job_search_count": [0.0, 4.0, 0.0, 0.0],
        "new_device_count": [0.0, 0.0, 1.0, 0.0],
        "file_archive_or_executable_count": [0.0, 0.0, 0.0, 0.0],
    })
    out = enricher.enrich(rows)
    ctx, m = out.context, out.matches
    assert list(ctx.columns) == list(CONTEXT_COLUMNS) and list(m.columns) == list(MATCH_COLUMNS)
    assert ctx["mitre_status"].tolist() == ["mapped", "unmapped", "unmapped", "not_evaluated"]
    assert ctx["user_id"].iloc[0] == "a"                                          # keys normalised like every chapter
    v = ctx["mitre_context"].to_numpy()
    assert 0 < v[0] <= 1 and v[1] == 0 and v[2] == 0 and np.isnan(v[3])
    assert ctx["mitre_top_rule"].iloc[0] == "R02_leak_site_access"                # the rare rule is the strongest
    assert ctx["mitre_techniques"].iloc[0] == "T1052.001,T1567" and ctx["mitre_match_count"].iloc[0] == 2
    assert ctx["mitre_unmapped_behaviours"].iloc[1] == "job-search browsing"
    assert "logon from a PC" in ctx["mitre_unmapped_behaviours"].iloc[2]
    assert pd.isna(ctx["mitre_top_technique"].iloc[1]) and pd.isna(ctx["mitre_techniques"].iloc[1])
    assert len(m) == 2 and set(m["user_id"]) == {"a"}
    usb = m[m["rule_id"] == "R01_removable_media_copy"].iloc[0]
    assert usb["technique_id"] == "T1052.001" and usb["tactic"] == "exfiltration" and usb["evidence"] == "observed"
    assert usb["trigger_column"] == "file_event_count" and usb["trigger_value"] == 3.0 and 0 < usb["strength"] <= 1
    assert usb["technique_url"].endswith("/T1052/001") and usb["attack_version"] == "19.2"


def test_enrich_event_equals_the_vectorised_row(table):
    enricher = MitreEnricher(table, _reference(table, _frame()))
    fv = {"file_event_count": 1, "http_cloud_storage_count": 2, "http_leak_paste_count": 0,
          "http_hacking_tools_count": 1, "http_job_search_count": 1, "unrelated": 9}
    one = enricher.enrich_event(fv, user_id="X", date="2010-02-02")
    frame = pd.DataFrame([{"user_id": "X", "date": "2010-02-02", **{k: float(v) for k, v in fv.items()}}])
    batch = enricher.enrich(frame).context.iloc[0]
    assert one["mitre_context"] == batch["mitre_context"] and one["mitre_techniques"] == batch["mitre_techniques"]
    assert {x["rule_id"] for x in one["matches"]} == {"R01_removable_media_copy", "R03_cloud_storage_access",
                                                      "R04_attack_tool_site_access"}


def test_enrich_refuses_missing_columns_and_a_foreign_reference(table):
    enricher = MitreEnricher(table, _reference(table, _frame()))
    with pytest.raises(MitreInputError):
        enricher.enrich(pd.DataFrame({"user_id": ["a"], "date": ["2010-01-01"]}))
    ref = _reference(table, _frame())
    ref.meta["table_sha256"] = "not-this-table"
    with pytest.raises(MitreUnavailableError):
        MitreEnricher(table, ref)


def test_the_cri_accepts_mitre_context_on_its_scale(table):
    """The enrichment's output is what the CRI engine expects (N33): [0, 1], 0 = no technique, null = not evaluated."""
    ctx = MitreEnricher(table, _reference(table, _frame())).enrich(_frame(50, seed=3)).context
    v = ctx["mitre_context"].to_numpy(dtype="float64")
    assert np.nanmin(v) >= 0 and np.nanmax(v) <= 1
    assert CRIConfig().effective_weights({"anomaly", "historical_deviation", "peer_deviation", "user_context",
                                          "mitre_context"})["anomaly"] == pytest.approx(0.60)


def test_runtime_is_unavailable_with_a_reason_without_a_pin(tmp_path):
    rt = MitreRuntime.load(pin_path=tmp_path / "none.json", models_root=tmp_path)
    assert not rt.available and "calibrate" in rt.status()["reason"]
    with pytest.raises(MitreUnavailableError):
        rt.enricher()


def test_formula_hash_changes_when_mitre_joins():
    from app.cri.batch import formula_hash

    cfg = CRIConfig()
    base = {"anomaly", "historical_deviation", "peer_deviation", "user_context"}
    a = formula_hash(cfg, base, None)
    b = formula_hash(cfg, base | {"mitre_context"}, {"ruleset_hash": ruleset_hash(), "reference_id": "r"})
    assert a != b and a == formula_hash(cfg, set(base), None)


# --- isolation (N5, N42) ----------------------------------------------------------

def test_serving_modules_never_import_labels_models_or_offline_code():
    import app.mitre as pkg

    for name in SERVING:
        tree = ast.parse((Path(pkg.__file__).parent / f"{name}.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                mods = [((".") * node.level) + (node.module or "")]
            elif isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            else:
                continue
            for m in mods:
                assert "ground_truth" not in m and "evaluation.labels" not in m and "evaluation.metrics" not in m, (name, m)
                assert not m.endswith("evaluate") and "stix_loader" not in m and "mitreattack" not in m, (name, m)
                assert "app.scoring" not in m and "app.tabnet.infer" not in m and "app.baselines" not in m, (name, m)


def test_only_the_offline_loader_imports_mitreattack():
    import app.mitre as pkg

    users = []
    for p in Path(pkg.__file__).parent.glob("*.py"):
        for node in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
            mods = ([node.module or ""] if isinstance(node, ast.ImportFrom)
                    else [a.name for a in node.names] if isinstance(node, ast.Import) else [])
            if any(m.startswith(("mitreattack", "stix2")) for m in mods):
                users.append(p.stem)
    assert sorted(set(users)) == ["stix_loader"]


# --- entity + migration -------------------------------------------------------------

def _row(**kw):
    base = dict(user_id="ACM2278", activity_date=pd.Timestamp("2010-06-01").date(), ruleset_version="c10-rules-v1",
                ruleset_hash="abc", attack_version="19.2", reference_id="r", mitre_run_id="m")
    return MITREMapping(**{**base, **kw})


def test_entity_refuses_a_forced_or_untraceable_mapping():
    engine = sa.create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=[MITREMapping.__table__])
    with Session(engine) as s:
        s.add_all([_row(status="mapped", technique_id="T1052.001", tactic="exfiltration", rule_id="R01_removable_media_copy",
                        evidence="observed", trigger_column="file_event_count", trigger_value=3.0, strength=0.2,
                        mitre_context=0.3),
                   _row(status="unmapped", mitre_context=0.0, unmapped_behaviours=["job-search browsing"])])
        s.commit()
    for bad in (dict(status="mapped", technique_id="T1052.001"),                      # no rule / tactic / column
                dict(status="unmapped", technique_id="T1567"),                        # an unmapped row names a technique
                dict(status="guessed"),
                dict(status="unmapped", mitre_context=1.5),
                dict(status="mapped", technique_id="T1567", tactic="exfiltration", rule_id="R02", evidence="suspected",
                     trigger_column="http_leak_paste_count")):
        with Session(engine) as s, pytest.raises(sa.exc.IntegrityError):
            s.add(_row(**bad))
            s.commit()


def _module(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_migration_is_the_head_and_matches_the_orm():
    mig = _module(next(VERSIONS.glob(f"{CH10_REVISION}_*.py")))
    assert mig.revision == CH10_REVISION and mig.down_revision == "50ba9f46d2ed"
    mods = [_module(p) for p in VERSIONS.glob("*.py")]
    assert {m.revision for m in mods} - {m.down_revision for m in mods} == {CH10_REVISION}
    engine = sa.create_engine("sqlite://")
    with engine.begin() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            mig.upgrade()
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert [d for d in diff if "mitre_mappings" in repr(d)] == []
    with engine.begin() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            mig.downgrade()
        assert "mitre_mappings" not in sa.inspect(conn).get_table_names()


def test_env_example_pins_the_same_release():
    env = {}
    for line in (Path(__file__).resolve().parents[3] / ".env.example").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip()
    assert env.get("MITRE_ATTACK_VERSION") == PINNED_VERSION
    assert "MITRE_MAPPING_CONFIDENCE_THRESHOLD" not in env                   # Chapter 1 placeholder; nothing reads it
