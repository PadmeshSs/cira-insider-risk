"""Chapter 9 Asset entity, its migration, and the criticality lookup (Bible Ch9 step 3)."""
import asyncio
import importlib.util
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
import sqlalchemy as sa
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy.orm import Session

from app.cri.assets import AssetCriticalityLookup, align, asset_lookup_query, load_asset_lookup
from app.database.base import Base
from app.database.models import Asset

VERSIONS = Path(__file__).resolve().parents[2] / "alembic" / "versions"
CH9_REVISION = "50ba9f46d2ed"


def _module(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_lookup_levels_and_user_day_max():
    lk = AssetCriticalityLookup.from_rows([("pc-0001", "High"), ("PC-0002", "low"), ("PC-0003", None)])
    assert len(lk) == 2 and lk.value("PC-0001") == 0.75 and np.isnan(lk.value("PC-0003")) and np.isnan(lk.value("PC-9"))
    touched = pd.DataFrame({"user_id": ["a", "a", "b", "c"], "date": ["2010-06-01"] * 4,
                            "asset_key": ["PC-0001", "PC-0002", "PC-0002", "PC-0003"]})
    comp = lk.user_day_component(touched)
    got = dict(zip(comp["user_id"], comp["asset_criticality"]))
    assert got["a"] == 0.75 and got["b"] == 0.25 and np.isnan(got["c"])       # unknown stays unknown
    keys = pd.DataFrame({"user_id": ["c", "a", "z"], "date": ["2010-06-01"] * 3})
    v = align(comp, keys)
    assert np.isnan(v[0]) and v[1] == 0.75 and np.isnan(v[2])
    with pytest.raises(ValueError):
        AssetCriticalityLookup.from_rows([("PC-1", "severe")])


def test_orm_constraints_and_lookup_query():
    engine = sa.create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=[Asset.__table__])
    with Session(engine) as s:
        s.add_all([Asset(asset_key="PC-0001", criticality="critical", criticality_source="asset register 2026-09"),
                   Asset(asset_key="PC-0002")])
        s.commit()
        lk = AssetCriticalityLookup.from_rows(s.execute(asset_lookup_query()).all())
    assert dict(lk.levels) == {"PC-0001": "critical"}
    for bad in (dict(asset_key="PC-9", criticality="severe", criticality_source="x"),
                dict(asset_key="PC-8", criticality="high")):                      # a criticality needs a source
        with Session(engine) as s, pytest.raises(sa.exc.IntegrityError):
            s.add(Asset(**bad))
            s.commit()


def test_migration_matches_the_orm():
    """Applying the Chapter 9 migration leaves nothing for autogenerate to add for ``assets``."""
    mig = _module(next(VERSIONS.glob(f"{CH9_REVISION}_*.py")))
    assert mig.revision == CH9_REVISION and mig.down_revision == "123b779f392e"
    mods = [_module(p) for p in VERSIONS.glob("*.py")]
    heads = {m.revision for m in mods} - {m.down_revision for m in mods}
    assert len(heads) == 1                                  # one linear history; later chapters add to it
    parent = {m.revision: m.down_revision for m in mods}
    chain, rev = [], next(iter(heads))
    while rev:
        chain.append(rev)
        rev = parent.get(rev)
    assert CH9_REVISION in chain
    engine = sa.create_engine("sqlite://")
    with engine.begin() as conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            mig.upgrade()
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assets_diff = [d for d in diff if "assets" in repr(d)]
    assert assets_diff == []
    with engine.begin() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            mig.downgrade()
        assert "assets" not in sa.inspect(conn).get_table_names()


def test_async_loader_uses_the_session():
    class _Result:
        def all(self):
            return [("PC-0001", "medium")]

    class _Session:
        async def execute(self, stmt):
            assert "assets" in str(stmt) and "criticality IS NOT NULL" in str(stmt)
            return _Result()

    lk = asyncio.run(load_asset_lookup(_Session()))
    assert lk.value("PC-0001") == 0.5
