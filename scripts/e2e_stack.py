"""Chapter 15: the e2e stack as a running API, for the Playwright click-through.

    python scripts/e2e_stack.py build      # raw CSV -> Chapters 5-12 -> fresh PostgreSQL -> load; writes .e2e/stack.json
    python scripts/e2e_stack.py serve      # uvicorn on that database at 127.0.0.1:8765 (blocks)
    python scripts/e2e_stack.py teardown   # drops the database, removes .e2e/

PostgreSQL comes from CIRA_E2E_DATABASE_URL (a server where a fresh database
may be created) or testcontainers, exactly as in the pytest suite. With
testcontainers the container lives only as long as ``build`` runs, so for
the click-through use CIRA_E2E_DATABASE_URL (for example the docker-compose
postgres: postgresql+asyncpg://cira:<password>@localhost:5433/postgres).

The stack is synthetic CERT-shaped data built by tests/fixtures. It proves the
code path end to end; it says nothing about detection on CERT r4.2.
Nothing here is imported by the application.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
E2E_DIR = REPO / ".e2e"
MANIFEST = E2E_DIR / "stack.json"
sys.path[:0] = [str(REPO / "backend"), str(REPO / "backend" / "tests"), str(REPO / "backend" / "tests" / "e2e")]


def build(args) -> int:
    import ch15_stack

    if MANIFEST.exists():
        print(f"{MANIFEST} exists; run teardown first", file=sys.stderr)
        return 2
    if not os.getenv("CIRA_E2E_DATABASE_URL"):
        print("note: without CIRA_E2E_DATABASE_URL the database is a testcontainers container that stops when this "
              "command ends, so `serve` will not find it", file=sys.stderr)
    try:
        stack = ch15_stack.build_stack(E2E_DIR / "world")
    except ch15_stack.StackUnavailable as exc:
        print(f"cannot build the stack: {exc}", file=sys.stderr)
        return 3
    ch15_stack.write_manifest(stack, MANIFEST)
    t = stack.trace
    print(f"[e2e] database {stack.db.name} ({stack.db.kind}) at {stack.alembic_revision}, alert run {stack.alert_run_id}")
    print(f"[e2e] traced raw row: {t['domain']} {t['raw_id']} of {t['user_id']} on {t['date']} "
          f"(alert {t['alert_key']})")
    print(f"[e2e] build {stack.build_seconds}; manifest {MANIFEST}")
    return 0


def serve(args) -> int:
    if not MANIFEST.exists():
        print("no stack: run `python scripts/e2e_stack.py build` first", file=sys.stderr)
        return 2
    m = json.loads(MANIFEST.read_text(encoding="utf-8"))
    for k in [k for k in os.environ if k.startswith(("CRI_", "MITRE_"))]:
        del os.environ[k]
    os.environ.update(m["pins"])
    os.environ.update({"DATABASE_URL": m["database"]["url"], "SECRET_KEY": m["secret"],
                       "POSTGRES_PASSWORD": os.getenv("POSTGRES_PASSWORD", "unused-by-the-api"),
                       "CORS_ORIGINS": args.cors, "ENVIRONMENT": "e2e", "ACCESS_TOKEN_MINUTES": "120"})
    import uvicorn

    print(f"[e2e] serving {m['alert_run_id']} from {m['database']['name']} on http://{args.host}:{args.port}", flush=True)
    uvicorn.run("app.main:app", host=args.host, port=args.port, log_level="warning")
    return 0


def teardown(args) -> int:
    import ch15_stack

    if MANIFEST.exists():
        m = json.loads(MANIFEST.read_text(encoding="utf-8"))
        from sqlalchemy.engine import make_url

        admin = os.getenv("CIRA_E2E_DATABASE_URL")
        if admin and m["database"]["kind"].startswith("server"):
            ch15_stack.Database(url=m["database"]["url"], kind=m["database"]["kind"], name=m["database"]["name"],
                                admin_url=ch15_stack._as_asyncpg(admin)).drop()
            print(f"[e2e] dropped {m['database']['name']} on {make_url(admin).host}")
    shutil.rmtree(E2E_DIR, ignore_errors=True)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build")
    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--cors", default="http://127.0.0.1:5174,http://localhost:5174")
    sub.add_parser("teardown")
    args = p.parse_args(argv)
    return {"build": build, "serve": serve, "teardown": teardown}[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
