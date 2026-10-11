"""Verify Chapter 19: the repository is ready to submit, and every claim it makes about itself is backed.

Sections (each check prints PASS, WARN or FAIL; exit code 1 on any FAIL):

    preflight   no untracked files or unstaged deletions: every later section reads git's index, not the disk.
    governance  CLAUDE.md, CIRA_FINAL_ARCHITECTURE.md and CIRA_IMPLEMENTATION_BIBLE.md at the root and the HCEA
                under docs/governance/; every repository path the README and the status table cite exists.
    readme      README.md is a real README: setup, per-chapter run steps, tests, reproducing Chapter 16, the
                status table. Its opening names the served XGBoost and the shadow TabNet (N71). Rows 17-18 are
                not claimed, and row 19 says IMPLEMENTED only once the audit names a passing run.
    status      docs/COMPONENT_STATUS.md has every Appendix B component, one taxonomy status each, evidence that
                exists for every claimed one, and no production extension claimed without code in the repository
                to back it. The TWOS row equals the loader's own TWOS_RELEASE_STATUS.
    structure   every Bible §2 path exists or is listed in docs/STRUCTURE.md; every tracked top-level entry is in
                §2 or listed as an addition; no scratch files; every script under scripts/ is referenced somewhere.
    secrets     no .env (other than the examples) was ever added to git; no private key, cloud or GitHub token,
                real SECRET_KEY or real database password in any commit; .gitignore covers .env; every environment
                variable the code reads is documented in an .env.example.
    lockfile    backend/requirements.lock.txt pins the libraries the reported models depend on (N87).
    regression  the final Chapter 15 run (N70, Bible Ch19 step 1): scripts/verify_chapter15.py with --browser and
                the CERT checks, 0 FAIL; and scripts/verify_chapter16.py --no-tests: the pinned readout and the
                report still agree (with --recompute, the rankings are recomputed from the stored scores too).
    notes       N82-N87 in docs/CARRY_FORWARD.md with table rows; the chapter and audit documents exist.

Release mode (``--release``, after the tag) runs only the release checks and writes nothing, so the tree stays
clean: HEAD carries an annotated v* tag, the tree is clean, the audit names a chapter19_verification run with
0 FAIL, and N82 is retired.

Usage, from the repository root (PostgreSQL reachable, the CERT API on :8000 for the CERT checks):

    python scripts/verify_chapter19.py --browser --cert-username <analyst> --cert-database-url "<DATABASE_URL>" --recompute
    python scripts/verify_chapter19.py --skip-regression             # static checks only (the regression rows FAIL)
    python scripts/verify_chapter19.py --finalize <stamp>            # write a passing run into the audit, README, N82
    python scripts/verify_chapter19.py --release                     # after `git tag -a v1.0.0`

Writes experiments/results/chapter19/verification_<stamp>.json and .md and one ``chapter19_verification``
runlog line. Reads no label.
"""
from __future__ import annotations

import argparse
import functools
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))
sys.path.insert(0, str(REPO / "scripts"))

from verify_chapter15 import Checks  # noqa: E402

from app.core.run_stamp import utc_run_stamp  # noqa: E402  (N74)

RUNLOG = Path(os.getenv("CIRA_RUNLOG", str(REPO / "experiments" / "runlog.jsonl")))  # same override as the pipeline
README = REPO / "README.md"
STATUS = REPO / "docs" / "COMPONENT_STATUS.md"
STRUCTURE = REPO / "docs" / "STRUCTURE.md"
AUDIT = REPO / "docs" / "audits" / "chapter_19_audit.md"
CHAPTER_DOC = REPO / "docs" / "chapters" / "chapter_19_finalization.md"
CARRY = REPO / "docs" / "CARRY_FORWARD.md"
LOCK = REPO / "backend" / "requirements.lock.txt"
NOTES = [f"N{n}" for n in range(82, 88)]
TAXONOMY = ("IMPLEMENTED", "PARTIALLY IMPLEMENTED", "PLANNED", "OPTIONAL", "PRODUCTION EXTENSION")
AUDIT_MARK_BEGIN = "<!-- ch19-result:begin -->"
AUDIT_MARK_END = "<!-- ch19-result:end -->"

GOVERNING = ("CLAUDE.md", "CIRA_FINAL_ARCHITECTURE.md", "CIRA_IMPLEMENTATION_BIBLE.md",
             "docs/governance/CIRA_Hardware_Constrained_Execution_Addendum_v1_0.pdf")

# Bible Appendix B, plus the FYP compose row the Bible's §1 table implies. Name -> production extension?
COMPONENTS: dict[str, bool] = {
    "Repository foundation": False, "DB/FastAPI skeleton": False, "CERT ingestion": False, "TWOS ingestion": False,
    "Preprocessing": False, "Feature engineering": False, "Baselines (rule/IF/LOF/LSTM-AE/GBDT)": False,
    "TabNet": False, "Anomaly scoring service": False, "CRI": False, "MITRE enrichment": False,
    "Explainability (masks + SHAP)": False, "Alert correlation/persistence": False, "FastAPI full integration": False,
    "React dashboard": False, "E2E validation": False, "Evaluation/ablations": False,
    "Docker Compose (FYP baseline)": False,
    "Kafka/Redpanda": True, "Redis": True, "Celery": True, "SSE": True, "OpenSearch": True,
    "Prometheus/Grafana": True, "Auth/RBAC hardening": True, "Docker productionization": True,
    "Kubernetes": True, "CI/CD": True,
}

# What would have to exist in the repository before a production row could say IMPLEMENTED.
PRODUCTION_EVIDENCE: dict[str, tuple[str, ...]] = {
    "Kafka/Redpanda": ("req:kafka", "req:confluent", "req:aiokafka"),
    "Redis": ("req:redis",),
    "Celery": ("req:celery",),
    "SSE": ("code:EventSourceResponse", "code:text/event-stream"),
    "OpenSearch": ("req:opensearch",),
    "Prometheus/Grafana": ("req:prometheus",),
    "Docker productionization": ("file:docker-compose.prod.yml",),
    "Kubernetes": ("dir:k8s", "dir:deploy/k8s", "dir:helm"),
    "CI/CD": ("dir:.github/workflows",),
    "Auth/RBAC hardening": ("code:require_role",),
}

# Bible §2, the paths it names. Brace groups are expanded by hand so the list is greppable.
BIBLE_PATHS = [
    "CLAUDE.md", "CIRA_FINAL_ARCHITECTURE.md", "CIRA_IMPLEMENTATION_BIBLE.md", "README.md", ".env.example",
    ".gitignore", "docker-compose.yml", "docker-compose.prod.yml",
    "backend/pyproject.toml", "backend/requirements.txt", "backend/alembic.ini", "backend/alembic/env.py",
    "backend/alembic/versions", "backend/app/main.py",
    "backend/app/core/config.py", "backend/app/core/logging.py", "backend/app/core/security.py",
    "backend/app/database/session.py", "backend/app/database/base.py", "backend/app/database/models",
    "backend/app/ingestion/cert_loader.py", "backend/app/ingestion/twos_loader.py",
    "backend/app/preprocessing/normalize.py", "backend/app/preprocessing/validate.py",
    *[f"backend/app/feature_engineering/{m}.py" for m in (
        "authentication", "file_activity", "email", "usb", "network", "application", "temporal",
        "historical_baseline", "peer_group", "pipeline")],
    *[f"backend/app/baselines/{m}.py" for m in ("rule_based", "isolation_forest", "lof", "lstm_autoencoder", "gbdt")],
    *[f"backend/app/tabnet/{m}.py" for m in ("dataset", "train", "infer", "model_registry")],
    "backend/app/cri/config.py", "backend/app/cri/engine.py",
    "backend/app/mitre/stix_loader.py", "backend/app/mitre/mapping_rules.py", "backend/app/mitre/enrich.py",
    "backend/app/explainability/tabnet_masks.py", "backend/app/explainability/shap_explainer.py",
    "backend/app/explainability/reason_builder.py",
    "backend/app/alerts/correlation.py", "backend/app/alerts/deduplication.py",
    "backend/app/api/deps.py",
    *[f"backend/app/api/v1/{m}.py" for m in (
        "auth", "users", "events", "features", "anomaly", "risk", "alerts", "investigations", "mitre",
        "explanations", "models", "health")],
    "backend/app/schemas", "backend/app/services",
    "backend/app/evaluation/metrics.py", "backend/app/evaluation/splitting.py", "backend/app/evaluation/ablation.py",
    "backend/app/utils", "backend/tests/unit", "backend/tests/integration", "backend/tests/e2e",
    "frontend/package.json", "frontend/vite.config.ts", "frontend/tsconfig.json", "frontend/src/main.tsx",
    "frontend/src/App.tsx", "frontend/src/components/common", "frontend/src/components/layout",
    "frontend/src/components/ui", "frontend/src/pages", "frontend/src/hooks", "frontend/src/services",
    "frontend/src/store", "frontend/src/utils", "frontend/src/constants", "frontend/src/types",
    "datasets/raw", "datasets/processed", "datasets/sample",
    "models/saved_models", "models/checkpoints", "models/artifacts",
    "experiments", "notebooks", "tests", "docker/backend.Dockerfile", "docker/frontend.Dockerfile",
    "docker/postgres/init.sql",
]
BIBLE_TOP = {p.split("/")[0] for p in BIBLE_PATHS}

SCRATCH = [re.compile(p) for p in (r"(^|/)[^/]* copy(\.[^/]*)?$", r"(^|/)scratch", r"(^|/)show_ch\d+_open\.py$",
                                   r"\.(orig|rej|bak|swp)$", r"(^|/)(\.DS_Store|Thumbs\.db)$")]

# Read by code, deliberately not in any .env.example.
ENV_NOT_IN_EXAMPLE = {"CIRA_ANALYST_PASSWORD": "a password, typed at a prompt or set for one command; never in a file"}

PLACEHOLDER_SECRETS = {"changeme", "changeme-generate-a-real-secret", "cira", "postgres", "password", "test", "secret",
                       "pw", "pass", "x"}


# ----------------------------------------------------------------------------------------------- helpers

def git(*args: str) -> str:
    p = subprocess.run(["git", *args], check=False, cwd=REPO, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if p.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {p.stderr.strip()[:200]}")
    return p.stdout


@functools.lru_cache(maxsize=1)
def tracked() -> list[str]:
    return [x for x in git("ls-files").splitlines() if x]


def read(p: Path) -> str:
    return p.read_text(encoding="utf-8") if p.exists() else ""


def runlog() -> list[dict]:
    out = []
    for line in read(RUNLOG).splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def counts_of(line: dict) -> dict:
    c = line.get("counts") or line
    return {k: int(c.get(k, 0)) for k in ("PASS", "WARN", "FAIL")}


def table_rows(text: str) -> list[list[str]]:
    rows = []
    for ln in text.splitlines():
        if ln.startswith("|") and not re.match(r"^\|\s*-", ln):
            rows.append([c.strip() for c in ln.strip().strip("|").split("|")])
    return rows


PATH_RE = re.compile(r"`((?:\.?[A-Za-z0-9_\-]+/)+[A-Za-z0-9_.\-]+|[A-Za-z0-9_\-]+\.(?:md|pdf|yml|ini|txt))`")
SKIP_PREFIXES = ("experiments/results/", "models/", "datasets/", "frontend/node_modules", "frontend/dist", ".e2e/",
                 "ch15-run-through/", "D:/", "backend/venv", "experiments/splits/user_split_<")


def cited_paths(text: str) -> list[str]:
    out = []
    for m in PATH_RE.finditer(text):
        p = m.group(1).rstrip("/.")
        if any(ch in p for ch in "<>*$") or p.startswith(SKIP_PREFIXES) or p.startswith("http"):
            continue
        if "/" not in p and not p.startswith(("CIRA_", "CLAUDE", "README")):
            continue
        if re.match(r"^[a-z_]+/[a-z_]+$", p) and not (REPO / p).exists() and p.split("/")[0] not in BIBLE_TOP:
            continue                                   # e.g. "full/user", a profile/split pair, not a path
        out.append(p)
    return sorted(set(out))


def resolve_cited(p: str) -> bool:
    for base in (REPO, REPO / "backend", REPO / "frontend"):
        if (base / p).exists():
            return True
    return False


# ----------------------------------------------------------------------------------------------- sections

def preflight(c: Checks) -> bool:
    """The structure, status and secrets checks read git's file list, so the patch has to be in the index."""
    st = [x for x in git("status", "--porcelain", "--untracked-files=all").splitlines() if x]
    untracked = [x[3:] for x in st if x.startswith("??")]
    removed = [x[3:] for x in st if x[1] == "D"]
    c.ok("preflight", "no untracked files and no unstaged deletions (the checks read git's index)",
         not untracked and not removed,
         ("untracked: " + ", ".join(untracked[:4]) + ("; " if removed else "") if untracked else "")
         + ("deleted but still tracked: " + ", ".join(removed[:4]) if removed else "")
         + ("  -> run `git add -A` (or commit) and run again" if untracked or removed else ""))
    return not untracked and not removed


def governance(c: Checks) -> None:
    for g in GOVERNING:
        c.ok("governance", f"{g} is in the repository", (REPO / g).exists())
    for doc in (README, STATUS):
        missing = [p for p in cited_paths(read(doc)) if not resolve_cited(p)]
        c.ok("governance", f"every path {doc.relative_to(REPO).as_posix()} cites exists", not missing,
             ", ".join(missing[:6]) or f"{len(cited_paths(read(doc)))} paths")


def readme(c: Checks, audit_ok: bool) -> None:
    text = read(README)
    c.ok("readme", "README.md is not a placeholder (200+ lines)", len(text.splitlines()) >= 200, f"{len(text.splitlines())} lines")
    heads = [h.strip("# ").strip() for h in text.splitlines() if h.startswith("## ")]
    need = ("Setup", "Status", "Tests", "Reproducing the Chapter 16 evaluation", "Running Chapters 3 and 4",
            "Running Chapter 14", "Chapter 19: final verification and release")
    miss = [h for h in need if h not in heads]
    c.ok("readme", "README has setup, run steps for every chapter, tests and reproduction", not miss, ", ".join(miss) or "all present")
    intro = text.split("## ", 1)[0]
    c.ok("readme", "the opening names the served XGBoost and the shadow TabNet (N71)",
         "XGBoost" in intro and "shadow" in intro and "with TabNet" not in intro)
    rows = {r[0]: r for r in table_rows(text) if r and re.match(r"^\d+(-\d+)?$", r[0])}
    for ch in [str(n) for n in range(1, 17)]:
        if ch not in rows:
            c.add("readme", f"status row for Chapter {ch}", "FAIL", "missing")
    c.ok("readme", "status rows for Chapters 1-16 present", all(str(n) in rows for n in range(1, 17)))
    prod = rows.get("17-18", [""])
    c.ok("readme", "Chapters 17-18 are not claimed", "NOT IMPLEMENTED" in " ".join(prod) or "PRODUCTION EXTENSION" in " ".join(prod),
         " | ".join(prod)[:120])
    r19 = " ".join(rows.get("19", []))
    c.ok("readme", "a status row for Chapter 19 exists", bool(r19))
    claims = "IMPLEMENTED" in r19 and "PARTIALLY" not in r19
    c.ok("readme", "row 19 says IMPLEMENTED only if the audit names a passing run", claims <= audit_ok,
         "status follows the evidence (N82)")
    c.ok("readme", "README points at docs/COMPONENT_STATUS.md", "docs/COMPONENT_STATUS.md" in text)


_TRACKED_TEXT: dict[str, str] = {}


def tracked_text(prefixes: tuple[str, ...], suffixes: tuple[str, ...]) -> str:
    """The text of tracked files under ``prefixes`` ending in ``suffixes``, each file read once.

    Reads git's file list, never the disk tree: a virtualenv inside backend/ (backend\\venv on the development
    machine) holds tens of thousands of .py files that are not the project's.
    """
    parts = []
    for f in tracked():
        if f.startswith(prefixes) and f.endswith(suffixes) and (REPO / f).is_file():
            if f not in _TRACKED_TEXT:
                _TRACKED_TEXT[f] = (REPO / f).read_text(encoding="utf-8", errors="replace")
            parts.append(_TRACKED_TEXT[f])
    return "\n".join(parts)


def _production_backed(name: str) -> tuple[bool, str]:
    req = (read(REPO / "backend" / "requirements.txt") + read(LOCK)).lower()
    code = tracked_text(("backend/app/",), (".py",))
    for ev in PRODUCTION_EVIDENCE.get(name, ()):
        kind, what = ev.split(":", 1)
        if kind == "req" and re.search(rf"(^|\n){re.escape(what)}", req):
            return True, ev
        if kind == "code" and what in code:
            return True, ev
        if kind in ("file", "dir") and (REPO / what).exists():
            return True, ev
    return False, "nothing in the repository backs it"


def status(c: Checks) -> None:
    text = read(STATUS)
    if not text:
        c.add("status", "docs/COMPONENT_STATUS.md exists", "FAIL", "missing")
        return
    rows = {r[0]: r for r in table_rows(text) if len(r) >= 3}
    missing = [n for n in COMPONENTS if n not in rows]
    c.ok("status", "every Appendix B component has a row", not missing, ", ".join(missing) or f"{len(COMPONENTS)} rows")
    bad_status, bad_evidence, overclaimed = [], [], []
    for name, prod in COMPONENTS.items():
        if name not in rows:
            continue
        st, ev = rows[name][1], rows[name][2]
        base = next((t for t in sorted(TAXONOMY, key=len, reverse=True) if st.startswith(t)), None)
        if base is None:
            bad_status.append(f"{name}: {st}")
            continue
        if base in ("IMPLEMENTED", "PARTIALLY IMPLEMENTED"):
            cited = cited_paths(ev)
            if not cited or not all(resolve_cited(p) for p in cited):
                bad_evidence.append(name)
        if prod and base in ("IMPLEMENTED", "PARTIALLY IMPLEMENTED"):
            backed, why = _production_backed(name)
            if not backed:
                overclaimed.append(f"{name} ({why})")
    c.ok("status", "every status is one of the Bible's five", not bad_status, "; ".join(bad_status))
    c.ok("status", "every claimed component cites evidence that exists", not bad_evidence, ", ".join(bad_evidence))
    c.ok("status", "no production extension claimed without code that backs it", not overclaimed, "; ".join(overclaimed))
    loader = read(REPO / "backend" / "app" / "ingestion" / "twos_loader.py")
    m = re.search(r'^TWOS_RELEASE_STATUS\s*=\s*"([A-Z\- ]+)"', loader, re.MULTILINE)
    want = m.group(1) if m else "?"
    got = rows.get("TWOS ingestion", ["", ""])[1]
    c.ok("status", "TWOS row equals the loader's TWOS_RELEASE_STATUS", got.startswith(want), f"loader {want}, table {got}")


def structure(c: Checks, files: list[str]) -> None:
    doc = read(STRUCTURE)
    if not doc:
        c.add("structure", "docs/STRUCTURE.md exists", "FAIL", "missing")
        return
    in_git = set(files)

    def tracked_path(p: str) -> bool:                     # a tracked file, or a folder holding one
        return p in in_git or any(f.startswith(p.rstrip("/") + "/") for f in in_git)

    absent = [p for p in BIBLE_PATHS if not tracked_path(p)]
    undocumented = [p for p in absent if f"`{p}`" not in doc]
    c.ok("structure", "every Bible §2 path is tracked or is a documented deviation", not undocumented,
         ", ".join(undocumented[:6]) or f"{len(absent)} documented deviations")
    stale = [p for p in BIBLE_PATHS if tracked_path(p) and re.search(rf"\|\s*`{re.escape(p)}`\s*\|", doc)]
    c.ok("structure", "no listed deviation is tracked in git now", not stale, ", ".join(stale))
    top = sorted({f.split("/")[0] for f in files})
    extra = [t for t in top if t not in BIBLE_TOP and f"`{t}`" not in doc and f"`{t}/`" not in doc]
    c.ok("structure", "every tracked top-level entry is in §2 or listed as an addition", not extra, ", ".join(extra))
    scratch = [f for f in files if any(r.search(f) for r in SCRATCH)]
    c.ok("structure", "no scratch or backup files tracked", not scratch, ", ".join(scratch[:6]))
    corpus = "\n".join((read(README), read(REPO / "frontend" / "README.md"),
                        tracked_text(("docs/", "scripts/", "backend/"), (".md", ".py"))))
    orphans = []
    for s in sorted(REPO / f for f in files if f.startswith("scripts/") and f.endswith(".py") and "/" not in f[8:]):
        if not s.is_file():                       # tracked but deleted on disk: preflight already reports it
            continue
        n = len(re.findall(re.escape(s.name), corpus)) + len(re.findall(rf"\bimport {s.stem}\b|from {s.stem} import", corpus))
        own = len(re.findall(re.escape(s.name), s.read_text(encoding="utf-8", errors="replace")))
        if n - own <= 0:
            orphans.append(s.name)
    c.ok("structure", "every script under scripts/ is referenced by the docs or another script", not orphans, ", ".join(orphans))


SECRET_PATTERNS = [
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("SECRET_KEY value", re.compile(r"""\bSECRET_KEY\s*[=:]\s*["']?([A-Za-z0-9_\-+/=]{16,})""")),
    ("database password", re.compile(r"postgres(?:ql)?(?:\+\w+)?://[^:/\s\"']+:([^@\s\"']+)@")),
]


def _is_placeholder(value: str) -> bool:
    v = value.strip("'\"").lower()
    if v and set(v) == {"*"}:                    # SQLAlchemy's rendered URL hides the password as ***
        return True
    return (v in PLACEHOLDER_SECRETS or v.startswith(("changeme", "$", "<", "{", "%", "test", "dummy", "fake", "example"))
            or "placeholder" in v or "generate" in v or "your" in v or "x" * 6 in v)


def secrets(c: Checks) -> None:
    added = [x for x in git("log", "--all", "--diff-filter=A", "--name-only", "--format=").splitlines() if x]
    envs = [x for x in added if re.search(r"(^|/)\.env($|\.)", x) and not x.endswith(".env.example")]
    c.ok("secrets", "no .env file was ever added to git", not envs, ", ".join(sorted(set(envs))))
    hits = []
    commit = ""
    path = ""
    for ln in git("log", "--all", "-p", "--no-color", "--format=commit %h").splitlines():
        if ln.startswith("commit "):
            commit = ln[7:].strip()
            continue
        if ln.startswith("+++ "):
            path = ln[6:] if ln.startswith("+++ b/") else ln[4:]
            continue
        if not ln.startswith("+") or ln.startswith("+++"):
            continue
        for label, rx in SECRET_PATTERNS:
            m = rx.search(ln)
            if not m:
                continue
            if m.groups() and _is_placeholder(m.group(1)):
                continue
            if label == "SECRET_KEY value" and ("token_urlsafe" in ln or "os.getenv" in ln or "settings." in ln):
                continue
            hits.append(f"{commit} {path}: {label}")
    hits = sorted(set(hits))
    known_block = read(AUDIT).split("## Secrets found in history", 1)[-1].split("\n## ", 1)[0] \
        if "## Secrets found in history" in read(AUDIT) else ""
    known = set(re.findall(r"`([0-9a-f]{7,40} [^`:]+)`", known_block))
    acknowledged = [h for h in hits if any(h.startswith(k) for k in known)]
    new_hits = [h for h in hits if h not in acknowledged]
    c.ok("secrets", "no secret-shaped value in any commit (git log -p --all)", not new_hits, "; ".join(new_hits[:5]))
    if acknowledged:
        c.add("secrets", "findings already in history are acknowledged in the audit", "WARN",
              "; ".join(acknowledged) + " (history not rewritten; the audit says what was done)")
    gi = read(REPO / ".gitignore").splitlines()
    c.ok("secrets", ".gitignore excludes .env and keeps .env.example", ".env" in gi and "!.env.example" in gi)
    used: set[str] = set()
    rx = re.compile(r"""(?:getenv|environ\.get|environ\[|environ\.setdefault)\(?\s*["']([A-Z][A-Z0-9_]{2,})["']""")
    used |= set(rx.findall(tracked_text(("backend/app/", "backend/alembic/", "scripts/"), (".py",))))
    cfg = read(REPO / "backend" / "app" / "core" / "config.py")
    used |= {f.upper() for f in re.findall(r"^\s{4}([a-z_]+)\s*:\s*[A-Za-z|\[\] ]+(?:=|$)", cfg, re.MULTILINE)}
    used.discard("MODEL_CONFIG")
    used |= set(re.findall(r"import\.meta\.env\.([A-Z_]+)", tracked_text(("frontend/src/",), (".ts", ".tsx"))))
    used -= {"DEV", "PROD", "MODE", "BASE_URL", "SSR"}
    documented = set(re.findall(r"^#?\s?([A-Z][A-Z0-9_]+)=", read(REPO / ".env.example") + "\n" +
                                read(REPO / "frontend" / ".env.example"), re.MULTILINE))
    undocumented = sorted(v for v in used - documented if v not in ENV_NOT_IN_EXAMPLE)
    c.ok("secrets", "every environment variable the code reads is in an .env.example", not undocumented,
         ", ".join(undocumented) or f"{len(used)} variables")
    ex = read(REPO / ".env.example")
    real = [ln for ln in ex.splitlines() if re.match(r"^(SECRET_KEY|POSTGRES_PASSWORD)=", ln)
            and not _is_placeholder(ln.split("=", 1)[1])]
    c.ok("secrets", ".env.example holds placeholders only", not real, "; ".join(real))


LOCK_REQUIRED = ("xgboost", "torch", "pytorch-tabnet", "shap", "scikit-learn", "numpy", "pandas", "pyarrow",
                 "fastapi", "sqlalchemy", "alembic", "asyncpg", "pydantic-settings", "pyjwt")


def lockfile(c: Checks) -> None:
    text = read(LOCK)
    if not text:
        c.add("lockfile", "backend/requirements.lock.txt exists (N87)", "FAIL",
              "run `pip freeze > backend/requirements.lock.txt` in the environment that produced the reported runs")
        return
    pins = {m.group(1).lower().replace("_", "-"): m.group(2) for m in re.finditer(r"^([A-Za-z0-9_.\-]+)==([^\s;#]+)", text, re.MULTILINE)}
    missing = [p for p in LOCK_REQUIRED if p not in pins]
    c.ok("lockfile", "the model and API libraries are pinned with ==", not missing, ", ".join(missing) or
         ", ".join(f"{k} {pins[k]}" for k in ("xgboost", "torch", "pytorch-tabnet", "shap")))
    c.ok("lockfile", "no editable or local-path entries", not re.search(r"^(-e |.* @ file:)", text, re.MULTILINE))
    header = re.search(r"^#.*[Pp]ython 3\.\d+.*$", text, re.MULTILINE)
    c.ok("lockfile", "the Python version is recorded in the header", bool(header),
         header.group(0).lstrip("# ") if header else "add a first line like `# Python 3.12.x, Windows 11, recorded <date>`",
         warn_only=True)


def _masked(cmd: list[str]) -> str:
    """The command line with any password in a database URL replaced, for the console and the audit."""
    return re.sub(r"(://[^:/\s@]+:)[^@\s]+@", r"\1***@", " ".join(cmd))


def regression(c: Checks, args, stamp: str, ready: bool = True) -> None:
    why = "skipped by --skip-regression" if args.skip_regression else \
        "not run: preflight failed, so this run could not be finalized anyway (git add -A, then run again)"
    if args.skip_regression or not ready:
        c.add("regression", "final Chapter 15 run, 0 FAIL (N70)", "FAIL", why)
        c.add("regression", "Chapter 16 readout and report still agree", "FAIL", why)
        return
    cmd = [sys.executable, "scripts/verify_chapter15.py"]
    if args.browser:
        cmd.append("--browser")
    if args.cert_username:
        cmd += ["--cert-username", args.cert_username, "--cert-api-port", str(args.cert_api_port)]
        if args.cert_password:
            cmd += ["--cert-password", args.cert_password]
        if args.cert_database_url:
            cmd += ["--cert-database-url", args.cert_database_url]
    print(f"\n[ch19] running {_masked(cmd[1:])} (output follows)\n", flush=True)
    t0 = time.perf_counter()
    rc15 = subprocess.run(cmd, check=False, cwd=REPO, env={**os.environ, "PYTHONIOENCODING": "utf-8"}).returncode
    secs = time.perf_counter() - t0
    line = next((x for x in reversed(runlog()) if x.get("stage") == "chapter15_verification"
                 and str(x.get("stamp", "")) >= stamp), None)
    if line is None:
        c.add("regression", "final Chapter 15 run, 0 FAIL (N70)", "FAIL", f"exit {rc15}; no runlog line written")
    else:
        k = counts_of(line)
        c.ok("regression", "final Chapter 15 run, 0 FAIL (N70)", rc15 == 0 and k["FAIL"] == 0,
             f"run {line['stamp']}: {k['PASS']} PASS, {k['WARN']} WARN, {k['FAIL']} FAIL, {secs:.0f} s")
        c.ok("regression", "the final run had no WARN", k["WARN"] == 0, f"{k['WARN']} WARN; explain each in the audit",
             warn_only=True)
        c.ok("regression", "the final run included the browser click-through", bool(line.get("browser")),
             "pass --browser")
        c.ok("regression", "the final run included the CERT API and dashboard checks", bool(line.get("cert")),
             "pass --cert-username (and --cert-database-url) with the CERT API running")
    cmd16 = [sys.executable, "scripts/verify_chapter16.py", "--no-tests"] + (["--recompute"] if args.recompute else [])
    print(f"\n[ch19] running {_masked(cmd16[1:])}\n", flush=True)
    rc16 = subprocess.run(cmd16, check=False, cwd=REPO, env={**os.environ, "PYTHONIOENCODING": "utf-8"}).returncode
    line16 = next((x for x in reversed(runlog()) if x.get("stage") == "chapter16_verification"
                   and str(x.get("stamp", "")) >= stamp), None)
    k16 = counts_of(line16) if line16 else {"PASS": 0, "WARN": 0, "FAIL": 1}
    c.ok("regression", "Chapter 16 readout and report still agree", rc16 == 0 and k16["FAIL"] == 0,
         f"{k16['PASS']} PASS, {k16['WARN']} WARN, {k16['FAIL']} FAIL" + (" with --recompute" if args.recompute else ""))
    c.ok("regression", "Chapter 16 rankings recomputed from the stored scores", bool(args.recompute) and k16["FAIL"] == 0,
         "pass --recompute with CERT_PROCESSED_DIR set", warn_only=True)


def notes(c: Checks) -> None:
    cf = read(CARRY)
    missing = [n for n in NOTES if f"## {n}." not in cf]
    c.ok("notes", "carry-forward notes N82-N87 present", not missing, ", ".join(missing) or "all six")
    rows = [n for n in NOTES if f"| {n} " in cf]
    c.ok("notes", "carry-forward table has a row for each", len(rows) == len(NOTES))
    c.ok("notes", "chapter and audit documents exist", CHAPTER_DOC.exists() and AUDIT.exists())


def audit_result() -> tuple[bool, str]:
    """Does the audit name a chapter19_verification run with 0 FAIL that is in the runlog?"""
    text = read(AUDIT)
    block = text.split(AUDIT_MARK_BEGIN, 1)[-1].split(AUDIT_MARK_END, 1)[0] if AUDIT_MARK_BEGIN in text else ""
    m = re.search(r"verification run `(\d{8}T\d{6}Z)`", block)
    if not m:
        return False, "the audit names no verification run yet (use --finalize <stamp>)"
    line = next((x for x in runlog() if x.get("stage") == "chapter19_verification" and x.get("stamp") == m.group(1)), None)
    if line is None:
        return False, f"run {m.group(1)} is not in the runlog"
    k = counts_of(line)
    return k["FAIL"] == 0, f"run {m.group(1)}: {k['PASS']} PASS, {k['WARN']} WARN, {k['FAIL']} FAIL"


# ----------------------------------------------------------------------------------------------- modes

def release(c: Checks) -> None:
    tags = [t for t in git("tag", "--points-at", "HEAD").split() if t.startswith("v")]
    annotated = [t for t in tags if git("cat-file", "-t", t).strip() == "tag"]
    c.ok("release", "HEAD carries an annotated v* tag", bool(annotated), ", ".join(tags) or "no tag at HEAD")
    dirty = [x for x in git("status", "--porcelain").splitlines() if x and not x[3:].startswith("experiments/results/")]
    c.ok("release", "the working tree is clean", not dirty, "; ".join(dirty[:5]))
    ok, detail = audit_result()
    c.ok("release", "the audit names a chapter19_verification run with 0 FAIL", ok, detail)
    text = read(AUDIT)
    left = text.count("EXPLAIN:")
    c.ok("release", "every WARN in the audit is explained", not left, f"{left} `EXPLAIN:` markers left" if left else "")
    cf = read(CARRY)
    n82 = cf.split("## N82.", 1)[-1].split("\n## ", 1)[0] if "## N82." in cf else ""
    c.ok("release", "N82 is RETIRED", "RETIRED (chapter 19" in n82)
    row = next((r for r in table_rows(read(README)) if r and r[0] == "19"), [])
    c.ok("release", "README row 19 says IMPLEMENTED", "IMPLEMENTED" in " ".join(row) and "PARTIALLY" not in " ".join(row))


def finalize(stamp: str) -> int:
    line = next((x for x in runlog() if x.get("stage") == "chapter19_verification" and x.get("stamp") == stamp), None)
    if line is None:
        print(f"no chapter19_verification line with stamp {stamp} in {RUNLOG.relative_to(REPO)}")
        return 2
    k = counts_of(line)
    if k["FAIL"]:
        print(f"run {stamp} has {k['FAIL']} FAIL; fix them and run the verifier again")
        return 2
    res = json.loads(read(REPO / "experiments" / "results" / "chapter19" / f"verification_{stamp}.json") or "{}")
    warns = [r for r in res.get("checks", []) if r["status"] == "WARN"]
    block = [AUDIT_MARK_BEGIN, "",
             (f"Result: **{k['PASS']} PASS, {k['WARN']} WARN, {k['FAIL']} FAIL**, verification run `{stamp}`"
              f" (`scripts/verify_chapter19.py`, flags recorded in the runlog line: {json.dumps(line.get('flags', {}))})."),
             "", f"Chapter 15 run inside it: `{line.get('ch15_stamp', 'see runlog')}`.", ""]
    if warns:
        block += ["WARN rows (each needs a sentence before the release check passes):", ""]
        block += [f"- {w['section']}: {w['check']} ({w['detail']}). EXPLAIN:" for w in warns]
        block.append("")
    block.append(AUDIT_MARK_END)
    text = read(AUDIT)
    if AUDIT_MARK_BEGIN not in text:
        print("audit has no result markers")
        return 2
    head, rest = text.split(AUDIT_MARK_BEGIN, 1)
    tail = rest.split(AUDIT_MARK_END, 1)[1]
    AUDIT.write_text(head + "\n".join(block) + tail, encoding="utf-8")
    rd = read(README)
    rd = re.sub(r"^\| 19 \|.*$", f"| 19 | Finalization: governing documents, component status table, structure, secrets scan, "
                                 f"lock file, final regression run, release tag | IMPLEMENTED; verifier run {stamp}, "
                                 f"{k['PASS']} PASS / {k['WARN']} WARN / 0 FAIL |", rd, count=1, flags=re.MULTILINE)
    README.write_text(rd, encoding="utf-8")
    cf = read(CARRY)
    marker = "## N82. Chapter 19 is PARTIALLY IMPLEMENTED until the final verification passes  (from Chapter 19)\n"
    if marker in cf and "RETIRED (chapter 19" not in cf.split(marker, 1)[1].split("\n## ", 1)[0]:
        cf = cf.replace(marker, marker + f"\nRETIRED (chapter 19, `scripts/verify_chapter19.py` run `{stamp}`: "
                                         f"{k['PASS']} PASS / {k['WARN']} WARN / 0 FAIL; see `docs/audits/chapter_19_audit.md`).\n")
        cf = cf.replace("| N82 Chapter 19 status | 19 |", "| N82 Chapter 19 status (RETIRED) | - |")
        CARRY.write_text(cf, encoding="utf-8")
    print(f"audit, README row 19 and N82 updated from run {stamp}.")
    if warns:
        print(f"{len(warns)} WARN rows were written to the audit with `EXPLAIN:`; replace each with a sentence.")
    print("Next: commit, `git tag -a v1.0.0 -m \"CIRA FYP submission\"`, then `python scripts/verify_chapter19.py --release`.")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Verify Chapter 19 (finalization and release)")
    ap.add_argument("--browser", action="store_true", help="passed to verify_chapter15.py")
    ap.add_argument("--cert-username", default=None, help="passed to verify_chapter15.py")
    ap.add_argument("--cert-password", default=None)
    ap.add_argument("--cert-api-port", type=int, default=8000)
    ap.add_argument("--cert-database-url", default=None)
    ap.add_argument("--recompute", action="store_true", help="passed to verify_chapter16.py (needs CERT_PROCESSED_DIR)")
    ap.add_argument("--skip-regression", action="store_true", help="static checks only; the regression rows FAIL")
    ap.add_argument("--finalize", metavar="STAMP", help="write a passing run into the audit, README row 19 and N82")
    ap.add_argument("--release", action="store_true", help="after tagging: release checks only, writes nothing")
    args = ap.parse_args(argv)

    if args.finalize:
        return finalize(args.finalize)

    c = Checks()
    if args.release:
        print("Chapter 19 release check")
        release(c)
        k = c.counts()
        print(f"\n{k['PASS']} PASS, {k['WARN']} WARN, {k['FAIL']} FAIL")
        return 1 if k["FAIL"] else 0

    stamp = utc_run_stamp()
    out = REPO / "experiments" / "results" / "chapter19"
    out.mkdir(parents=True, exist_ok=True)
    print(f"Chapter 19 verification {stamp}")
    files = tracked()
    audit_ok, _ = audit_result()
    ready = preflight(c)
    governance(c)
    readme(c, audit_ok)
    status(c)
    structure(c, files)
    secrets(c)
    lockfile(c)
    regression(c, args, stamp, ready)
    notes(c)

    k = c.counts()
    flags = {"browser": args.browser, "cert": bool(args.cert_username), "recompute": args.recompute,
             "skip_regression": args.skip_regression}
    ch15 = next((x.get("stamp") for x in reversed(runlog()) if x.get("stage") == "chapter15_verification"
                 and str(x.get("stamp", "")) >= stamp), None)
    (out / f"verification_{stamp}.json").write_text(json.dumps({"stamp": stamp, "counts": k, "flags": flags,
                                                                "ch15_stamp": ch15, "checks": c.rows}, indent=2),
                                                    encoding="utf-8")
    md = [f"# Chapter 19 verification {stamp}", "", f"{k['PASS']} PASS, {k['WARN']} WARN, {k['FAIL']} FAIL", ""]
    md += [f"- {x['status']} {x['section']}: {x['check']}" + (f" ({x['detail']})" if x["detail"] else "") for x in c.rows]
    (out / f"verification_{stamp}.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    try:
        from app.feature_engineering.common import append_experiment_runlog

        append_experiment_runlog({"stage": "chapter19_verification", "stamp": stamp, "counts": k, "flags": flags,
                                  "ch15_stamp": ch15})
    except Exception as exc:                                      # the report is already written
        print(f"(runlog line not written: {exc})")
    print(f"\n{k['PASS']} PASS, {k['WARN']} WARN, {k['FAIL']} FAIL; report {out / f'verification_{stamp}.md'}")
    if not k["FAIL"]:
        print(f"Next: python scripts/verify_chapter19.py --finalize {stamp}")
    return 1 if k["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
