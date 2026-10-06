"""C15-4: run stamps are never reused within a process, and keep their format."""
import re
import threading

from app.core.run_stamp import utc_run_stamp


def test_back_to_back_stamps_are_strictly_increasing_and_keep_the_format():
    stamps = [utc_run_stamp() for _ in range(3)]          # within one second without the fix
    assert all(re.fullmatch(r"\d{8}T\d{6}Z", s) for s in stamps)
    assert stamps == sorted(stamps) and len(set(stamps)) == 3


def test_threads_never_share_a_stamp():
    out: list[str] = []
    ts = [threading.Thread(target=lambda: out.append(utc_run_stamp())) for _ in range(3)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(set(out)) == 3


def test_every_entry_point_uses_it():
    """No pipeline module builds a run id from the clock directly any more."""
    from pathlib import Path

    app = Path(__file__).resolve().parents[2] / "app"
    direct = [str(p.relative_to(app)) for p in app.rglob("*.py")
              if re.search(r"""strftime\(["']%Y%m%dT%H%M%SZ["']\)""", p.read_text(encoding="utf-8"))
              and p.name != "run_stamp.py"]
    assert direct == []
