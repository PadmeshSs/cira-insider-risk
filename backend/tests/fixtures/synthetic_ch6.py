"""Synthetic CERT tree with enough insiders to exercise Chapter 6.

Built on ``synthetic_cert.build`` and then extended:

* 13 insiders across scenarios 1-3 (5 / 5 / 3), written to insiders.csv
  and to per-insider answer files, like the real r4.2 layout;
* on each malicious day the insider gets planted activity (a 23:00 logon,
  an off-hours USB connect, cloud-storage browsing) and the answer file
  lists exactly those planted events;
* one scenario-3 insider also sends an email from a supervisor account
  (masquerade), so the account view differs from the primary view.

The planted behaviour means a working detector should beat random ranking.
Nothing here is used outside tests.
"""
from __future__ import annotations

import random
from pathlib import Path

import pandas as pd

from fixtures import synthetic_cert

SCENARIOS = {1: range(0, 5), 2: range(5, 10), 3: range(10, 13)}
SUPERVISOR_INDEX = 25


def build(root: Path, *, n_users: int = 32, start: str = "2010-01-04", end: str = "2010-03-05", seed: int = 11) -> dict:
    paths = synthetic_cert.build(root, n_users=n_users, start=start, end=end, seed=seed)
    raw, gt, users = paths["raw"], paths["gt"], paths["users"]
    rng = random.Random(seed)
    days = [d for d in pd.date_range(start, end, freq="D") if d.dayofweek < 5]

    extra = {"logon": [], "device": [], "http": [], "email": []}
    answers: dict[tuple[int, str], list[str]] = {}
    roster = []
    counter = [0]

    def nid() -> str:
        counter[0] += 1
        return f"{{M{counter[0]:09d}}}"

    for scenario, idx in SCENARIOS.items():
        for i in idx:
            u = users[i]
            mal_days = sorted(rng.sample(days[5:], 3))
            roster.append((4.2, scenario, "synthetic", u, f"{mal_days[0]:%m/%d/%Y} 00:00:00", f"{mal_days[-1]:%m/%d/%Y} 23:59:59"))
            lines = []
            for d in mal_days:
                pc = f"PC-{9000 + i:04d}"
                t_logon, t_usb = f"{d:%m/%d/%Y} 23:05:00", f"{d:%m/%d/%Y} 23:20:00"
                ev = nid()
                extra["logon"].append((ev, t_logon, u, pc, "Logon"))
                lines.append(f"logon,{ev},{t_logon},{u},{pc},Logon")
                ev = nid()
                extra["device"].append((ev, t_usb, u, pc, "Connect"))
                lines.append(f"device,{ev},{t_usb},{u},{pc},Connect")
                for k in range(4):
                    t = f"{d:%m/%d/%Y} 23:{30 + k:02d}:00"
                    ev = nid()
                    extra["http"].append((ev, t, u, pc, f"http://dropbox.com/up{k}.html", "w"))
                    lines.append(f"http,{ev},{t},{u},{pc},http://dropbox.com/up{k}.html,w")
            if scenario == 3 and i == 10:
                boss, d = users[SUPERVISOR_INDEX], mal_days[0]
                t = f"{d:%m/%d/%Y} 09:15:00"
                ev = nid()
                extra["email"].append((ev, t, boss, "PC-0999", "all@dtaa.com", "", "", f"{boss.lower()}@dtaa.com", 4000, 0, "b"))
                lines.append(f"email,{ev},{t},{boss},PC-0999,all@dtaa.com,,,{boss.lower()}@dtaa.com,4000,0,b")
            answers[(scenario, u)] = lines

    cols = {
        "logon.csv": ["id", "date", "user", "pc", "activity"],
        "device.csv": ["id", "date", "user", "pc", "activity"],
        "http.csv": ["id", "date", "user", "pc", "url", "content"],
        "email.csv": ["id", "date", "user", "pc", "to", "cc", "bcc", "from", "size", "attachments", "content"],
    }
    for name, key in (("logon.csv", "logon"), ("device.csv", "device"), ("http.csv", "http"), ("email.csv", "email")):
        base = pd.read_csv(raw / name, dtype=str, keep_default_na=False)
        add = pd.DataFrame(extra[key], columns=cols[name]).astype(str)
        both = pd.concat([base, add], ignore_index=True)
        order = pd.to_datetime(both["date"], format="%m/%d/%Y %H:%M:%S").argsort(kind="stable")
        both.iloc[order].to_csv(raw / name, index=False)

    pd.DataFrame(roster, columns=["dataset", "scenario", "details", "user", "start", "end"]).to_csv(gt / "insiders.csv", index=False)
    for folder in ("r4.2-1", "r4.2-2", "r4.2-3"):
        d = gt / folder
        d.mkdir(parents=True, exist_ok=True)
        for f in d.glob("*.csv"):
            f.unlink()
    for (scenario, u), lines in answers.items():
        (gt / f"r4.2-{scenario}" / f"r4.2-{scenario}-{u}.csv").write_text("\n".join(lines) + "\n", encoding="utf-8")

    insiders = {u.casefold(): s for s, idx in SCENARIOS.items() for u in (users[i] for i in idx)}
    return {**paths, "insiders": insiders, "supervisor": users[SUPERVISOR_INDEX].casefold()}
