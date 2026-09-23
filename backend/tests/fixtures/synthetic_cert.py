"""Tiny synthetic CERT r4.2-shaped tree for fast Chapter 5 tests.

Label-free except for the ground-truth folder, which mirrors the real
layout (insiders.csv + r4.2-N/ answer files) so label tooling can be tested.
"""
from __future__ import annotations

import random
from pathlib import Path

import pandas as pd

HOSTS = ["google.com", "linkedin.com", "dropbox.com", "cnn.com", "wikipedia.org", "a.drive.google.com"]


def build(root: Path, *, n_users: int = 12, start: str = "2010-01-04", end: str = "2010-02-12", seed: int = 3) -> dict[str, Path]:
    raw = root / "raw" / "cert_r4.2"
    gt = root / "ground_truth" / "cert_r4.2"
    (raw / "LDAP").mkdir(parents=True, exist_ok=True)
    (gt / "r4.2-1").mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    users = [f"U{i:04d}" for i in range(n_users)]
    counter = [0]

    def nid() -> str:
        counter[0] += 1
        return f"{{S{counter[0]:010d}}}"

    def ts(day, hour) -> str:
        return f"{day:%m/%d/%Y} {hour:02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}"

    logon, device, file, email, http = [], [], [], [], []
    for day in pd.date_range(start, end, freq="D"):
        for u in users:
            if day.dayofweek >= 5 or rng.random() < 0.15:
                continue
            pcs = [f"PC-{rng.randint(1, 60):04d}" for _ in range(rng.randint(1, 3))]
            h0 = rng.choice([8, 9, 22])
            logon.append((nid(), ts(day, h0), u, pcs[0], "Logon"))
            logon.append((nid(), ts(day, min(h0 + 1, 23)), u, pcs[-1], "Logoff"))
            for k in range(rng.randint(0, 3)):
                pc = rng.choice(pcs)
                device.append((nid(), ts(day, rng.randint(6, 21)), u, pc, "Connect"))
                device.append((nid(), ts(day, 21), u, pc, "Disconnect"))
                file.append((nid(), ts(day, rng.randint(6, 21)), u, pc, f"R:\\{u}\\f{k}.{rng.choice(['doc', 'zip', 'exe', 'pdf'])}", "x"))
            email.append((nid(), ts(day, 10), u, pcs[0], f"{u.lower()}@dtaa.com;ext{rng.randint(1, 3)}@mail{rng.randint(1, 2)}.com", "", "", f"{u.lower()}@dtaa.com", rng.randint(1000, 5000), rng.randint(0, 2), "b"))
            for k in range(rng.randint(3, 12)):
                http.append((nid(), ts(day, rng.randint(7, 20)), u, pcs[0], f"http://{rng.choice(HOSTS)}/p{k}.html", "w"))

    def write(name, rows, cols):
        df = pd.DataFrame(rows, columns=cols)
        order = pd.to_datetime(df["date"], format="%m/%d/%Y %H:%M:%S").argsort(kind="stable")
        df.iloc[order].to_csv(raw / name, index=False)

    write("logon.csv", logon, ["id", "date", "user", "pc", "activity"])
    write("device.csv", device, ["id", "date", "user", "pc", "activity"])
    write("file.csv", file, ["id", "date", "user", "pc", "filename", "content"])
    write("email.csv", email, ["id", "date", "user", "pc", "to", "cc", "bcc", "from", "size", "attachments", "content"])
    write("http.csv", http, ["id", "date", "user", "pc", "url", "content"])
    pd.DataFrame({"employee_name": users, "user_id": users, "O": 30, "C": 31, "E": 32, "A": 33, "N": 34}).to_csv(raw / "psychometric.csv", index=False)
    for month in ("2009-12", "2010-01", "2010-02"):
        pd.DataFrame({
            "employee_name": users, "user_id": users, "email": [f"{u.lower()}@dtaa.com" for u in users],
            "role": "Eng", "business_unit": 1, "functional_unit": "1 - FU",
            "department": [f"D{i % 2}" for i in range(n_users)], "team": "T", "supervisor": "Boss",
        }).to_csv(raw / "LDAP" / f"{month}.csv", index=False)

    pd.DataFrame({
        "dataset": [4.2, 4.2, 4.2, 5.1], "scenario": [1, 1, 1, 1], "details": "x",
        "user": [users[0], users[1], users[2], "ZZZ9999"],
        "start": ["01/10/2010 00:00:00", "06/10/2010 00:00:00", "07/01/2010 00:00:00", "01/01/2010 00:00:00"],
        "end": ["01/20/2010 00:00:00", "07/10/2010 00:00:00", "08/01/2010 00:00:00", "01/02/2010 00:00:00"],
    }).to_csv(gt / "insiders.csv", index=False)
    (gt / "r4.2-1" / f"r4.2-1-{users[0]}.csv").write_text(
        f"logon,{{G1}},01/11/2010 22:01:02,{users[0]},PC-0001,Logon\n"
        f"device,{{G2}},01/11/2010 22:05:00,{users[0]},PC-0001,Connect\n"
        f"http,{{G3}},01/12/2010 23:00:00,{users[0]},PC-0001,http://wikileaks.org/x.html,some, words, here\n",
        encoding="utf-8",
    )
    return {"raw": raw, "gt": gt, "users": users}
