"""LSTM autoencoder baseline (Bible Ch6 step 4, HCEA §6.2 / deviation D-3).

Sequence-aware reconstruction-error baseline over per-user day sequences.

HCEA D-3 adjustments
    * A documented core numeric subset (``CORE_COLUMNS``): daily counts and
      volumes only. All of them have the Chapter 5 "zero" null policy, so no
      imputation is needed; a null here is treated as a data error.
    * Window 30 days; training windows use stride 7.
    * Windows are generated lazily by a ``Dataset`` from one compact
      (user, day)-ordered float32 array. The full window tensor is never
      built (it would be ~10 GB at full scale).
    * batch 128, hidden 64, 1 layer by default, ``num_workers=0`` (Windows),
      AMP only when running on CUDA, fixed seed, checkpoint every epoch.

Causal scoring (N3: nothing may look ahead)
    Day t is scored from the window that ENDS on day t, using that window's
    last-step reconstruction error. A window centred on t would use up to
    29 future days, which a live detector could not have. Scoring therefore
    uses stride 1 over the requested rows; that is a forward pass only and
    stays lazy.

    ``score(frame, history=...)`` accepts earlier rows as context. The time
    split needs this: a test day in February is scored with the user's
    January days as history, which is past data and allowed.

GPU is optional (R11). ``device="auto"`` uses CUDA when available and falls
back to CPU; an explicit ``cuda`` request on a machine without CUDA also
falls back, and the device actually used is recorded.

Resumability (R7): with a ``checkpoint_dir`` set, each epoch writes
``epoch_NNN.pt`` atomically. A re-run with the same config resumes from the
latest checkpoint instead of starting over.
"""
from __future__ import annotations

import json
import os
import random
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from torch import nn
from torch.utils.data import DataLoader, Dataset

from .base import BaselineDetector, config_hash

CORE_COLUMNS: tuple[str, ...] = (
    # logon
    "login_count", "logoff_count", "off_hours_logins", "weekend_logins", "distinct_auth_pcs", "new_device_count",
    # removable media
    "usb_connect_count", "usb_off_hours_events", "usb_distinct_pcs",
    # files
    "file_event_count", "file_off_hours_events", "file_doc_count", "file_pdf_count", "file_txt_count",
    "file_jpg_count", "file_zip_count", "file_exe_count", "file_distinct_pcs",
    # email
    "emails_sent", "email_recipient_count", "email_external_recipient_count", "email_attachment_count",
    "email_total_size", "email_off_hours_count", "email_distinct_external_domains",
    # web
    "http_request_count", "http_off_hours_count", "http_job_search_count", "http_cloud_storage_count",
    "http_leak_paste_count", "http_hacking_tools_count", "http_distinct_hosts", "http_new_host_count",
    # day context
    "total_event_count", "is_active_day", "is_weekend",
)


def _resolve_device(requested: str) -> torch.device:
    requested = (requested or "auto").lower()
    if requested in ("auto", "cuda") and torch.cuda.is_available():
        return torch.device("cuda")
    return torch.device("cpu")


class _Windows(Dataset):
    """Lazily cut windows that end at ``ends`` (row positions)."""

    def __init__(self, x: np.ndarray, user_start: np.ndarray, ends: np.ndarray, window: int) -> None:
        self.x, self.user_start, self.ends, self.window = x, user_start, ends, window

    def __len__(self) -> int:
        return len(self.ends)

    def __getitem__(self, i: int):
        e = int(self.ends[i])
        s = max(int(self.user_start[e]), e - self.window + 1)
        seq = self.x[s : e + 1]
        pad = self.window - len(seq)
        out = np.zeros((self.window, self.x.shape[1]), dtype="float32")
        mask = np.zeros(self.window, dtype="float32")
        out[pad:] = seq
        mask[pad:] = 1.0
        return torch.from_numpy(out), torch.from_numpy(mask)


class _LSTMAE(nn.Module):
    def __init__(self, n_features: int, hidden: int, layers: int) -> None:
        super().__init__()
        self.encoder = nn.LSTM(n_features, hidden, num_layers=layers, batch_first=True)
        self.decoder = nn.LSTM(hidden, hidden, num_layers=layers, batch_first=True)
        self.head = nn.Linear(hidden, n_features)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        _, (h, _) = self.encoder(x)
        z = h[-1].unsqueeze(1).repeat(1, x.shape[1], 1)
        y, _ = self.decoder(z)
        return self.head(y)


def _seed_everything(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


class LSTMAutoencoderDetector(BaselineDetector):
    name = "lstm_autoencoder"

    def __init__(self, *, seed: int = 42, **config) -> None:
        config.setdefault("columns", list(CORE_COLUMNS))
        config.setdefault("window", 30)
        config.setdefault("train_stride", 7)
        config.setdefault("hidden", 64)
        config.setdefault("layers", 1)
        config.setdefault("batch_size", 128)
        config.setdefault("lr", 1e-3)
        config.setdefault("max_epochs", 20)
        config.setdefault("patience", 3)
        config.setdefault("device", os.getenv("CIRA_DEVICE", "auto"))
        config.setdefault("calibration_rows", 100_000)
        config.setdefault("checkpoint_dir", None)
        # Set by the runner from the feature file + split; part of the
        # checkpoint key so a resume never reuses weights from other data.
        config.setdefault("data_fingerprint", "")
        super().__init__(seed=seed, **config)
        self.mean: np.ndarray | None = None
        self.std: np.ndarray | None = None
        self.net: _LSTMAE | None = None
        self.device = _resolve_device(self.config["device"])
        self.history: list[dict] = []
        self.info: dict = {}

    # --- data -------------------------------------------------------------
    def _matrix(self, frame: pd.DataFrame) -> tuple[pd.DataFrame, np.ndarray, np.ndarray]:
        cols = list(self.config["columns"])
        missing = [c for c in cols if c not in frame.columns]
        if missing:
            raise KeyError(f"LSTM core columns missing from the matrix: {missing}")
        nulls = [c for c in cols if frame[c].isna().any()]
        if nulls:
            raise ValueError(f"Core columns have a zero null policy but contain nulls: {nulls[:5]}")
        ordered = frame.sort_values(["user_id", "date"], kind="mergesort")
        x = np.log1p(np.clip(ordered[cols].to_numpy(dtype="float64"), 0, None))
        users = ordered["user_id"].astype("string").to_numpy()
        change = np.r_[True, users[1:] != users[:-1]]
        user_start = np.maximum.accumulate(np.where(change, np.arange(len(users)), 0))
        return ordered, x, user_start

    def _normalise(self, x: np.ndarray) -> np.ndarray:
        return ((x - self.mean) / self.std).astype("float32")

    def _train_ends(self, user_start: np.ndarray) -> np.ndarray:
        n, w, stride = len(user_start), int(self.config["window"]), int(self.config["train_stride"])
        ends = []
        bounds = np.r_[np.flatnonzero(np.r_[True, user_start[1:] != user_start[:-1]]), n]
        for a, b in zip(bounds[:-1], bounds[1:]):
            first = min(a + w - 1, b - 1)
            user_ends = list(range(first, b, stride))
            if user_ends[-1] != b - 1:
                user_ends.append(b - 1)  # cover the user's final days too
            ends.extend(user_ends)
        return np.asarray(ends, dtype="int64")

    @staticmethod
    def _date_gaps(ordered: pd.DataFrame) -> int:
        d = pd.to_datetime(ordered["date"].astype("string"))
        same_user = ordered["user_id"].astype("string").to_numpy()
        same = np.r_[False, same_user[1:] == same_user[:-1]]
        diff = d.diff().dt.days.to_numpy()
        return int(((diff != 1) & same).sum())

    # --- training -------------------------------------------------------
    def _loss(self, batch: torch.Tensor, mask: torch.Tensor) -> torch.Tensor:
        recon = self.net(batch)
        per_step = ((recon.float() - batch) ** 2).mean(dim=2)
        return (per_step * mask).sum() / mask.sum().clamp(min=1.0)

    def _epoch_loss(self, loader: DataLoader, train: bool, optimiser=None, scaler=None) -> float:
        self.net.train(train)
        total, count = 0.0, 0
        use_amp = self.device.type == "cuda"
        for seq, mask in loader:
            seq, mask = seq.to(self.device), mask.to(self.device)
            with torch.set_grad_enabled(train), torch.autocast(device_type=self.device.type, enabled=use_amp):
                loss = self._loss(seq, mask)
            if train:
                optimiser.zero_grad(set_to_none=True)
                if scaler is not None:
                    scaler.scale(loss).backward()
                    scaler.step(optimiser)
                    scaler.update()
                else:
                    loss.backward()
                    optimiser.step()
            total += float(loss.detach()) * len(seq)
            count += len(seq)
        return total / max(count, 1)

    def _checkpoint_dir(self) -> Path | None:
        root = self.config.get("checkpoint_dir")
        if not root:
            return None
        key = config_hash({k: v for k, v in self.config.items() if k != "checkpoint_dir"} | {"seed": self.seed})
        return Path(root) / f"{self.name}-{key}"

    def _fit(self, train, y, validation, y_validation) -> None:
        _seed_everything(self.seed)
        ordered, x_raw, user_start = self._matrix(train)
        self.mean = x_raw.mean(axis=0)
        std = x_raw.std(axis=0)
        self.std = np.where(std > 0, std, 1.0)
        x = self._normalise(x_raw)
        ends = self._train_ends(user_start)
        window = int(self.config["window"])
        gen = torch.Generator().manual_seed(self.seed)
        train_loader = DataLoader(
            _Windows(x, user_start, ends, window), batch_size=int(self.config["batch_size"]),
            shuffle=True, num_workers=0, generator=gen, drop_last=False,
        )
        val_loader = None
        if validation is not None and len(validation):
            _, xv_raw, vstart = self._matrix(validation)
            val_loader = DataLoader(
                _Windows(self._normalise(xv_raw), vstart, self._train_ends(vstart), window),
                batch_size=int(self.config["batch_size"]), shuffle=False, num_workers=0,
            )

        self.net = _LSTMAE(x.shape[1], int(self.config["hidden"]), int(self.config["layers"])).to(self.device)
        optimiser = torch.optim.Adam(self.net.parameters(), lr=float(self.config["lr"]))
        scaler = torch.amp.GradScaler("cuda") if self.device.type == "cuda" else None

        start_epoch, best, best_state, stale = 0, float("inf"), None, 0
        ckpt_dir = self._checkpoint_dir()
        if ckpt_dir is not None:
            ckpt_dir.mkdir(parents=True, exist_ok=True)
            existing = sorted(ckpt_dir.glob("epoch_*.pt"))
            if existing:
                state = torch.load(existing[-1], map_location=self.device, weights_only=False)
                self.net.load_state_dict(state["model"])
                optimiser.load_state_dict(state["optimiser"])
                start_epoch, best, stale = state["epoch"] + 1, state["best"], state["stale"]
                best_state, self.history = state["best_state"], state["history"]
                self.info["resumed_from_epoch"] = int(state["epoch"])
                print(f"[lstm_autoencoder] resuming after epoch {state['epoch'] + 1} from {existing[-1]}", flush=True)

        for epoch in range(start_epoch, int(self.config["max_epochs"])):
            if stale >= int(self.config["patience"]):
                break
            tr = self._epoch_loss(train_loader, True, optimiser, scaler)
            va = self._epoch_loss(val_loader, False) if val_loader is not None else tr
            self.history.append({"epoch": epoch, "train_loss": tr, "val_loss": va})
            print(f"[lstm_autoencoder] epoch {epoch + 1}/{self.config['max_epochs']} train {tr:.5f} val {va:.5f}", flush=True)
            if va < best - 1e-6:
                best, stale = va, 0
                best_state = {k: v.detach().cpu().clone() for k, v in self.net.state_dict().items()}
            else:
                stale += 1
            if ckpt_dir is not None:
                tmp = ckpt_dir / f"epoch_{epoch:03d}.pt.tmp"
                torch.save(
                    {"model": self.net.state_dict(), "optimiser": optimiser.state_dict(), "epoch": epoch, "best": best,
                     "stale": stale, "best_state": best_state, "history": self.history},
                    tmp,
                )
                os.replace(tmp, ckpt_dir / f"epoch_{epoch:03d}.pt")

        if best_state is not None:
            self.net.load_state_dict(best_state)
        self.info.update(
            {
                "device_used": self.device.type,
                "amp": self.device.type == "cuda",
                "n_core_columns": int(x.shape[1]),
                "train_windows_per_epoch": int(len(ends)),
                "epochs_run": len(self.history),
                "best_validation_loss": None if best == float("inf") else float(best),
                "early_stopping_on": "validation reconstruction loss" if val_loader is not None else "training loss",
                "train_date_gaps": self._date_gaps(ordered),
                "checkpoint_dir": None if ckpt_dir is None else str(ckpt_dir),
            }
        )

    def _calibration_scores(self, train: pd.DataFrame) -> np.ndarray:
        n = int(self.config["calibration_rows"])
        rows = np.arange(len(train))
        if len(rows) > n:
            rows = np.sort(np.random.default_rng(self.seed).choice(rows, size=n, replace=False))
        self.info["calibration_rows_used"] = int(len(rows))
        return self._raw_score(train.iloc[rows], history=train)

    # --- scoring --------------------------------------------------------
    @torch.no_grad()
    def _raw_score(self, frame: pd.DataFrame, history: pd.DataFrame | None = None, **_) -> np.ndarray:
        cols = ["user_id", "date", *self.config["columns"]]
        req = frame[cols].copy()
        req["_req"] = np.arange(len(frame))
        if history is not None and len(history):
            hist = history[cols].copy()
            keys = set(zip(req["user_id"].astype("string"), req["date"].astype("string")))
            hmask = [(u, d) not in keys for u, d in zip(hist["user_id"].astype("string"), hist["date"].astype("string"))]
            hist = hist[np.asarray(hmask, dtype=bool)]
            hist["_req"] = -1
            combined = pd.concat([hist, req], ignore_index=True)
        else:
            combined = req.reset_index(drop=True)
        ordered, x_raw, user_start = self._matrix(combined)
        x = self._normalise(x_raw)
        req_pos = ordered["_req"].to_numpy()
        ends = np.flatnonzero(req_pos >= 0)

        self.net.eval()
        loader = DataLoader(
            _Windows(x, user_start, ends, int(self.config["window"])),
            batch_size=max(int(self.config["batch_size"]), 512), shuffle=False, num_workers=0,
        )
        errs = []
        use_amp = self.device.type == "cuda"
        for seq, _mask in loader:
            seq = seq.to(self.device)
            with torch.autocast(device_type=self.device.type, enabled=use_amp):
                recon = self.net(seq)
            last = ((recon[:, -1, :].float() - seq[:, -1, :]) ** 2).mean(dim=1)
            errs.append(last.cpu().numpy().astype("float64"))
        err = np.concatenate(errs) if errs else np.zeros(0)
        out = np.empty(len(frame), dtype="float64")
        out[req_pos[ends]] = err
        return out

    def _extra_metadata(self) -> dict:
        return {**self.info, "history": self.history}

    def _save_artifacts(self, directory: Path) -> dict:
        torch.save(self.net.state_dict(), directory / "model.pt")
        (directory / "normalisation.json").write_text(
            json.dumps({"mean": self.mean.tolist(), "std": self.std.tolist(), "transform": "log1p then (x - mean) / std"}),
            encoding="utf-8",
        )
        return {"model": "model.pt", "normalisation": "normalisation.json"}

    def _load_artifacts(self, directory: Path, meta: dict) -> None:
        norm = json.loads((directory / "normalisation.json").read_text(encoding="utf-8"))
        self.mean, self.std = np.asarray(norm["mean"]), np.asarray(norm["std"])
        self.net = _LSTMAE(len(self.config["columns"]), int(self.config["hidden"]), int(self.config["layers"])).to(self.device)
        self.net.load_state_dict(torch.load(directory / "model.pt", map_location=self.device, weights_only=True))
        self.info = {k: meta[k] for k in ("device_used", "epochs_run") if k in meta}
        self.history = meta.get("history", [])
