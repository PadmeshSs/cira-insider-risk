"""Train TabNet, evaluate it with the Chapter 6 harness, register it.

Bible Ch7 steps 2-4, HCEA §7.2-§7.6, CARRY_FORWARD N1-N13, N15-N18.

Usage (from backend/, with .env loaded):

    python -m app.tabnet.train --profile dev                 # debugging only
    python -m app.tabnet.train --profile mid                 # user split
    python -m app.tabnet.train --profile mid --split time
    python -m app.tabnet.train --profile full

The detector
    ``TabNetDetector`` follows the Chapter 6 contract (``fit``, ``raw_score``,
    ``score``, ``save``, ``load``), so every harness that ran the baselines
    runs TabNet unchanged. It is supervised: it refuses to fit without labels.

Settings (HCEA §7.2, used as defaults)
    n_d = n_a = 16, n_steps = 4, gamma = 1.3, n_independent = n_shared = 2,
    sparsemax masks, Adam lr 2e-2, StepLR(step 10, gamma 0.9), max 100 epochs,
    patience 15, batch 4096, virtual batch 256 (capped at 512),
    num_workers = 0, drop_last = False, seed from CIRA_SEED.

Class imbalance (HCEA §7.3 / D-7, N2)
    Default: class-weighted cross-entropy, weight(benign) = 1 and
    weight(malicious) = negatives / positives on the training rows. That is
    the same ratio XGBoost used as ``scale_pos_weight`` in Chapter 6, so the
    two supervised models see the same imbalance correction. Nothing is
    resampled. ``--imbalance balanced_sampler`` switches to pytorch-tabnet's
    ``weights=1`` (a WeightedRandomSampler that draws both classes equally
    often); it exists for the one-off ablation HCEA §7.3 suggests. The
    method, the effective weight and the positive rate are recorded in the
    metadata and the registry entry. SMOTE is not implemented (D-7).

Early stopping (deviation C7-1)
    On validation PR-AUC (average precision), the Chapter 6 headline metric
    and the metric XGBoost early-stopped on. ROC-AUC is logged per epoch too.
    HCEA §7.2 shows ``eval_metric=["auc"]`` with a note that a PR metric
    comes later; it is used now so both supervised models are selected on
    the same criterion. Masquerade account-days are removed from training
    and validation rows (N13). Test rows are never seen during training.

Checkpoints (HCEA R7, §7.6)
    Every epoch writes network, optimiser, LR scheduler, early-stopping
    state and history atomically. A re-run with the same config and data
    resumes after the last finished epoch. Epoch e shuffles with seed + e,
    so a resumed run trains exactly like an uninterrupted one on the same
    device. ``--fresh`` clears the checkpoints first (needed for a
    determinism re-run, otherwise the second run just reloads the first).

Pretraining (HCEA §7.4)
    ``--pretrain`` runs TabNetPretrainer on the training features (no
    labels) for at most 20 epochs, then fine-tunes. Optional and
    time-boxed: keep it only if validation PR-AUC improves over the same
    config without it. Not checkpointed; skipped when resuming, because the
    checkpoint already holds the fine-tuned weights.

Outputs of one run
    <processed>/scores/chapter7/<run_id>/tabnet.parquet   no labels (N5)
    experiments/results/chapter7/<run_id>/metrics.json      same shape as Chapter 6
    <MODEL_PATH>/tabnet/vNNNN/                              registry artifact
    experiments/runlog.jsonl                                one chapter7_tabnet line (R8)
"""
from __future__ import annotations

from app.core.runtime import apply_thread_caps

apply_thread_caps()

import argparse  # noqa: E402
import contextlib  # noqa: E402
import copy  # noqa: E402
import io  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import shutil  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402
import warnings  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
from pathlib import Path  # noqa: E402

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import torch  # noqa: E402
from pytorch_tabnet.callbacks import Callback, EarlyStopping, LRSchedulerCallback  # noqa: E402
from pytorch_tabnet.metrics import Metric  # noqa: E402
from pytorch_tabnet.tab_model import TabNetClassifier  # noqa: E402
from sklearn.metrics import average_precision_score  # noqa: E402

from app.baselines.base import BaselineDetector, config_hash  # noqa: E402
from app.evaluation.labels import attach_labels, insider_scenarios, label_coverage, load_label_views  # noqa: E402
from app.evaluation.metrics import DEFAULT_BUDGETS, evaluate_scores, headline  # noqa: E402
from app.evaluation.splitting import DEFAULT_FRACTIONS, SPLITS  # noqa: E402
from app.feature_engineering.common import append_experiment_runlog, atomic_to_parquet, memory_rss_mb, repo_root  # noqa: E402

from . import CHAPTER7_VERSION, MODEL_NAME  # noqa: E402
from .dataset import (  # noqa: E402
    STATIC_TRAIT_PREFIXES,
    TabNetPreprocessor,
    data_fingerprint,
    feature_fingerprint,
    grouped_importance,
    load_feature_matrix,
    make_split,
    supervised_rows,
)
from .infer import IMPORTANCE_FILE, PREPROCESSOR_FILE, TABNET_ZIP, load_tabnet_classifier, margins, sigmoid  # noqa: E402
from .model_registry import ModelRegistry  # noqa: E402

IMBALANCE_METHODS = ("class_weighted_loss", "balanced_sampler")
MAX_PRETRAIN_EPOCHS = 20          # HCEA §7.4
MAX_VIRTUAL_BATCH = 512           # HCEA §7.2
HYPERPARAMETER_BUDGET = 12        # HCEA §7.6: manual search, at most 12 configurations
KEEP_CHECKPOINTS = 3
IMPORTANCE_CHUNK_ROWS = 50_000    # HCEA §11.1: explain() in chunks


# ---------------------------------------------------------------------------
# Pieces handed to pytorch-tabnet
# ---------------------------------------------------------------------------

class ValidationPRAUC(Metric):
    """Average precision of the malicious class; name shown as valid_pr_auc."""

    def __init__(self) -> None:
        self._name = "pr_auc"
        self._maximize = True

    def __call__(self, y_true, y_score) -> float:
        return float(average_precision_score(y_true, y_score[:, 1]))


class ClassWeightedCrossEntropy:
    """Cross-entropy with fixed per-class weights (weighted mean reduction)."""

    def __init__(self, benign_weight: float, malicious_weight: float) -> None:
        self.weights = torch.tensor([benign_weight, malicious_weight], dtype=torch.float32)

    def __call__(self, y_pred: torch.Tensor, y_true: torch.Tensor) -> torch.Tensor:
        return torch.nn.functional.cross_entropy(y_pred, y_true, weight=self.weights.to(y_pred.device))


class _EpochCheckpoint(Callback):
    """Per-epoch checkpoint and exact resume inside pytorch-tabnet's fit loop.

    pytorch-tabnet numbers epochs from 0 on every ``fit`` call. On resume the
    runner calls ``fit`` with only the remaining epochs, and this callback
    restores the saved state in ``on_train_begin`` (it runs after the
    built-in History, EarlyStopping and scheduler callbacks were created)
    and maps local epoch numbers to global ones with ``offset``.
    """

    def __init__(self, directory: Path | None, seed: int, max_epochs: int, state: dict | None, extra: dict) -> None:
        super().__init__()
        self.directory = directory
        self.seed = int(seed)
        self.max_epochs = int(max_epochs)
        self.state = state
        self.extra = extra
        self.offset = 0 if state is None else int(state["epoch"]) + 1
        self.epoch_seconds: list[float] = [] if state is None else list(state.get("epoch_seconds", []))
        self.best_epoch_global: int | None = None
        self._t0 = 0.0

    def _find(self, cls):
        return next((c for c in self.trainer._callback_container.callbacks if isinstance(c, cls)), None)

    def on_train_begin(self, logs=None):
        self.es = self._find(EarlyStopping)
        self.sched = self._find(LRSchedulerCallback)
        if self.state is None:
            return
        t, s, dev = self.trainer, self.state, self.trainer.device
        t.network.load_state_dict(s["model"])
        t._optimizer.load_state_dict(s["optimizer"])
        if self.sched is not None and s.get("scheduler") is not None:
            self.sched.scheduler.load_state_dict(s["scheduler"])
        if self.es is not None and s.get("early_stopping") is not None:
            es = s["early_stopping"]
            self.es.best_loss = es["best_loss"]
            self.es.wait = es["wait"]
            self.es.best_epoch = es["best_epoch"] - self.offset
            self.es.best_weights = None if es["best_weights"] is None else {k: v.to(dev) for k, v in es["best_weights"].items()}
        t.history.history = copy.deepcopy(s["history"])

    def on_epoch_begin(self, epoch, logs=None):
        # Shuffle order (and the balanced sampler's draws) depend only on
        # (seed, global epoch), so a resumed run repeats the same batches.
        torch.manual_seed(self.seed + self.offset + epoch)
        self._t0 = time.perf_counter()

    def on_epoch_end(self, epoch, logs=None):
        g = self.offset + epoch
        self.epoch_seconds.append(round(time.perf_counter() - self._t0, 3))
        logs = logs or {}
        shown = "  ".join(f"{k} {v:.5f}" for k, v in logs.items() if isinstance(v, float) and k != "lr")
        print(f"[tabnet] epoch {g + 1}/{self.max_epochs}  {shown}  lr {logs.get('lr', float('nan')):.5f}  "
              f"{self.epoch_seconds[-1]:.1f}s", flush=True)
        if self.directory is None:
            return
        es = None
        if self.es is not None:
            es = {
                "best_loss": float(self.es.best_loss),
                "wait": int(self.es.wait),
                "best_epoch": int(self.offset + self.es.best_epoch),
                "best_weights": None if self.es.best_weights is None
                else {k: v.detach().cpu().clone() for k, v in self.es.best_weights.items()},
            }
        state = {
            "epoch": g,
            "model": {k: v.detach().cpu().clone() for k, v in self.trainer.network.state_dict().items()},
            "optimizer": self.trainer._optimizer.state_dict(),
            "scheduler": None if self.sched is None else self.sched.scheduler.state_dict(),
            "early_stopping": es,
            "history": copy.deepcopy(self.trainer.history.history),
            "stop_training": bool(self.trainer._stop_training),
            "epoch_seconds": self.epoch_seconds,
            **self.extra,
        }
        tmp = self.directory / f"epoch_{g:03d}.pt.tmp"
        torch.save(state, tmp)
        os.replace(tmp, self.directory / f"epoch_{g:03d}.pt")
        for old in sorted(self.directory.glob("epoch_*.pt"))[:-KEEP_CHECKPOINTS]:
            old.unlink()

    def on_train_end(self, logs=None):
        if self.es is not None:
            self.best_epoch_global = int(self.offset + self.es.best_epoch)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

def _device_name(requested: str) -> str:
    requested = (requested or "auto").lower()
    if requested in ("auto", "cuda") and torch.cuda.is_available():
        return "cuda"
    return "cpu"


def global_importance(clf, x: np.ndarray, chunk_rows: int = IMPORTANCE_CHUNK_ROWS) -> np.ndarray:
    """Normalised sum of TabNet's aggregate mask over ``x``.

    Same quantity as pytorch-tabnet's ``feature_importances_``, computed in
    chunks so the per-step mask stack never holds the whole training split.
    """
    total = np.zeros(x.shape[1], dtype="float64")
    for start in range(0, len(x), chunk_rows):
        m, _ = clf.explain(x[start:start + chunk_rows])
        total += np.asarray(m, dtype="float64").sum(axis=0)
    s = total.sum()
    return total / s if s > 0 else total


class TabNetDetector(BaselineDetector):
    name = MODEL_NAME
    supervised = True
    calibrate = False     # the score is sigmoid(margin); see infer.py

    def __init__(self, *, seed: int = 42, **config) -> None:
        config.setdefault("n_d", 16)
        config.setdefault("n_a", 16)
        config.setdefault("n_steps", 4)
        config.setdefault("gamma", 1.3)
        config.setdefault("n_independent", 2)
        config.setdefault("n_shared", 2)
        config.setdefault("momentum", 0.02)
        config.setdefault("lambda_sparse", 1e-3)
        config.setdefault("mask_type", "sparsemax")
        config.setdefault("clip_value", 1)
        config.setdefault("lr", 2e-2)
        config.setdefault("scheduler_step_size", 10)
        config.setdefault("scheduler_gamma", 0.9)
        config.setdefault("max_epochs", 100)
        config.setdefault("patience", 15)
        config.setdefault("batch_size", 4096)
        config.setdefault("virtual_batch_size", 256)
        config.setdefault("imbalance", "class_weighted_loss")
        config.setdefault("early_stopping_metric", "valid_pr_auc")
        config.setdefault("pretrain", False)
        config.setdefault("pretrain_max_epochs", MAX_PRETRAIN_EPOCHS)
        config.setdefault("pretraining_ratio", 0.8)
        config.setdefault("device", os.getenv("CIRA_DEVICE", "auto"))
        config.setdefault("nullable_columns", None)
        config.setdefault("data_fingerprint", "")
        config.setdefault("checkpoint_dir", None)
        config.setdefault("shuffle", "per-epoch-seed")
        super().__init__(seed=seed, **config)
        self._validate_config()
        self.preprocessor = TabNetPreprocessor()
        self.clf: TabNetClassifier | None = None
        self.importance: np.ndarray | None = None
        self.info: dict = {}

    def _validate_config(self) -> None:
        c = self.config
        if c["imbalance"] not in IMBALANCE_METHODS:
            raise ValueError(f"imbalance must be one of {IMBALANCE_METHODS}, got {c['imbalance']!r}")
        if c["mask_type"] not in ("sparsemax", "entmax"):
            raise ValueError(f"mask_type must be sparsemax or entmax, got {c['mask_type']!r}")
        if not 0 < int(c["virtual_batch_size"]) <= min(MAX_VIRTUAL_BATCH, int(c["batch_size"])):
            raise ValueError(f"virtual_batch_size must be in (0, min({MAX_VIRTUAL_BATCH}, batch_size)] (HCEA §7.2)")
        if int(c["pretrain_max_epochs"]) > MAX_PRETRAIN_EPOCHS:
            raise ValueError(f"pretraining is time-boxed at {MAX_PRETRAIN_EPOCHS} epochs (HCEA §7.4)")
        if c["early_stopping_metric"] != "valid_pr_auc":
            raise ValueError("early stopping is on validation PR-AUC only (C7-1)")

    # --- identity -------------------------------------------------------
    def _identity_config(self) -> dict:
        # Machine paths do not change the model; everything else does.
        return {k: v for k, v in self.config.items() if k != "checkpoint_dir"}

    @property
    def model_version(self) -> str:
        return f"{self.name}-{CHAPTER7_VERSION}-{config_hash({'config': self._identity_config(), 'seed': self.seed})}"

    def checkpoint_path(self) -> Path | None:
        root = self.config.get("checkpoint_dir")
        if not root:
            return None
        return Path(root) / f"{self.name}-{config_hash({'config': self._identity_config(), 'seed': self.seed})}"

    def clear_checkpoints(self) -> int:
        """Delete this config's checkpoints (``--fresh``). Returns files removed."""
        d = self.checkpoint_path()
        if d is None or not d.exists():
            return 0
        n = len(list(d.glob("epoch_*.pt")))
        shutil.rmtree(d)
        return n

    # --- training -------------------------------------------------------
    def _network_params(self, device: str) -> dict:
        c = self.config
        return dict(
            n_d=int(c["n_d"]), n_a=int(c["n_a"]), n_steps=int(c["n_steps"]), gamma=float(c["gamma"]),
            n_independent=int(c["n_independent"]), n_shared=int(c["n_shared"]), momentum=float(c["momentum"]),
            lambda_sparse=float(c["lambda_sparse"]), mask_type=str(c["mask_type"]), clip_value=c["clip_value"],
            optimizer_fn=torch.optim.Adam, optimizer_params=dict(lr=float(c["lr"])),
            seed=self.seed, verbose=0, device_name=device,
        )

    def _drop_last(self, n_rows: int) -> tuple[bool, str | None]:
        # A final batch of one row cannot pass batch norm in training mode.
        # HCEA §7.2 asks for drop_last=False; the one-row case is the only
        # exception, and it is recorded.
        if n_rows % int(self.config["batch_size"]) == 1:
            return True, "training rows = 1 (mod batch_size); a 1-row batch breaks batch norm"
        return False, None

    def _pretrain(self, x_train: np.ndarray, x_valid: np.ndarray | None, device: str, drop_last: bool):
        from pytorch_tabnet.pretraining import TabNetPretrainer

        c = self.config
        pre = TabNetPretrainer(**self._network_params(device))
        started = time.perf_counter()
        with warnings.catch_warnings(), contextlib.redirect_stdout(io.StringIO()):
            warnings.simplefilter("ignore", UserWarning)
            pre.fit(
                x_train, eval_set=[x_valid] if x_valid is not None else None, eval_name=["valid"] if x_valid is not None else None,
                pretraining_ratio=float(c["pretraining_ratio"]), max_epochs=int(c["pretrain_max_epochs"]), patience=5,
                batch_size=int(c["batch_size"]), virtual_batch_size=int(c["virtual_batch_size"]),
                num_workers=0, drop_last=drop_last,
            )
        info = {
            "used": True,
            "epochs_run": len(pre.history["loss"]),
            "max_epochs": int(c["pretrain_max_epochs"]),
            "pretraining_ratio": float(c["pretraining_ratio"]),
            "best_epoch": int(getattr(pre, "best_epoch", -1)),
            "best_valid_unsup_loss": None if x_valid is None else float(getattr(pre, "best_cost", float("nan"))),
            "wall_seconds": round(time.perf_counter() - started, 2),
            "data": "training features only, no labels",
        }
        return pre, info

    def _fit(self, train, y, validation, y_validation) -> None:
        c = self.config
        y = np.asarray(y).astype("int64")
        pos, neg = int(y.sum()), int(len(y) - y.sum())
        if pos == 0 or neg == 0:
            raise ValueError("tabnet: the training rows need both malicious and benign user-days")
        device = _device_name(c["device"])
        if device == "cuda":
            torch.cuda.reset_peak_memory_stats()

        self.preprocessor = TabNetPreprocessor().fit(train, c["nullable_columns"])
        x_tr = self.preprocessor.transform(train)
        early = validation is not None and y_validation is not None and 0 < int(np.sum(y_validation)) < len(y_validation)
        x_va = self.preprocessor.transform(validation) if validation is not None and len(validation) else None
        eval_kwargs: dict = {"patience": 0}
        if early:
            eval_kwargs = dict(eval_set=[(x_va, np.asarray(y_validation).astype("int64"))], eval_name=["valid"],
                               eval_metric=["auc", ValidationPRAUC], patience=int(c["patience"]))

        if c["imbalance"] == "class_weighted_loss":
            weight = neg / pos
            loss_fn, sampler_weights = ClassWeightedCrossEntropy(1.0, weight), 0
            imbalance = {"method": "class_weighted_loss", "benign_weight": 1.0, "malicious_weight": weight,
                         "effective_positive_weight": weight, "resampling": "none"}
        else:
            loss_fn, sampler_weights = None, 1
            imbalance = {"method": "balanced_sampler", "effective_positive_weight": neg / pos,
                         "resampling": "pytorch-tabnet weights=1: WeightedRandomSampler with inverse class frequency; "
                                       "draws with replacement, n_train draws per epoch"}
        imbalance.update({"train_positives": pos, "train_negatives": neg, "train_positive_rate": pos / len(y)})

        drop_last, drop_reason = self._drop_last(len(x_tr))
        ckpt_dir = self.checkpoint_path()
        state = None
        if ckpt_dir is not None:
            ckpt_dir.mkdir(parents=True, exist_ok=True)
            existing = sorted(ckpt_dir.glob("epoch_*.pt"))
            if existing:
                state = torch.load(existing[-1], map_location="cpu", weights_only=False)
                print(f"[tabnet] resuming after epoch {state['epoch'] + 1} from {existing[-1]}", flush=True)
        max_epochs = int(c["max_epochs"])
        done = 0 if state is None else int(state["epoch"]) + 1
        remaining = 0 if (state is not None and state.get("stop_training")) else max(0, max_epochs - done)

        pre, pre_info = None, {"used": False}
        if c["pretrain"]:
            if state is None:
                pre, pre_info = self._pretrain(x_tr, x_va, device, drop_last)
            else:
                pre_info = dict(state.get("pretraining") or {}, note="weights restored from checkpoint; pretraining not re-run")

        self.clf = TabNetClassifier(
            **self._network_params(device),
            scheduler_fn=torch.optim.lr_scheduler.StepLR,
            scheduler_params=dict(step_size=int(c["scheduler_step_size"]), gamma=float(c["scheduler_gamma"])),
        )
        cb = _EpochCheckpoint(ckpt_dir, self.seed, max_epochs, state, extra={"pretraining": pre_info})
        with warnings.catch_warnings(), contextlib.redirect_stdout(_Filtered(sys.stdout)):
            warnings.simplefilter("ignore", UserWarning)
            self.clf.fit(
                x_tr, y, loss_fn=loss_fn, weights=sampler_weights, max_epochs=remaining,
                batch_size=int(c["batch_size"]), virtual_batch_size=int(c["virtual_batch_size"]),
                num_workers=0, drop_last=drop_last, callbacks=[cb], from_unsupervised=pre,
                compute_importance=False, **eval_kwargs,
            )
        self.clf.network.eval()
        self.importance = global_importance(self.clf, x_tr)
        self.clf.feature_importances_ = self.importance

        hist = {k: [float(v) for v in vals] for k, vals in self.clf.history.history.items()}
        top = grouped_importance(self.importance, self.preprocessor.output_columns)
        best_epoch = cb.best_epoch_global if early else None
        self.info = {
            "imbalance": imbalance,
            "loss": "cross-entropy, class-weighted" if loss_fn is not None else "cross-entropy (sampler balances classes)",
            "early_stopping": "validation pr_auc (average precision)" if early else "not used (validation split has no positives); last epoch kept",
            "best_epoch": best_epoch,
            "best_valid_pr_auc": (hist.get("valid_pr_auc") or [None])[best_epoch] if early and best_epoch is not None else None,
            "epochs_run": len(hist.get("loss", [])),
            "max_epochs": max_epochs,
            "resumed_from_epoch": None if state is None else int(state["epoch"]),
            "completed_from_checkpoint": state is not None and remaining == 0,
            "device_used": self.clf.device.type,
            "peak_vram_mb": round(torch.cuda.max_memory_allocated() / 2**20, 1) if self.clf.device.type == "cuda" else None,
            "n_input_columns": len(self.preprocessor.output_columns),
            "n_missing_indicators": len(self.preprocessor.imputer.indicator_columns),
            "constant_columns_in_train": self.preprocessor.constant_columns,
            "all_null_in_train": self.preprocessor.imputer.all_null_in_train,
            "drop_last": drop_last,
            "drop_last_reason": drop_reason,
            "pretraining": pre_info,
            "top_features_by_mask": top[:20],
            "static_traits_in_top10": [f for f, _ in top[:10] if f.startswith(STATIC_TRAIT_PREFIXES)],
            "history": hist,
            "epoch_seconds": cb.epoch_seconds,
            "checkpoint_dir": None if ckpt_dir is None else str(ckpt_dir),
            "pytorch_tabnet_version": _version("pytorch_tabnet"),
            "torch_version": torch.__version__,
        }

    # --- scoring --------------------------------------------------------
    def _raw_score(self, frame: pd.DataFrame, **_) -> np.ndarray:
        return margins(self.clf, self.preprocessor.transform(frame))

    def score(self, frame: pd.DataFrame, **kwargs) -> np.ndarray:
        return sigmoid(self.raw_score(frame, **kwargs))

    def scores(self, frame: pd.DataFrame, **kwargs) -> tuple[np.ndarray, np.ndarray]:
        raw = self.raw_score(frame, **kwargs)
        return raw, sigmoid(raw)

    def metadata(self) -> dict:
        meta = super().metadata()
        meta["calibrator"] = {"method": "sigmoid(logit margin), float64; equals predict_proba[:, 1]"}
        meta["raw_score"] = "logit(malicious) - logit(benign)"
        return meta

    def _extra_metadata(self) -> dict:
        return dict(self.info)

    # --- persistence ----------------------------------------------------
    def _save_artifacts(self, directory: Path) -> dict:
        with contextlib.redirect_stdout(io.StringIO()):
            self.clf.save_model(str(directory / TABNET_ZIP.removesuffix(".zip")))
        (directory / PREPROCESSOR_FILE).write_text(json.dumps(self.preprocessor.to_dict()), encoding="utf-8")
        names = self.preprocessor.output_columns
        (directory / IMPORTANCE_FILE).write_text(json.dumps({
            "method": "normalised sum of TabNet aggregate masks over the training rows",
            "columns": names,
            "importance": [float(v) for v in self.importance],
            "grouped": grouped_importance(self.importance, names),
        }), encoding="utf-8")
        return {"model": TABNET_ZIP, "preprocessor": PREPROCESSOR_FILE, "global_importance": IMPORTANCE_FILE}

    def _load_artifacts(self, directory: Path, meta: dict) -> None:
        self.preprocessor = TabNetPreprocessor.from_dict(json.loads((directory / PREPROCESSOR_FILE).read_text(encoding="utf-8")))
        self.clf = load_tabnet_classifier(directory / TABNET_ZIP, device_name=_device_name(self.config["device"]))
        imp = json.loads((directory / IMPORTANCE_FILE).read_text(encoding="utf-8"))
        self.importance = np.asarray(imp["importance"], dtype="float64")
        self.clf.feature_importances_ = self.importance
        self.info = {k: meta[k] for k in ("imbalance", "device_used", "epochs_run", "best_epoch") if k in meta}


class _Filtered(io.TextIOBase):
    """Pass prints through, minus pytorch-tabnet's per-fit chatter."""

    _DROP = ("Early stopping occurred", "Stop training because", "Successfully saved model")

    def __init__(self, target) -> None:
        self.target = target
        self._dropped = False

    def write(self, s: str) -> int:
        if s.strip() and any(s.lstrip("\n").startswith(p) for p in self._DROP):
            self._dropped = True
            return len(s)
        if self._dropped and s == "\n":      # print()'s trailing newline of a dropped line
            self._dropped = False
            return len(s)
        self._dropped = False
        return self.target.write(s)

    def flush(self) -> None:
        self.target.flush()


def _version(module: str) -> str | None:
    try:
        from importlib.metadata import version

        return version(module.replace("_", "-"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

SCORE_COLUMNS = ("user_id", "date", "split", "raw_score", "anomaly_score", "model_name", "model_version")


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    root = repo_root()
    d = TabNetDetector()
    c = d.config
    p = argparse.ArgumentParser(description="CIRA Chapter 7 TabNet")
    p.add_argument("--processed-dir", default=os.getenv("CERT_PROCESSED_DIR"), required=os.getenv("CERT_PROCESSED_DIR") is None)
    p.add_argument("--profile", default=os.getenv("CIRA_PROFILE", "dev"), choices=("dev", "mid", "full"))
    p.add_argument("--split", default="user", choices=("user", "time"))
    p.add_argument("--seed", type=int, default=int(os.getenv("CIRA_SEED", "42")))
    p.add_argument("--budgets", default=",".join(str(k) for k in DEFAULT_BUDGETS))
    p.add_argument("--fractions", default=",".join(str(f) for f in DEFAULT_FRACTIONS))
    p.add_argument("--rebuild-split", action="store_true", help="only if the split must change; say so in the write-up (N11)")
    p.add_argument("--time-validation-start", default="2011-01-01")
    p.add_argument("--time-test-start", default="2011-02-01")
    p.add_argument("--device", default=os.getenv("CIRA_DEVICE", "auto"), choices=("auto", "cpu", "cuda"))
    p.add_argument("--n-d", type=int, default=c["n_d"])
    p.add_argument("--n-a", type=int, default=c["n_a"])
    p.add_argument("--n-steps", type=int, default=c["n_steps"])
    p.add_argument("--gamma", type=float, default=c["gamma"])
    p.add_argument("--n-independent", type=int, default=c["n_independent"])
    p.add_argument("--n-shared", type=int, default=c["n_shared"])
    p.add_argument("--lambda-sparse", type=float, default=c["lambda_sparse"])
    p.add_argument("--mask-type", default=c["mask_type"], choices=("sparsemax", "entmax"))
    p.add_argument("--lr", type=float, default=c["lr"])
    p.add_argument("--scheduler-step", type=int, default=c["scheduler_step_size"])
    p.add_argument("--scheduler-gamma", type=float, default=c["scheduler_gamma"])
    p.add_argument("--max-epochs", type=int, default=c["max_epochs"])
    p.add_argument("--patience", type=int, default=c["patience"])
    p.add_argument("--batch-size", type=int, default=c["batch_size"])
    p.add_argument("--virtual-batch-size", type=int, default=c["virtual_batch_size"])
    p.add_argument("--imbalance", default=c["imbalance"], choices=IMBALANCE_METHODS)
    p.add_argument("--pretrain", action="store_true", help="HCEA §7.4: optional, mid profile, <= 20 epochs")
    p.add_argument("--pretrain-max-epochs", type=int, default=c["pretrain_max_epochs"])
    p.add_argument("--pretraining-ratio", type=float, default=c["pretraining_ratio"])
    p.add_argument("--exclude-features", default="",
                   help="comma-separated column prefixes the model must not see, e.g. psych_,peer_department_size "
                        "(static-trait ablation); recorded in the config, so it is a new model version")
    p.add_argument("--tag", default="", help="free-text note for the hyperparameter log")
    p.add_argument("--fresh", action="store_true", help="delete this config's checkpoints before training")
    p.add_argument("--no-register", action="store_true", help="do not write a registry version (smoke tests)")
    p.add_argument("--splits-dir", default=str(root / "experiments" / "splits"))
    p.add_argument("--results-dir", default=str(root / "experiments" / "results" / "chapter7"))
    p.add_argument("--models-dir", default=os.getenv("MODEL_PATH", str(root / "models" / "saved_models")))
    p.add_argument("--checkpoint-dir", default=str(root / "models" / "checkpoints"))
    return p.parse_args(argv)


def detector_config(args: argparse.Namespace) -> dict:
    return dict(
        n_d=args.n_d, n_a=args.n_a, n_steps=args.n_steps, gamma=args.gamma, n_independent=args.n_independent,
        n_shared=args.n_shared, lambda_sparse=args.lambda_sparse, mask_type=args.mask_type, lr=args.lr,
        scheduler_step_size=args.scheduler_step, scheduler_gamma=args.scheduler_gamma, max_epochs=args.max_epochs,
        patience=args.patience, batch_size=args.batch_size, virtual_batch_size=args.virtual_batch_size,
        imbalance=args.imbalance, pretrain=args.pretrain, pretrain_max_epochs=args.pretrain_max_epochs,
        pretraining_ratio=args.pretraining_ratio, device=args.device,
    )


def excluded_columns(matrix: pd.DataFrame, prefixes: str) -> list[str]:
    """Feature columns matching any comma-separated prefix; refuses a prefix that matches nothing."""
    wanted = [p.strip() for p in (prefixes or "").split(",") if p.strip()]
    cols = [c for c in matrix.columns if c not in ("user_id", "date")]
    out = []
    for p in wanted:
        hit = [c for c in cols if c.startswith(p)]
        if not hit:
            raise SystemExit(f"--exclude-features: no feature column starts with {p!r}")
        out.extend(hit)
    return sorted(set(out))


def _configs_already_run(profile: str) -> set[str]:
    path = Path(os.getenv("CIRA_RUNLOG", str(repo_root() / "experiments" / "runlog.jsonl")))
    if not path.exists():
        return set()
    seen = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            if r.get("stage") == "chapter7_tabnet" and r.get("profile") == profile and r.get("config_hash"):
                seen.add(r["config_hash"])
    return seen


def _scenario_summary(block: dict, budgets) -> dict:
    out = {}
    for k in budgets:
        b = block["primary"]["budgets"][str(k)]
        out[f"recall_by_scenario_at_{k}"] = {s: f"{v['alerted']}/{v['positives']}" for s, v in b["recall_by_scenario"].items()}
        out[f"caught_by_scenario_at_{k}"] = {s: f"{v['caught']}/{v['insiders']}" for s, v in b["per_user"]["by_scenario"].items()}
    return out


def run(args: argparse.Namespace) -> dict:
    started = time.perf_counter()
    processed = Path(args.processed_dir)
    budgets = tuple(int(k) for k in args.budgets.split(",") if k.strip())
    fractions = tuple(float(f) for f in args.fractions.split(","))
    fm = load_feature_matrix(processed, args.profile)
    matrix, keys = fm.matrix, fm.keys

    # --- labels: evaluation and training only, in memory (N5) -------------
    views = load_label_views(processed)
    labels = attach_labels(keys, views)
    coverage = label_coverage(keys, views)
    for view in ("primary", "account"):
        if coverage[view]["unmatched"]:
            raise RuntimeError(f"{view} label days inside the feature window have no feature row: {coverage[view]}")
        if args.profile != "dev" and coverage[view]["outside_feature_window"]:
            raise RuntimeError(f"{view} label days outside the feature window under profile={args.profile}: {coverage[view]}")
    scen = insider_scenarios(views, set(keys["user_id"].unique().tolist()))

    # --- split (N3, N11) ---------------------------------------------------
    split = make_split(
        keys, mode=args.split, insider_scenarios=scen, seed=args.seed, profile=args.profile, splits_dir=args.splits_dir,
        fractions=fractions, rebuild=args.rebuild_split,
        time_validation_start=args.time_validation_start, time_test_start=args.time_test_start,
    )
    if split.info.get("created_now") and args.profile != "dev":
        print(f"NOTE: {split.info['file']} did not exist and was created now. Chapter 6 comparisons (N18) "
              "are valid only if the baselines used this same file.", flush=True)
    lab = {s: labels.iloc[ix].reset_index(drop=True) for s, ix in split.parts.items()}
    split.info["positives_primary"] = {s: int(lab[s]["y_primary"].sum()) for s in SPLITS}
    split.info["masquerade_rows_excluded"] = {s: int(lab[s]["exclude_primary"].sum()) for s in SPLITS}

    reportable = args.profile != "dev"
    run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{args.profile}-{args.split}-s{args.seed}"
    feature_fp = feature_fingerprint(fm.features_path)
    data_fp = data_fingerprint(feature_fp, split)
    split.info["data_fingerprint"] = data_fp
    frames = {s: matrix.iloc[ix].reset_index(drop=True) for s, ix in split.parts.items()}

    excluded = excluded_columns(matrix, args.exclude_features)
    extra_cfg = {"excluded_features": excluded} if excluded else {}   # absent when empty: default model_version unchanged
    detector = TabNetDetector(
        seed=args.seed, nullable_columns=[c for c in fm.nullable if c not in excluded], data_fingerprint=data_fp,
        checkpoint_dir=str(Path(args.checkpoint_dir) / "chapter7" / args.profile / args.split),
        **detector_config(args), **extra_cfg,
    )
    if excluded:
        print(f"[tabnet] excluded from the model input: {', '.join(excluded)}", flush=True)
    cfg_hash = detector.model_version.rsplit("-", 1)[-1]
    already = _configs_already_run(args.profile)
    if cfg_hash not in already and len(already) >= HYPERPARAMETER_BUDGET and reportable:
        print(f"WARNING: {len(already)} TabNet configurations already logged at {args.profile}; "
              f"HCEA §7.6 caps manual search at {HYPERPARAMETER_BUDGET}. Record why this one is needed.", flush=True)
    if args.fresh:
        removed = detector.clear_checkpoints()
        if removed:
            print(f"[tabnet] --fresh: removed {removed} checkpoint(s)", flush=True)

    # --- fit on train, early-stop on validation (N13: no masquerade rows) ---
    keep_tr, keep_va = supervised_rows(lab["train"]), supervised_rows(lab["validation"])
    t0 = time.perf_counter()
    detector.fit(
        frames["train"][keep_tr].drop(columns=excluded).reset_index(drop=True),
        lab["train"]["y_primary"].to_numpy()[keep_tr],
        validation=frames["validation"][keep_va].drop(columns=excluded).reset_index(drop=True),
        y_validation=lab["validation"]["y_primary"].to_numpy()[keep_va],
    )
    # Scoring passes the full rows: the fitted preprocessor selects its own
    # columns by name, which is also what the serving path will do.
    fit_seconds = time.perf_counter() - t0

    # --- score every validation and test row, masquerade days included -----
    t1 = time.perf_counter()
    blocks, score_rows, saturated = {}, [], {}
    for s in ("validation", "test"):
        raw, cal = detector.scores(frames[s])
        blocks[s] = evaluate_scores(frames[s][["user_id", "date"]], cal, lab[s], budgets=budgets, seed=args.seed)
        saturated[s] = int((cal >= 1.0).sum())
        score_rows.append(pd.DataFrame({
            "user_id": frames[s]["user_id"].to_numpy(), "date": frames[s]["date"].to_numpy(), "split": s,
            "raw_score": raw, "anomaly_score": cal, "model_name": MODEL_NAME, "model_version": detector.model_version,
        }))
    score_seconds = time.perf_counter() - t1
    scores_path = processed / "scores" / "chapter7" / run_id / f"{MODEL_NAME}.parquet"
    atomic_to_parquet(pd.concat(score_rows, ignore_index=True)[list(SCORE_COLUMNS)], scores_path)

    meta = detector.metadata()
    provenance = {
        "profile": args.profile, "split_mode": args.split, "run_id": run_id, "feature_fingerprint": feature_fp,
        "data_fingerprint": data_fp, "wall_clock_fit_seconds": round(fit_seconds, 2),
        "wall_clock_score_seconds": round(score_seconds, 2), "saturated_scores": saturated, "tag": args.tag,
    }
    val_head, test_head = headline(blocks["validation"], budgets), headline(blocks["test"], budgets)

    # --- register (Bible Ch7 step 4) ----------------------------------------
    entry = None
    if not args.no_register:
        registry = ModelRegistry(args.models_dir, MODEL_NAME)
        entry = registry.register(
            lambda d: detector.save(d, extra=provenance),
            {
                "model_version": detector.model_version,
                "run_id": run_id,
                "chapter": 7,
                "profile": args.profile,
                "reportable": reportable,
                "split": {k: split.info.get(k) for k in ("mode", "file", "file_sha256", "validation_start", "test_start", "rows")},
                "seed": args.seed,
                "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "training_data": {
                    "dataset": fm.schema.get("dataset", "CERT r4.2"), "features_path": str(fm.features_path),
                    "feature_fingerprint": feature_fp, "data_fingerprint": data_fp,
                    "rows_matrix": int(len(matrix)), "rows_train_used": int(keep_tr.sum()),
                    "rows_train_masquerade_dropped": int((~keep_tr).sum()), "n_features": int(matrix.shape[1] - 2),
                },
                "feature_schema": {
                    "path": str(fm.schema_path), "pipeline_version": fm.schema.get("pipeline_version"),
                    "host_categories_version": fm.schema.get("host_categories_version"),
                    "config_fingerprint": fm.schema.get("config_fingerprint"),
                },
                "config": detector._identity_config(),
                "imbalance": meta["imbalance"],
                "training": {k: meta.get(k) for k in ("device_used", "epochs_run", "best_epoch", "best_valid_pr_auc",
                                                        "early_stopping", "resumed_from_epoch", "pretraining")},
                "metrics": {"validation": {**val_head, **_scenario_summary(blocks["validation"], budgets)},
                            "test": {**test_head, **_scenario_summary(blocks["test"], budgets)}},
                "score_convention": "anomaly_score = sigmoid(logit margin) in [0, 1], higher = more anomalous (N10)",
                "scores_path": str(scores_path),
            },
        )
        provenance["registry_version"] = entry["registry_version"]
        provenance["model_dir"] = entry["artifact_dir"]

    report = {
        "chapter": 7,
        "version": CHAPTER7_VERSION,
        "run_id": run_id,
        "profile": args.profile,
        "reportable": reportable,
        "reportable_note": None if reportable else "dev profile: debugging only, never report these numbers (N6, HCEA R10)",
        "seed": args.seed,
        "budgets": list(budgets),
        "features": {"path": str(fm.features_path), "fingerprint": feature_fp, "schema": str(fm.schema_path),
                     "pipeline_version": fm.schema.get("pipeline_version"), "n_features": int(matrix.shape[1] - 2),
                     "rows": int(len(matrix)), "excluded_from_model": excluded},
        "label_coverage": coverage,
        "split": split.info,
        "training_rows": {"train_used": int(keep_tr.sum()), "train_masquerade_dropped": int((~keep_tr).sum()),
                          "validation_used": int(keep_va.sum()), "validation_masquerade_dropped": int((~keep_va).sum())},
        "registry": None if entry is None else {k: entry[k] for k in ("registry_version", "artifact_dir", "files")},
        "models": {MODEL_NAME: {"metadata": {**meta, **provenance, "scores_path": str(scores_path)}, **blocks}},
    }
    report["wall_seconds"] = round(time.perf_counter() - started, 2)
    report["peak_rss_mb"] = round(memory_rss_mb(), 1)
    results_dir = Path(args.results_dir) / run_id
    results_dir.mkdir(parents=True, exist_ok=True)
    tmp = results_dir / "metrics.json.tmp"
    tmp.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    tmp.replace(results_dir / "metrics.json")
    report["results_path"] = str(results_dir / "metrics.json")

    append_experiment_runlog({
        "stage": "chapter7_tabnet", "run_id": run_id, "model": MODEL_NAME, "model_version": detector.model_version,
        "config_hash": cfg_hash, "registry_version": provenance.get("registry_version"), "profile": args.profile,
        "reportable": reportable, "split_mode": args.split, "seed": args.seed, "tag": args.tag,
        "excluded_features": excluded,
        "imbalance": meta["imbalance"]["method"], "effective_positive_weight": meta["imbalance"]["effective_positive_weight"],
        "train_positive_rate": meta["imbalance"]["train_positive_rate"], "pretrain": bool(args.pretrain),
        "device": meta.get("device_used"), "epochs_run": meta.get("epochs_run"), "best_epoch": meta.get("best_epoch"),
        "resumed_from_epoch": meta.get("resumed_from_epoch"), "valid_pr_auc": val_head["pr_auc"],
        "rows_train": int(keep_tr.sum()), "rows_test": int(len(frames["test"])),
        "wall_seconds_fit": round(fit_seconds, 2), "wall_seconds_score": round(score_seconds, 2),
        "peak_rss_mb": round(memory_rss_mb(), 1), "peak_vram_mb": meta.get("peak_vram_mb"),
        "feature_fingerprint": feature_fp, "data_fingerprint": data_fp, "split_sha256": split.info.get("file_sha256"),
        "saturated_test_scores": saturated["test"],
        **{f"test_{k}": v for k, v in test_head.items()},
        **{f"test_{k}": v for k, v in _scenario_summary(blocks["test"], budgets).items()},
    })
    _print_summary(report, budgets)
    return report


def _fmt(v) -> str:
    return "n/a" if v is None else (f"{v:.3f}" if isinstance(v, float) else str(v))


def _print_summary(report: dict, budgets) -> None:
    """Validation only. Test metrics are written to metrics.json, the
    registry and the runlog, but not shown here: during tuning the console
    is what gets read, and test must be read once, for the write-up (N11)."""
    md = report["models"][MODEL_NAME]["metadata"]
    print()
    if not report["reportable"]:
        print("!! dev profile: debugging numbers only, do not report (N6) !!")
    print(f"run {report['run_id']}  split={report['split']['mode']}  registry={md.get('registry_version', 'not registered')}")
    imb = md["imbalance"]
    print(f"imbalance: {imb['method']}, positive weight {imb['effective_positive_weight']:.1f}, "
          f"train positive rate {imb['train_positive_rate']:.4f}; device {md.get('device_used')}; "
          f"epochs {md.get('epochs_run')} (best {md.get('best_epoch')})")
    if report["features"].get("excluded_from_model"):
        print(f"excluded from the model input: {', '.join(report['features']['excluded_from_model'])}")
    print(f"{'part':<11}{'PR-AUC':>8}{'ROC-AUC*':>10}" + "".join(f"{f'R@{k}':>8}{f'caught@{k}':>11}" for k in budgets))
    p = report["models"][MODEL_NAME]["validation"]["primary"]
    row = f"{'validation':<11}{_fmt(p['pr_auc']):>8}{_fmt(p['roc_auc_secondary']):>10}"
    for k in budgets:
        b = p["budgets"][str(k)]
        row += f"{_fmt(b['recall']):>8}{b['per_user']['caught']:>6}/{b['per_user']['insiders']:<4}"
    print(row)
    k = budgets[0]
    b = p["budgets"][str(k)]
    print(f"validation recall@{k} by scenario: "
          + ", ".join(f"s{s} {v['alerted']}/{v['positives']}" for s, v in b["recall_by_scenario"].items())
          + "  (N15: scenario 2 dominates the headline)")
    print("test: written to metrics.json, not shown. Read it once, for the write-up, with "
          "python -m app.evaluation.compare ... --part test (N11)")
    if md["saturated_scores"]["test"] or md["saturated_scores"]["validation"]:
        print(f"NOTE: rows with score exactly 1.0: {md['saturated_scores']}; ties at the top are broken by the seeded key")
    if md.get("static_traits_in_top10"):
        print(f"NOTE: static per-user traits in the mask top 10: {md['static_traits_in_top10']}")
    print("* ROC-AUC is secondary (N2). Full metrics:", report.get("results_path"))
    print("Compare with the Chapter 6 baselines: python -m app.evaluation.compare "
          f"--profile {report['profile']} --split {report['split']['mode']} --run-id {report['run_id']}")


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    try:
        run(args)
    except Exception as exc:
        print(f"chapter7 run failed: {exc}", file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
