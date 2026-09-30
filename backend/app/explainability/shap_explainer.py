"""SHAP for the served model (Bible Ch11 step 2, HCEA D-5, N30).

TreeShapExplainer: the model-side explanation of an XGBoost score
    Exact, path-dependent TreeSHAP computed by XGBoost itself
    (``Booster.predict(pred_contribs=True)``), the same algorithm
    ``shap.TreeExplainer`` runs for a tree model without a background set.
    The verifier cross-checks the two on a sample. It is cheap enough to run
    on every user-day, so it takes the role the HCEA gave TabNet's masks
    ("already cover every row").

    The contributions are in the model's margin units (log-odds) and satisfy
        sum_j phi_j + expected_value = margin
    for the margin the served model actually produced. That is checked on
    every row against ``adapter.raw_score``; a row that does not add up raises
    ExplanationFailedError instead of producing an explanation.

    Early stopping matters here. The sklearn wrapper scores with the best
    iteration, but a raw ``Booster.predict`` uses every tree unless told
    otherwise, so the iteration range is set from ``best_iteration`` (a
    regression test covers it: on a probe model the contributions were off by
    4.56 log-odds without it).

KernelCorroborator: the corroborating signal (D-5), bounded rows only
    ``shap.KernelExplainer`` on the same margin function, for the user-days
    Chapter 11 selects (``selection.py``), never the whole matrix.

    * Background. For XGBoost: 50 real training user-days, a label-free
      user-stratified sample (C11-2). ``shap.kmeans`` cannot take the nulls
      XGBoost routes natively, and a centroid would turn "no activity" into a
      fractional count. For TabNet (preprocessed, no nulls):
      ``shap.kmeans(training sample, 50)`` as D-5 says.
    * nsamples. Default ``2 * M + 2048`` (shap's own "auto"), M = model
      inputs. D-5's 100 is fewer samples than inputs (106 for XGBoost), which
      leaves the regression underdetermined; a value <= M is refused (C11-3).
    * Output per row: overlap of the top-5 features with the primary
      explanation, rank correlation over the union of both top-10s, sign
      agreement, and KernelSHAP's own additivity error. KernelSHAP estimates
      interventional SHAP against the background, TreeSHAP the path-dependent
      value, so perfect agreement is not expected; the verifier WARNs on low
      agreement, it does not FAIL.

Deletion check (label-free faithfulness test, same bounded rows)
    Replace a row's top-k raising features (by the primary explanation) with
    background values and measure how much the margin falls; do the same with
    k features picked at random. An explanation that names the features the
    model actually relied on should lose more. Reported per row.

Label-free (N5). Thread caps are applied by the entry points (N8).
"""
from __future__ import annotations

import warnings

import numpy as np
import pandas as pd

from app.core.runtime import max_workers
from app.scoring.contracts import check_frame

from .attributions import Attributions, ExplanationFailedError, ExplanationUnavailableError, order_by_importance

ADDITIVITY_TOL = 1e-3          # log-odds; float32 inputs, float32 tree sums
CHUNK_ROWS = 50_000            # HCEA §11.1
N_BACKGROUND = 50              # D-5
DELETION_K = 5
KERNEL_TOP = 5


def _xgb():
    import xgboost

    return xgboost


class TreeShapExplainer:
    method = "treeshap"

    def __init__(self, adapter, *, role: str = "served", chunk_rows: int = CHUNK_ROWS) -> None:
        detector = getattr(adapter, "detector", None)
        model = getattr(detector, "model", None)
        if model is None:
            raise ExplanationUnavailableError(f"{getattr(adapter, 'model_name', '?')} adapter holds no XGBoost model")
        self.adapter = adapter
        self.role = role
        self.chunk_rows = max(1, int(chunk_rows))
        self.booster = model.get_booster()
        self.booster.set_param({"nthread": max_workers()})
        best = getattr(model, "best_iteration", None)
        self.best_iteration = None if best is None else int(best)
        self.iteration_range = (0, self.best_iteration + 1) if self.best_iteration is not None else (0, 0)
        self.features = list(adapter.input_columns)

    @property
    def model(self) -> dict:
        a = self.adapter
        return {"model_name": a.model_name, "model_version": a.model_version,
                "registry_version": a.registry_version, "role": self.role}

    def describe(self) -> dict:
        return {"method": self.method, **self.model, "engine": "xgboost Booster.predict(pred_contribs=True)",
                "algorithm": "path-dependent TreeSHAP (exact)", "iteration_range": list(self.iteration_range),
                "best_iteration": self.best_iteration, "n_inputs": len(self.features),
                "additivity_tolerance": ADDITIVITY_TOL}

    def contributions(self, x: np.ndarray) -> np.ndarray:
        """[n x (F + 1)] TreeSHAP values, the last column is the expected value (bias)."""
        xgb = _xgb()
        dm = xgb.DMatrix(np.asarray(x, dtype="float32"), missing=np.nan, nthread=max_workers())
        out = self.booster.predict(dm, pred_contribs=True, iteration_range=self.iteration_range)
        return np.asarray(out, dtype="float64")

    def explain(self, frame: pd.DataFrame) -> Attributions:
        check_frame(frame, self.features)
        vals, bias, raw = [], [], []
        for start in range(0, len(frame), self.chunk_rows):
            block = frame.iloc[start:start + self.chunk_rows]
            c = self.contributions(block[self.features].to_numpy(dtype="float32"))
            vals.append(c[:, :-1])
            bias.append(c[:, -1])
            raw.append(np.asarray(self.adapter.raw_score(block), dtype="float64"))
        values, expected, margin = np.vstack(vals), np.concatenate(bias), np.concatenate(raw)
        err = np.abs(values.sum(axis=1) + expected - margin)
        if not np.isfinite(values).all() or err.max(initial=0.0) > ADDITIVITY_TOL:
            raise ExplanationFailedError(
                f"TreeSHAP does not reproduce the served margin (max error {err.max():.3g} > {ADDITIVITY_TOL}); "
                "no explanation is produced from contributions that do not add up to the score")
        return Attributions(keys=frame[["user_id", "date"]].reset_index(drop=True), features=list(self.features),
                            values=values, method=self.method, raw_score=margin, model=self.model,
                            expected_value=expected, additivity_error=err, info=self.describe())


# ---------------------------------------------------------------------------
# KernelSHAP corroboration and the deletion check (bounded rows, D-5)
# ---------------------------------------------------------------------------

CORROBORATION_COLUMNS = (
    "user_id", "date", "kernel_expected_value", "kernel_additivity_error", "kernel_top_features",
    "top5_overlap", "rank_correlation", "sign_agreement", "deletion_k", "deletion_drop_top",
    "deletion_drop_random", "deletion_top_beats_random",
)


def auto_nsamples(n_inputs: int) -> int:
    return 2 * int(n_inputs) + 2048


def _spearman(a: np.ndarray, b: np.ndarray) -> float:
    if len(a) < 3 or np.all(a == a[0]) or np.all(b == b[0]):
        return float("nan")
    ra, rb = pd.Series(a).rank().to_numpy(), pd.Series(b).rank().to_numpy()
    return float(np.corrcoef(ra, rb)[0, 1])


class KernelCorroborator:
    """KernelSHAP on the served model's margin, in the model's own input space, grouped per base feature."""

    def __init__(self, adapter, pool: pd.DataFrame, *, n_background: int = N_BACKGROUND,
                 nsamples: int | str = "auto", seed: int = 42) -> None:
        self.adapter = adapter
        self.seed = int(seed)
        self.background_keys: list[list[str]] = []
        name = getattr(adapter, "model_name", None)
        if len(pool) == 0:
            raise ExplanationUnavailableError("no training rows to draw a KernelSHAP background from")
        import shap

        self._shap = shap
        if name == "gbdt":
            self.input_columns = list(adapter.input_columns)
            self.groups = {c: [i] for i, c in enumerate(self.input_columns)}
            model = adapter.detector.model

            def f(z):
                return np.asarray(model.predict(np.asarray(z, dtype="float32"), output_margin=True), dtype="float64")

            self.to_input = lambda frame: frame[self.input_columns].to_numpy(dtype="float64", na_value=np.nan)
            rng = np.random.default_rng(self.seed)
            pick = np.sort(rng.choice(len(pool), size=min(n_background, len(pool)), replace=False))
            self.background = self.to_input(pool.iloc[pick])
            self.weights = np.full(len(self.background), 1.0 / len(self.background))
            self.background_data = self.background
            self.background_method = f"{len(self.background)} training user-days, user-stratified sample (C11-2)"
            if {"user_id", "date"} <= set(pool.columns):
                bg = pool.iloc[pick]
                self.background_keys = [[str(u), str(d)] for u, d in zip(bg["user_id"], bg["date"])]
        elif name == "tabnet":
            from app.tabnet.dataset import feature_groups
            from app.tabnet.infer import margins

            scorer = adapter.scorer
            self.input_columns = list(scorer.preprocessor.output_columns)
            self.groups = feature_groups(self.input_columns)

            def f(z):
                return margins(scorer.clf, np.asarray(z, dtype="float32"))

            self.to_input = lambda frame: scorer.preprocessor.transform(frame).astype("float64")
            k = min(n_background, len(pool))
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                dense = shap.kmeans(self.to_input(pool), k)
            self.background = np.asarray(dense.data, dtype="float64")
            self.weights = np.asarray(dense.weights, dtype="float64") / float(np.sum(dense.weights))
            self.background_data = dense
            self.background_method = f"shap.kmeans(preprocessed training sample of {len(pool)} rows, {k}) (D-5)"
        else:
            raise ExplanationUnavailableError(f"no KernelSHAP corroboration for model {name!r}")
        self.f = f
        m = len(self.input_columns)
        self.nsamples = auto_nsamples(m) if nsamples == "auto" else int(nsamples)
        if self.nsamples <= m:
            raise ValueError(f"nsamples={self.nsamples} is not above the {m} model inputs; KernelSHAP's "
                             "regression would be underdetermined (C11-3)")
        self.base_features = list(self.groups)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self.explainer = shap.KernelExplainer(self.f, self.background_data)

    def describe(self) -> dict:
        return {"method": "kernelshap", "background": self.background_method,
                "n_background": int(len(self.background)), "nsamples": self.nsamples,
                "n_inputs": len(self.input_columns), "seed": self.seed, "l1_reg": False,
                "deletion_k": DELETION_K, "background_keys": self.background_keys}

    def _grouped(self, phi: np.ndarray) -> np.ndarray:
        return np.column_stack([phi[:, idx].sum(axis=1) for idx in self.groups.values()])

    def _deletion(self, x: np.ndarray, cols: list[int]) -> float:
        rep = np.tile(x, (len(self.background), 1))
        rep[:, cols] = self.background[:, cols]
        return float(self.f(x[None, :])[0] - np.dot(self.weights, self.f(rep)))

    def corroborate(self, frame: pd.DataFrame, primary: Attributions) -> pd.DataFrame:
        """One row per user-day in ``frame`` (which must be aligned with ``primary``)."""
        if len(frame) != len(primary.keys):
            raise ValueError("frame and primary attributions are not aligned")
        x = self.to_input(frame)
        np.random.seed(self.seed)                   # KernelExplainer samples with the global RNG
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            phi = np.asarray(self.explainer.shap_values(x, nsamples=self.nsamples, l1_reg=False, silent=True),
                             dtype="float64")
        if phi.ndim == 3:                           # some shap versions add an output axis
            phi = phi[..., 0]
        kernel = self._grouped(phi)
        ev = float(np.asarray(self.explainer.expected_value).reshape(-1)[0])
        fx = self.f(x)
        pos = {c: i for i, c in enumerate(primary.features)}
        prim = primary.values[:, [pos[c] for c in self.base_features]]
        rng = np.random.default_rng(self.seed)
        rows = []
        for i in range(len(x)):
            ko, po = order_by_importance(kernel[i:i + 1])[0], order_by_importance(prim[i:i + 1])[0]
            k5, p5 = set(ko[:KERNEL_TOP]), set(po[:KERNEL_TOP])
            union = sorted(set(ko[:10]) | set(po[:10]))
            rho = _spearman(np.abs(kernel[i, union]), np.abs(prim[i, union]))
            signs = [np.sign(kernel[i, j]) == np.sign(prim[i, j]) for j in po[:KERNEL_TOP] if prim[i, j] != 0]
            raising = [j for j in po if prim[i, j] > 0][:DELETION_K]
            k = len(raising)
            if k:
                top_cols = [c for j in raising for c in self.groups[self.base_features[j]]]
                rand = rng.choice(len(self.base_features), size=k, replace=False)
                rand_cols = [c for j in rand for c in self.groups[self.base_features[j]]]
                d_top, d_rand = self._deletion(x[i].copy(), top_cols), self._deletion(x[i].copy(), rand_cols)
            else:
                d_top = d_rand = float("nan")
            rows.append({
                "user_id": str(primary.keys["user_id"].iloc[i]), "date": str(primary.keys["date"].iloc[i]),
                "kernel_expected_value": ev,
                "kernel_additivity_error": float(abs(kernel[i].sum() + ev - fx[i])),
                "kernel_top_features": ",".join(self.base_features[j] for j in ko[:KERNEL_TOP]),
                "top5_overlap": len(k5 & p5) / len(k5 | p5) if (k5 | p5) else float("nan"),
                "rank_correlation": rho,
                "sign_agreement": (float(np.mean(signs)) if (signs and primary.signed) else float("nan")),
                "deletion_k": k, "deletion_drop_top": d_top, "deletion_drop_random": d_rand,
                "deletion_top_beats_random": (bool(d_top > d_rand) if k else None),
            })
        return pd.DataFrame(rows, columns=list(CORROBORATION_COLUMNS))


def shap_tree_cross_check(adapter, frame: pd.DataFrame, attributions: Attributions) -> dict:
    """Compare XGBoost's own TreeSHAP with ``shap.TreeExplainer`` on the same rows (verifier)."""
    try:
        import shap

        te = shap.TreeExplainer(adapter.detector.model)
        sv = np.asarray(te.shap_values(frame[attributions.features].to_numpy(dtype="float32")), dtype="float64")
    except Exception as exc:   # an unparseable model format is a WARN for the verifier, not a crash
        return {"ok": None, "detail": f"shap.TreeExplainer could not run: {exc!r}"[:300]}
    if sv.shape != attributions.values.shape:
        return {"ok": False, "detail": f"shape {sv.shape} vs {attributions.values.shape}"}
    diff = float(np.abs(sv - attributions.values).max())
    return {"ok": diff <= 1e-4, "detail": f"max |shap.TreeExplainer - xgboost pred_contribs| = {diff:.3g} "
                                          f"on {len(frame)} rows (shap {shap.__version__})"}
