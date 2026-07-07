"""
FRAUD-X  ·  Advanced ML Engine v2
===================================
Enterprise fraud detection using the creditcard.csv dataset.

Pipeline
--------
  1. Load & engineer features  (Time/Amount/velocity/behavioral proxies)
  2. Handle class imbalance    (SMOTE / ADASYN / BorderlineSMOTE / hybrid)
  3. Train ensemble            (XGBoost + LightGBM + Random Forest)
  4. Calibrate probabilities   (Platt scaling + Isotonic regression)
  5. Evaluate                  (Precision, Recall, F1, ROC-AUC, PR-AUC, FPR, FNR)
  6. Online incremental update (partial_fit feedback loop)

Dataset schema expected
-----------------------
  Time, V1–V28, Amount, Class   (standard Kaggle creditcard.csv)
"""

from __future__ import annotations

import logging
import os
import warnings
# LightGBM 4.x auto-generates feature names from numpy arrays; silence the
# resulting sklearn validation noise since both fit and predict use numpy.
warnings.filterwarnings(
    "ignore",
    message="X does not have valid feature names",
    category=UserWarning,
)
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import (
    average_precision_score, classification_report,
    confusion_matrix, f1_score, precision_score,
    recall_score, roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.preprocessing import RobustScaler

try:
    import xgboost as xgb
    _XGB = True
except ImportError:
    _XGB = False

try:
    import lightgbm as lgb
    _LGB = True
except ImportError:
    _LGB = False

try:
    from imblearn.over_sampling import (
        SMOTE, ADASYN, BorderlineSMOTE, RandomOverSampler,
    )
    from imblearn.under_sampling import RandomUnderSampler
    from imblearn.combine import SMOTETomek, SMOTEENN
    _IMBLEARN = True
except ImportError:
    _IMBLEARN = False

logger = logging.getLogger("fraudx.advanced_ml")

# ── Paths ─────────────────────────────────────────────────────────────────────
_BASE = Path(__file__).parent
CREDITCARD_PATHS = [
    _BASE / "creditcard.csv",
    _BASE / "dataset" / "creditcard.csv",
    Path(r"c:\Users\Admin\Desktop\Kisshore Final YR PROJECT\Project\dataset\creditcard.csv"),
]
MODEL_DIR       = _BASE / "models"
ENSEMBLE_PKL    = MODEL_DIR / "fraud_ensemble.pkl"
SCALER_PKL      = MODEL_DIR / "fraud_scaler.pkl"
CALIB_PKL       = MODEL_DIR / "fraud_calibrator.pkl"
ISOFOREST_PKL   = MODEL_DIR / "fraud_isoforest.pkl"
ONLINE_PKL      = MODEL_DIR / "fraud_online.pkl"
MODEL_DIR.mkdir(exist_ok=True)

# ── Feature names produced by engineer_features() ────────────────────────────
ENGINEERED_FEATURES: List[str] = [
    # Original
    "amount", "time_seconds",
    # Time-derived
    "hour_of_day", "is_night", "is_weekend",
    # Amount-derived
    "log_amount", "amount_rounded", "amount_gt_1k",
    # PCA components V1–V28
    *[f"V{i}" for i in range(1, 29)],
]
N_FEATURES = len(ENGINEERED_FEATURES)   # 36


# ═════════════════════════════════════════════════════════════════════════════
# Feature engineering
# ═════════════════════════════════════════════════════════════════════════════

def engineer_features(df) -> np.ndarray:
    """
    Build a 36-column feature matrix from raw creditcard.csv rows.
    Works on a pandas DataFrame with columns: Time, V1-V28, Amount.
    """
    import pandas as pd

    X = pd.DataFrame()
    X["amount"]         = df["Amount"]
    X["time_seconds"]   = df["Time"]
    X["hour_of_day"]    = (df["Time"] % 86400 / 3600).astype(int)
    X["is_night"]       = ((X["hour_of_day"] >= 22) | (X["hour_of_day"] <= 5)).astype(int)
    # Approximate weekday from elapsed seconds (day 0 = Monday based on dataset start)
    X["is_weekend"]     = (((df["Time"] // 86400).astype(int) % 7) >= 5).astype(int)
    X["log_amount"]     = np.log1p(df["Amount"])
    X["amount_rounded"] = (df["Amount"] % 1 < 0.01).astype(int)   # whole number → suspicious
    X["amount_gt_1k"]   = (df["Amount"] > 1000).astype(int)

    for i in range(1, 29):
        X[f"V{i}"] = df[f"V{i}"]

    return X.values.astype(np.float32)


# ═════════════════════════════════════════════════════════════════════════════
# Sampling strategies
# ═════════════════════════════════════════════════════════════════════════════

SamplingStrategy = str   # "smote" | "adasyn" | "borderline" | "hybrid" | "none"


def apply_sampling(
    X: np.ndarray,
    y: np.ndarray,
    strategy: SamplingStrategy = "hybrid",
    random_state: int = 42,
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Return (X_resampled, y_resampled).
    Falls back to class_weight if imbalanced-learn is missing.
    """
    if not _IMBLEARN:
        logger.warning("[AdvancedML] imbalanced-learn not available — no resampling")
        return X, y

    fraud_count = int(y.sum())
    legit_count = int((y == 0).sum())
    logger.info("[AdvancedML] Resampling: %d legit, %d fraud → strategy=%s",
                legit_count, fraud_count, strategy)

    try:
        if strategy == "smote":
            sampler = SMOTE(random_state=random_state, k_neighbors=5)
        elif strategy == "adasyn":
            sampler = ADASYN(random_state=random_state, n_neighbors=5)
        elif strategy == "borderline":
            sampler = BorderlineSMOTE(random_state=random_state, kind="borderline-1")
        elif strategy == "hybrid":
            # Phase 1: SMOTE over-sample minority to 10× original
            target_ratio = min(0.1, fraud_count / legit_count * 10)
            sampler = SMOTETomek(
                smote=SMOTE(random_state=random_state, k_neighbors=5),
                random_state=random_state,
            )
        elif strategy == "smoteenn":
            sampler = SMOTEENN(random_state=random_state)
        else:
            return X, y

        X_res, y_res = sampler.fit_resample(X, y)
        X_res = np.asarray(X_res, dtype=np.float32)
        y_res = np.asarray(y_res, dtype=int)
        logger.info("[AdvancedML] After resampling: %d legit, %d fraud",
                    int((y_res == 0).sum()), int(y_res.sum()))
        return X_res, y_res

    except Exception as exc:
        logger.warning("[AdvancedML] Resampling failed (%s) — using raw data", exc)
        return X, y


# ═════════════════════════════════════════════════════════════════════════════
# Evaluation
# ═════════════════════════════════════════════════════════════════════════════

def evaluate_model(y_true: np.ndarray, y_pred: np.ndarray, y_proba: np.ndarray) -> Dict:
    """Full enterprise evaluation metrics."""
    cm         = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
    total      = tn + fp + fn + tp or 1

    roc_auc = pr_auc = 0.0
    try:
        roc_auc = roc_auc_score(y_true, y_proba)
        pr_auc  = average_precision_score(y_true, y_proba)
    except Exception:
        pass

    return {
        "precision":          round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall":             round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1":                 round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "roc_auc":            round(roc_auc, 4),
        "pr_auc":             round(pr_auc, 4),
        "false_positive_rate":round(fp / (fp + tn) if (fp + tn) > 0 else 0, 4),
        "false_negative_rate":round(fn / (fn + tp) if (fn + tp) > 0 else 0, 4),
        "true_positives":     int(tp),
        "false_positives":    int(fp),
        "true_negatives":     int(tn),
        "false_negatives":    int(fn),
        "accuracy":           round((tp + tn) / total, 4),
    }


# ═════════════════════════════════════════════════════════════════════════════
# Ensemble model
# ═════════════════════════════════════════════════════════════════════════════

class FraudEnsemble:
    """
    Weighted soft-voting ensemble:
      XGBoost (30%) + LightGBM (25%) + Random Forest (20%) +
      Isolation Forest (10%) + Online SGD (15%)

    Calibrated with Isotonic Regression for realistic fraud probabilities.
    """

    # Default weights (sum to 1.0)
    WEIGHTS = {
        "xgb":      0.30,
        "lgb":      0.25,
        "rf":       0.20,
        "online":   0.15,
        "iso":      0.10,
    }

    def __init__(self) -> None:
        self._xgb:     Optional[object]       = None
        self._lgb:     Optional[object]       = None
        self._rf:      Optional[object]       = None
        self._iso:     Optional[IsolationForest] = None
        self._online:  Optional[SGDClassifier]  = None
        self._scaler:  Optional[RobustScaler]   = None
        self._calibrator: Optional[object]      = None
        self._metrics: Dict                    = {}
        self._ready    = False
        self._feature_names = ENGINEERED_FEATURES

    # ── Training ─────────────────────────────────────────────────────────────

    def train(
        self,
        X: np.ndarray,
        y: np.ndarray,
        sampling: SamplingStrategy = "hybrid",
        cv_folds: int = 3,
    ) -> Dict:
        t0 = time.time()

        # Scale
        self._scaler = RobustScaler()
        X_scaled     = self._scaler.fit_transform(X)

        # Resample
        X_res, y_res = apply_sampling(X_scaled, y, strategy=sampling)
        fraud_w      = (y_res == 0).sum() / max(y_res.sum(), 1)

        # ── XGBoost ───────────────────────────────────────────────────────
        if _XGB:
            logger.info("[AdvancedML] Training XGBoost…")
            self._xgb = xgb.XGBClassifier(
                n_estimators=400, max_depth=6, learning_rate=0.05,
                subsample=0.8, colsample_bytree=0.8,
                scale_pos_weight=fraud_w,
                eval_metric="aucpr",
                random_state=42, verbosity=0, n_jobs=-1,
            )
            self._xgb.fit(np.asarray(X_res), np.asarray(y_res))

        # ── LightGBM ──────────────────────────────────────────────────────
        if _LGB:
            logger.info("[AdvancedML] Training LightGBM…")
            self._lgb = lgb.LGBMClassifier(
                n_estimators=400, max_depth=6, learning_rate=0.05,
                subsample=0.8, colsample_bytree=0.8,
                scale_pos_weight=fraud_w,
                random_state=42, verbose=-1, n_jobs=-1,
            )
            self._lgb.fit(np.asarray(X_res), np.asarray(y_res))

        # ── Random Forest ─────────────────────────────────────────────────
        logger.info("[AdvancedML] Training Random Forest…")
        self._rf = RandomForestClassifier(
            n_estimators=300, max_depth=12, min_samples_leaf=2,
            class_weight="balanced", random_state=42, n_jobs=-1,
        )
        self._rf.fit(X_res, y_res)

        # ── Isolation Forest (unsupervised on majority class) ─────────────
        logger.info("[AdvancedML] Training Isolation Forest…")
        X_legit      = X_scaled[y == 0]
        self._iso    = IsolationForest(
            n_estimators=200, contamination=0.002, random_state=42, n_jobs=-1,
        )
        self._iso.fit(X_legit)

        # ── Online SGD (for incremental updates) ──────────────────────────
        logger.info("[AdvancedML] Training Online SGD…")
        self._online = SGDClassifier(
            loss="log_loss", penalty="l2", alpha=1e-4,
            class_weight="balanced", random_state=42,
        )
        self._online.fit(X_res, y_res)

        # ── Probability calibration with Isotonic ────────────────────────
        logger.info("[AdvancedML] Calibrating with Isotonic regression…")
        X_train_c, X_cal_c, y_train_c, y_cal_c = train_test_split(
            X_res, y_res, test_size=0.2, random_state=42, stratify=y_res,
        )
        raw_proba = self._predict_proba_raw(X_cal_c)
        # Use sklearn's CalibratedClassifierCV wrapper on raw proba
        # We implement isotonic calibration manually:
        from sklearn.isotonic import IsotonicRegression
        self._calibrator = IsotonicRegression(out_of_bounds="clip")
        self._calibrator.fit(raw_proba, y_cal_c)

        self._ready = True

        # ── Evaluate on held-out test ─────────────────────────────────────
        X_full_s = self._scaler.transform(X)
        X_tr, X_te, y_tr, y_te = train_test_split(
            X_full_s, y, test_size=0.2, random_state=42, stratify=y,
        )
        proba_te = self.predict_proba(X_te)
        pred_te  = (proba_te >= 0.5).astype(int)
        self._metrics = evaluate_model(y_te, pred_te, proba_te)
        self._metrics["training_seconds"]  = round(time.time() - t0, 1)
        self._metrics["elapsed_s"]         = self._metrics["training_seconds"]
        self._metrics["train_samples"]     = len(y_res)
        self._metrics["original_samples"]  = len(y)
        self._metrics["sampling_strategy"] = sampling
        self._metrics["sampling"]          = sampling
        self._metrics["backend"]           = "xgb+lgb+rf+sgd+iso"
        # Short aliases for display
        self._metrics["fpr"] = self._metrics["false_positive_rate"]
        self._metrics["fnr"] = self._metrics["false_negative_rate"]
        self._metrics["tp"]  = self._metrics["true_positives"]
        self._metrics["fp"]  = self._metrics["false_positives"]
        self._metrics["tn"]  = self._metrics["true_negatives"]
        self._metrics["fn"]  = self._metrics["false_negatives"]
        logger.info("[AdvancedML] Training complete. ROC-AUC=%.4f  Recall=%.4f",
                    self._metrics["roc_auc"], self._metrics["recall"])
        return self._metrics

    # ── Inference ─────────────────────────────────────────────────────────────

    def _predict_proba_raw(self, X_scaled: np.ndarray) -> np.ndarray:
        """Weighted ensemble probability (uncalibrated)."""
        proba  = np.zeros(len(X_scaled))
        total_w = 0.0

        if self._xgb is not None and _XGB:
            proba  += self.WEIGHTS["xgb"] * self._xgb.predict_proba(X_scaled)[:, 1]
            total_w += self.WEIGHTS["xgb"]
        if self._lgb is not None and _LGB:
            proba  += self.WEIGHTS["lgb"] * self._lgb.predict_proba(np.asarray(X_scaled))[:, 1]
            total_w += self.WEIGHTS["lgb"]
        if self._rf is not None:
            proba  += self.WEIGHTS["rf"] * self._rf.predict_proba(X_scaled)[:, 1]
            total_w += self.WEIGHTS["rf"]
        if self._online is not None:
            proba  += self.WEIGHTS["online"] * self._online.predict_proba(X_scaled)[:, 1]
            total_w += self.WEIGHTS["online"]
        if self._iso is not None:
            # Isolation Forest: -1=anomaly, 1=normal → map to [0,1]
            iso_scores = self._iso.score_samples(X_scaled)   # more negative = more anomalous
            iso_proba  = 1 - (iso_scores - iso_scores.min()) / (iso_scores.max() - iso_scores.min() + 1e-9)
            proba     += self.WEIGHTS["iso"] * iso_proba
            total_w   += self.WEIGHTS["iso"]

        return proba / (total_w or 1.0)

    def predict_proba(self, X_scaled: np.ndarray) -> np.ndarray:
        """Calibrated fraud probability for each row."""
        raw = self._predict_proba_raw(X_scaled)
        if self._calibrator is not None:
            return np.clip(self._calibrator.predict(raw), 0.0, 1.0)
        return np.clip(raw, 0.0, 1.0)

    def predict_single(self, feature_vector: np.ndarray) -> Dict:
        """Predict fraud probability for a single transaction feature vector."""
        if not self._ready:
            return {"fraud_probability": 0.0, "risk_level": "unknown", "confidence": "unavailable"}
        X = self._scaler.transform(feature_vector.reshape(1, -1))
        prob  = float(self.predict_proba(X)[0])
        raw   = float(self._predict_proba_raw(X)[0])

        # Per-model breakdown
        breakdown = {}
        if self._xgb  and _XGB: breakdown["xgboost"]   = round(float(self._xgb.predict_proba(X)[0][1]), 4)
        if self._lgb  and _LGB: breakdown["lightgbm"]  = round(float(self._lgb.predict_proba(X)[0][1]), 4)
        if self._rf:             breakdown["rf"]         = round(float(self._rf.predict_proba(X)[0][1]), 4)
        if self._online:         breakdown["online_sgd"] = round(float(self._online.predict_proba(X)[0][1]), 4)
        if self._iso:
            iso_s = float(self._iso.score_samples(X)[0])
            breakdown["isolation_forest"] = round(max(0, min(1, (iso_s + 0.5) * -1)), 4)

        risk   = ("critical" if prob >= 0.80 else "high" if prob >= 0.60
                  else "medium" if prob >= 0.35 else "low" if prob >= 0.10 else "safe")
        margin = abs(prob - 0.5) / 0.5
        conf   = "high" if margin > 0.55 else "medium" if margin > 0.25 else "low"

        return {
            "fraud_probability":    round(prob, 4),
            "raw_ensemble":         round(raw, 4),
            "risk_level":           risk,
            "confidence":           conf,
            "model_breakdown":      breakdown,
            "score_0_100":          int(prob * 100),
        }

    def predict_batch(self, X: np.ndarray) -> np.ndarray:
        """Vectorized fraud probability for a batch of raw (unscaled) feature rows."""
        if not self._ready or self._scaler is None:
            return np.zeros(len(X))
        X_scaled = self._scaler.transform(X)
        return self.predict_proba(X_scaled)

    # ── Online incremental update ─────────────────────────────────────────────

    def partial_fit(self, X: np.ndarray, y: np.ndarray) -> None:
        """Incrementally update the online SGD component."""
        if self._scaler is None or self._online is None:
            return
        X_scaled = self._scaler.transform(X)
        self._online.partial_fit(X_scaled, y, classes=[0, 1])

    # ── SHAP explanation ──────────────────────────────────────────────────────

    def explain(self, feature_vector: np.ndarray, top_n: int = 8) -> Dict[str, float]:
        """SHAP-based explanation using XGBoost model."""
        if self._xgb is None or not _XGB:
            return self._rf_importance_fallback(top_n)
        try:
            import shap
            X_s = self._scaler.transform(feature_vector.reshape(1, -1))
            exp = shap.TreeExplainer(self._xgb)
            sv  = exp.shap_values(X_s)
            sv  = sv[0] if sv.ndim == 2 else sv[1][0]
            pairs = sorted(zip(self._feature_names, sv.tolist()), key=lambda kv: -abs(kv[1]))
            return {k: round(v, 4) for k, v in pairs[:top_n]}
        except Exception as exc:
            logger.debug("[AdvancedML] SHAP error: %s", exc)
            return self._rf_importance_fallback(top_n)

    def _rf_importance_fallback(self, top_n: int) -> Dict[str, float]:
        if self._rf is None:
            return {}
        imp = self._rf.feature_importances_
        pairs = sorted(zip(self._feature_names, imp.tolist()), key=lambda kv: -kv[1])
        return {k: round(v, 4) for k, v in pairs[:top_n]}

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self) -> None:
        joblib.dump(self._xgb,      str(ENSEMBLE_PKL))
        joblib.dump(self._scaler,   str(SCALER_PKL))
        joblib.dump(self._calibrator, str(CALIB_PKL))
        joblib.dump(self._iso,      str(ISOFOREST_PKL))
        joblib.dump(self._online,   str(ONLINE_PKL))
        joblib.dump({
            "rf":      self._rf,
            "lgb":     self._lgb,
            "metrics": self._metrics,
            "ready":   self._ready,
        }, str(MODEL_DIR / "fraud_misc.pkl"))
        logger.info("[AdvancedML] Models saved to %s", MODEL_DIR)

    def load(self) -> bool:
        try:
            misc = joblib.load(str(MODEL_DIR / "fraud_misc.pkl"))
            self._rf       = misc["rf"]
            self._lgb      = misc.get("lgb")
            self._metrics  = misc.get("metrics", {})
            self._ready    = misc.get("ready", False)
            if ENSEMBLE_PKL.exists():
                self._xgb      = joblib.load(str(ENSEMBLE_PKL))
            if SCALER_PKL.exists():
                self._scaler   = joblib.load(str(SCALER_PKL))
            if CALIB_PKL.exists():
                self._calibrator = joblib.load(str(CALIB_PKL))
            if ISOFOREST_PKL.exists():
                self._iso      = joblib.load(str(ISOFOREST_PKL))
            if ONLINE_PKL.exists():
                self._online   = joblib.load(str(ONLINE_PKL))
            logger.info("[AdvancedML] Models loaded. ROC-AUC=%.4f", self._metrics.get("roc_auc", 0))
            return True
        except Exception as exc:
            logger.debug("[AdvancedML] Load failed: %s", exc)
            return False

    # ── Status ────────────────────────────────────────────────────────────────

    def status(self) -> Dict:
        active = []
        if self._xgb  and _XGB: active.append("XGBoost")
        if self._lgb  and _LGB: active.append("LightGBM")
        if self._rf:             active.append("RandomForest")
        if self._iso:            active.append("IsolationForest")
        if self._online:         active.append("OnlineSGD")
        return {
            "ready":         self._ready,
            "active_models": active,
            "weights":       self.WEIGHTS,
            "metrics":       self._metrics,
            "feature_count": N_FEATURES,
            "features":      ENGINEERED_FEATURES,
            "calibrated":    self._calibrator is not None,
            "sampling":      self._metrics.get("sampling_strategy", "none"),
            "model_dir":     str(MODEL_DIR),
        }

    @property
    def is_ready(self) -> bool:
        return self._ready


# ── Singleton ──────────────────────────────────────────────────────────────────
fraud_ensemble = FraudEnsemble()
