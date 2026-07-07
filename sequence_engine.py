"""
FRAUD-X  ·  LSTM/GRU Transaction Sequence Engine
=================================================
Detects fraud by learning SEQUENTIAL user transaction patterns.

Architecture
------------
  PyTorch LSTM / GRU trained on sliding windows of a user's
  historical transactions. An anomaly is flagged when a new
  transaction deviates sharply from the learned sequence pattern.

  Fallback: rolling-window statistical anomaly (numpy) when
  PyTorch is unavailable.

Per-user tracking
-----------------
  Each user gets an in-memory deque of their last N transactions.
  The LSTM predicts the next transaction's features; high prediction
  error = behavioral drift = fraud signal.

Usage
-----
  seq = SequenceEngine()
  seq.train(X_sequences, y_sequences)     # offline training
  result = seq.score(user_id, feature_vec)  # online scoring
  seq.save() / seq.load()
"""

from __future__ import annotations

import logging
import math
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
from sklearn.preprocessing import RobustScaler

logger = logging.getLogger("fraudx.sequence")

_SEQ_DIR = Path(__file__).parent / "models"
_SEQ_DIR.mkdir(exist_ok=True)
_SEQ_MODEL  = _SEQ_DIR / "lstm_model.pt"
_SEQ_SCALER = _SEQ_DIR / "seq_scaler.pkl"
_SEQ_META   = _SEQ_DIR / "seq_meta.pkl"

WINDOW      = 10    # look at last 10 transactions
HIDDEN_DIM  = 64
N_LAYERS    = 2

# ── PyTorch availability ──────────────────────────────────────────────────────
try:
    import torch
    import torch.nn as nn
    _TORCH = True
    logger.info("[SEQ] PyTorch %s available", torch.__version__)
except ImportError:
    _TORCH = False
    logger.info("[SEQ] PyTorch not available — using statistical fallback")


# ═════════════════════════════════════════════════════════════════════════════
# PyTorch LSTM model
# ═════════════════════════════════════════════════════════════════════════════

if _TORCH:
    class _LSTMPredictor(nn.Module):
        """Predicts next transaction feature vector from sequence of WINDOW steps."""
        def __init__(self, input_dim: int, hidden: int = HIDDEN_DIM, layers: int = N_LAYERS):
            super().__init__()
            self.lstm = nn.LSTM(input_dim, hidden, layers,
                                batch_first=True, dropout=0.2)
            self.fc   = nn.Linear(hidden, input_dim)

        def forward(self, x):                 # x: (B, T, D)
            out, _ = self.lstm(x)
            return self.fc(out[:, -1, :])     # predict next from last hidden

    class _GRUPredictor(nn.Module):
        """GRU variant — faster, slightly less expressive."""
        def __init__(self, input_dim: int, hidden: int = HIDDEN_DIM, layers: int = N_LAYERS):
            super().__init__()
            self.gru = nn.GRU(input_dim, hidden, layers,
                              batch_first=True, dropout=0.2)
            self.fc  = nn.Linear(hidden, input_dim)

        def forward(self, x):
            out, _ = self.gru(x)
            return self.fc(out[:, -1, :])


# ═════════════════════════════════════════════════════════════════════════════
# SequenceEngine
# ═════════════════════════════════════════════════════════════════════════════

class SequenceEngine:
    """
    Online LSTM sequence anomaly detector.

    Training: provide sliding-window sequences from a dataset where
    each sample is (window, next_transaction).

    Scoring: for a specific user_id, maintain their rolling transaction
    history and flag large prediction errors as sequence anomalies.
    """

    def __init__(self, use_gru: bool = False) -> None:
        self._use_gru   = use_gru
        self._model     = None
        self._scaler    = RobustScaler()
        self._threshold = 0.0
        self._train_mean= 0.0
        self._train_std = 0.0
        self._input_dim = 0
        self._ready     = False
        self._backend   = "none"
        # Per-user rolling transaction history (deques of feature vectors)
        self._user_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=WINDOW + 5))

    # ── Training ─────────────────────────────────────────────────────────────

    def train(
        self,
        X: np.ndarray,
        epochs: int = 20,
        batch_size: int = 512,
        lr: float = 1e-3,
        k_sigma: float = 4.0,
    ) -> Dict:
        """
        Train on a matrix of transactions (N, D).
        Sequences are created by sliding a WINDOW over the rows.
        """
        t0 = time.time()
        self._input_dim = X.shape[1]
        X_s = self._scaler.fit_transform(X)

        # Build sequences: (B, WINDOW, D) → target (B, D)
        seqs, targets = self._make_sequences(X_s)
        if len(seqs) < 50:
            logger.warning("[SEQ] Too few sequences (%d) — skipping training", len(seqs))
            self._backend = "statistical"
            self._ready   = True
            errors = self._statistical_errors(X_s)
            self._calibrate_threshold(errors, k_sigma)
            return {"backend": "statistical", "sequences": 0}

        if _TORCH:
            self._backend = "gru" if self._use_gru else "lstm"
            errors        = self._train_torch(seqs, targets, epochs, batch_size, lr)
        else:
            self._backend = "statistical"
            errors        = self._statistical_errors(X_s)

        self._calibrate_threshold(errors, k_sigma)
        self._ready = True

        elapsed = round(time.time() - t0, 1)
        logger.info("[SEQ] Trained %s. threshold=%.6f  elapsed=%ss",
                    self._backend, self._threshold, elapsed)
        return {
            "backend":    self._backend,
            "sequences":  len(seqs),
            "threshold":  round(self._threshold, 6),
            "elapsed_s":  elapsed,
        }

    def _make_sequences(self, X_s: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        seqs, targets = [], []
        for i in range(WINDOW, len(X_s)):
            seqs.append(X_s[i - WINDOW:i])
            targets.append(X_s[i])
        if not seqs:
            return np.array([]), np.array([])
        return np.array(seqs, dtype=np.float32), np.array(targets, dtype=np.float32)

    def _train_torch(self, seqs, targets, epochs, batch_size, lr) -> np.ndarray:
        import torch, torch.nn as nn
        Cls   = _GRUPredictor if self._use_gru else _LSTMPredictor
        model = Cls(self._input_dim)
        opt   = torch.optim.Adam(model.parameters(), lr=lr)
        loss_fn = nn.MSELoss()

        X_t = torch.tensor(seqs)
        y_t = torch.tensor(targets)

        model.train()
        for epoch in range(epochs):
            perm = torch.randperm(len(X_t))
            for i in range(0, len(X_t), batch_size):
                idx = perm[i:i + batch_size]
                xb, yb = X_t[idx], y_t[idx]
                opt.zero_grad()
                loss = loss_fn(model(xb), yb)
                loss.backward()
                opt.step()
            if (epoch + 1) % 5 == 0:
                logger.debug("[SEQ] epoch %d/%d  loss=%.5f", epoch+1, epochs, float(loss))

        model.eval()
        with torch.no_grad():
            preds  = model(X_t).numpy()
        errors = np.mean((seqs[:, -1, :] - preds) ** 2, axis=1)
        self._model = model
        return errors

    def _statistical_errors(self, X_s: np.ndarray) -> np.ndarray:
        """Rolling mean absolute deviation as fallback 'error'."""
        errors = []
        for i in range(WINDOW, len(X_s)):
            window_mean = X_s[i - WINDOW:i].mean(axis=0)
            errors.append(float(np.mean((X_s[i] - window_mean) ** 2)))
        return np.array(errors) if errors else np.zeros(1)

    def _calibrate_threshold(self, errors: np.ndarray, k_sigma: float) -> None:
        self._train_mean = float(np.mean(errors))
        self._train_std  = float(np.std(errors))
        self._threshold  = self._train_mean + k_sigma * self._train_std

    # ── Online scoring ────────────────────────────────────────────────────────

    def score(self, user_id: str, feature_vector: np.ndarray) -> Dict:
        """
        Score a new transaction for a specific user.
        Updates the user's rolling history after scoring.
        """
        history = self._user_history[user_id]
        history.append(feature_vector.copy())

        if not self._ready or len(history) < WINDOW:
            return {
                "sequence_anomaly_score": 0.0,
                "is_anomaly":             False,
                "drift_score":            0.0,
                "history_len":            len(history),
                "backend":               self._backend,
            }

        X_s       = self._scaler.transform(np.array(list(history)[-WINDOW:]))
        error     = self._predict_error(X_s)
        z_score   = (error - self._train_mean) / max(self._train_std, 1e-9)
        drift     = float(min(1.0, max(0.0, 1 / (1 + math.exp(-z_score + 3.0)))))
        is_anomaly = error > self._threshold

        # Behavioral drift: compare last tx to user's mean
        if len(history) >= 3:
            hist_arr  = self._scaler.transform(np.array(list(history)[:-1]))
            user_mean = hist_arr.mean(axis=0)
            curr      = X_s[-1]
            deviation = float(np.linalg.norm(curr - user_mean))
        else:
            deviation = 0.0

        return {
            "sequence_anomaly_score": round(error, 6),
            "is_anomaly":             bool(is_anomaly),
            "drift_score":            round(drift, 4),
            "behavioral_deviation":   round(deviation, 4),
            "z_score":                round(z_score, 3),
            "threshold":              round(self._threshold, 6),
            "history_len":            len(history),
            "backend":               self._backend,
        }

    def _predict_error(self, X_s: np.ndarray) -> float:
        """MSE prediction error for the latest step."""
        if _TORCH and self._model is not None and self._backend in ("lstm", "gru"):
            import torch
            window = torch.tensor(X_s[np.newaxis, :, :], dtype=torch.float32)
            self._model.eval()
            with torch.no_grad():
                pred = self._model(window).numpy()[0]
            return float(np.mean((X_s[-1] - pred) ** 2))
        else:
            window_mean = X_s[:-1].mean(axis=0)
            return float(np.mean((X_s[-1] - window_mean) ** 2))

    def clear_user(self, user_id: str) -> None:
        self._user_history.pop(user_id, None)

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self) -> None:
        import joblib
        if _TORCH and self._model is not None:
            import torch
            torch.save(self._model.state_dict(), str(_SEQ_MODEL))
        joblib.dump(self._scaler, str(_SEQ_SCALER))
        joblib.dump({
            "threshold":  self._threshold,
            "train_mean": self._train_mean,
            "train_std":  self._train_std,
            "input_dim":  self._input_dim,
            "backend":    self._backend,
            "use_gru":    self._use_gru,
            "ready":      self._ready,
        }, str(_SEQ_META))
        logger.info("[SEQ] Saved to %s", _SEQ_DIR)

    def load(self) -> bool:
        import joblib
        try:
            meta = joblib.load(str(_SEQ_META))
            self._threshold  = meta["threshold"]
            self._train_mean = meta["train_mean"]
            self._train_std  = meta["train_std"]
            self._input_dim  = meta["input_dim"]
            self._backend    = meta["backend"]
            self._use_gru    = meta["use_gru"]
            self._ready      = meta["ready"]
            self._scaler     = joblib.load(str(_SEQ_SCALER))

            if _TORCH and _SEQ_MODEL.exists() and self._backend in ("lstm", "gru"):
                Cls = _GRUPredictor if self._use_gru else _LSTMPredictor
                self._model = Cls(self._input_dim)
                self._model.load_state_dict(
                    torch.load(str(_SEQ_MODEL), map_location="cpu")
                )
                self._model.eval()
            logger.info("[SEQ] Loaded %s. threshold=%.6f", self._backend, self._threshold)
            return True
        except Exception as exc:
            logger.debug("[SEQ] Load failed: %s", exc)
            return False

    def status(self) -> Dict:
        return {
            "ready":        self._ready,
            "backend":      self._backend,
            "window":       WINDOW,
            "threshold":    round(self._threshold, 6) if self._ready else None,
            "torch_available": _TORCH,
            "active_users": len(self._user_history),
        }

    @property
    def is_ready(self) -> bool:
        return self._ready


# ── Singleton ──────────────────────────────────────────────────────────────────
sequence_engine = SequenceEngine(use_gru=False)
