"""
FRAUD-X  ·  Autoencoder Anomaly Detection Engine
=================================================
Trains a Dense Autoencoder exclusively on legitimate transactions.
High reconstruction error ≡ anomalous (fraudulent) pattern.

Architecture
------------
  Dense AE:  36 → 24 → 12 → 6 → 12 → 24 → 36
  VAE:       36 → [μ, σ] (dim=6) → reparameterize → 36

Fallback
--------
  If TensorFlow is unavailable, uses sklearn MLPRegressor
  as a lightweight autoencoder substitute.

Usage
-----
  ae = AutoencoderEngine()
  ae.train(X_legitimate)          # numpy array, shape (N, 36)
  result = ae.score(x)            # single row → reconstruction error + anomaly flag
  ae.save() / ae.load()
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

import numpy as np
from sklearn.preprocessing import RobustScaler

logger = logging.getLogger("fraudx.autoencoder")

_AE_DIR  = Path(__file__).parent / "models"
_AE_DIR.mkdir(exist_ok=True)
_AE_PKL  = _AE_DIR / "autoencoder.pkl"      # sklearn fallback
_AE_H5   = _AE_DIR / "autoencoder.h5"       # TF model
_AE_SCALER = _AE_DIR / "ae_scaler.pkl"
_AE_THRESH = _AE_DIR / "ae_threshold.pkl"

# ── TensorFlow availability ────────────────────────────────────────────────────
try:
    import tensorflow as tf
    from tensorflow import keras
    _TF = True
    logger.info("[AE] TensorFlow %s available", tf.__version__)
except ImportError:
    _TF = False
    logger.info("[AE] TensorFlow not available — using sklearn MLP fallback")


# ═════════════════════════════════════════════════════════════════════════════
# TensorFlow Autoencoder builders
# ═════════════════════════════════════════════════════════════════════════════

def _build_dense_ae(input_dim: int, bottleneck: int = 6) -> "keras.Model":
    """Dense autoencoder: encoder → bottleneck → decoder."""
    inp  = keras.Input(shape=(input_dim,))
    x    = keras.layers.Dense(input_dim * 2 // 3, activation="relu")(inp)
    x    = keras.layers.Dense(input_dim // 2,     activation="relu")(x)
    x    = keras.layers.Dense(bottleneck,          activation="relu", name="bottleneck")(x)
    x    = keras.layers.Dense(input_dim // 2,     activation="relu")(x)
    x    = keras.layers.Dense(input_dim * 2 // 3, activation="relu")(x)
    out  = keras.layers.Dense(input_dim,           activation="linear")(x)
    model = keras.Model(inp, out, name="dense_autoencoder")
    model.compile(optimizer=keras.optimizers.Adam(1e-3), loss="mse")
    return model


class _VAESampling(keras.layers.Layer):
    """Reparameterization trick for VAE."""
    def call(self, inputs):
        z_mean, z_log_var = inputs
        eps = tf.random.normal(shape=tf.shape(z_mean))
        return z_mean + tf.exp(0.5 * z_log_var) * eps


def _build_vae(input_dim: int, latent_dim: int = 6) -> Tuple["keras.Model", "keras.Model", "keras.Model"]:
    """Variational Autoencoder; returns (encoder, decoder, vae)."""
    # Encoder
    inp     = keras.Input(shape=(input_dim,))
    h       = keras.layers.Dense(input_dim // 2, activation="relu")(inp)
    z_mean  = keras.layers.Dense(latent_dim, name="z_mean")(h)
    z_log_v = keras.layers.Dense(latent_dim, name="z_log_var")(h)
    z       = _VAESampling()([z_mean, z_log_v])
    encoder = keras.Model(inp, [z_mean, z_log_v, z], name="vae_encoder")

    # Decoder
    lat_inp = keras.Input(shape=(latent_dim,))
    h2      = keras.layers.Dense(input_dim // 2, activation="relu")(lat_inp)
    dec_out = keras.layers.Dense(input_dim, activation="linear")(h2)
    decoder = keras.Model(lat_inp, dec_out, name="vae_decoder")

    # VAE combined
    z_m, z_lv, z_s = encoder(inp)
    out = decoder(z_s)
    vae = keras.Model(inp, out, name="vae")

    # Custom ELBO loss
    rec_loss = tf.reduce_mean(tf.reduce_sum(tf.square(inp - out), axis=1))
    kl_loss  = -0.5 * tf.reduce_mean(1 + z_lv - tf.square(z_m) - tf.exp(z_lv))
    vae.add_loss(rec_loss + kl_loss)
    vae.compile(optimizer=keras.optimizers.Adam(1e-3))
    return encoder, decoder, vae


# ═════════════════════════════════════════════════════════════════════════════
# sklearn MLP fallback autoencoder
# ═════════════════════════════════════════════════════════════════════════════

def _build_sklearn_ae(input_dim: int):
    from sklearn.neural_network import MLPRegressor
    hidden = (input_dim * 2 // 3, input_dim // 2, 6, input_dim // 2, input_dim * 2 // 3)
    return MLPRegressor(
        hidden_layer_sizes=hidden, activation="relu",
        solver="adam", learning_rate_init=1e-3,
        max_iter=50, random_state=42, early_stopping=True,
        validation_fraction=0.1, n_iter_no_change=5,
    )


# ═════════════════════════════════════════════════════════════════════════════
# AutoencoderEngine
# ═════════════════════════════════════════════════════════════════════════════

class AutoencoderEngine:
    """
    Wraps Dense AE + VAE (TF) or MLP AE (sklearn fallback).

    threshold: reconstruction error above which a transaction is
               classified as anomalous. Set at mean + k*std of training
               errors on legitimate samples (default k=3 for ~99.7% coverage).
    """

    def __init__(self, use_vae: bool = False, k_sigma: float = 3.0) -> None:
        self._use_vae    = use_vae
        self._k_sigma    = k_sigma
        self._scaler     = RobustScaler()
        self._model      = None          # TF model or sklearn MLPRegressor
        self._vae_enc    = None
        self._threshold  = 0.0
        self._train_mean = 0.0
        self._train_std  = 0.0
        self._input_dim  = 0
        self._ready      = False
        self._backend    = "none"

    # ── Training ─────────────────────────────────────────────────────────────

    def train(self, X_legit: np.ndarray, epochs: int = 30, batch_size: int = 256) -> Dict:
        """Train on LEGITIMATE transactions only."""
        t0 = time.time()
        self._input_dim = X_legit.shape[1]
        X_s = self._scaler.fit_transform(X_legit)

        if _TF:
            self._backend = "vae" if self._use_vae else "dense"
            self._model, errors = self._train_tf(X_s, epochs, batch_size)
        else:
            self._backend = "sklearn_mlp"
            self._model, errors = self._train_sklearn(X_s)

        self._train_mean = float(np.mean(errors))
        self._train_std  = float(np.std(errors))
        self._threshold  = self._train_mean + self._k_sigma * self._train_std
        self._ready      = True

        elapsed = round(time.time() - t0, 1)
        logger.info("[AE] Trained %s. threshold=%.6f  elapsed=%ss",
                    self._backend, self._threshold, elapsed)
        return {
            "backend":    self._backend,
            "threshold":  round(self._threshold, 6),
            "train_mean": round(self._train_mean, 6),
            "train_std":  round(self._train_std, 6),
            "k_sigma":    self._k_sigma,
            "samples":    len(X_legit),
            "elapsed_s":  elapsed,
        }

    def _train_tf(self, X_s: np.ndarray, epochs: int, batch_size: int):
        if self._use_vae:
            enc, _, model = _build_vae(self._input_dim)
            self._vae_enc = enc
        else:
            model = _build_dense_ae(self._input_dim)

        cb = [
            keras.callbacks.EarlyStopping(patience=5, restore_best_weights=True, verbose=0),
            keras.callbacks.ReduceLROnPlateau(factor=0.5, patience=3, verbose=0),
        ]
        model.fit(X_s, X_s if not self._use_vae else None,
                  epochs=epochs, batch_size=batch_size,
                  validation_split=0.1, callbacks=cb, verbose=0)
        recon  = model.predict(X_s, verbose=0)
        errors = np.mean((X_s - recon) ** 2, axis=1)
        return model, errors

    def _train_sklearn(self, X_s: np.ndarray):
        model = _build_sklearn_ae(self._input_dim)
        model.fit(X_s, X_s)
        recon  = model.predict(X_s)
        errors = np.mean((X_s - recon) ** 2, axis=1)
        return model, errors

    # ── Inference ─────────────────────────────────────────────────────────────

    def reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        """MSE reconstruction error per row."""
        if not self._ready:
            return np.zeros(len(X))
        X_s   = self._scaler.transform(X)
        recon = self._model.predict(X_s, verbose=0) if _TF and self._backend != "sklearn_mlp" \
                else self._model.predict(X_s)
        return np.mean((X_s - recon) ** 2, axis=1)

    def score(self, feature_vector: np.ndarray) -> Dict:
        """Score a single transaction. Returns error, anomaly flag, probability."""
        if not self._ready:
            return {"reconstruction_error": 0.0, "is_anomaly": False,
                    "anomaly_probability": 0.0, "threshold": 0.0}

        error  = float(self.reconstruction_error(feature_vector.reshape(1, -1))[0])
        z_score = (error - self._train_mean) / max(self._train_std, 1e-9)
        # Sigmoid-like mapping: z_score → [0,1]
        anomaly_prob = float(1 / (1 + np.exp(-z_score + self._k_sigma)))

        return {
            "reconstruction_error": round(error, 6),
            "is_anomaly":           error > self._threshold,
            "anomaly_probability":  round(min(1.0, max(0.0, anomaly_prob)), 4),
            "z_score":              round(z_score, 3),
            "threshold":            round(self._threshold, 6),
            "backend":              self._backend,
        }

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self) -> None:
        import joblib, pickle
        if _TF and self._backend != "sklearn_mlp" and self._model is not None:
            self._model.save(str(_AE_H5))
        else:
            joblib.dump(self._model, str(_AE_PKL))
        joblib.dump(self._scaler, str(_AE_SCALER))
        joblib.dump({
            "threshold":  self._threshold,
            "train_mean": self._train_mean,
            "train_std":  self._train_std,
            "k_sigma":    self._k_sigma,
            "input_dim":  self._input_dim,
            "backend":    self._backend,
            "use_vae":    self._use_vae,
            "ready":      self._ready,
        }, str(_AE_THRESH))
        logger.info("[AE] Saved to %s", _AE_DIR)

    def load(self) -> bool:
        import joblib
        try:
            meta = joblib.load(str(_AE_THRESH))
            self._threshold  = meta["threshold"]
            self._train_mean = meta["train_mean"]
            self._train_std  = meta["train_std"]
            self._k_sigma    = meta["k_sigma"]
            self._input_dim  = meta["input_dim"]
            self._backend    = meta["backend"]
            self._use_vae    = meta["use_vae"]
            self._ready      = meta["ready"]
            self._scaler     = joblib.load(str(_AE_SCALER))

            if _TF and self._backend != "sklearn_mlp" and _AE_H5.exists():
                self._model = keras.models.load_model(str(_AE_H5), compile=False)
            elif _AE_PKL.exists():
                self._model = joblib.load(str(_AE_PKL))
            else:
                return False
            logger.info("[AE] Loaded %s. threshold=%.6f", self._backend, self._threshold)
            return True
        except Exception as exc:
            logger.debug("[AE] Load failed: %s", exc)
            return False

    def status(self) -> Dict:
        return {
            "ready":     self._ready,
            "backend":   self._backend,
            "threshold": round(self._threshold, 6) if self._ready else None,
            "k_sigma":   self._k_sigma,
            "tf_available": _TF,
        }

    @property
    def is_ready(self) -> bool:
        return self._ready


# ── Singleton ──────────────────────────────────────────────────────────────────
autoencoder_engine = AutoencoderEngine(use_vae=False, k_sigma=3.0)
