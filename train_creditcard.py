"""
FRAUD-X  ·  Credit Card Fraud Ensemble Training Script
=======================================================
Trains the full enterprise ML stack on creditcard.csv.

  creditcard.csv — 284,807 rows, 492 fraud (0.172%)
  Columns: Time, V1-V28 (PCA), Amount, Class

What this script does
---------------------
  1. Load & validate creditcard.csv (searches several paths)
  2. Engineer 36 features (time, amount transforms, V1-V28)
  3. Apply class-imbalance sampling (default: hybrid SMOTETomek)
  4. Train FraudEnsemble (XGBoost + LightGBM + RF + OnlineSGD + IsoForest)
  5. Train AutoencoderEngine on legitimate-only transactions
  6. Train SequenceEngine (LSTM or statistical fallback)
  7. Print enterprise evaluation metrics
  8. Save all models to models/

Usage
-----
  python train_creditcard.py
  python train_creditcard.py --csv path/to/creditcard.csv
  python train_creditcard.py --sampling smote   # smote|adasyn|borderline|hybrid|smoteenn
  python train_creditcard.py --epochs 40 --no-autoencoder --no-sequence
  python train_creditcard.py --dry-run           # validate CSV only, no training
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent))

# ── Locate creditcard.csv ─────────────────────────────────────────────────────

SEARCH_PATHS = [
    Path(__file__).parent / "creditcard.csv",
    Path(__file__).parent / "data" / "creditcard.csv",
    Path.home() / "Downloads" / "creditcard.csv",
    Path.home() / "Desktop" / "creditcard.csv",
]


def find_csv(override: str | None) -> Path:
    if override:
        p = Path(override)
        if not p.exists():
            raise FileNotFoundError(f"CSV not found: {p}")
        return p
    for p in SEARCH_PATHS:
        if p.exists():
            return p
    raise FileNotFoundError(
        "creditcard.csv not found. Download from Kaggle (Credit Card Fraud Detection) "
        "and place it in the project folder, or pass --csv <path>."
    )


# ═════════════════════════════════════════════════════════════════════════════
# Helpers
# ═════════════════════════════════════════════════════════════════════════════

def _sep(title: str = "") -> None:
    line = "=" * 60
    if title:
        print(f"\n{line}\n  {title}\n{line}")
    else:
        print(line)


def _print_class_dist(y: np.ndarray, label: str = "") -> None:
    fraud = int(y.sum())
    total = len(y)
    legit = total - fraud
    pct   = fraud / total * 100
    print(f"  {label} -> Total={total:,}  Legit={legit:,}  Fraud={fraud:,}  ({pct:.3f}%)")


def _print_eval(metrics: dict) -> None:
    rows = [
        ("Precision",  f"{metrics.get('precision', 0):.4f}"),
        ("Recall",     f"{metrics.get('recall', 0):.4f}"),
        ("F1 Score",   f"{metrics.get('f1', 0):.4f}"),
        ("ROC-AUC",    f"{metrics.get('roc_auc', 0):.4f}"),
        ("PR-AUC",     f"{metrics.get('pr_auc', 0):.4f}"),
        ("FPR",        f"{metrics.get('false_positive_rate', 0):.4f}"),
        ("FNR",        f"{metrics.get('false_negative_rate', 0):.4f}"),
        ("Accuracy",   f"{metrics.get('accuracy', 0):.4f}"),
        ("TP",         str(metrics.get('true_positives', 0))),
        ("FP",         str(metrics.get('false_positives', 0))),
        ("TN",         str(metrics.get('true_negatives', 0))),
        ("FN",         str(metrics.get('false_negatives', 0))),
    ]
    for k, v in rows:
        print(f"  {k:<14} {v}")


# ═════════════════════════════════════════════════════════════════════════════
# Main
# ═════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(description="Train FRAUD-X enterprise ML stack")
    parser.add_argument("--csv",            type=str, default=None)
    parser.add_argument("--sampling",       type=str, default="hybrid",
                        choices=["smote", "adasyn", "borderline", "hybrid", "smoteenn", "none"])
    parser.add_argument("--epochs-ae",      type=int, default=30, dest="epochs_ae")
    parser.add_argument("--epochs-seq",     type=int, default=20, dest="epochs_seq")
    parser.add_argument("--cv",             type=int, default=5)
    parser.add_argument("--no-autoencoder", action="store_true")
    parser.add_argument("--no-sequence",    action="store_true")
    parser.add_argument("--dry-run",        action="store_true")
    args = parser.parse_args()

    total_t0 = time.time()

    # ── Step 1: Load CSV ──────────────────────────────────────────────────────
    _sep("Step 1 · Load Dataset")
    csv_path = find_csv(args.csv)
    print(f"  Source: {csv_path}")

    try:
        import pandas as pd
    except ImportError:
        print("ERROR: pandas is required.  pip install pandas")
        sys.exit(1)

    df = pd.read_csv(str(csv_path))
    required = {"Time", "Amount", "Class"} | {f"V{i}" for i in range(1, 29)}
    missing = required - set(df.columns)
    if missing:
        print(f"ERROR: Missing columns: {missing}")
        sys.exit(1)

    print(f"  Rows: {len(df):,}   Columns: {len(df.columns)}")
    _print_class_dist(df["Class"].values, "Raw")

    if args.dry_run:
        print("\n  [dry-run] Validation passed. Exiting without training.")
        return

    # ── Step 2: Feature engineering ───────────────────────────────────────────
    _sep("Step 2 · Feature Engineering")
    from advanced_ml_engine import engineer_features, fraud_ensemble

    X_all = engineer_features(df)
    y_all = df["Class"].values.astype(int)
    print(f"  Feature matrix: {X_all.shape}")

    # Train / test split (stratified, 80/20)
    from sklearn.model_selection import train_test_split
    X_tr, X_te, y_tr, y_te = train_test_split(
        X_all, y_all, test_size=0.20, stratify=y_all, random_state=42
    )
    _print_class_dist(y_tr, "Train")
    _print_class_dist(y_te, "Test ")

    # ── Step 3: Train ensemble ────────────────────────────────────────────────
    _sep("Step 3 · Train FraudEnsemble")
    sampling = None if args.sampling == "none" else args.sampling
    print(f"  Sampling strategy: {sampling or 'none'}")
    print(f"  CV folds: {args.cv}")

    result = fraud_ensemble.train(X_tr, y_tr, sampling=sampling, cv_folds=args.cv)
    print(f"\n  Backend:   {result.get('backend', 'xgb+lgb+rf+sgd+iso')}")
    print(f"  Sampling:  {result.get('sampling_strategy', '?')}")
    print(f"  Train samples (after sampling): {result.get('train_samples', 0):,}")
    print(f"  Elapsed:   {result.get('training_seconds', '?')}s")

    # ── Step 4: Evaluate ensemble ─────────────────────────────────────────────
    _sep("Step 4 · Evaluate Ensemble")
    from advanced_ml_engine import evaluate_model

    y_proba = fraud_ensemble.predict_batch(X_te)
    y_pred  = (y_proba >= 0.5).astype(int)
    metrics = evaluate_model(y_te, y_pred, y_proba)
    _print_eval(metrics)

    cv_scores = result.get("cv_scores", {})
    if cv_scores:
        print(f"\n  CV Results (train):")
        for metric, vals in cv_scores.items():
            if isinstance(vals, list):
                print(f"    {metric:<10} {np.mean(vals):.4f} ± {np.std(vals):.4f}")

    # ── Step 5: Autoencoder ───────────────────────────────────────────────────
    ae_result = {}
    if not args.no_autoencoder:
        _sep("Step 5 · Train Autoencoder")
        from autoencoder_engine import autoencoder_engine

        X_legit = X_tr[y_tr == 0]
        print(f"  Training on {len(X_legit):,} legitimate transactions only")
        ae_result = autoencoder_engine.train(X_legit, epochs=args.epochs_ae)
        print(f"  Backend:   {ae_result.get('backend')}")
        print(f"  Threshold: {ae_result.get('threshold')}")
        print(f"  Elapsed:   {ae_result.get('elapsed_s')}s")

        # Quick AE evaluation
        ae_scores   = autoencoder_engine.reconstruction_error(X_te)
        ae_thresh   = ae_result.get('threshold', 0.0)
        ae_preds    = (ae_scores > ae_thresh).astype(int)
        ae_max      = ae_scores.max() or 1.0
        ae_metrics  = evaluate_model(y_te, ae_preds, np.clip(ae_scores / ae_max, 0, 1))
        print(f"\n  AE standalone metrics:")
        print(f"    Precision={ae_metrics['precision']:.4f}  "
              f"Recall={ae_metrics['recall']:.4f}  "
              f"F1={ae_metrics['f1']:.4f}")
        autoencoder_engine.save()

    # ── Step 6: Sequence engine ───────────────────────────────────────────────
    seq_result = {}
    if not args.no_sequence:
        _sep("Step 6 · Train Sequence Engine (LSTM/GRU)")
        from sequence_engine import sequence_engine

        # Use training set as the sequence dataset
        seq_result = sequence_engine.train(X_tr, epochs=args.epochs_seq)
        print(f"  Backend:   {seq_result.get('backend')}")
        print(f"  Sequences: {seq_result.get('sequences', 0):,}")
        print(f"  Threshold: {seq_result.get('threshold')}")
        print(f"  Elapsed:   {seq_result.get('elapsed_s')}s")
        sequence_engine.save()

    # ── Step 7: Save ensemble ─────────────────────────────────────────────────
    _sep("Step 7 · Save Models")
    fraud_ensemble.save()
    print(f"  Ensemble    -> models/fraud_ensemble.pkl")
    if ae_result:
        print(f"  Autoencoder -> models/autoencoder.h5 / autoencoder.pkl")
    if seq_result:
        print(f"  Sequence    -> models/lstm_model.pt / seq_meta.pkl")

    # ── Summary ───────────────────────────────────────────────────────────────
    _sep("Training Complete")
    elapsed = round(time.time() - total_t0, 1)
    print(f"  Total time:  {elapsed}s")
    print(f"  F1 Score:    {metrics.get('f1', 0):.4f}")
    print(f"  ROC-AUC:     {metrics.get('roc_auc', 0):.4f}")
    print(f"  PR-AUC:      {metrics.get('pr_auc', 0):.4f}")
    print(f"\n  Restart the FRAUD-X server to load the new models.")
    _sep()


if __name__ == "__main__":
    main()
