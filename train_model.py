"""
FRAUD-X  ·  URL Model Training Script
======================================
Trains a Random Forest (and optional Logistic Regression comparison)
on URL features and saves url_model.pkl.

Usage
-----
  # Train on built-in synthetic dataset (fast, no file needed):
  python train_model.py

  # Train on a real CSV dataset (recommended for production):
  python train_model.py --csv phishing_dataset.csv

  # Compare Random Forest vs Logistic Regression:
  python train_model.py --compare

  # Use a larger synthetic dataset:
  python train_model.py --n 5000

Real Dataset Sources
--------------------
  PhishTank    https://www.phishtank.com/developer_info.php
  OpenPhish    https://openphish.com/feed.txt
  ISCX-URL2016 https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
  URLhaus      https://urlhaus.abuse.ch/downloads/csv_recent/

CSV Format Required
-------------------
  Columns:  url, label
  label:    1 = phishing / malicious,   0 = legitimate / benign
  Example:
    url,label
    http://paypa1-login.tk/verify,1
    https://google.com,0
"""

from __future__ import annotations

import argparse
import csv
import sys
import time
from pathlib import Path
from typing import List, Tuple

# ── Ensure project root is on path ──────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))

from ml_url_model import (
    FEATURE_NAMES,
    URLFraudModel,
    _build_synthetic_dataset,
    extract_features,
)


def load_csv_dataset(csv_path: str) -> Tuple[List[List[float]], List[int]]:
    """
    Load a CSV file with columns 'url' and 'label'.
    Skips rows with missing/invalid data.
    """
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {csv_path}")

    X, y = [], []
    skipped = 0
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        # Try common column name variants
        url_col   = next((c for c in (reader.fieldnames or [])
                          if c.lower() in ("url", "urls", "address", "link")), None)
        label_col = next((c for c in (reader.fieldnames or [])
                          if c.lower() in ("label", "labels", "class", "type",
                                           "phishing", "result")), None)
        if not url_col or not label_col:
            raise ValueError(
                f"CSV must have 'url' and 'label' columns. Found: {reader.fieldnames}"
            )

        for row in reader:
            url = (row.get(url_col) or "").strip()
            lbl = (row.get(label_col) or "").strip()
            if not url or lbl == "":
                skipped += 1
                continue
            try:
                label = int(float(lbl))
                if label not in (0, 1):
                    skipped += 1
                    continue
            except ValueError:
                # Try string labels: "phishing" / "benign" etc.
                lbl_l = lbl.lower()
                if lbl_l in ("1", "phishing", "malicious", "bad", "spam"):
                    label = 1
                elif lbl_l in ("0", "legitimate", "legit", "benign", "good", "clean"):
                    label = 0
                else:
                    skipped += 1
                    continue
            X.append(extract_features(url))
            y.append(label)

    print(f"  Loaded {len(X)} samples ({skipped} skipped).")
    return X, y


def evaluate(clf, X_test, y_test) -> None:
    """Print a detailed evaluation report."""
    from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
    import numpy as np

    preds = clf.predict(X_test)
    proba = clf.predict_proba(X_test)[:, 1]

    print("\n-- Classification Report -------------------------------------")
    print(classification_report(y_test, preds,
                                 target_names=["Legitimate", "Phishing"]))
    print("-- Confusion Matrix ------------------------------------------")
    cm = confusion_matrix(y_test, preds)
    tn, fp, fn, tp = cm.ravel()
    print(f"  True  Negative (correct legit):   {tn:>5}")
    print(f"  False Positive (legit → phish):   {fp:>5}  ← false positives")
    print(f"  False Negative (phish → legit):   {fn:>5}  ← missed phishing")
    print(f"  True  Positive (correct phish):   {tp:>5}")
    print(f"\n  False Positive Rate: {fp/(fp+tn)*100:.1f}%")
    print(f"  False Negative Rate: {fn/(fn+tp)*100:.1f}%")
    try:
        auc = roc_auc_score(y_test, proba)
        print(f"\n  ROC-AUC: {auc:.4f}")
    except Exception:
        pass


def print_feature_importance(clf, top: int = 12) -> None:
    """Print feature importance table (Random Forest only)."""
    try:
        imp = clf.feature_importances_
    except AttributeError:
        return
    ranked = sorted(zip(FEATURE_NAMES, imp), key=lambda kv: -kv[1])
    print("\n-- Feature Importance ----------------------------------------")
    print(f"  {'Feature':<28}  Importance")
    print(f"  {'-'*28}  ----------")
    for name, score in ranked[:top]:
        bar = "#" * int(score * 60)
        print(f"  {name:<28}  {score:.4f}  {bar}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train FRAUD-X URL classifier")
    parser.add_argument("--csv",     type=str, default=None,
                        help="Path to CSV dataset (url, label columns)")
    parser.add_argument("--n",       type=int, default=2000,
                        help="Synthetic samples PER CLASS (default 1000 each = 2000 total)")
    parser.add_argument("--compare", action="store_true",
                        help="Also train Logistic Regression for comparison")
    parser.add_argument("--out",     type=str, default=None,
                        help="Output model path (default: url_model.pkl)")
    args = parser.parse_args()

    print("=" * 58)
    print("  FRAUD-X  ·  URL Fraud Classifier  ·  Training")
    print("=" * 58)

    # ── Load dataset ─────────────────────────────────────────────
    if args.csv:
        print(f"\n[1/4] Loading CSV dataset: {args.csv}")
        X, y = load_csv_dataset(args.csv)
    else:
        n_each = max(200, args.n // 2)
        print(f"\n[1/4] Generating synthetic dataset ({n_each} phishing + {n_each} legit)…")
        X, y = _build_synthetic_dataset(n_phish=n_each, n_legit=n_each)
        print(f"  Generated {len(X)} samples.")

    # ── Split ────────────────────────────────────────────────────
    from sklearn.model_selection import train_test_split
    import numpy as np

    X_arr = np.array(X, dtype=float)
    y_arr = np.array(y, dtype=int)

    X_train, X_test, y_train, y_test = train_test_split(
        X_arr, y_arr, test_size=0.20, random_state=42, stratify=y_arr
    )
    phish_count = int(y_arr.sum())
    legit_count = int((y_arr == 0).sum())
    print(f"\n  Total : {len(y_arr):<6}  Phishing: {phish_count}  Legit: {legit_count}")
    print(f"  Train : {len(y_train):<6}  Test: {len(y_test)}")

    # ── Train Random Forest ──────────────────────────────────────
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import cross_val_score

    print("\n[2/4] Training Random Forest (200 trees)…")
    t0 = time.time()
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    cv_f1 = cross_val_score(rf, X_train, y_train, cv=5, scoring="f1")
    rf.fit(X_train, y_train)
    elapsed = time.time() - t0
    print(f"  Done in {elapsed:.1f}s  |  CV F1: {cv_f1.mean():.4f} +/- {cv_f1.std():.4f}")
    evaluate(rf, X_test, y_test)
    print_feature_importance(rf)

    # ── Optional: Logistic Regression comparison ─────────────────
    if args.compare:
        from sklearn.linear_model import LogisticRegression
        from sklearn.preprocessing import StandardScaler
        from sklearn.pipeline import Pipeline

        print("\n-- Logistic Regression (comparison) -------------------------")
        lr = Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(
                max_iter=1000, class_weight="balanced", random_state=42
            )),
        ])
        cv_lr = cross_val_score(lr, X_train, y_train, cv=5, scoring="f1")
        lr.fit(X_train, y_train)
        print(f"  CV F1: {cv_lr.mean():.4f} +/- {cv_lr.std():.4f}")
        evaluate(lr, X_test, y_test)
        print(f"\n  Winner: {'Random Forest' if cv_f1.mean() >= cv_lr.mean() else 'Logistic Regression'}")

    # ── Save model ───────────────────────────────────────────────
    from ml_url_model import MODEL_PATH
    import joblib

    out_path = Path(args.out) if args.out else MODEL_PATH
    joblib.dump(rf, str(out_path))
    print(f"\n[3/4] Model saved → {out_path}")

    # ── Sanity-check inference ───────────────────────────────────
    print("\n[4/4] Inference sanity check:")
    test_urls = [
        ("http://paypa1-login.tk/verify/account",          "expect HIGH"),
        ("http://192.168.1.5/banking/confirm.php",         "expect HIGH"),
        ("https://google.com/search?q=test",               "expect LOW"),
        ("https://paypal.com/us/signin",                   "expect LOW"),
        ("http://secure-amazon-update.xyz/account/login",  "expect HIGH"),
        ("https://github.com/openai/gpt-4",                "expect LOW"),
    ]
    wrapper = URLFraudModel()
    wrapper.load(out_path)
    print(f"  {'URL':<55}  Prob    Conf      Note")
    print(f"  {'-'*55}  ------  --------  ------")
    for url, note in test_urls:
        prob, conf = wrapper.predict(url)
        flag = "🔴" if prob >= 60 else "🟡" if prob >= 30 else "🟢"
        print(f"  {url[:54]:<55}  {prob:>5.1f}%  {conf:<8}  {flag} {note}")

    print("\n✓ Training complete. Restart the server to activate the new model.")


if __name__ == "__main__":
    main()
