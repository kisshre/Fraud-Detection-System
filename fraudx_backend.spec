# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for FRAUD-X backend.
Run: pyinstaller fraudx_backend.spec
Output: backend-dist/fraudx_backend.exe
"""

import os
import sys
from PyInstaller.utils.hooks import collect_all, collect_submodules, collect_data_files

block_cipher = None

# ── Collect data files ────────────────────────────────────────────────────────
datas = []

# Model files
for model_file in [
    "models/fraud_ensemble.pkl",
    "models/fraud_isoforest.pkl",
    "models/fraud_scaler.pkl",
    "models/fraud_calibrator.pkl",
    "models/fraud_misc.pkl",
    "models/fraud_online.pkl",
    "models/autoencoder.h5",
    "models/ae_scaler.pkl",
    "models/ae_threshold.pkl",
    "models/lstm_model.pt",
    "models/seq_meta.pkl",
    "models/seq_scaler.pkl",
    "url_model.pkl",
]:
    if os.path.exists(model_file):
        datas.append((model_file, os.path.dirname(model_file) or "."))

# Static files
for static in ["index.html", "login.html", "signup.html", ".env.example"]:
    if os.path.exists(static):
        datas.append((static, "."))

# ── Hidden imports ────────────────────────────────────────────────────────────
hiddenimports = [
    # FastAPI / Starlette
    "uvicorn.logging",
    "uvicorn.loops.auto",
    "uvicorn.loops.asyncio",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.protocols.websockets.websockets_impl",
    "uvicorn.lifespan.on",
    "fastapi",
    "starlette",
    "pydantic",
    "pydantic.v1",
    "pydantic_core",
    # Database
    "aiosqlite",
    "sqlite3",
    # ML
    "sklearn",
    "sklearn.ensemble",
    "sklearn.svm",
    "sklearn.preprocessing",
    "xgboost",
    "lightgbm",
    # Deep learning
    "tensorflow",
    "keras",
    "torch",
    # Data
    "numpy",
    "pandas",
    "scipy",
    "joblib",
    # Crypto / auth
    "cryptography",
    "bcrypt",
    "jwt",
    # Network
    "httpx",
    "httpcore",
    "h11",
    "websockets",
    # Other
    "networkx",
    "python_multipart",
    "email_validator",
    "dotenv",
    "main",
    "database",
    "ml_engine",
    "ml_url_model",
    "scoring_engine",
    "behavior_engine",
    "graph_engine",
    "xai_engine",
    "payment_gateway_analyzer",
    "advanced_ml_engine",
    "autoencoder_engine",
    "biometrics_engine",
    "ato_engine",
    "simulation_engine",
    "risk_engine_v2",
    "threat_intel",
    "sequence_engine",
    "session_intelligence",
    "signature_engine",
    "campaign_detector",
    "event_correlation_engine",
    "drift_monitor",
    "memory_engine",
    "multi_agent_orchestrator",
    "feedback_engine",
    "confidence_fusion",
    "transaction_engine",
    "stream_engine",
    "window_analytics",
    "auth_service",
]

# Collect all submodules for key packages
for pkg in ["sklearn", "xgboost", "networkx", "cryptography", "fastapi"]:
    try:
        hiddenimports += collect_submodules(pkg)
    except Exception:
        pass

# ── Analysis ──────────────────────────────────────────────────────────────────
a = Analysis(
    ["run_backend.py"],
    pathex=["."],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "IPython", "jupyter"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="fraudx_backend",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,   # console=True so Electron can read stdout for health checks
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="assets/icon.ico" if os.path.exists("assets/icon.ico") else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="fraudx_backend",
    distpath="backend-dist",
)
