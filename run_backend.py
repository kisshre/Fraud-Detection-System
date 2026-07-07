"""
FRAUD-X Backend Launcher
========================
Entry point used by PyInstaller to bundle the backend.
Handles frozen executable path resolution and starts uvicorn.
"""

import sys
import os
import multiprocessing

# ── PyInstaller path fix ──────────────────────────────────────────────────────
if getattr(sys, "frozen", False):
    # Running as PyInstaller bundle
    BASE_DIR = sys._MEIPASS  # type: ignore[attr-defined]
    os.chdir(BASE_DIR)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Ensure the base directory is on the path
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# ── Environment defaults ──────────────────────────────────────────────────────
os.environ.setdefault("FRAUDX_EMBEDDED", "1")
os.environ.setdefault("PYTHONUNBUFFERED", "1")

# ── Load .env if available ───────────────────────────────────────────────────
env_path = os.path.join(BASE_DIR, ".env")
if os.path.exists(env_path):
    try:
        from dotenv import load_dotenv
        load_dotenv(env_path)
    except ImportError:
        # Manual fallback
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, val = line.partition("=")
                    os.environ.setdefault(key.strip(), val.strip())

# ── Start server ─────────────────────────────────────────────────────────────
def main():
    port = int(os.environ.get("FRAUDX_PORT", 8000))
    host = os.environ.get("FRAUDX_HOST", "127.0.0.1")

    print(f"[FRAUD-X Backend] Starting on {host}:{port}", flush=True)

    import uvicorn
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        log_level="info",
        access_log=True,
        workers=1,
        loop="asyncio",
    )


if __name__ == "__main__":
    # Required for PyInstaller + multiprocessing on Windows
    multiprocessing.freeze_support()
    main()
