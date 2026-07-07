@echo off
setlocal enabledelayedexpansion
title FRAUD-X Production Build

echo.
echo  ===============================================================
echo   FRAUD-X Enterprise ^|^| Production Build System
echo  ===============================================================
echo.

:: ── Check prerequisites ──────────────────────────────────────────────────────
echo [1/6] Checking prerequisites...

where node >nul 2>&1 || (
    echo  ERROR: Node.js not found. Install from https://nodejs.org
    pause & exit /b 1
)
where python >nul 2>&1 || (
    echo  ERROR: Python not found. Install from https://python.org
    pause & exit /b 1
)

for /f "tokens=*" %%v in ('node --version') do echo  Node.js   %%v
for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo  Python    %%v
echo.

:: ── Install root Electron dependencies ──────────────────────────────────────
echo [2/6] Installing Electron dependencies...
call npm install --prefer-offline 2>&1
if errorlevel 1 (
    echo  ERROR: npm install failed.
    pause & exit /b 1
)
echo  Done.
echo.

:: ── Install frontend dependencies ────────────────────────────────────────────
echo [3/6] Installing frontend dependencies...
pushd frontend
call npm install --prefer-offline 2>&1
if errorlevel 1 (
    echo  ERROR: Frontend npm install failed.
    popd & pause & exit /b 1
)
popd
echo  Done.
echo.

:: ── Build Next.js frontend ───────────────────────────────────────────────────
echo [4/6] Building Next.js frontend (standalone mode)...
pushd frontend
call npm run build 2>&1
if errorlevel 1 (
    echo  ERROR: Next.js build failed.
    popd & pause & exit /b 1
)
popd
echo  Frontend build complete.
echo.

:: ── Build Python backend with PyInstaller ────────────────────────────────────
echo [5/6] Building Python backend with PyInstaller...
python -m pip install pyinstaller --quiet 2>&1
pyinstaller fraudx_backend.spec --noconfirm --distpath backend-dist 2>&1
if errorlevel 1 (
    echo  ERROR: PyInstaller build failed.
    pause & exit /b 1
)
echo  Backend build complete.
echo.

:: ── Package Electron app ─────────────────────────────────────────────────────
echo [6/6] Packaging Electron application...
call npm run build:electron 2>&1
if errorlevel 1 (
    echo  ERROR: Electron packaging failed.
    pause & exit /b 1
)

echo.
echo  ===============================================================
echo   BUILD COMPLETE
echo  ===============================================================
echo.
echo   Output:  dist\FRAUD-X-Setup-3.0.0.exe
echo.
echo   The installer bundles:
echo     - FRAUD-X Desktop Application (Electron)
echo     - Python Backend (PyInstaller, no Python required)
echo     - Next.js Frontend (standalone, no Node required)
echo     - AI/ML Models
echo     - SQLite Database
echo.
echo   Users only need to run: FRAUD-X-Setup-3.0.0.exe
echo.

if exist "dist\FRAUD-X-Setup-3.0.0.exe" (
    echo   Opening dist folder...
    explorer dist
)

pause
