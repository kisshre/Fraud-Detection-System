@echo off
setlocal enabledelayedexpansion
title FRAUD-X Development Mode

echo.
echo  ===============================================================
echo   FRAUD-X Enterprise ^|^| Development Launcher
echo  ===============================================================
echo.

:: ── Activate Python venv ──────────────────────────────────────────────────────
if exist "venv\Scripts\activate.bat" (
    echo  Activating Python virtual environment...
    call venv\Scripts\activate.bat
) else (
    echo  No venv found — using system Python.
    echo  Tip: run  python -m venv venv  and  pip install -r requirements.txt
)

:: ── Check .env ───────────────────────────────────────────────────────────────
if not exist ".env" (
    echo.
    echo  WARNING: .env file not found.
    echo  Copy .env.example to .env and add your GEMINI_API_KEY
    echo.
)

:: ── Kill stale services from any previous run ─────────────────────────────────
echo  Cleaning up stale services...
taskkill /fi "WINDOWTITLE eq FRAUD-X Backend"  /f >nul 2>&1
taskkill /fi "WINDOWTITLE eq FRAUD-X Frontend" /f >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000 "') do taskkill /f /pid %%a >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":3000 "') do taskkill /f /pid %%a >nul 2>&1
timeout /t 1 /nobreak >nul

:: ── Start Next.js frontend in a VISIBLE window so errors are easy to see ──────
echo  Starting Next.js frontend (visible window — errors shown there if any)...
start "FRAUD-X Frontend" cmd /c "cd frontend && npm run dev && pause"

:: ── Launch Electron immediately — it starts the backend and polls the frontend ─
echo  Launching Electron (backend starts via Electron splash screen)...
echo.
set NODE_ENV=development
call npm run dev

:: ── Cleanup on exit ──────────────────────────────────────────────────────────
echo.
echo  Stopping services...
taskkill /fi "WINDOWTITLE eq FRAUD-X Frontend" /f >nul 2>&1
echo  Done.
