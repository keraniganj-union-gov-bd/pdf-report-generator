@echo off
title Free PDF Report Generator v8
echo ==========================================
echo   Free PDF Report Generator - v8
echo ==========================================
echo.

if not exist ".venv\Scripts\python.exe" (
    echo [1/3] Creating Python virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo ERROR: Python is not installed or not in PATH.
        pause
        exit /b 1
    )
)

echo [2/3] Installing/updating packages...
call ".venv\Scripts\python.exe" -m pip install --upgrade pip
call ".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Package installation failed.
    pause
    exit /b 1
)

echo [3/3] Starting server...
echo Website: http://127.0.0.1:8000
echo Press Ctrl+C to stop.
echo.
call ".venv\Scripts\python.exe" run.py
echo.
echo Server stopped.
pause
