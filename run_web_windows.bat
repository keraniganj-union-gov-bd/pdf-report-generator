@echo off
title Free PDF Report Generator - Web Version
cd /d "%~dp0"
if not exist .venv (
  py -m venv .venv
)
call .venv\Scripts\activate
python -m pip install -r requirements.txt
echo.
echo Starting Web Version...
echo Open: http://127.0.0.1:8000
echo.
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
pause
