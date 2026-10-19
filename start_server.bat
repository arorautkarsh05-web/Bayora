@echo off
title Bayora Secure AI Platform
cd /d "%~dp0"
echo =================================================================
echo   Starting Bayora Platform...
echo   Dashboard will be live at: http://127.0.0.1:8000
echo =================================================================
backend\.venv\Scripts\python.exe run.py
pause
