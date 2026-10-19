@echo off
title Bayora Test Suite
cd /d "%~dp0"
set PYTHONPATH=%cd%
echo Running automated security and boundary test suite...
backend\.venv\Scripts\pytest.exe -v backend\tests
pause
