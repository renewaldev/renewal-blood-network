@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

title Renewal Blood Network Server (Port 5500)

set PYTHONUTF8=1
set PYTHONUNBUFFERED=1

set "PYTHON_EXE=python"
if exist ".venv\Scripts\python.exe" (
    set "PYTHON_EXE=.venv\Scripts\python.exe"
)

echo ================================================================
echo   RENEWAL BLOOD NETWORK - FASTAPI SERVER (PORT 5500)
echo ================================================================
echo   Public App  : http://localhost:5500
echo   Admin Panel : http://localhost:5500/admin
echo   Python      : %PYTHON_EXE%
echo   Press Ctrl+C to stop the server.
echo ================================================================
echo.

if not exist ".env" (
    echo [WARNING] .env file not found! Copy .env.example to .env first.
    echo.
)

"%PYTHON_EXE%" -m uvicorn app:app --host 0.0.0.0 --port 5500 --proxy-headers --log-level info

echo.
echo [INFO] Server stopped (exit code: %errorlevel%).
pause

