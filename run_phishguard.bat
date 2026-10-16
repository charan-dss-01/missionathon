@echo off
title PhishGuard AI - Launch Control
color 0B
echo ================================================================
echo           PHISHGUARD AI - QUICK LAUNCH CONTROLLER
echo ================================================================
echo.
echo [1/3] Checking service status...

:: Check if backend is already listening on port 8000
netstat -ano | findstr ":8000" | findstr "LISTENING" >nul
if %ERRORLEVEL% equ 0 (
    echo [*] Backend FastAPI already running on port 8000.
) else (
    echo [+] Starting FastAPI Backend on http://127.0.0.1:8000 ...
    start "PhishGuard Backend (FastAPI)" cmd /k "cd /d %~dp0backend && call venv\Scripts\activate.bat && uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"
)

:: Check if frontend is already listening on port 3000
netstat -ano | findstr ":3000" | findstr "LISTENING" >nul
if %ERRORLEVEL% equ 0 (
    echo [*] Frontend Next.js already running on port 3000.
) else (
    echo [+] Starting Next.js Frontend on http://localhost:3000 ...
    start "PhishGuard Frontend (Next.js)" cmd /k "cd /d %~dp0frontend && npm run dev"
)

echo.
echo [2/3] Waiting for services to initialize...
timeout /t 3 /nobreak >nul

echo [3/3] Opening PhishGuard Investigation Console in your browser...
start http://localhost:3000/investigate

echo.
echo ================================================================
echo                   PHISHGUARD AI SERVICES ACTIVE
echo ================================================================
echo  * Investigation Console : http://localhost:3000/investigate
echo  * System Trace & Health : http://localhost:3000/trace
echo  * Backend API Swagger   : http://127.0.0.1:8000/docs
echo ================================================================
echo.
echo Leave this window open or close it at any time.
echo Press any key to exit launcher...
pause >nul
