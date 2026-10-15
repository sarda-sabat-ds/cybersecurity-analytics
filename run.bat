@echo off
title CyberSecurity Analytics Platform

echo ============================================================
echo  CyberSecurity Analytics Platform - Launcher
echo ============================================================
echo.

REM ---- Resolve project root (same folder as this bat file) ----
set "ROOT=%~dp0"
set "BACKEND=%ROOT%backend"
set "FRONTEND=%ROOT%frontend"
set "VENV=%BACKEND%\venv\Scripts"

REM ---- Check Python venv ----
if not exist "%VENV%\python.exe" (
    echo [ERROR] Python virtual environment not found.
    echo.
    echo  Run these setup commands first:
    echo    cd backend
    echo    python -m venv venv
    echo    venv\Scripts\pip install -r requirements.txt
    pause
    exit /b 1
)

REM ---- Check Node ----
where node >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js not found. Install from https://nodejs.org
    pause
    exit /b 1
)

REM ---- Install frontend deps if missing ----
if not exist "%FRONTEND%\node_modules" (
    echo [INFO] Installing frontend dependencies...
    pushd "%FRONTEND%"
    call npm install
    popd
)

REM ---- Train model if missing ----
if not exist "%ROOT%models\best_model.joblib" (
    echo [INFO] No trained model found. Running training + seed pipeline...
    pushd "%BACKEND%"
    "%VENV%\python.exe" scripts\train_model.py
    "%VENV%\python.exe" scripts\seed_database.py
    popd
) else (
    echo [OK] Model artifacts found.
)

REM ---- Seed DB if empty ----
pushd "%BACKEND%"
"%VENV%\python.exe" -c "import sys,os; sys.path.insert(0,'.'); os.chdir('.'); from app.database.connection import init_db,SessionLocal; from app.database.models import SecurityLog; init_db(); db=SessionLocal(); c=db.query(SecurityLog).count(); db.close(); print('COUNT='+str(c))" > "%TEMP%\cybercheck.txt" 2>&1
popd
findstr /C:"COUNT=0" "%TEMP%\cybercheck.txt" >nul 2>&1
if not errorlevel 1 (
    echo [INFO] Database empty - seeding...
    pushd "%BACKEND%"
    "%VENV%\python.exe" scripts\seed_database.py
    popd
)
del "%TEMP%\cybercheck.txt" 2>nul

REM ---- Start backend in new window ----
echo.
echo [INFO] Starting Backend API  ^>^>  http://localhost:8000
start "CyberSec Backend" cmd /k "cd /d %BACKEND% && %VENV%\uvicorn.exe app.main:app --reload --port 8000"

echo [INFO] Waiting for backend to initialize...
timeout /t 5 /nobreak >nul

REM ---- Start frontend in new window ----
echo [INFO] Starting Frontend     ^>^>  http://localhost:5173
start "CyberSec Frontend" cmd /k "cd /d %FRONTEND% && npm run dev"

echo.
echo ============================================================
echo  Platform is starting!
echo.
echo  Dashboard :  http://localhost:5173
echo  API Docs  :  http://localhost:8000/docs
echo  Health    :  http://localhost:8000/health
echo.
echo  Two terminal windows opened.
echo  Close them to stop the servers.
echo ============================================================
echo.
pause
