@echo off
title PII-Detection-System
cls
echo ========================================
echo   PII Detection and Sanitization System
echo ========================================
echo.
echo [1/3] Checking Dependencies...
cd /d "c:\Users\KATHAN BHANDARI\Desktop\MineD\backend"
python -c "import fastapi, uvicorn, sqlalchemy; print('✅ Backend dependencies OK')" 2>nul
if errorlevel 1 (
    echo ❌ Backend dependencies missing!
    echo Installing dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ❌ Failed to install dependencies
        pause
        exit /b 1
    )
)

echo [2/3] Starting Backend Server...
start "Backend Server" cmd /k "title Backend Server && echo Starting backend... && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"

echo [3/3] Waiting for backend to initialize...
echo ⏳ Checking if backend is healthy...
timeout /t 5 /nobreak >nul

:check_backend
python -c "import requests; requests.get('http://localhost:8000/health', timeout=2); print('✅ Backend is healthy!')" 2>nul
if errorlevel 1 (
    echo ⏳ Backend not ready yet, waiting...
    timeout /t 2 /nobreak >nul
    goto check_backend
)

echo [4/4] Starting Frontend...
cd /d "c:\Users\KATHAN BHANDARI\Desktop\MineD\frontend"
python -c "import streamlit, requests; print('✅ Frontend dependencies OK')" 2>nul
if errorlevel 1 (
    echo ❌ Frontend dependencies missing!
    echo Installing dependencies...
    pip install -r requirements.txt
)
start "Frontend" cmd /k "title Frontend && echo Starting frontend... && python -m streamlit run app.py"

echo.
echo ========================================
echo           SYSTEM STARTING UP!
echo ========================================
echo.
echo 🌐 Opening browser in 5 seconds...
timeout /t 5 /nobreak >nul
start http://localhost:8501

echo.
echo ========================================
echo         SYSTEM IS READY!
echo ========================================
echo 📱 Frontend: http://localhost:8501
echo 🔧 Backend:  http://localhost:8000
echo 👤 Login:    admin / admin123
echo.
echo 💡 Keep this window open
echo 🛑 Close windows to stop
echo ========================================
echo.
pause
