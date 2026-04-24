@echo off
title GitHub Secret Scanner
color 0A

echo.
echo  ==========================================
echo   GitHub Secret History Scanner
echo  ==========================================
echo.

:: Check if we're in the right folder
if not exist "backend" (
    echo  ERROR: Run this from the project root folder
    echo  i.e. the folder that contains backend/ and frontend/
    pause
    exit
)

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo  ERROR: Python not found. Install from python.org
    pause
    exit
)

:: Create venv if it doesn't exist
if not exist "backend\venv" (
    echo  Creating virtual environment...
    cd backend
    py -3.11 -m venv venv 2>nul || python -m venv venv
    cd ..
)

:: Install dependencies if needed
if not exist "backend\venv\Lib\site-packages\fastapi" (
    echo  Installing dependencies...
    call backend\venv\Scripts\activate
    pip install -r backend\requirements.txt -q
)

echo  Starting backend on http://localhost:8000
echo  Starting frontend on http://localhost:3000
echo.
echo  Press CTRL+C to stop
echo.

:: Start backend in a new window
start "Secret Scanner - Backend" cmd /k "cd backend && venv\Scripts\activate && uvicorn main:app --port 8000"

:: Wait for backend to start
timeout /t 3 /nobreak >nul

:: Start frontend in a new window
start "Secret Scanner - Frontend" cmd /k "cd frontend && python -m http.server 3000"

:: Wait for frontend to start
timeout /t 2 /nobreak >nul

:: Open browser automatically
start http://localhost:3000

echo  App is running! Browser should open automatically.
echo  Close the two black terminal windows to stop the app.
echo.
pause
