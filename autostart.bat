@echo off
cd /d "C:\Users\Talha Chougle\Downloads\Cybersecurity projects\Github Secret History Scanner\backend"
call venv\Scripts\activate
start /min cmd /k "uvicorn main:app --port 8000"
exit