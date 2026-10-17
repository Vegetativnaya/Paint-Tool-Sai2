@echo off
chcp 65001 >nul
py -3 -c "import cryptography" >nul 2>&1
if errorlevel 1 (
    echo Install Python 3.9+ first, then run:
    echo py -3 -m pip install -r "%~dp0requirements.txt"
    pause
    exit /b 1
)
py -3 "%~dp0owner.py" menu
pause
