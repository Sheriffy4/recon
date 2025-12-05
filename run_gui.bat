@echo off
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1

echo ========================================
echo   Recon DPI Bypass GUI
echo ========================================
echo.

REM Проверка Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found!
    echo Please install Python 3.8+ from python.org
    pause
    exit /b 1
)

REM Проверка PyQt6
python -c "import PyQt6" >nul 2>&1
if errorlevel 1 (
    echo [WARNING] PyQt6 not installed!
    echo.
    echo Installing PyQt6...
    pip install PyQt6
    if errorlevel 1 (
        echo [ERROR] Failed to install PyQt6
        pause
        exit /b 1
    )
)

echo [OK] Starting GUI...
echo.

python gui_app_qt.py

if errorlevel 1 (
    echo.
    echo [ERROR] GUI crashed or exited with error
    pause
)
