@echo off

REM Проверка прав администратора
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with administrator privileges...
    goto :run
) else (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:run
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1

echo ========================================
echo   Recon DPI Bypass GUI (Admin Mode)
echo ========================================
echo.
echo [OK] Administrator privileges granted
echo [OK] Service mode will be available
echo.

python gui_app_qt.py

if errorlevel 1 (
    echo.
    echo [ERROR] GUI crashed or exited with error
    pause
)
