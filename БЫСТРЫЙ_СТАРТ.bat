@echo off
chcp 65001 >nul
title Система обхода блокировок - Быстрый старт

echo.
echo ╔══════════════════════════════════════════════════════════════╗
echo ║                🚀 СИСТЕМА ОБХОДА БЛОКИРОВОК                  ║
echo ║                      Быстрый старт                           ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.

echo 🔍 Проверка системы...
python quick_test.py

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✅ СИСТЕМА РАБОТАЕТ ОТЛИЧНО!
    echo.
    echo 🌐 Доступные сайты:
    echo    • x.com ^(Twitter^)
    echo    • instagram.com
    echo    • rutracker.org  
    echo    • nnmclub.to
    echo.
    echo 🎯 Что делать дальше:
    echo    1. Откройте браузер
    echo    2. Переходите на любые заблокированные сайты
    echo    3. Наслаждайтесь свободным интернетом!
    echo.
) else (
    echo.
    echo ❌ ОБНАРУЖЕНЫ ПРОБЛЕМЫ
    echo.
    echo 🔧 Попробуйте:
    echo    1. Перезапустить службу обхода
    echo    2. Очистить кэш браузера ^(Ctrl+Shift+Del^)
    echo    3. Перезапустить браузер
    echo.
)

echo 📋 Дополнительные команды:
echo    • python smart_bypass_cli.py test-multiple x.com instagram.com
echo    • python smart_bypass_cli.py stats
echo    • smart_bypass.bat ^(полное меню^)
echo.

pause