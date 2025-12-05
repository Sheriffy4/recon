@echo off
chcp 65001 >nul
title Smart Bypass - Обход блокировок доменов

echo ========================================
echo Smart Bypass - Обход блокировок доменов
echo ========================================
echo.

:menu
echo Выберите действие:
echo.
echo 1. Быстрый тест системы
echo 2. Проверить домен (x.com, instagram.com и т.д.)
echo 3. Тестировать подключения к доменам
echo 4. Настроить hosts файл (требуются права админа)
echo 5. Анализ PCAP файла
echo 6. Генерировать отчет
echo 7. Показать справку
echo 8. Выход
echo.

set /p choice="Введите номер (1-8): "

if "%choice%"=="1" goto test
if "%choice%"=="2" goto check
if "%choice%"=="3" goto test_domains
if "%choice%"=="4" goto setup_hosts
if "%choice%"=="5" goto analyze_pcap
if "%choice%"=="6" goto report
if "%choice%"=="7" goto help
if "%choice%"=="8" goto exit

echo Неверный выбор. Попробуйте снова.
echo.
goto menu

:test
echo.
echo === Запуск быстрого теста системы ===
python test_smart_bypass.py
echo.
pause
goto menu

:check
echo.
set /p domain="Введите домен для проверки (например, x.com): "
if "%domain%"=="" (
    echo Домен не указан
    goto menu
)
echo.
echo === Проверка домена %domain% ===
python smart_bypass_cli.py check %domain% --verbose
echo.
pause
goto menu

:test_domains
echo.
echo Примеры доменов: x.com instagram.com facebook.com youtube.com
set /p domains="Введите домены через пробел: "
if "%domains%"=="" (
    echo Домены не указаны
    goto menu
)
echo.
echo === Тестирование доменов ===
python smart_bypass_cli.py test-multiple %domains%
echo.
pause
goto menu

:setup_hosts
echo.
echo === Настройка hosts файла ===
echo ВНИМАНИЕ: Требуются права администратора!
echo.
python setup_hosts_bypass.py setup
echo.
pause
goto menu

:analyze_pcap
echo.
echo === Анализ PCAP файла ===
echo DEPRECATED: Use UnifiedPCAPAnalyzer instead
echo python -m core.pcap.unified_analyzer [pcap_file] [domain]
echo.
pause
goto menu

:report
echo.
set /p output="Введите имя файла для отчета (или Enter для вывода на экран): "
if "%output%"=="" (
    python smart_bypass_cli.py report
) else (
    python smart_bypass_cli.py report --output %output%
    echo Отчет сохранен в %output%
)
echo.
pause
goto menu

:help
echo.
echo === Справка по Smart Bypass ===
echo.
echo Система автоматически определяет заблокированные домены и предоставляет
echo решения для обхода через DoH (DNS over HTTPS) и другие методы.
echo.
echo Основные возможности:
echo - Автоматическое определение типа блокировки
echo - DoH поддержка (Cloudflare, Google, Quad9)
echo - Интеграция с hosts файлом
echo - Умный выбор стратегии обхода
echo - Подробная статистика и отчеты
echo.
echo Примеры команд CLI:
echo   python smart_bypass_cli.py check x.com
echo   python smart_bypass_cli.py test-multiple x.com instagram.com
echo   python smart_bypass_cli.py strategies x.com
echo   python smart_bypass_cli.py report --output report.json
echo.
echo Настройка hosts файла:
echo   python setup_hosts_bypass.py setup
echo   python setup_hosts_bypass.py restore
echo.
echo Для подробной документации см. SMART_BYPASS_README.md
echo.
pause
goto menu

:exit
echo.
echo Спасибо за использование Smart Bypass!
exit /b 0