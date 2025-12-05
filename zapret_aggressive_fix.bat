@echo off
chcp 65001 >nul
echo ========================================
echo ZAPRET: Агрессивная фрагментация TLS
echo Домен: abs-0.twimg.com  
echo Стратегия: Множественное разделение пакетов
echo ========================================
echo.

echo Создание конфигурации zapret...
echo TPPORT=80,443 > zapret_aggressive.conf
echo TPWS_OPT="--dpi-desync=multisplit --dpi-desync-split-count=20 --dpi-desync-split-seqovl=100 --dpi-desync-fooling=badsum --dpi-desync-ttl=1 --dpi-desync-repeats=5" >> zapret_aggressive.conf
echo NFQWS_OPT_DESYNC_HTTPS="--dpi-desync=multisplit --dpi-desync-split-count=20 --dpi-desync-split-seqovl=100 --dpi-desync-fooling=badsum --dpi-desync-ttl=1 --dpi-desync-repeats=5" >> zapret_aggressive.conf

echo Конфигурация создана: zapret_aggressive.conf
echo.

echo Запуск zapret...
zapret start --config zapret_aggressive.conf

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✅ Zapret успешно запущен!
    echo.
    echo 🔍 Проверьте доступность abs-0.twimg.com в браузере
    echo.
    echo Для остановки zapret выполните: zapret stop
    echo Или запустите файл: stop_zapret.bat
) else (
    echo.
    echo ❌ Ошибка запуска zapret!
    echo Проверьте:
    echo 1. Установлен ли zapret
    echo 2. Запущена ли консоль от имени администратора
    echo 3. Правильность пути к zapret
)

echo.
pause