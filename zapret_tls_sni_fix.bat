@echo off
chcp 65001 >nul
echo ========================================
echo ZAPRET: Исправление TLS SNI блокировки
echo Домен: abs-0.twimg.com
echo Стратегия: Разделение SNI в TLS пакетах
echo ========================================
echo.

echo Создание конфигурации zapret...
echo TPPORT=80,443 > zapret_tls_sni.conf
echo TPWS_OPT="--dpi-desync=fake,disorder --dpi-desync-split-tls=sni --dpi-desync-fooling=badseq --dpi-desync-ttl=1 --dpi-desync-repeats=3" >> zapret_tls_sni.conf
echo NFQWS_OPT_DESYNC_HTTPS="--dpi-desync=fake,disorder --dpi-desync-split-tls=sni --dpi-desync-fooling=badseq --dpi-desync-ttl=1 --dpi-desync-repeats=3" >> zapret_tls_sni.conf

echo Конфигурация создана: zapret_tls_sni.conf
echo.

echo Запуск zapret...
zapret start --config zapret_tls_sni.conf

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