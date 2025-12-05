@echo off
chcp 65001 >nul
echo ========================================
echo ОСТАНОВКА ZAPRET
echo ========================================
echo.

echo Остановка zapret...
zapret stop

if %ERRORLEVEL% EQU 0 (
    echo ✅ Zapret успешно остановлен!
) else (
    echo ⚠️ Zapret возможно уже был остановлен или произошла ошибка
)

echo.
echo Очистка временных файлов...
if exist zapret_tls_sni.conf del zapret_tls_sni.conf
if exist zapret_aggressive.conf del zapret_aggressive.conf
if exist zapret_abs_twimg.conf del zapret_abs_twimg.conf

echo ✅ Готово!
echo.
pause