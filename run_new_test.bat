@echo off
echo ================================================================================
echo ЗАПУСК НОВОГО ТЕСТА С ИСПРАВЛЕННЫМ КОДОМ (v4 - FINAL)
echo ================================================================================
echo.
echo Применены исправления:
echo   1. Приоритет forced override над domain strategy
echo   2. Сохранение forced override при start()
echo   3. Сохранение ВСЕХ атак в fallback (adaptive_engine.py)
echo   4. Сохранение ВСЕХ атак в UnifiedStrategyLoader
echo.

echo Шаг 1: Удаление старых PCAP файлов...
del /Q "C:\Users\admin\AppData\Local\Temp\recon_pcap\*.pcap" 2>nul
echo ✅ Старые PCAP удалены
echo.

echo Шаг 2: Запуск testing mode с исправленным кодом...
echo Команда: python cli.py auto www.googlevideo.com --mode deep
echo.
python cli.py auto www.googlevideo.com --mode deep > test_googlevideo_FIXED4.txt 2>&1
echo ✅ Тест завершен
echo.

echo Шаг 3: Проверка forced override в логе...
findstr /C:"FORCED OVERRIDE ACTIVE" test_googlevideo_FIXED4.txt >nul
if %ERRORLEVEL% EQU 0 (
    echo ✅ Forced override работает!
) else (
    echo ❌ Forced override НЕ найден в логе
)
echo.

echo Шаг 4: Проверка комбинированных атак...
findstr /C:"All attacks included" test_googlevideo_FIXED4.txt >nul
if %ERRORLEVEL% EQU 0 (
    echo ✅ Комбинированные атаки сохраняются!
) else (
    echo ⚠️  Сообщения о комбинированных атаках не найдены
)
echo.

echo Шаг 5: Быстрый анализ PCAP файлов...
python quick_pcap_check.py "C:\Users\admin\AppData\Local\Temp\recon_pcap"
echo.

echo ================================================================================
echo ТЕСТ ЗАВЕРШЕН
echo ================================================================================
echo.
echo Проверьте результаты выше:
echo - Forced override: должен быть активен
echo - Комбинированные атаки: должны сохраняться
echo - PCAP стратегии: должно быть 80-100%% успеха
echo.
pause
