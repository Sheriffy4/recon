@echo off
chcp 65001 >nul
echo ═══════════════════════════════════════════════════════════════
echo   X.COM ИСПРАВЛЕНИЕ - КОМАНДЫ ДЛЯ ЗАПУСКА
echo ═══════════════════════════════════════════════════════════════
echo.
echo ✅ Стратегия с роутера применена
echo ✅ strategies.json обновлен
echo ✅ Готово к тестированию
echo.
echo ═══════════════════════════════════════════════════════════════
echo   ВЫБЕРИТЕ ДЕЙСТВИЕ:
echo ═══════════════════════════════════════════════════════════════
echo.
echo [1] Протестировать стратегию (основная)
echo [2] Протестировать стратегию (упрощенная)
echo [3] Протестировать стратегию (с fake пакетами)
echo [4] Запустить службу обхода (НУЖНЫ ПРАВА АДМИНИСТРАТОРА!)
echo [5] Показать документацию
echo [0] Выход
echo.
set /p choice="Ваш выбор: "

if "%choice%"=="1" goto test_main
if "%choice%"=="2" goto test_simple
if "%choice%"=="3" goto test_fake
if "%choice%"=="4" goto start_service
if "%choice%"=="5" goto show_docs
if "%choice%"=="0" goto end

:test_main
echo.
echo ═══════════════════════════════════════════════════════════════
echo   ТЕСТ: Основная стратегия (с роутера)
echo ═══════════════════════════════════════════════════════════════
echo.
python cli.py x.com --strategy "multidisorder --split-pos=46 --split-seqovl=1 --autottl=2 --fooling=badseq --repeats=2"
echo.
pause
goto menu

:test_simple
echo.
echo ═══════════════════════════════════════════════════════════════
echo   ТЕСТ: Упрощенная стратегия
echo ═══════════════════════════════════════════════════════════════
echo.
python cli.py x.com --strategy "multidisorder --split-pos=1 --autottl=2 --fooling=badseq --repeats=2"
echo.
pause
goto menu

:test_fake
echo.
echo ═══════════════════════════════════════════════════════════════
echo   ТЕСТ: Стратегия с fake пакетами
echo ═══════════════════════════════════════════════════════════════
echo.
python cli.py x.com --strategy "fake,multidisorder --split-pos=46 --split-seqovl=1 --autottl=2 --fooling=badseq --repeats=2"
echo.
pause
goto menu

:start_service
echo.
echo ═══════════════════════════════════════════════════════════════
echo   ЗАПУСК СЛУЖБЫ ОБХОДА
echo ═══════════════════════════════════════════════════════════════
echo.
echo ⚠ ВНИМАНИЕ: Служба должна быть запущена от имени Администратора!
echo.
echo Если вы НЕ запустили этот файл от имени Администратора:
echo 1. Закройте это окно
echo 2. Нажмите правой кнопкой на КОМАНДЫ_ДЛЯ_ЗАПУСКА.bat
echo 3. Выберите "Запуск от имени администратора"
echo.
pause
echo.
python setup.py
goto end

:show_docs
echo.
echo ═══════════════════════════════════════════════════════════════
echo   ДОКУМЕНТАЦИЯ
echo ═══════════════════════════════════════════════════════════════
echo.
echo Быстрый старт:
echo   ЗАПУСТИТЬ_СЕЙЧАС.txt
echo.
echo Полная инструкция:
echo   ФИНАЛЬНОЕ_РЕШЕНИЕ_X_COM.txt
echo.
echo Чеклист:
echo   ЧЕКЛИСТ_X_COM.txt
echo.
echo Итоговая сводка:
echo   ИТОГОВАЯ_СВОДКА_X_COM.txt
echo.
echo Техническая информация:
echo   РАБОЧАЯ_СТРАТЕГИЯ_X_COM.txt
echo   X_COM_FIX_COMPLETE.md
echo   X_COM_SOLUTION_SUMMARY.md
echo.
echo Предыдущие исправления:
echo   ПОЛНОЕ_РЕШЕНИЕ_ПРОБЛЕМЫ.txt
echo.
pause
goto menu

:menu
cls
goto start

:end
echo.
echo Удачи! 🚀
echo.
pause
