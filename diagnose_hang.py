# diagnose_hang.py
import sys
import trace
import logging
import threading
import time
from pathlib import Path

# Убедимся, что корневая папка проекта в путях для импорта
# Это важно, чтобы импорты внутри recon работали корректно
project_root = Path(__file__).parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# Настройка логирования для самого диагноста
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger("HangDiagnoser")

# --- Конфигурация ---
TARGET_SCRIPT = "cli"  # Путь для импорта вашего скрипта
TARGET_FUNCTION = "main"     # Функция, которую нужно запустить
# Аргументы, которые нужно передать в cli.py
# Первый элемент - имя скрипта, как в командной строке
SCRIPT_ARGS = ['cli.py', '-d', 'insta.txt', '--debug']
# Файл для вывода лога трассировки
TRACE_LOG_FILE = "hang_trace.log"
# Таймаут в секундах, после которого считаем, что скрипт завис
HANG_TIMEOUT = 60

def run_traced_target():
    """
    Функция, которая будет запущена в отдельном потоке под трассировкой.
    """
    log.info(f"Preparing to run '{TARGET_SCRIPT}.{TARGET_FUNCTION}()' with args: {SCRIPT_ARGS[1:]}")
    
    # Подменяем аргументы командной строки
    sys.argv = SCRIPT_ARGS

    try:
        # Динамически импортируем модуль и получаем функцию
        import importlib
        target_module = importlib.import_module(TARGET_SCRIPT)
        main_func = getattr(target_module, TARGET_FUNCTION)
        
        # Создаем объект трассировщика
        # trace=1: печатать каждую строку
        # count=0: не считать вызовы
        # timing=True: показывать время выполнения
        with open(TRACE_LOG_FILE, "w", encoding="utf-8") as f:
            tracer = trace.Trace(trace=1, count=0, timing=True, file=f)
            
            # Запускаем целевую функцию под трассировкой
            # Используем runctx для изоляции глобальных и локальных переменных
            tracer.runctx('main_func()', globals={'main_func': main_func}, locals={})

    except Exception as e:
        log.error(f"An exception occurred during traced execution: {e}", exc_info=True)
        # Записываем ошибку в лог, чтобы не потерять ее
        with open(TRACE_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"\n\n--- TRACE FAILED WITH EXCEPTION ---\n{e}\n")
            import traceback
            traceback.print_exc(file=f)

def main():
    """Основная функция диагностики."""
    log.info("Starting hang diagnosis...")
    log.info(f"Trace output will be written to: {TRACE_LOG_FILE}")
    log.info(f"Timeout set to {HANG_TIMEOUT} seconds.")

    # Запускаем целевой скрипт в отдельном потоке, чтобы мы могли его прервать
    trace_thread = threading.Thread(target=run_traced_target, daemon=True)
    trace_thread.start()

    # Ждем завершения потока или таймаута
    trace_thread.join(timeout=HANG_TIMEOUT)

    if trace_thread.is_alive():
        log.error("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        log.error("!!! SCRIPT HANG DETECTED (timed out)      !!!")
        log.error("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        log.info(f"The script did not finish within {HANG_TIMEOUT} seconds.")
        log.info(f"Check the last lines of '{TRACE_LOG_FILE}' to see where it stopped.")
        # В Python нет безопасного способа "убить" поток,
        # поэтому просто выходим, оставляя его работать.
        # Для чистого завершения можно было бы использовать multiprocessing.
        sys.exit(1)
    else:
        log.info("***********************************************")
        log.info("*** SCRIPT FINISHED NORMALLY (no hang)      ***")
        log.info("***********************************************")
        log.info(f"If there was an error, check the contents of '{TRACE_LOG_FILE}'.")
        sys.exit(0)

if __name__ == "__main__":
    main()