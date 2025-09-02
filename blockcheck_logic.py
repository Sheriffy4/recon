# -*- coding: utf-8 -*-
# blockcheck_logic.py

import subprocess
import aiohttp
import asyncio
import time
import logging
import os
import shutil
from datetime import datetime
import socket
import config
from urllib.parse import urlparse
import traceback  # Добавлено для полного трейсбека

# --- КОНСТАНТЫ ---
FAKE_SNI = "www.google.com"
FAKE_HEX = "5fc220bc088ae1a45235e46de591be50a50c979be92694471697a299ce78c1c276737bef7abc9668142b92c395810a659ff47dfd2411c010e990"
PAYLOADTLS = "tls_clienthello_www_google_com.bin"
PAYLOADQUIC = "quic_initial_www_google_com.bin"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6753.0 Safari/537.36"
}

ANTI_DPI_TOOLS_LIST = ["goodbyedpi", "zapret", "none"]
# Пути для Windows (относительно base_path)
ZAPRET_NT_TOOL_NAME = "winws.exe"
ZAPRET_NT_PATH = "bin"
ZAPRET_NT_ARGS = ["--wf-l3=ipv4", "--wf-tcp=443"]
GOODBYEDPI_NT_TOOL_NAME = "goodbyedpi.exe"
GOODBYEDPI_NT_ARGS = []
GOODBYEDPI_NT_PATH = "bin"
# Пути для Linux (могут быть абсолютными или относительными)
ZAPRET_LINUX_PATH = "/opt/zapret"  # Пример абсолютного пути
ZAPRET_LINUX_TOOL_NAME = "zapret"  # Имя сервиса/скрипта
ZAPRET_LINUX_CONFIG_TEMPLATE_PATH = (
    "configs/zapret_linux_config"  # Относительно base_path
)
ZAPRET_LINUX_TARGET_CONFIG_PATH = "/opt/zapret/config"  # Куда монтировать
ZAPRET_LINUX_SERVICE_SCRIPT = "/opt/zapret/init.d/sysv/zapret"  # Скрипт управления

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---


def setup_iteration_logging(tool_name, iteration_num, output_dir):
    """Настраивает отдельный логгер для одной итерации тестирования."""
    now = datetime.now()
    # Используем output_dir для логов
    log_filename = os.path.join(
        output_dir,
        f"test_log_{tool_name}_iter_{iteration_num}_{now.strftime('%Y%m%d_%H%M%S')}.txt",
    )

    iteration_logger = logging.getLogger(
        f"BlockCheck_Iter_{iteration_num}"
    )  # Уникальное имя логгера
    # Убираем существующих хендлеров, чтобы избежать дублирования при повторных вызовах
    if iteration_logger.hasHandlers():
        iteration_logger.handlers.clear()

    iteration_logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(message)s")  # Формат как в оригинальном blockcheck

    # Файловый хендлер для итерации
    try:
        # Убедимся, что директория существует
        os.makedirs(output_dir, exist_ok=True)
        file_handler = logging.FileHandler(log_filename, encoding="utf-8")
        file_handler.setFormatter(formatter)
        iteration_logger.addHandler(file_handler)
    except Exception as e:
        # Используем корневой логгер для сообщения об ошибке, если логгер итерации не создался
        logging.error(
            f"Не удалось создать файловый хендлер для лога итерации {log_filename}: {e}"
        )
        return None, None  # Возвращаем None, если не удалось настроить логгирование

    # НЕ добавляем консольный хендлер сюда, чтобы вывод шел через основной логгер оркестратора
    iteration_logger.propagate = (
        True  # Позволяем сообщениям идти к корневому логгеру (и в консоль мастера)
    )

    logging.info(
        f"Лог тестирования для итерации {iteration_num} настроен: {log_filename}"
    )
    return iteration_logger, log_filename


def read_sites(set_name, base_path):
    """Читает список сайтов из файла."""
    file_path = os.path.join(base_path, "sites_list", f"{set_name}.txt")
    logger = logging.getLogger("BlockCheck_Logic")  # Используем общий логгер модуля
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            sites = [
                line.strip()
                for line in file
                if line.strip() and not line.startswith("#")
            ]
            if not sites:
                logger.warning(
                    f"Файл сайтов {file_path} пуст или содержит только комментарии."
                )
            return sites
    except FileNotFoundError:
        logger.error(f"Файл списка сайтов не найден: {file_path}")
        return []
    except Exception as e:
        logger.error(f"Ошибка чтения файла сайтов {file_path}: {e}")
        return []


def read_strategies_from_file(file_path):
    """Читает список стратегий из файла."""
    logger = logging.getLogger("BlockCheck_Logic")
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            strategies = [
                line.strip()
                for line in file
                if line.strip() and not line.strip().startswith(("/", "#"))
            ]
            return strategies
    except FileNotFoundError:
        logger.error(f"Файл стратегий не найден: {file_path}")
        return None  # Возвращаем None при ошибке
    except Exception as e:
        logger.error(f"Ошибка чтения файла стратегий {file_path}: {e}")
        return None


def replace_parameters(parameters_str: str, base_path: str) -> str:
    logger = logging.getLogger(
        "BlockCheck_Logic.ReplaceParams"
    )  # Используем свой логгер или общий
    try:
        # Замена плейсхолдеров из config.PAYLOAD_PLACEHOLDERS
        # PAYLOAD_PLACEHOLDERS содержит { "PLACEHOLDER_NAME": "relative/path/to/file.bin" }
        # base_path - это путь к директории, относительно которой строятся пути из PAYLOAD_PLACEHOLDERS

        processed_parameters = parameters_str

        # Сначала заменяем стандартные плейсхолдеры, не являющиеся файлами
        processed_parameters = processed_parameters.replace(
            "FAKESNI", FAKE_SNI
        )  # FAKE_SNI определен в blockcheck_logic
        processed_parameters = processed_parameters.replace(
            "FAKEHEX", FAKE_HEX
        )  # FAKE_HEX определен в blockcheck_logic

        # Затем заменяем плейсхолдеры файлов
        for placeholder, rel_path in config.PAYLOAD_PLACEHOLDERS.items():
            if (
                placeholder in processed_parameters
            ):  # Проверяем наличие плейсхолдера в строке
                # Формируем абсолютный или корректный относительный путь
                # base_path должен быть путем к корневой директории проекта или директории, где лежат bin/ и т.д.
                # rel_path из config.PAYLOAD_PLACEHOLDERS уже содержит "bin/..."
                # Поэтому os.path.join(base_path, rel_path) должен дать правильный путь.

                # Убедимся, что base_path - это действительно корень проекта,
                # а rel_path - это путь от корня проекта.
                # Если base_path - это, например, C:\Users\admin\Downloads\zapretttt\DPI_Blockcheck\
                # а rel_path - 'bin/tls_clienthello_www_google_com.bin',
                # то os.path.join даст C:\Users\admin\Downloads\zapretttt\DPI_Blockcheck\bin\tls_clienthello_www_google_com.bin

                full_path = os.path.join(base_path, rel_path)
                full_path = os.path.normpath(full_path)  # Нормализуем путь для ОС

                # Важно: Заменяем именно плейсхолдер, а не часть пути
                processed_parameters = processed_parameters.replace(
                    placeholder, full_path
                )
                logger.debug(
                    f"Replaced placeholder '{placeholder}' with path '{full_path}'"
                )

        if processed_parameters != parameters_str:
            logger.debug(f"Parameters after replacement: {processed_parameters}")
        return processed_parameters
    except Exception as e:
        logger.error(f"Ошибка при замене параметров в строке '{parameters_str}': {e}")
        return parameters_str


def find_tool_path(tool_name, base_path):
    """Находит абсолютный путь к исполняемому файлу инструмента."""
    logger = logging.getLogger("BlockCheck_Logic")
    if tool_name == "none":
        return None
    if tool_name not in ANTI_DPI_TOOLS_LIST:
        raise ValueError(f"Инструмент не поддерживается: {tool_name}")

    path_map_nt = {"zapret": ZAPRET_NT_PATH, "goodbyedpi": GOODBYEDPI_NT_PATH}
    name_map_nt = {"zapret": ZAPRET_NT_TOOL_NAME, "goodbyedpi": GOODBYEDPI_NT_TOOL_NAME}
    path_map_posix = {
        "zapret": ZAPRET_LINUX_PATH,
        "goodbyedpi": None,
    }  # goodbyedpi не поддерживается в Linux в этой логике
    name_map_posix = {"zapret": ZAPRET_LINUX_TOOL_NAME, "goodbyedpi": None}

    tool_path_rel = ""
    tool_path_abs = ""  # Инициализируем здесь
    found_in_path = None  # Инициализируем здесь

    if os.name == "nt":
        if tool_name in path_map_nt:
            # --- ИСПРАВЛЕНИЕ: Строим путь относительно base_path ---
            tool_path_abs = os.path.join(
                base_path, path_map_nt[tool_name], name_map_nt[tool_name]
            )
            # --- КОНЕЦ ИСПРАВЛЕНИЯ ---
        else:
            raise RuntimeError(
                f"Определение инструмента отсутствует для '{tool_name}' в Windows"
            )
    else:  # posix
        if tool_name in path_map_posix:
            if path_map_posix[tool_name] is None:
                raise RuntimeError(
                    f"Инструмент '{tool_name}' не поддерживается в Linux/POSIX в этой реализации"
                )

            # --- ИСПРАВЛЕНИЕ: Логика поиска пути с использованием base_path ---
            # 1. Проверяем абсолютный путь, если он указан в константе
            abs_path_const = os.path.join(
                path_map_posix[tool_name], name_map_posix[tool_name]
            )
            if os.path.isabs(path_map_posix[tool_name]) and os.path.exists(
                abs_path_const
            ):
                tool_path_abs = (
                    abs_path_const  # Используем абсолютный путь из константы
                )
            else:
                # 2. Ищем в системном PATH
                found_in_path = shutil.which(name_map_posix[tool_name])
                if found_in_path:
                    logger.debug(
                        f"Инструмент '{tool_name}' найден в PATH: {found_in_path}"
                    )
                    tool_path_abs = found_in_path  # Нашли в PATH
                else:
                    # 3. Ищем относительно base_path
                    tool_path_rel = os.path.join(
                        path_map_posix[tool_name], name_map_posix[tool_name]
                    )
                    tool_path_abs = os.path.join(base_path, tool_path_rel)
            # --- КОНЕЦ ИСПРАВЛЕНИЯ ---
        else:
            raise RuntimeError(
                f"Определение инструмента отсутствует для '{tool_name}' в Linux/POSIX"
            )

    # Финальная проверка существования файла
    if not tool_path_abs or not os.path.exists(tool_path_abs):
        # Дополнительная проверка для случая, когда tool_path_abs был из PATH
        if found_in_path and os.path.exists(found_in_path):
            tool_path_abs = found_in_path
        else:
            # Формируем более информативное сообщение об ошибке
            search_locations = []
            if os.name == "nt":
                search_locations.append(
                    f"относительно base_path: {os.path.join(base_path, path_map_nt.get(tool_name, ''), name_map_nt.get(tool_name, ''))}"
                )
            else:
                if os.path.isabs(path_map_posix.get(tool_name, "")):
                    search_locations.append(
                        f"абсолютный путь из константы: {abs_path_const}"
                    )
                search_locations.append(
                    f"в системном PATH: {name_map_posix.get(tool_name, '')}"
                )
                search_locations.append(
                    f"относительно base_path: {os.path.join(base_path, path_map_posix.get(tool_name, ''), name_map_posix.get(tool_name, ''))}"
                )

            raise RuntimeError(
                f"Не удалось найти исполняемый файл инструмента '{tool_name}'. Проверенные расположения: {'; '.join(search_locations)}"
            )

    logger.debug(f"Найден путь к инструменту '{tool_name}': {tool_path_abs}")
    return tool_path_abs


def write_zapret_linux_config(args_list, output_dir, base_path):
    """Записывает временный конфигурационный файл для Zapret Linux."""
    logger = logging.getLogger("BlockCheck_Logic")
    temp_dir = os.path.join(output_dir, "tmp")
    os.makedirs(temp_dir, exist_ok=True)
    args_str = " ".join(args_list)
    # --- ИСПРАВЛЕНИЕ: Убедимся, что путь к шаблону правильный ---
    template_path = os.path.join(base_path, ZAPRET_LINUX_CONFIG_TEMPLATE_PATH)
    # --- КОНЕЦ ИСПРАВЛЕНИЯ ---
    temp_config_path = os.path.join(
        temp_dir, "zapret_linux_config_temp"
    )  # Используем фиксированное имя для простоты
    try:
        if not os.path.exists(template_path):
            raise FileNotFoundError(
                f"Файл шаблона конфига Zapret Linux не найден: {template_path}"
            )
        with open(template_path, "r", encoding="utf-8") as f_in:
            config_content = f_in.read()
        # Заменяем плейсхолдер
        config_content = config_content.replace(
            'NFQWS_OPT_DESYNC_HTTPS="ARGS"', f'NFQWS_OPT_DESYNC_HTTPS="{args_str}"'
        )
        with open(temp_config_path, "w", encoding="utf-8") as f_out:
            f_out.write(config_content)
        logger.debug(
            f"Конфиг Zapret Linux записан в {temp_config_path} с аргументами: {args_str}"
        )
        return True, temp_config_path
    except Exception as e:
        logger.error(f"Не удалось записать конфиг Zapret Linux: {e}")
        return False, ""


def remove_zapret_linux_config(temp_config_path):
    """Удаляет временный конфигурационный файл."""
    logger = logging.getLogger("BlockCheck_Logic")
    if temp_config_path and os.path.exists(temp_config_path):
        try:
            os.remove(temp_config_path)
            logger.debug(f"Удален временный конфиг Zapret Linux: {temp_config_path}")
        except Exception as e:
            logger.warning(
                f"Не удалось удалить временный конфиг Zapret Linux {temp_config_path}: {e}"
            )


def mount_zapret_linux_config(temp_config_path):
    """Монтирует временный конфиг поверх стандартного."""
    logger = logging.getLogger("BlockCheck_Logic")
    if not temp_config_path or not os.path.exists(temp_config_path):
        logger.error(
            "Невозможно смонтировать конфиг Zapret Linux: временный файл не найден."
        )
        return False
    target_path = ZAPRET_LINUX_TARGET_CONFIG_PATH
    if not os.path.exists(target_path):
        logger.warning(
            f"Целевой путь для конфига Zapret {target_path} не существует. Пропуск монтирования."
        )
        # Возможно, стоит создать файл-пустышку? Зависит от установки Zapret.
        # try: open(target_path, 'a').close() except: pass
        return False  # Считаем ошибкой, если целевого файла нет
    command = f"mount -o bind {temp_config_path} {target_path}"
    logger.debug(f"Выполнение команды монтирования: {command}")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        logger.error(f"Не удалось смонтировать конфиг Zapret Linux: {result.stderr}")
        return False
    logger.info("Конфиг Zapret Linux смонтирован.")
    return True


def umount_zapret_linux_config():
    """Отмонтирует временный конфиг."""
    logger = logging.getLogger("BlockCheck_Logic")
    target_path = ZAPRET_LINUX_TARGET_CONFIG_PATH
    command = f"umount {target_path}"
    logger.debug(f"Выполнение команды отмонтирования: {command}")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    # Проверяем код возврата и stderr, чтобы избежать ложных срабатываний на EBUSY
    if (
        result.returncode != 0
        and "not mounted" not in result.stderr.lower()
        and "not found" not in result.stderr.lower()
    ):
        logger.warning(
            f"Не удалось отмонтировать конфиг Zapret Linux (возможно, уже отмонтирован или занят): {result.stderr}"
        )
        return False  # Возвращаем False, если отмонтирование не удалось (кроме случая "not mounted")
    logger.info("Конфиг Zapret Linux отмонтирован (или уже был отмонтирован).")
    return True


def manage_zapret_service(action="start"):
    """Управляет сервисом Zapret в Linux."""
    logger = logging.getLogger("BlockCheck_Logic")
    zapret_script_path = ZAPRET_LINUX_SERVICE_SCRIPT
    if not os.path.exists(zapret_script_path):
        logger.error(
            f"Скрипт управления сервисом Zapret не найден: {zapret_script_path}"
        )
        return False
    command = [zapret_script_path, action]
    logger.debug(f"Выполнение команды сервиса Zapret: {' '.join(command)}")
    # Используем DEVNULL для stdout/stderr, чтобы не засорять лог мастера
    result = subprocess.run(
        command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True
    )
    # Игнорируем ошибку "not running" при остановке
    if result.returncode != 0 and not (
        action == "stop"
        and (
            "not running" in result.stderr.lower() or "failed" in result.stderr.lower()
        )
    ):  # Добавил проверку на "failed" для некоторых систем
        logger.error(f"Не удалось {action} сервис Zapret: {result.stderr}")
        return False
    logger.info(f"Сервис Zapret успешно {action}ed (или уже был в этом состоянии).")
    return True


# --- Основные функции start/stop tool ---
def start_tool(
    tool_name,
    parameters_str,
    base_path,
    output_dir,
    current_linux_mounted_status,
    current_linux_conf_path,
):  # Убраны target_protocol, target_port
    logger = logging.getLogger("BlockCheck_Logic")

    # Получаем текущие целевые параметры из config
    current_target_protocol = config.TARGET_PROTOCOL
    current_target_port = config.TARGET_PORT
    # current_target_ip_version = config.TARGET_IP_VERSION # Если нужен для Linux

    logger.info(f"Запуск инструмента '{tool_name}' с параметрами: {parameters_str}")
    logger.info(
        f"Целевой протокол для инструмента: {current_target_protocol}, порт: {current_target_port}"
    )

    parameters_list = parameters_str.split() if parameters_str else []

    if os.name == "nt":
        zapret_nt_args_custom = []

        # Формируем --wf-l3
        if config.TARGET_IP_VERSION == "ipv4":  # Используем config напрямую
            wf_l3_arg = "--wf-l3=ipv4"
        elif config.TARGET_IP_VERSION == "ipv6":
            wf_l3_arg = "--wf-l3=ipv6"
        else:  # 'any'
            # Для 'any' можно либо не добавлять флаг, либо выбрать IPv4 по умолчанию.
            # Если Zapret/winws по умолчанию слушает обе версии, флаг можно опустить.
            # Если нужно явно указать, то IPv4 более распространен.
            wf_l3_arg = "--wf-l3=ipv4"
            logger.warning(
                "TARGET_IP_VERSION is 'any', defaulting winws --wf-l3 to ipv4."
            )
        zapret_nt_args_custom.append(wf_l3_arg)

        # Формируем --wf-tcp или --wf-udp
        if config.TARGET_PROTOCOL == "tcp":
            zapret_nt_args_custom.append(f"--wf-tcp={config.TARGET_PORT}")
        elif config.TARGET_PROTOCOL == "udp":
            zapret_nt_args_custom.append(f"--wf-udp={config.TARGET_PORT}")
        elif config.TARGET_PROTOCOL == "any":
            # Для 'any', если Zapret/winws может слушать оба протокола одновременно без явного указания,
            # можно не добавлять эти флаги. Либо, если нужно указать один, то TCP более вероятен.
            # Если Zapret/winws требует указания хотя бы одного, то TCP.
            # Если стратегия сама содержит any-protocol=1, то Zapret может это учесть.
            # Пока оставим TCP по умолчанию для 'any', если инструмент требует.
            logger.warning(
                f"TARGET_PROTOCOL is 'any' for winws, defaulting to TCP on port {config.TARGET_PORT}."
            )
            zapret_nt_args_custom.append(f"--wf-tcp={config.TARGET_PORT}")

        if tool_name == "zapret":  # winws.exe
            parameters_list = zapret_nt_args_custom + parameters_list
            logger.info(
                f"Using winws args based on TARGET settings: {zapret_nt_args_custom}"
            )

        # Формируем --wf-tcp или --wf-udp
        if config.TARGET_PROTOCOL == "tcp":
            zapret_nt_args_custom.append(f"--wf-tcp={config.TARGET_PORT}")
        elif config.TARGET_PROTOCOL == "udp":
            zapret_nt_args_custom.append(f"--wf-udp={config.TARGET_PORT}")
        elif config.TARGET_PROTOCOL == "any":
            # Для 'any' можно, например, по умолчанию использовать TCP или не добавлять эти флаги,
            # если Zapret/winws имеет свое поведение по умолчанию.
            # Пока что будем использовать TCP по умолчанию для 'any'.
            logger.warning(
                f"TARGET_PROTOCOL is 'any' for {tool_name}, defaulting to TCP on port {config.TARGET_PORT}."
            )
            zapret_nt_args_custom.append(f"--wf-tcp={config.TARGET_PORT}")
        else:
            logger.error(
                f"Unsupported TARGET_PROTOCOL '{config.TARGET_PROTOCOL}' for Zapret NT args."
            )
            # Можно вернуть ошибку или использовать дефолт

        if tool_name == "goodbyedpi":
            parameters_list = (
                GOODBYEDPI_NT_ARGS + parameters_list
            )  # goodbyedpi не использует эти флаги
        elif tool_name == "zapret":  # winws.exe
            # Добавляем сформированные аргументы В НАЧАЛО списка параметров стратегии,
            # чтобы они не конфликтовали с параметрами самой стратегии, если вдруг есть пересечения.
            # Или можно их не добавлять, если параметры стратегии (--dpi-desync-*) имеют приоритет
            # и winws сам разберется с фильтрацией по L3/L4 на основе этих параметров.
            # Судя по документации Zapret, --wf-* это глобальные фильтры для winfilter.
            # Параметры стратегии (--filter-l3, --filter-tcp/udp) действуют на уровне профилей nfqws.
            # Для winws, вероятно, нужно передавать --wf-*.
            parameters_list = zapret_nt_args_custom + parameters_list
            logger.info(
                f"Using winws args based on TARGET settings: {zapret_nt_args_custom}"
            )
        try:
            tool_path = find_tool_path(tool_name, base_path)
            logger.debug(f"Выполнение: {tool_path} {' '.join(parameters_list)}")
            os.makedirs(output_dir, exist_ok=True)
            process = subprocess.Popen(
                [tool_path] + parameters_list,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=os.path.dirname(tool_path),
            )
            logger.info(f"Инструмент '{tool_name}' запущен (PID: {process.pid}).")
            return True, process, current_linux_mounted_status, current_linux_conf_path
        except Exception:
            logger.exception(f"Не удалось запустить инструмент '{tool_name}':")
            return False, None, current_linux_mounted_status, current_linux_conf_path
    # ... (остальная часть для Linux без изменений, т.к. там конфиг формируется по-другому) ...
    elif os.name == "posix":
        if tool_name == "goodbyedpi":
            logger.error(
                f"Инструмент '{tool_name}' не поддерживается в OS '{os.name}' в этой реализации"
            )
            return (
                False,
                None,
                current_linux_mounted_status,
                current_linux_conf_path,
            )  # Ошибка
        elif tool_name == "zapret":
            # 1. Остановить сервис (на всякий случай)
            if not manage_zapret_service("stop"):
                logger.warning(
                    "Не удалось остановить сервис Zapret перед стартом, но продолжаем."
                )
            # 2. Отмонтировать старый конфиг, если был
            if current_linux_mounted_status:
                if not umount_zapret_linux_config():  # Попытка отмонтировать
                    logger.warning(
                        "Не удалось отмонтировать предыдущий конфиг Zapret, но продолжаем."
                    )
                remove_zapret_linux_config(
                    current_linux_conf_path
                )  # Удалить старый временный файл
                current_linux_mounted_status = False  # Обновляем статус локально

            # 3. Записать и смонтировать новый конфиг
            written, new_conf_path = write_zapret_linux_config(
                parameters_list, output_dir, base_path
            )
            if written:
                if mount_zapret_linux_config(new_conf_path):
                    # 4. Запустить сервис
                    if manage_zapret_service("start"):
                        # Успех: возвращаем True, None (нет хендла), новые статусы
                        return True, None, True, new_conf_path
                    else:  # Ошибка старта сервиса
                        logger.error(
                            "Не удалось запустить сервис Zapret после обновления конфига."
                        )
                        umount_zapret_linux_config()  # Пытаемся откатить монтирование
                        remove_zapret_linux_config(new_conf_path)
                        return False, None, False, ""  # Ошибка
                else:  # Ошибка монтирования
                    logger.error("Не удалось смонтировать новый конфиг Zapret.")
                    remove_zapret_linux_config(new_conf_path)  # Удаляем ненужный конфиг
                    return False, None, False, ""  # Ошибка
            else:  # Ошибка записи конфига
                logger.error("Не удалось записать новый конфиг Zapret.")
                return False, None, False, ""  # Ошибка
        else:
            logger.error(f"Неизвестный инструмент '{tool_name}' для Linux.")
            return False, None, current_linux_mounted_status, current_linux_conf_path

    # --- Другие ОС ---
    else:
        logger.error(f"Неподдерживаемая OS: {os.name}")
        return False, None, current_linux_mounted_status, current_linux_conf_path

    # Эта строка не должна достигаться при нормальной работе, но нужна для полноты
    return False, None, current_linux_mounted_status, current_linux_conf_path


def stop_tool(
    process_or_status,
    tool_name,
    output_dir,
    current_linux_mounted_status,
    current_linux_conf_path,
):
    """Останавливает инструмент, принимает хендл или статус."""
    logger = logging.getLogger("BlockCheck_Logic")
    logger.info(f"Остановка инструмента '{tool_name}'...")
    success = True  # Флаг успешности остановки

    if os.name == "posix" and tool_name == "zapret":
        # ... (логика для Linux остается без изменений) ...
        # Останавливаем сервис Zapret
        stopped_service = manage_zapret_service("stop")
        if not stopped_service:
            logger.warning(
                "Не удалось штатно остановить сервис Zapret (возможно, уже был остановлен)."
            )
            # Не меняем success, так как цель достигнута - сервис не работает с нашим конфигом

        unmounted = True  # Считаем успехом по умолчанию, если нечего отмонтировать
        if current_linux_mounted_status:
            unmounted = umount_zapret_linux_config()
            if not unmounted:
                logger.warning(
                    "Не удалось отмонтировать конфиг Zapret (возможно, уже отмонтирован)."
                )
                # Не меняем success, так как цель - убрать наш конфиг
            # Удаляем временный файл независимо от успеха отмонтирования
            remove_zapret_linux_config(current_linux_conf_path)

        # Пытаемся запустить сервис с дефолтным конфигом (если он есть)
        if not manage_zapret_service("start"):
            logger.warning(
                "Не удалось перезапустить сервис Zapret с дефолтным конфигом после остановки."
            )
            # Не меняем success, т.к. основная задача - остановить текущую конфигурацию

        return success  # Возвращаем общий статус успеха остановки/очистки

    elif process_or_status and os.name == "nt":  # Если это хендл процесса (для NT)
        process = process_or_status
        pid = process.pid  # Получаем PID до terminate
        logger.debug(f"Попытка остановки процесса '{tool_name}' (PID: {pid})...")
        try:
            # Проверяем, жив ли еще процесс
            if process.poll() is None:  # None означает, что процесс еще работает
                logger.debug(f"Процесс (PID: {pid}) активен. Используем taskkill...")
                # Используем taskkill для более надежного завершения дерева процессов в Windows
                try:
                    # --- ИСПРАВЛЕНИЕ: Добавляем capture_output и check=False ---
                    result = subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(pid)],
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=5,
                    )
                    # --- КОНЕЦ ИСПРАВЛЕНИЯ ---
                    logger.debug(f"taskkill stdout: {result.stdout}")
                    logger.debug(f"taskkill stderr: {result.stderr}")
                    if result.returncode == 0:
                        logger.info(
                            f"Инструмент '{tool_name}' (PID: {pid}) и его дочерние процессы успешно завершены через taskkill."
                        )
                    else:
                        # --- ИСПРАВЛЕНИЕ: Логируем ошибку taskkill и пробуем terminate/kill ---
                        logger.warning(
                            f"taskkill завершился с кодом {result.returncode} (PID: {pid}). Ошибка: {result.stderr.strip()}. Пробуем terminate/kill..."
                        )
                        process.terminate()
                        try:
                            process.wait(timeout=3)  # Короткое ожидание после terminate
                            logger.info(
                                f"Инструмент '{tool_name}' завершен (PID: {pid}) после terminate."
                            )
                        except subprocess.TimeoutExpired:
                            logger.warning(
                                f"Инструмент '{tool_name}' (PID: {pid}) не завершился после terminate, принудительное завершение (kill)..."
                            )
                            process.kill()
                            process.wait(timeout=3)  # Ждем завершения после kill
                            logger.info(
                                f"Инструмент '{tool_name}' принудительно завершен (PID: {pid}) после kill."
                            )
                        except Exception as wait_err:
                            logger.warning(
                                f"Ошибка ожидания завершения процесса {pid} после terminate/kill: {wait_err}"
                            )
                    # --- КОНЕЦ ИСПРАВЛЕНИЯ ---
                except (subprocess.TimeoutExpired, FileNotFoundError) as kill_err:
                    logger.warning(
                        f"taskkill не удался (PID: {pid}), пробуем terminate/kill: {kill_err}"
                    )
                    # --- ИСПРАВЛЕНИЕ: Дублирующая логика terminate/kill на случай ошибки taskkill ---
                    try:
                        process.terminate()
                        process.wait(timeout=3)
                        logger.info(
                            f"Инструмент '{tool_name}' завершен (PID: {pid}) после terminate (fallback)."
                        )
                    except subprocess.TimeoutExpired:
                        logger.warning(
                            f"Инструмент '{tool_name}' (PID: {pid}) не завершился после terminate (fallback), принудительное завершение (kill)..."
                        )
                        process.kill()
                        process.wait(timeout=3)
                        logger.info(
                            f"Инструмент '{tool_name}' принудительно завершен (PID: {pid}) после kill (fallback)."
                        )
                    except Exception as term_kill_err:
                        logger.error(
                            f"Ошибка при fallback terminate/kill для PID {pid}: {term_kill_err}"
                        )
                        success = False  # Явно указываем на неуспех
                    # --- КОНЕЦ ИСПРАВЛЕНИЯ ---
            else:
                logger.info(
                    f"Инструмент '{tool_name}' (PID: {pid}) уже был завершен до вызова stop_tool."
                )
        except ProcessLookupError:
            logger.info(
                f"Процесс '{tool_name}' (PID: {pid}) не найден, возможно, уже завершен."
            )
        except Exception as e:
            logger.warning(
                f"Ошибка при остановке инструмента '{tool_name}' (PID: {pid}, возможно уже завершен): {e}"
            )
            # Не меняем success, так как цель - чтобы процесс не работал
    else:
        # Либо process_or_status был None (Linux или инструмент не запускался), либо процесс уже завершен (NT)
        logger.info(
            f"Для инструмента '{tool_name}' не найден активный процесс/статус для остановки."
        )

    logger.info(
        f"Завершение остановки инструмента '{tool_name}'. Статус успеха: {success}"
    )
    return success


# --- Функции тестирования сайтов ---
async def test_site(session, site, semaphore):
    """Асинхронно тестирует доступность одного сайта (логика: WORKING = любой ответ от сервера)."""
    logger = logging.getLogger("BlockCheck_Logic")
    async with semaphore:
        start_time = asyncio.get_event_loop().time()
        status_code = "NOT WORKING"
        http_status = 0
        latency = 0.0
        ip_address = "unknown"
        parsed_url = urlparse(site)
        hostname = parsed_url.hostname
        error_detail = ""

        if not hostname:
            logger.warning(f"Не удалось извлечь хост из URL: {site}")
            latency = asyncio.get_event_loop().time() - start_time
            # Возвращаем 6 значений
            return (
                site,
                "INVALID_URL",
                ip_address,
                round(latency * 1000, 2),
                0,
                "Invalid Hostname",
            )

        try:  # Основной try для DNS и HTTP запроса
            timeout = aiohttp.ClientTimeout(
                total=5.0, connect=2.0, sock_read=3.0, sock_connect=2.0
            )

            # --- Попытка получить IP ---
            try:
                addr_info = await asyncio.wait_for(
                    asyncio.get_event_loop().getaddrinfo(
                        hostname, parsed_url.port or 443, proto=socket.IPPROTO_TCP
                    ),
                    timeout=1.5,
                )
                if addr_info:
                    ip_address = next(
                        (
                            sockaddr[0]
                            for family, type, proto, canonname, sockaddr in addr_info
                            if family == socket.AF_INET
                        ),
                        "unknown",
                    )
                    port = parsed_url.port or 443
                    if ip_address != "unknown":
                        ip_address = f"{ip_address}:{port}"
            except asyncio.TimeoutError:
                logger.debug(f"Таймаут DNS для {hostname} ({site})")
                ip_address = "dns_timeout"
            except socket.gaierror as ip_err:
                logger.debug(
                    f"Не удалось получить IP для {hostname} ({site}): {ip_err}"
                )
                ip_address = "dns_error"
            except Exception as ip_err:
                logger.debug(
                    f"Неожиданная ошибка при получении IP для {hostname} ({site}): {ip_err}"
                )
                ip_address = "ip_error"
            # --- Конец получения IP ---

            # --- Основной запрос ---
            response = None
            try:  # Внутренний try для HTTP запроса
                async with session.get(
                    site,
                    headers=HEADERS,
                    timeout=timeout,
                    ssl=False,
                    allow_redirects=True,
                ) as response:
                    status_code = "WORKING"
                    http_status = response.status
                    latency = asyncio.get_event_loop().time() - start_time

                    if not (200 <= http_status < 300):
                        logger.debug(
                            f"Сайт {site} ответил статусом {http_status} (считается WORKING)"
                        )

                    # Попытка чтения части ответа
                    try:
                        await response.content.readexactly(1)
                    except (
                        aiohttp.ClientPayloadError,
                        asyncio.TimeoutError,
                        ConnectionResetError,
                        OSError,
                    ) as read_err:
                        logger.debug(
                            f"Ошибка чтения payload для {site} после получения статуса {http_status}: {type(read_err).__name__} - {read_err}"
                        )
                        error_detail = f"ReadError: {type(read_err).__name__}"
                    except Exception as read_err:
                        logger.warning(
                            f"Неожиданная ошибка чтения payload для {site}: {type(read_err).__name__} - {read_err}"
                        )
                        error_detail = f"ReadError: {type(read_err).__name__}"

            # --- Блок except для внутреннего try (HTTP запрос) ---
            except asyncio.TimeoutError:
                latency = asyncio.get_event_loop().time() - start_time
                status_code = "NOT WORKING"
                http_status = 0
                error_detail = "Timeout"
                logger.debug(f"Таймаут при доступе к {site}")
            except aiohttp.ClientResponseError as e:
                status_code = "WORKING"
                http_status = e.status
                latency = asyncio.get_event_loop().time() - start_time
                error_detail = f"ClientResponseError: {e.status}"
                logger.warning(
                    f"Ошибка ответа клиента для {site}: Status={e.status}, Message='{e.message}'. Считается WORKING."
                )
            except aiohttp.ClientConnectionError as e:
                latency = asyncio.get_event_loop().time() - start_time
                status_code = "NOT WORKING"
                http_status = 0
                error_detail = f"ClientConnectionError: {type(e).__name__}"
                logger.debug(f"Ошибка соединения с {site}: {e}")
            except aiohttp.ClientSSLError as e:
                latency = asyncio.get_event_loop().time() - start_time
                status_code = "NOT WORKING"
                http_status = 0
                error_detail = "ClientSSLError"
                logger.debug(f"Ошибка SSL с {site}: {e}")
            except OSError as e:
                latency = asyncio.get_event_loop().time() - start_time
                status_code = "NOT WORKING"
                http_status = 0
                error_detail = f"OSError: {e.errno}"
                logger.warning(f"OSError при тестировании {site}: {e}")
                if hasattr(e, "winerror") and e.winerror == 10038:
                    logger.error(
                        f"!!! WinError 10038 (Not a socket) для {site}. Response status: {response.status if response else 'N/A'}"
                    )
            except asyncio.CancelledError:
                status_code = "CANCELLED"
                http_status = 0
                latency = asyncio.get_event_loop().time() - start_time
                error_detail = "Cancelled"
                logger.warning(f"Тест для сайта {site} был отменен.")
            except Exception as e:
                latency = asyncio.get_event_loop().time() - start_time
                status_code = "NOT WORKING"
                http_status = 0
                error_type = type(e).__name__
                error_detail = f"UnknownError: {error_type}"
                logger.warning(
                    f"Неожиданная ошибка при HTTP запросе {site}: {error_type} - {e}"
                )
                logger.debug(traceback.format_exc())
            # --- Конец блока except для внутреннего try ---

        except Exception as outer_e:  # Блок except для основного try
            latency = asyncio.get_event_loop().time() - start_time
            status_code = (
                "TEST_ERROR"  # Используем другой статус для критических ошибок
            )
            http_status = 0
            error_detail = f"OuterError: {type(outer_e).__name__}"
            logger.error(f"Критическая ошибка в test_site для {site}: {outer_e}")
            logger.debug(traceback.format_exc())

        # --- ИСПРАВЛЕНИЕ: return находится ПОСЛЕ основного блока try...except ---
        return (
            site,
            status_code,
            ip_address,
            round(latency * 1000, 2),
            http_status,
            error_detail,
        )
        # --- КОНЕЦ ИСПРАВЛЕНИЯ ---


async def run_async_tests(sites):
    """Запускает асинхронное тестирование для списка сайтов."""
    logger = logging.getLogger("BlockCheck_Logic")
    results = {}
    # Уменьшаем лимит одновременных соединений и семафор для стабильности
    connector = aiohttp.TCPConnector(
        limit=70, ttl_dns_cache=300, ssl=False
    )  # Уменьшено с 100 до 70
    async with aiohttp.ClientSession(
        connector=connector,
        read_bufsize=16384,  # Увеличено для потенциально больших ответов
        max_line_size=16384,
        max_field_size=16384,
    ) as session:
        semaphore = asyncio.Semaphore(35)  # Уменьшено с 50 до 35
        tasks = [test_site(session, site, semaphore) for site in sites]
        completed_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in completed_results:
            if isinstance(result, Exception):
                logger.error(f"Ошибка во время выполнения gather: {result}")
                # Можно добавить заглушку, но пока пропускаем
            # --- ИЗМЕНЕНИЕ: Ожидаем 6 элементов, сохраняем 5 ---
            elif result is not None and isinstance(result, tuple) and len(result) == 6:
                site, status, ip, latency, http_status, error_detail = result
                # Сохраняем 5 значений:
                results[site] = (status, ip, latency, http_status, error_detail)
            # Обработка случая INVALID_URL (тоже 6 элементов)
            elif (
                result is not None
                and isinstance(result, tuple)
                and len(result) == 6
                and result[1] == "INVALID_URL"
            ):
                site, status, ip, latency, http_status, error_detail = result
                # Сохраняем 5 значений
                results[site] = (status, ip, latency, http_status, error_detail)
            # --- КОНЕЦ ИЗМЕНЕНИЯ ---
            else:
                logger.warning(f"Получен некорректный результат от test_site: {result}")
                site_name = (
                    result[0]
                    if result and isinstance(result, tuple) and len(result) > 0
                    else "unknown_invalid_result"
                )
                # Сохраняем как ошибку с 5 значениями
                results[site_name] = (
                    "INVALID_RESULT",
                    "unknown",
                    0.0,
                    0,
                    "Invalid format",
                )
    return results


def log_test_results(
    iteration_logger, params, results, current_strategy_index, total_strategies
):
    """Логирует результаты тестирования для одной стратегии в логгер итерации."""
    if iteration_logger is None:
        logging.error("Логгер итерации не инициализирован для log_test_results")
        return 0, 0

    successes = 0
    total_tested = 0
    detailed_log_lines = []

    sorted_sites = sorted(results.keys())

    for site in sorted_sites:
        data = results[site]
        # --- ИЗМЕНЕНИЕ: Ожидаем 5 элементов, как сохранено в run_async_tests ---
        if data is None or not isinstance(data, tuple) or len(data) != 5:
            logging.warning(f"Некорректный формат результата для сайта {site}: {data}")
            status, ip, latency, http_status_val, error_detail = (
                "INVALID_FMT",
                "unknown",
                0.0,
                0,
                "Invalid format",
            )
        else:
            status, ip, latency, http_status_val, error_detail = data
        # --- КОНЕЦ ИЗМЕНЕНИЯ ---

        if status not in [
            "CANCELLED",
            "INVALID_URL",
            "INVALID_RESULT",
            "INVALID_FMT",
            "GATHER_ERROR",
            "TEST_ERROR",
            "TOOL_START_FAIL",
            "TEST_RUN_FAIL",
        ]:  # Добавлены статусы ошибок
            total_tested += 1
            if status == "WORKING":
                successes += 1

        status_out = status
        ip_out = ip if ip else "unknown"
        http_status_str = f" (HTTP: {http_status_val})" if http_status_val > 0 else ""
        error_str = f" (Error: {error_detail})" if error_detail else ""
        fmt_spaces = max(1, 11 - len(str(status_out)))
        detailed_log_lines.append(
            f"{status_out}{' '*fmt_spaces}\tURL: {site} | IP: {ip_out} | Latency: {latency:.2f} ms{http_status_str}{error_str}"
        )

    param_line = f"Launching Zapret with a strategy {current_strategy_index}/{total_strategies}: {params}"
    iteration_logger.info(param_line)
    iteration_logger.info("Making requests, pass 1/1...")
    iteration_logger.info("Displaying results...")

    for line in detailed_log_lines:
        iteration_logger.info(line)

    success_summary_line = f"Successes: {successes}/{total_tested}"
    iteration_logger.info(success_summary_line)
    iteration_logger.info("")

    return successes, total_tested


# --- ГЛАВНАЯ ФУНКЦИЯ МОДУЛЯ ---
def run_blockcheck_iteration(
    strategy_file_path,
    sites_set_name,
    tool_name,
    iteration_num,
    output_dir,
    base_path,
    target_protocol: str = "tcp",  # <--- НОВЫЙ АРГУМЕНТ
    target_port: int = 443,
):  # <--- НОВЫЙ АРГУМЕНТ
    master_logger = logging.getLogger("MasterOrchestrator")
    iteration_logger, log_file_path = setup_iteration_logging(
        tool_name, iteration_num, output_dir
    )

    if iteration_logger is None:
        master_logger.error(
            f"Не удалось настроить логгирование для итерации {iteration_num}."
        )
        return None

    master_logger.info(f"--- Запуск итерации тестирования {iteration_num} ---")
    master_logger.info(
        f"Инструмент: {tool_name}, Сайты: {sites_set_name}, Стратегии: {strategy_file_path}"
    )
    master_logger.info(
        f"Целевой протокол: {target_protocol}, Целевой порт: {target_port}"
    )  # Логируем

    # Переменные состояния для Linux Zapret
    linux_mounted_status = False
    linux_conf_path = ""
    tool_process_handle = None  # Для Windows

    try:
        sites = read_sites(sites_set_name, base_path)
        if not sites:
            master_logger.error("Не удалось прочитать список сайтов или он пуст.")
            # Создаем пустой лог, чтобы генератор мог его обработать
            if iteration_logger:
                log_test_results(iteration_logger, "<No sites found>", {}, 0, 0)
            master_logger.info(
                f"--- Завершение итерации тестирования {iteration_num} (нет сайтов) ---"
            )
            # Возвращаем путь к (возможно пустому) логу, чтобы цикл мог продолжиться
            return log_file_path if log_file_path else None

        strategies = read_strategies_from_file(strategy_file_path)
        if strategies is None:
            master_logger.error(
                f"Не удалось прочитать стратегии из {strategy_file_path}."
            )
            return None  # Критическая ошибка чтения файла
        if not strategies:
            master_logger.warning(f"Файл стратегий {strategy_file_path} пуст.")
            # Создаем пустой лог, чтобы генератор мог его обработать
            log_test_results(iteration_logger, "<No strategies found>", {}, 0, 0)
            master_logger.info(
                f"--- Завершение итерации тестирования {iteration_num} (нет стратегий) ---"
            )
            return log_file_path

        total_strategies = len(strategies)
        master_logger.info(f"Загружено {total_strategies} стратегий для тестирования.")

        # Словарь для хранения итоговых результатов {strategy_string: (successes, total)}
        final_results_summary = {}

        if tool_name == "none":
            master_logger.info(
                "Инструмент не используется. Выполняется базовый тест доступности."
            )
            results = {}
            try:
                # Используем asyncio.run() для выполнения асинхронной функции
                results = asyncio.run(run_async_tests(sites))
                log_test_results(
                    iteration_logger, "<baseline (no tool)>", results, 1, 1
                )
            except Exception as e:
                master_logger.error(f"Ошибка при базовом тестировании сайтов: {e}")
                # Логируем ошибку для всех сайтов
                results = {
                    s: ("TEST_FAIL", "unknown", 0.0, 0, f"Error: {e}") for s in sites
                }  # Добавляем 5-й элемент
                log_test_results(
                    iteration_logger, "<baseline (no tool) - ERROR>", results, 1, 1
                )
            # Базовый тест не влияет на итоговую сводку по стратегиям, просто логируется
            pass
        else:
            # --- Цикл по стратегиям ---
            for current_line, original_params in enumerate(strategies, start=1):
                # Проверка флага прерывания перед началом обработки стратегии
                if "stop_requested" in globals() and globals()["stop_requested"]():
                    master_logger.warning(
                        f"Запрос на остановку получен перед тестированием стратегии {current_line}/{total_strategies}. Прерывание итерации."
                    )
                    break  # Выход из цикла по стратегиям

                master_logger.info(
                    f"Итерация {iteration_num}: Тестирование стратегии {current_line}/{total_strategies}"
                )
                iteration_logger.info(
                    f"Raw Params: {original_params}"
                )  # Логируем исходные параметры
                parameters = replace_parameters(original_params, base_path)
                # iteration_logger.info(f"Processed Params: {parameters}") # Можно раскомментировать для отладки

                # Запуск инструмента ...
                started, handle, new_linux_mounted, new_linux_conf = start_tool(
                    tool_name,
                    parameters,
                    base_path,
                    output_dir,
                    linux_mounted_status,
                    linux_conf_path,
                )
                if not started:
                    master_logger.error(
                        f"Не удалось запустить инструмент для стратегии: {parameters}. Пропуск."
                    )
                    # Записываем ошибку в лог итерации
                    results_fail = {
                        site: (
                            "TOOL_START_FAIL",
                            "unknown",
                            0.0,
                            0,
                            "Tool start failed",
                        )
                        for site in sites
                    }  # Добавляем 5-й элемент
                    log_test_results(
                        iteration_logger,
                        parameters,
                        results_fail,
                        current_line,
                        total_strategies,
                    )
                    final_results_summary[original_params] = (
                        0,
                        len(sites),
                    )  # Сохраняем как 0 успехов по исходным параметрам
                    continue  # Переходим к следующей стратегии

                tool_process_handle = handle
                linux_mounted_status = new_linux_mounted
                linux_conf_path = new_linux_conf

                # Даем инструменту время на инициализацию
                time.sleep(2.0)  # Можно настроить

                # Тестирование сайтов ...
                results = {}
                try:
                    # Используем asyncio.run() для выполнения асинхронной функции
                    results = asyncio.run(run_async_tests(sites))
                except Exception as e:
                    master_logger.error(
                        f"Ошибка при асинхронном тестировании сайтов для стратегии {parameters}: {e}"
                    )
                    results = {
                        site: ("TEST_RUN_FAIL", "unknown", 0.0, 0, f"Error: {e}")
                        for site in sites
                    }  # Добавляем 5-й элемент

                # Логирование результатов и получение успехов/всего
                successes, total_tested = log_test_results(
                    iteration_logger,
                    parameters,
                    results,
                    current_line,
                    total_strategies,
                )
                # Сохраняем результат по ИСХОДНЫМ параметрам для генератора
                final_results_summary[original_params] = (successes, total_tested)

                # Остановка инструмента ...
                stopped = stop_tool(
                    tool_process_handle,
                    tool_name,
                    output_dir,
                    linux_mounted_status,
                    linux_conf_path,
                )
                if not stopped:
                    master_logger.warning(
                        f"Не удалось корректно остановить/очистить инструмент '{tool_name}' после стратегии: {parameters}"
                    )
                # Сбрасываем статусы Linux и хендл Windows после остановки
                linux_mounted_status = False
                linux_conf_path = ""
                tool_process_handle = None

                # Небольшая пауза перед следующей стратегией
                time.sleep(0.5)  # Можно настроить

        # --- ЗАПИСЬ ИТОГОВОЙ СВОДКИ В КОНЕЦ ЛОГА ---
        if (
            tool_name != "none" and final_results_summary
        ):  # Только если были стратегии и инструмент использовался
            iteration_logger.info(
                "\n--- All strategies have been tested, displaying final results ---"
            )
            # Группируем стратегии по количеству успехов
            results_by_success = {}
            for params, (s, t) in final_results_summary.items():
                # Используем total_tested из результатов, если он > 0, иначе берем общее кол-во сайтов
                total_for_key = t if t > 0 else len(sites)
                key = f"{s}/{total_for_key}"
                if key not in results_by_success:
                    results_by_success[key] = []
                results_by_success[key].append(params)  # Добавляем ИСХОДНЫЕ параметры

            # Записываем группы в лог, сортируя по количеству успехов (от большего к меньшему)
            # Сортируем сначала по числу успехов (первое число до '/'), затем по общему числу (второе число)
            def sort_key(k):
                try:
                    s, t = map(int, k.split("/"))
                    return s, t
                except ValueError:  # Обработка случая, если ключ не в формате "s/t"
                    return -1, -1  # Помещаем некорректные ключи в начало

            sorted_keys = sorted(results_by_success.keys(), key=sort_key, reverse=True)

            for key in sorted_keys:
                iteration_logger.info(f"\nStrategies with {key} successes:")
                # Сортируем стратегии внутри группы для консистентности
                sorted_params_in_group = sorted(results_by_success[key])
                for params in sorted_params_in_group:
                    iteration_logger.info(params)  # Выводим ИСХОДНУЮ строку параметров

        master_logger.info(f"--- Завершение итерации тестирования {iteration_num} ---")
        return log_file_path

    except Exception:
        master_logger.exception(
            f"Критическая ошибка в итерации тестирования {iteration_num}:"
        )
        # Попытка остановить инструмент при критической ошибке
        if tool_name != "none":
            master_logger.warning(
                "Попытка аварийной остановки инструмента из-за критической ошибки..."
            )
            try:
                stop_tool(
                    tool_process_handle,
                    tool_name,
                    output_dir,
                    linux_mounted_status,
                    linux_conf_path,
                )
            except Exception as stop_err:
                master_logger.error(
                    f"Ошибка при аварийной остановке инструмента: {stop_err}"
                )
        return None  # Сигнализируем об ошибке
    finally:
        # Закрываем файловый хендлер логгера итерации, если он был создан
        if iteration_logger:
            handlers = iteration_logger.handlers[
                :
            ]  # Копируем список для безопасного удаления
            for handler in handlers:
                if isinstance(handler, logging.FileHandler):
                    try:
                        handler.close()
                    except Exception as close_err:
                        # Логируем ошибку закрытия через корневой логгер
                        logging.error(
                            f"Ошибка при закрытии хендлера лога итерации {handler.baseFilename}: {close_err}"
                        )
                    iteration_logger.removeHandler(handler)


# Этот блок не будет выполняться при импорте модуля, но полезен для автономного тестирования
if __name__ == "__main__":
    print("Этот скрипт предназначен для импорта как модуль ('blockcheck_logic').")
    print("Для запуска используйте iterative_master.py.")

    # Пример настройки логгирования для автономного теста
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Пример вызова функции для теста (замените пути и параметры)
    # print("Запуск тестового прогона run_blockcheck_iteration...")
    # test_output_dir = "test_run_output"
    # test_base_path = os.path.dirname(os.path.abspath(__file__)) # Путь к директории этого скрипта
    # test_strategy_file = os.path.join(test_base_path, "test_strategies.txt") # Создайте этот файл с 1-2 стратегиями
    #
    # # Создайте файл test_strategies.txt рядом с blockcheck_logic.py
    # # Пример содержимого test_strategies.txt:
    # # --dpi-desync=fake --split-http=M --hostspell=do --hostlist=ya.ru
    # # --dpi-desync=fake --split-http=M --hostspell=ho --hostlist=google.com
    #
    # if not os.path.exists(test_strategy_file):
    #      print(f"Создайте тестовый файл стратегий: {test_strategy_file}")
    # else:
    #      # Настройка asyncio для Windows
    #      if sys.platform == 'win32':
    #          asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    #
    #      test_log = run_blockcheck_iteration(
    #          strategy_file_path=test_strategy_file,
    #          sites_set_name="min", # Убедитесь, что sites_list/min.txt существует
    #          tool_name="zapret", # или "goodbyedpi", "none"
    #          iteration_num=999, # Тестовый номер итерации
    #          output_dir=test_output_dir,
    #          base_path=test_base_path
    #      )
    #      if test_log:
    #          print(f"Тестовый запуск завершен. Лог файл: {test_log}")
    #      else:
    #          print("Тестовый запуск не удался.")
