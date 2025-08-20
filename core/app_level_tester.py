# recon/core/app_level_tester.py
import asyncio
import logging
import os
import shutil
import subprocess
import time
from typing import Dict, List, Tuple, Optional
import aiohttp

# Используем абсолютный импорт, чтобы избежать проблем с путями
from .. import config as main_config_module

LOG = logging.getLogger("AppTester")


def _replace_placeholders(parameters_str: str, base_path: str) -> str:
    """Заменяет плейсхолдеры в строке параметров, включая пути к файлам."""
    try:
        processed_parameters = parameters_str
        # Стандартные плейсхолдеры
        processed_parameters = processed_parameters.replace(
            "FAKESNI", main_config_module.FAKE_SNI
        )
        processed_parameters = processed_parameters.replace(
            "FAKEHEX", main_config_module.FAKE_HEX
        )

        # Плейсхолдеры файлов
        for placeholder, rel_path in main_config_module.PAYLOAD_PLACEHOLDERS.items():
            if placeholder in processed_parameters:
                full_path = os.path.join(base_path, rel_path)
                full_path = os.path.normpath(full_path)
                processed_parameters = processed_parameters.replace(
                    placeholder, full_path
                )
                LOG.debug(
                    f"Replaced placeholder '{placeholder}' with path '{full_path}'"
                )
        return processed_parameters
    except Exception as e:
        LOG.error(f"Error replacing parameters in '{parameters_str}': {e}")
        return parameters_str


def _find_tool_path(tool_name: str, base_path: str) -> str:
    """Находит абсолютный путь к исполняемому файлу."""
    if tool_name == "none":
        return "none"

    tool_path_rel = ""
    if os.name == "nt":
        path_map = {
            "zapret": main_config_module.ZAPRET_NT_PATH,
            "goodbyedpi": main_config_module.GOODBYEDPI_NT_PATH,
        }
        name_map = {
            "zapret": main_config_module.ZAPRET_NT_TOOL_NAME,
            "goodbyedpi": main_config_module.GOODBYEDPI_NT_TOOL_NAME,
        }
        tool_path_rel = os.path.join(
            path_map.get(tool_name, ""), name_map.get(tool_name, "")
        )
    else:  # posix
        found_in_path = shutil.which(main_config_module.ZAPRET_LINUX_TOOL_NAME)
        if found_in_path:
            return found_in_path
        tool_path_rel = os.path.join(
            main_config_module.ZAPRET_LINUX_PATH,
            main_config_module.ZAPRET_LINUX_TOOL_NAME,
        )

    absolute_path = os.path.join(base_path, tool_path_rel)
    if not os.path.exists(absolute_path):
        raise FileNotFoundError(
            f"Tool executable not found at expected path: {absolute_path}"
        )
    return absolute_path


async def _test_single_site(
    session: aiohttp.ClientSession, site: str, semaphore: asyncio.Semaphore
) -> Tuple[str, str, float, int, str]:
    """
    Асинхронно тестирует один сайт, возвращая детальный результат.
    """
    async with semaphore:
        start_time = asyncio.get_event_loop().time()
        status, http_status, error_detail = "NOT WORKING", 0, "Unknown"

        try:
            # Устанавливаем таймауты для разных фаз соединения
            timeout = aiohttp.ClientTimeout(total=5.0, connect=2.0, sock_read=3.0)
            async with session.get(
                site,
                headers=main_config_module.HEADERS,
                timeout=timeout,
                ssl=False,
                allow_redirects=True,
            ) as response:
                status = "WORKING"
                http_status = response.status
                # Попытка прочитать хотя бы один байт, чтобы убедиться в наличии тела ответа
                await response.content.readexactly(1)
                error_detail = "OK"
        except (
            aiohttp.ClientPayloadError,
            asyncio.TimeoutError,
            ConnectionResetError,
        ) as e:
            # Эти ошибки часто означают, что соединение было установлено, но потом разорвано (возможно, DPI)
            # Мы все еще считаем это "WORKING", но с деталями ошибки, т.к. соединение было установлено
            status = "WORKING"
            http_status = response.status if "response" in locals() and response else 0
            error_detail = f"ReadError: {type(e).__name__}"
        except aiohttp.ClientConnectionError as e:
            # Эти ошибки означают, что соединение не удалось установить вообще
            error_detail = f"ConnError: {type(e).__name__}"
        except asyncio.CancelledError:
            # Обработка отмены задачи
            error_detail = "Cancelled"
        except Exception as e:
            # Прочие ошибки
            error_detail = f"OtherError: {type(e).__name__}"

        latency = (asyncio.get_event_loop().time() - start_time) * 1000
        return site, status, latency, http_status, error_detail


class AppLevelTester:
    """Выполняет тестирование стратегий на уровне приложений."""

    def __init__(self, tool_name: str, base_path: str, output_dir: str):
        self.tool_name = tool_name
        self.base_path = base_path
        self.output_dir = output_dir
        self.tool_path = _find_tool_path(tool_name, base_path)
        self.process: Optional[subprocess.Popen] = None

    def start_tool(self, strategy_str: str) -> bool:
        """Запускает внешний инструмент с заданной стратегией."""
        if self.tool_name == "none":
            return True

        params_with_placeholders = _replace_placeholders(strategy_str, self.base_path)
        params_list = params_with_placeholders.split()

        if os.name == "nt":
            if self.tool_name == "zapret":
                final_args = main_config_module.ZAPRET_NT_ARGS + params_list
            elif self.tool_name == "goodbyedpi":
                final_args = main_config_module.GOODBYEDPI_NT_ARGS + params_list
            else:
                final_args = params_list

            try:
                LOG.info(
                    f"Starting '{self.tool_path}' with args: {' '.join(final_args)}"
                )
                self.process = subprocess.Popen(
                    [self.tool_path] + final_args,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    cwd=os.path.dirname(self.tool_path),
                )
                time.sleep(1.5)  # Время на инициализацию
                if self.process.poll() is not None:
                    LOG.error(
                        f"Tool '{self.tool_name}' terminated immediately after start."
                    )
                    return False
                LOG.info(
                    f"Tool '{self.tool_name}' started with PID: {self.process.pid}"
                )
                return True
            except Exception:
                LOG.exception(f"Failed to start tool '{self.tool_name}':")
                return False
        else:  # posix
            LOG.error(
                "Linux service management is not fully implemented in this version of the tester."
            )
            return False

    def stop_tool(self):
        """Останавливает запущенный инструмент."""
        if self.tool_name == "none" or self.process is None:
            return

        LOG.info(f"Stopping tool '{self.tool_name}' (PID: {self.process.pid})...")
        if os.name == "nt":
            try:
                # Используем taskkill для корректного завершения процесса и его дочерних процессов
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(self.process.pid)],
                    capture_output=True,
                    check=False,
                    timeout=5,
                )
                self.process.wait(timeout=5)
            except (subprocess.TimeoutExpired, Exception) as e:
                LOG.warning(
                    f"Could not gracefully stop process {self.process.pid}, killing. Error: {e}"
                )
                self.process.kill()
        else:  # posix
            self.process.terminate()
        self.process = None
        LOG.info("Tool stopped.")

    async def test_strategy(self, sites: List[str]) -> Dict[str, Tuple]:
        """
        Запускает асинхронное тестирование для списка сайтов с правильным
        управлением ресурсами для предотвращения ошибок на Windows.
        """
        results = {}
        # Создаем коннектор один раз для всей сессии тестирования
        connector = aiohttp.TCPConnector(
            limit=100,  # Общий лимит одновременных соединений
            limit_per_host=25,  # Лимит на один хост
            ttl_dns_cache=300,  # Кэшируем DNS на 5 минут
            ssl=False,  # Отключаем проверку SSL, так как мы тестируем доступность
            force_close=True,  # Важно: закрывать соединения после каждого запроса для чистоты теста
        )
        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                semaphore = asyncio.Semaphore(25)  # Ограничиваем параллелизм
                tasks = [_test_single_site(session, site, semaphore) for site in sites]
                completed_results = await asyncio.gather(*tasks, return_exceptions=True)

                for res in completed_results:
                    if isinstance(res, Exception):
                        LOG.error(f"A testing task failed unexpectedly: {res}")
                    elif res:
                        site, status, latency, http_status, error_detail = res
                        results[site] = (status, latency, http_status, error_detail)
        finally:
            # Гарантированно закрываем коннектор, чтобы освободить все ресурсы
            await connector.close()

        return results
