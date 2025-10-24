"""
SystemBypassManager для управления внешними инструментами обхода DPI.
Адаптирован из apply_bypass.py и app_level_tester.py для централизованного управления.
"""


def apply_forced_override(original_func, *args, **kwargs):
    """
    Обертка для принудительного применения стратегий.
    КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ для идентичного поведения с режимом тестирования.
    """
    # Добавляем forced параметры
    if len(args) > 1 and isinstance(args[1], dict):
        # Второй аргумент - стратегия
        strategy = args[1].copy()
        strategy["no_fallbacks"] = True
        strategy["forced"] = True
        args = (args[0], strategy) + args[2:]
        print(f"🔥 FORCED OVERRIDE: Applied to {args[0] if args else 'unknown'}")

    return original_func(*args, **kwargs)


import asyncio
import logging
import os
import platform
import shutil
import subprocess
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

LOG = logging.getLogger("SystemBypassManager")


class ToolStatus(Enum):
    """Статус внешнего инструмента"""

    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"


@dataclass
class ToolConfig:
    """Конфигурация внешнего инструмента"""

    name: str
    executable_path: str
    base_args: List[str]
    proxy_port: Optional[int] = None
    dns_port: Optional[int] = None
    requires_admin: bool = True
    startup_delay: float = 1.5
    shutdown_timeout: float = 5.0


@dataclass
class ToolInstance:
    """Экземпляр запущенного инструмента"""

    config: ToolConfig
    process: Optional[subprocess.Popen] = None
    status: ToolStatus = ToolStatus.STOPPED
    pid: Optional[int] = None
    start_time: Optional[float] = None
    strategy_args: List[str] = None


class SystemBypassManager:
    """
    Менеджер для управления внешними инструментами обхода DPI.
    Поддерживает zapret, goodbyedpi и другие системные инструменты.
    """

    def __init__(self, base_path: str = "."):
        self.base_path = base_path
        self.tools: Dict[str, ToolInstance] = {}
        self._lock = asyncio.Lock()
        self._init_tool_configs()

    def _init_tool_configs(self):
        """Инициализирует конфигурации поддерживаемых инструментов"""
        zapret_path = self._find_tool_executable("zapret")
        if zapret_path:
            zapret_config = ToolConfig(
                name="zapret",
                executable_path=zapret_path,
                base_args=self._get_zapret_base_args(),
                proxy_port=8080,
                dns_port=5353,
                requires_admin=True,
            )
            self.tools["zapret"] = ToolInstance(config=zapret_config)
        goodbyedpi_path = self._find_tool_executable("goodbyedpi")
        if goodbyedpi_path:
            goodbyedpi_config = ToolConfig(
                name="goodbyedpi",
                executable_path=goodbyedpi_path,
                base_args=self._get_goodbyedpi_base_args(),
                requires_admin=True,
            )
            self.tools["goodbyedpi"] = ToolInstance(config=goodbyedpi_config)

    def _find_tool_executable(self, tool_name: str) -> Optional[str]:
        """Находит исполняемый файл инструмента"""
        executable = shutil.which(tool_name)
        if executable:
            return executable
        if platform.system() == "Windows":
            return self._find_windows_executable(tool_name)
        else:
            return self._find_linux_executable(tool_name)

    def _find_windows_executable(self, tool_name: str) -> Optional[str]:
        """Находит исполняемый файл в Windows"""
        try:
            from recon.core import config as main_config_module

            if tool_name == "zapret":
                tool_path = os.path.join(
                    self.base_path,
                    main_config_module.ZAPRET_NT_PATH,
                    main_config_module.ZAPRET_NT_TOOL_NAME,
                )
            elif tool_name == "goodbyedpi":
                tool_path = os.path.join(
                    self.base_path,
                    main_config_module.GOODBYEDPI_NT_PATH,
                    main_config_module.GOODBYEDPI_NT_TOOL_NAME,
                )
            else:
                return None
            if os.path.exists(tool_path):
                return tool_path
        except ImportError:
            LOG.warning("Could not import config module for tool paths")
        return None

    def _find_linux_executable(self, tool_name: str) -> Optional[str]:
        """Находит исполняемый файл в Linux"""
        try:
            from recon.core import config as main_config_module

            if tool_name == "zapret":
                found_in_path = shutil.which(main_config_module.ZAPRET_LINUX_TOOL_NAME)
                if found_in_path:
                    return found_in_path
                tool_path = os.path.join(
                    self.base_path,
                    main_config_module.ZAPRET_LINUX_PATH,
                    main_config_module.ZAPRET_LINUX_TOOL_NAME,
                )
                if os.path.exists(tool_path):
                    return tool_path
        except ImportError:
            LOG.warning("Could not import config module for tool paths")
        return None

    def _get_zapret_base_args(self) -> List[str]:
        """Получает базовые аргументы для zapret"""
        try:
            from recon.core import config as main_config_module

            if platform.system() == "Windows":
                return main_config_module.ZAPRET_NT_ARGS.copy()
            else:
                return []
        except ImportError:
            return []

    def _get_goodbyedpi_base_args(self) -> List[str]:
        """Получает базовые аргументы для goodbyedpi"""
        try:
            from recon.core import config as main_config_module

            if platform.system() == "Windows":
                return main_config_module.GOODBYEDPI_NT_ARGS.copy()
            else:
                return []
        except ImportError:
            return []

    def _check_admin_rights(self) -> bool:
        """Проверяет права администратора"""
        if platform.system() == "Windows":
            try:
                import ctypes

                return ctypes.windll.shell32.IsUserAnAdmin()
            except:
                return False
        else:
            return os.geteuid() == 0

    def _replace_placeholders(self, parameters_str: str) -> str:
        """Заменяет плейсхолдеры в строке параметров"""
        try:
            from recon.core import config as main_config_module

            processed_parameters = parameters_str
            processed_parameters = processed_parameters.replace(
                "FAKESNI", main_config_module.FAKE_SNI
            )
            processed_parameters = processed_parameters.replace(
                "FAKEHEX", main_config_module.FAKE_HEX
            )
            for (
                placeholder,
                rel_path,
            ) in main_config_module.PAYLOAD_PLACEHOLDERS.items():
                if placeholder in processed_parameters:
                    full_path = os.path.join(self.base_path, rel_path)
                    full_path = os.path.normpath(full_path)
                    processed_parameters = processed_parameters.replace(
                        placeholder, full_path
                    )
                    LOG.debug(
                        f"Replaced placeholder '{placeholder}' with path '{full_path}'"
                    )
            return processed_parameters
        except ImportError:
            LOG.warning("Could not import config module for placeholder replacement")
            return parameters_str
        except Exception as e:
            LOG.error(f"Error replacing parameters in '{parameters_str}': {e}")
            return parameters_str

    async def start_tool(self, tool_name: str, strategy_args: str = "") -> bool:
        """
        Запускает внешний инструмент с заданной стратегией.

        Args:
            tool_name: Имя инструмента (zapret, goodbyedpi)
            strategy_args: Строка с аргументами стратегии

        Returns:
            True если инструмент успешно запущен
        """
        async with self._lock:
            if tool_name not in self.tools:
                LOG.error(f"Unknown tool: {tool_name}")
                return False
            tool_instance = self.tools[tool_name]
            if tool_instance.status == ToolStatus.RUNNING:
                LOG.warning(f"Tool {tool_name} is already running")
                return True
            if tool_instance.config.requires_admin and (not self._check_admin_rights()):
                LOG.error(f"Tool {tool_name} requires administrator privileges")
                return False
            try:
                tool_instance.status = ToolStatus.STARTING
                processed_args = self._replace_placeholders(strategy_args)
                strategy_list = processed_args.split() if processed_args else []
                full_args = tool_instance.config.base_args + strategy_list
                if tool_instance.config.proxy_port:
                    full_args.extend(
                        [f"--http-proxy=127.0.0.1:{tool_instance.config.proxy_port}"]
                    )
                if tool_instance.config.dns_port:
                    full_args.extend(
                        [f"--dns-proxy=127.0.0.1:{tool_instance.config.dns_port}"]
                    )
                LOG.info(f"Starting {tool_name} with args: {' '.join(full_args)}")
                tool_instance.process = subprocess.Popen(
                    [tool_instance.config.executable_path] + full_args,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    cwd=os.path.dirname(tool_instance.config.executable_path),
                )
                tool_instance.pid = tool_instance.process.pid
                tool_instance.start_time = time.time()
                tool_instance.strategy_args = strategy_list
                await asyncio.sleep(tool_instance.config.startup_delay)
                if tool_instance.process.poll() is not None:
                    LOG.error(f"Tool {tool_name} terminated immediately after start")
                    tool_instance.status = ToolStatus.ERROR
                    return False
                tool_instance.status = ToolStatus.RUNNING
                LOG.info(
                    f"Tool {tool_name} started successfully with PID: {tool_instance.pid}"
                )
                return True
            except Exception as e:
                LOG.exception(f"Failed to start tool {tool_name}: {e}")
                tool_instance.status = ToolStatus.ERROR
                return False

    async def stop_tool(self, tool_name: str) -> bool:
        """
        Останавливает внешний инструмент.

        Args:
            tool_name: Имя инструмента для остановки

        Returns:
            True если инструмент успешно остановлен
        """
        async with self._lock:
            if tool_name not in self.tools:
                LOG.error(f"Unknown tool: {tool_name}")
                return False
            tool_instance = self.tools[tool_name]
            if tool_instance.status != ToolStatus.RUNNING or not tool_instance.process:
                LOG.warning(f"Tool {tool_name} is not running")
                return True
            try:
                tool_instance.status = ToolStatus.STOPPING
                LOG.info(f"Stopping tool {tool_name} (PID: {tool_instance.pid})")
                if platform.system() == "Windows":
                    try:
                        subprocess.run(
                            ["taskkill", "/F", "/T", "/PID", str(tool_instance.pid)],
                            capture_output=True,
                            check=False,
                            timeout=tool_instance.config.shutdown_timeout,
                        )
                        tool_instance.process.wait(
                            timeout=tool_instance.config.shutdown_timeout
                        )
                    except subprocess.TimeoutExpired:
                        LOG.warning(f"Timeout stopping {tool_name}, killing forcefully")
                        tool_instance.process.kill()
                else:
                    tool_instance.process.terminate()
                    try:
                        tool_instance.process.wait(
                            timeout=tool_instance.config.shutdown_timeout
                        )
                    except subprocess.TimeoutExpired:
                        LOG.warning(f"Timeout stopping {tool_name}, killing forcefully")
                        tool_instance.process.kill()
                tool_instance.process = None
                tool_instance.pid = None
                tool_instance.start_time = None
                tool_instance.strategy_args = None
                tool_instance.status = ToolStatus.STOPPED
                LOG.info(f"Tool {tool_name} stopped successfully")
                return True
            except Exception as e:
                LOG.exception(f"Error stopping tool {tool_name}: {e}")
                tool_instance.status = ToolStatus.ERROR
                return False

    async def stop_all_tools(self) -> bool:
        """Останавливает все запущенные инструменты"""
        success = True
        for tool_name in list(self.tools.keys()):
            if not await self.stop_tool(tool_name):
                success = False
        return success

    def get_tool_status(self, tool_name: str) -> Optional[ToolStatus]:
        """Получает статус инструмента"""
        if tool_name not in self.tools:
            return None
        return self.tools[tool_name].status

    def get_running_tools(self) -> List[str]:
        """Получает список запущенных инструментов"""
        return [
            name
            for name, instance in self.tools.items()
            if instance.status == ToolStatus.RUNNING
        ]

    def is_tool_available(self, tool_name: str) -> bool:
        """Проверяет доступность инструмента"""
        return tool_name in self.tools and os.path.exists(
            self.tools[tool_name].config.executable_path
        )

    def get_available_tools(self) -> List[str]:
        """Получает список доступных инструментов"""
        return [name for name in self.tools.keys() if self.is_tool_available(name)]

    def get_tool_info(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Получает информацию об инструменте"""
        if tool_name not in self.tools:
            return None
        instance = self.tools[tool_name]
        return {
            "name": instance.config.name,
            "executable_path": instance.config.executable_path,
            "status": instance.status.value,
            "pid": instance.pid,
            "start_time": instance.start_time,
            "proxy_port": instance.config.proxy_port,
            "dns_port": instance.config.dns_port,
            "requires_admin": instance.config.requires_admin,
            "strategy_args": instance.strategy_args,
        }

    async def restart_tool(self, tool_name: str, strategy_args: str = "") -> bool:
        """Перезапускает инструмент с новой стратегией"""
        await self.stop_tool(tool_name)
        await asyncio.sleep(0.5)
        return await self.start_tool(tool_name, strategy_args)

    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - останавливаем все инструменты"""
        await self.stop_all_tools()