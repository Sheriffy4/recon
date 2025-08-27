import asyncio
import pytest
import platform
from unittest.mock import patch, AsyncMock, MagicMock

# Добавляем корень проекта в путь, чтобы работали импорты
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.hybrid_engine import HybridEngine
if sys.platform == "win32":
    from core.bypass_engine import BypassEngine
else:
    BypassEngine = MagicMock()
from core.fingerprint.advanced_models import DPIType
# --- Моделирование зависимостей ---
# Нам не нужен полный фингерпринт для этого теста
class MockDPIFingerprint:
    def __init__(self, dpi_type="UNKNOWN"):
        # Set dpi_type as actual DPIType enum for realistic behavior
        self.dpi_type = getattr(DPIType, dpi_type, DPIType.UNKNOWN)
        
        # Add missing attributes to match real DPIFingerprint
        self.rst_injection_detected = False
        self.tcp_window_manipulation = False
        self.connection_reset_timing = 50.0  # Realistic default value (in ms)
        self.confidence = 0.8  # Add if needed for other parts

# --- Тестовый класс ---

@pytest.mark.skipif(sys.platform != "win32", reason="pydivert requires Windows")
@pytest.mark.asyncio
class TestHybridEngineIntegration:

    @pytest.fixture
    def hybrid_engine(self):
        """Фикстура для создания экземпляра HybridEngine."""
        return HybridEngine(debug=True, timeout=5.0)

    @patch('core.hybrid_engine.BypassEngine')
    async def test_real_world_strategy_execution_success(self, MockBypassEngine, hybrid_engine):
        """
        Тестирует успешное выполнение стратегии в реальном мире.
        Имитирует успешный запуск BypassEngine и успешный ответ от curl.
        """
        # --- 1. Подготовка (Arrange) ---

        # Мокаем BypassEngine, чтобы он не запускал pydivert
        mock_engine_instance = MockBypassEngine.return_value
        mock_engine_instance.start.return_value = MagicMock() # start возвращает поток
        mock_engine_instance.stop.return_value = None

        # Мокаем subprocess, который вызывает curl
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            # Настраиваем мок так, чтобы он имитировал успешный вывод curl
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            # Важно: stderr должен содержать "200 OK" для успешной проверки
            mock_proc.communicate.return_value = (b'', b'< HTTP/1.1 200 OK')
            mock_subprocess.return_value = mock_proc

            # Входные данные для теста
            strategy = "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3"
            test_sites = ["https://rutracker.org"]
            target_ips = {"104.21.32.39"}
            dns_cache = {"rutracker.org": "104.21.32.39"}
            port = 443
            fingerprint = MockDPIFingerprint(dpi_type="ROSKOMNADZOR_TSPU")

            # --- 2. Действие (Act) ---
            result_status, successful_count, total_count, avg_latency = await hybrid_engine.execute_strategy_real_world(
                strategy_str=strategy,
                test_sites=test_sites,
                target_ips=target_ips,
                dns_cache=dns_cache,
                target_port=port,
                fingerprint=fingerprint
            )

            # --- 3. Проверка (Assert) ---
            
            # Проверяем, что BypassEngine был запущен с правильными параметрами
            mock_engine_instance.start.assert_called_once()
            
            # ИЗМЕНЕНИЕ: Проверяем, что curl был вызван ХОТЯ БЫ ОДИН РАЗ с нужными параметрами
            # Это делает тест устойчивым к добавлению проверочных вызовов типа "curl --version"
            from unittest.mock import call
            
            expected_curl_call = call(
                'curl', '-v', '-sS', 
                '--connect-to', '::rutracker.org:443:104.21.32.39', 
                '--max-time', '5.0', 
                '-k', 
                '-o', 'NUL' if platform.system() == "Windows" else "/dev/null", 
                'https://rutracker.org',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Проверяем, что среди всех вызовов был и наш целевой вызов
            mock_subprocess.assert_any_call(*expected_curl_call.args, **expected_curl_call.kwargs)
            
            # Проверяем, что результат соответствует успешному выполнению
            assert result_status == "ALL_SITES_WORKING"
            assert successful_count == 1
            assert total_count == 1
            assert avg_latency > 0

            # Проверяем, что движок был остановлен
            mock_engine_instance.stop.assert_called_once()

    @patch('core.hybrid_engine.BypassEngine')
    async def test_real_world_strategy_execution_failure(self, MockBypassEngine, hybrid_engine):
        """
        Тестирует провальное выполнение стратегии.
        Имитирует, что curl завершился с ошибкой (таймаут).
        """
        # --- 1. Подготовка (Arrange) ---
        mock_engine_instance = MockBypassEngine.return_value
        mock_engine_instance.start.return_value = MagicMock()
        mock_engine_instance.stop.return_value = None

        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            # Настраиваем мок на имитацию таймаута curl
            mock_proc = AsyncMock()
            mock_proc.returncode = 28 # Код ошибки curl для таймаута
            mock_proc.communicate.return_value = (b'', b'curl: (28) Connection timed out')
            mock_subprocess.return_value = mock_proc

            # Изменяем strategy на валидную, которая транслируется (с fooling)
            strategy = "--dpi-desync=fake --dpi-desync-fooling=badsum"
            test_sites = ["https://rutracker.org"]
            target_ips = {"104.21.32.39"}
            dns_cache = {"rutracker.org": "104.21.32.39"}
            port = 443

            # --- 2. Действие (Act) ---
            result_status, successful_count, total_count, avg_latency = await hybrid_engine.execute_strategy_real_world(
                strategy_str=strategy,
                test_sites=test_sites,
                target_ips=target_ips,
                dns_cache=dns_cache,
                target_port=port
            )

            # --- 3. Проверка (Assert) ---
            assert result_status == "NO_SITES_WORKING"
            assert successful_count == 0
            assert total_count == 1