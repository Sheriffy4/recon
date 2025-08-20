# recon/core/bypass/engines/scapy_engine.py

import logging
import threading
from typing import Dict, Set, Optional, Any

try:
    import os
    import tempfile

    # Set Scapy cache directory to temp to avoid permission issues
    os.environ["SCAPY_CACHE_DIR"] = tempfile.gettempdir()

    from scapy.all import sniff, send, IP, TCP, Raw, conf

    SCAPY_AVAILABLE = True
except (ImportError, PermissionError, OSError) as e:
    SCAPY_AVAILABLE = False
    import logging

    logging.getLogger("ScapyEngine").warning(f"Scapy not available: {e}")

from .base import BaseBypassEngine, EngineConfig
from ..types import EngineStatus
from ..exceptions import EngineError

LOG = logging.getLogger("ScapyEngine")


class ScapyEngine(BaseBypassEngine):
    """
    Движок обхода на основе Scapy. Кросс-платформенный, но менее производительный,
    чем PyDivert. Идеален как fallback или для систем, отличных от Windows.
    """

    def __init__(self, config: Optional[EngineConfig] = None):
        super().__init__(config)
        if not SCAPY_AVAILABLE:
            raise EngineError("Scapy не установлен. ScapyEngine не может работать.")

        # Здесь также можно инициализировать AttackAdapter и другие компоненты
        # ...

    def _initialize_components(self) -> None:
        LOG.info("Инициализация компонентов ScapyEngine...")

    def start(
        self, target_ips: Set[str], strategy_map: Dict[str, Dict]
    ) -> Optional[threading.Thread]:
        """Запускает сниффер Scapy."""
        # ... (логика запуска, аналогичная PacketProcessingEngine) ...
        self._thread = threading.Thread(
            target=self._run, args=(target_ips, strategy_map), daemon=True
        )
        self._thread.start()
        return self._thread

    def stop(self) -> None:
        super().stop()

    def _run(self, target_ips: Set[str], strategy_map: Dict[str, Dict]) -> None:
        """Основной цикл Scapy sniff."""
        self._change_status(EngineStatus.RUNNING)

        def packet_callback(packet):
            if not self._running:
                # Scapy sniff не имеет простого способа остановки,
                # поэтому мы просто перестаем обрабатывать пакеты.
                return

            # ... (логика обработки пакета, аналогичная _should_process) ...
            # ... (вызов self.apply_strategy) ...

        # Собираем BPF фильтр
        filter_str = "tcp and port 443 and tcp[tcpflags] & (tcp-push|tcp-ack) != 0"

        try:
            sniff(
                filter=filter_str,
                prn=packet_callback,
                store=0,
                stop_filter=lambda p: not self._running,
            )
        except Exception as e:
            LOG.error(f"Ошибка в Scapy sniff: {e}")
        finally:
            self._change_status(EngineStatus.STOPPED)

    def apply_strategy(self, packet, w, strategy: Dict[str, Any]) -> None:
        # В ScapyEngine 'w' (хендл pydivert) не нужен, отправка идет через scapy.send
        # ... (логика применения стратегии и отправки через scapy.send) ...
        pass

    def _cleanup(self) -> None:
        LOG.info("Очистка ресурсов ScapyEngine...")
