"""
Автоматический сбор PCAP при неудачах для последующего анализа
"""

import threading
import logging
from pathlib import Path
from datetime import datetime
from collections import deque


class FailurePcapCollector:
    """Автоматический сборщик PCAP при неудачах"""

    def __init__(
        self,
        output_dir: str = "pcap_failures",
        capture_duration: int = 10,
        max_pcaps: int = 100,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.capture_duration = capture_duration
        self.max_pcaps = max_pcaps
        self.logger = logging.getLogger("PcapCollector")
        self.failure_queue = deque(maxlen=10)
        self.capturing = {}
        self.pcap_count = 0
        self._cleanup_old_pcaps()

    def _cleanup_old_pcaps(self):
        """Удаляет старые PCAP файлы если их слишком много"""
        pcaps = list(self.output_dir.glob("*.pcap"))
        if len(pcaps) > self.max_pcaps:
            pcaps.sort(key=lambda p: p.stat().st_mtime)
            for pcap in pcaps[: len(pcaps) - self.max_pcaps]:
                try:
                    pcap.unlink()
                    self.logger.info(f"Deleted old PCAP: {pcap.name}")
                except Exception as e:
                    self.logger.error(f"Failed to delete {pcap}: {e}")

    def trigger_capture(self, domain: str, error_type: str = "unknown"):
        """Запускает захват PCAP для домена с ошибкой"""
        if domain in self.capturing:
            self.logger.debug(f"Already capturing for {domain}")
            return
        self.failure_queue.append(
            {"domain": domain, "error_type": error_type, "timestamp": datetime.now()}
        )
        thread = threading.Thread(target=self._capture_pcap, args=(domain, error_type), daemon=True)
        thread.start()

    def _capture_pcap(self, domain: str, error_type: str):
        """Выполняет захват PCAP"""
        try:
            from scapy.all import sniff, PcapWriter
        except ImportError:
            self.logger.error("Scapy not available for PCAP capture")
            return
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"failure_{domain}_{error_type}_{timestamp}.pcap"
        self.capturing[domain] = True
        self.logger.info(f"Starting PCAP capture for {domain} -> {filename}")
        try:
            bpf = f"host {domain} or port 443 or port 80"
            writer = PcapWriter(str(filename), append=True, sync=True)

            def packet_handler(pkt):
                writer.write(pkt)

            sniff(
                filter=bpf,
                prn=packet_handler,
                store=False,
                timeout=self.capture_duration,
            )
            writer.close()
            self.pcap_count += 1
            file_size = filename.stat().st_size / 1024
            self.logger.info(f"PCAP capture completed: {filename.name} ({file_size:.1f} KB)")
        except Exception as e:
            self.logger.error(f"PCAP capture failed for {domain}: {e}")
        finally:
            del self.capturing[domain]
