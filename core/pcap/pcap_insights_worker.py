import asyncio
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime

try:
    from scapy.all import rdpcap, IP, TCP, UDP, Raw, ICMP

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
from core.knowledge_base import CdnAsnKnowledgeBase
from core.bypass.types import BlockType

LOG = logging.getLogger("PcapInsightsWorker")


class PcapInsightsWorker:
    """
    Worker для анализа PCAP-файлов с фиксацией причин сбоя в CdnAsnKnowledgeBase.
    Поддерживает как одиночный анализ файла, так и фоновый просмотр директории.
    """

    def __init__(self, pcap_dir: str = "pcap_failures", kb: Optional[CdnAsnKnowledgeBase] = None):
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for PCAP insights worker. pip install scapy")
        self.dir = Path(pcap_dir)
        self.dir.mkdir(exist_ok=True)
        self.kb = kb or CdnAsnKnowledgeBase()
        self._seen: set[Path] = set()

    async def run(self, interval: float = 10.0):
        """Фоновый режим: раз в interval секунд анализировать новые PCAP в директории."""
        LOG.info(f"PcapInsightsWorker started, watching '{self.dir}'")
        try:
            while True:
                try:
                    for p in sorted(self.dir.glob("failure_*.pcap")):
                        if p in self._seen:
                            continue
                        try:
                            insight = self.analyze_file(p)
                            if insight:
                                self._update_kb_from_insight(insight)
                        except Exception as e:
                            LOG.warning(f"PCAP insight failed for {p.name}: {e}")
                        self._seen.add(p)
                except Exception as e:
                    LOG.error(f"Worker error: {e}")

                try:
                    await asyncio.sleep(interval)
                except asyncio.CancelledError:
                    LOG.info("PcapInsightsWorker cancelled, shutting down gracefully")
                    break
        except asyncio.CancelledError:
            LOG.info("PcapInsightsWorker cancelled during processing")
        finally:
            LOG.info("PcapInsightsWorker stopped")

    def analyze_file(self, pcap_path: str | Path) -> Optional[Dict[str, Any]]:
        """Анализ одного PCAP-файла. Возвращает insight dict или None."""
        pcap_path = Path(pcap_path)
        if not pcap_path.exists():
            LOG.warning(f"PCAP not found: {pcap_path}")
            return None
        LOG.info(f"Analyzing PCAP: {pcap_path.name}")

        try:
            pkts = rdpcap(str(pcap_path))
        except Exception as e:
            LOG.error(f"rdpcap failed: {e}")
            return None

        rst_ttls = []
        tls_alerts = 0
        icmp_unreach = 0
        server_ip = None
        first_ts = None
        last_ts = None

        for pkt in pkts:
            try:
                ts = getattr(pkt, "time", None)
                if ts is not None:
                    first_ts = first_ts or ts
                    last_ts = ts
                if IP in pkt and TCP in pkt:
                    if pkt[TCP].flags & 0x04:  # RST
                        rst_ttls.append(int(pkt[IP].ttl))
                        server_ip = pkt[IP].src
                    if Raw in pkt:
                        payload = bytes(pkt[Raw])
                        if len(payload) > 0 and payload[0] == 0x15:  # TLS Alert
                            tls_alerts += 1
                if IP in pkt and ICMP in pkt:
                    # ICMP destination unreachable
                    if int(pkt[ICMP].type) == 3:
                        icmp_unreach += 1
                        server_ip = pkt[IP].src
            except Exception:
                continue

        block_type = None
        details: Dict[str, Any] = {}
        if rst_ttls:
            avg_ttl = sum(rst_ttls) / len(rst_ttls)
            details["rst_avg_ttl"] = avg_ttl
            # простая эвристика
            block_type = BlockType.RST_INJECTION
        elif tls_alerts > 0:
            block_type = BlockType.TLS_ALERT
            details["tls_alert_count"] = tls_alerts
        elif icmp_unreach > 0:
            block_type = BlockType.ICMP_UNREACH
            details["icmp_unreach_count"] = icmp_unreach
        else:
            return None

        # Извлечь домен из имени: failure_{domain}_{error}_{timestamp}.pcap
        domain = "unknown"
        try:
            name = pcap_path.stem
            parts = name.split("_")
            # failure_{domain}_{errorType}_{timestamp}
            if len(parts) >= 4:
                domain = parts[1]
        except Exception:
            pass

        insight = {
            "domain": domain,
            "ip": server_ip or "",
            "block_type": block_type,
            "details": details,
            "pcap": str(pcap_path),
            "timestamp": datetime.now().isoformat(),
        }
        return insight

    def _update_kb_from_insight(self, insight: Dict[str, Any]):
        """Запись инсайта в KB (как неудачный результат с типом блокировки)."""
        try:
            self.kb.update_with_result(
                domain=insight.get("domain", ""),
                ip=insight.get("ip", ""),
                strategy={"raw": "unknown"},  # не знаем стратегию из одного PCAP
                success=False,
                block_type=(insight.get("block_type") or BlockType.UNKNOWN),
                latency_ms=0.0,
            )
            self.kb.save()
            LOG.info(
                f"KB updated with PCAP insight for {insight.get('domain')}: {insight.get('block_type')}"
            )
        except Exception as e:
            LOG.warning(f"KB update failed for PCAP insight: {e}")
