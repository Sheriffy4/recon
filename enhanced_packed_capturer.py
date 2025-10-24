from collections import defaultdict
import time
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

try:
    from scapy.all import TCP, Raw, rdpcap

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class EnhancedPacketCapturer:
    def __init__(
        self,
        pcap_file: str = "",
        bpf: Optional[str] = None,
        interface: Optional[str] = None,
    ):
        self.pcap_file = pcap_file
        self.bpf = bpf
        self.interface = interface
        self.strategy_markers = {}
        self.current_strategy = None
        self._windows: List[Tuple[float, float, str]] = []
        self.strategy_packets = defaultdict(list)
        self.packets = []

    def mark_strategy_start(self, strategy_id: str):
        timestamp = time.time()
        self.strategy_markers[timestamp] = ("start", strategy_id)
        self.current_strategy = strategy_id
        self._windows.append([timestamp, None, strategy_id])

    def mark_strategy_end(self, strategy_id: str):
        timestamp = time.time()
        self.strategy_markers[timestamp] = ("end", strategy_id)
        self.current_strategy = None
        for w in reversed(self._windows):
            if w[2] == strategy_id and (w[1] is None):
                w[1] = timestamp
                break

    def analyze_all_strategies(self) -> Dict[str, Dict[str, Any]]:
        analysis = {}
        for strategy_id in self.strategy_packets.keys():
            analysis[strategy_id] = {
                "total_packets": len(self.strategy_packets[strategy_id])
            }
        return analysis

    def analyze_all_strategies_offline(
        self, pcap_file: str, window_slack: float = 0.5
    ) -> Dict[str, Dict[str, Any]]:
        """
        Offline-анализ PCAP по временным окнам стратегий (между mark_strategy_start/end).
        Считывает готовый PCAP и считает CH/SH/RST в окнах. Возвращает словарь по стратегиям.
        """
        if not SCAPY_AVAILABLE:
            return {}
        pcap_path = Path(pcap_file)
        if not pcap_path.exists():
            return {}
        now_ts = time.time()
        norm_windows: List[Tuple[float, float, str]] = []
        for w in self._windows:
            start_ts = float(w[0])
            end_ts = float(w[1] if w[1] else now_ts)
            sid = w[2]
            norm_windows.append(
                (max(0.0, start_ts - window_slack), end_ts + window_slack, sid)
            )
        if not norm_windows:
            return {}
        try:
            packets = rdpcap(str(pcap_path))
        except Exception:
            return {}
        result: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "total_packets": 0,
                "tls_clienthellos": 0,
                "tls_serverhellos": 0,
                "rst_packets": 0,
                "data_packets": 0,
                "total_bytes": 0,
                "success_score": 0.0,
            }
        )
        for pkt in packets:
            ts = float(getattr(pkt, "time", time.time()))
            for ws, we, sid in norm_windows:
                if ws <= ts <= we:
                    res = result[sid]
                    res["total_packets"] += 1
                    if TCP in pkt:
                        flags = int(pkt[TCP].flags)
                        if flags & 0x04:
                            res["rst_packets"] += 1
                        if Raw in pkt:
                            payload = bytes(pkt[Raw])
                            if len(payload) > 6 and payload[0] == 0x16:
                                hs_type = payload[5]
                                if hs_type == 0x01:
                                    res["tls_clienthellos"] += 1
                                elif hs_type == 0x02:
                                    res["tls_serverhellos"] += 1
                            res["data_packets"] += 1
                            res["total_bytes"] += len(payload)
                    break
        for sid, res in result.items():
            ch = max(1, res["tls_clienthellos"])
            res["success_score"] = res["tls_serverhellos"] / float(ch)
        result_sorted = dict(
            sorted(
                result.items(),
                key=lambda kv: kv[1].get("success_score", 0.0),
                reverse=True,
            )
        )
        return result_sorted
