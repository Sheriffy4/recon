from collections import defaultdict
import time
from typing import Dict, List, Optional, Any, Tuple, Set
import logging

try:
    from scapy.all import TCP, Raw, wrpcap, rdpcap

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class StrategyMetricsCollector:
    """Collects detailed metrics for strategy testing with connection tracking."""

    def __init__(self, strategy_id: str):
        self.id = strategy_id
        self.connections = {}
        self.start = time.time()

    def start_conn(self, domain: str, ip: str):
        self.connections[domain] = {
            "ip": ip,
            "start": time.time(),
            "sent": 0,
            "recv": 0,
            "success": False,
            "events": [],
        }
        self.connections[domain]["events"].append(("start", time.time()))

    def sent(self, domain: str, n: int):
        self._mark(domain, "sent", n)

    def recv(self, domain: str, n: int):
        self._mark(domain, "recv", n)

    def ok(self, domain: str):
        self._mark(domain, "ok", 0, success=True)

    def fail(self, domain: str, reason: str):
        self._mark(domain, f"fail:{reason}", 0)

    def _mark(self, domain: str, event: str, n: int, success: bool = False):
        c = self.connections.get(domain)
        if not c:
            return
        if event == "sent":
            c["sent"] += n
        elif event == "recv":
            c["recv"] += n
        if success:
            c["success"] = True
        c["events"].append((event, time.time(), n))

    def agg(self) -> Dict[str, Any]:
        total = len(self.connections)
        ok = sum(1 for c in self.connections.values() if c["success"])
        return {
            "total_connections": total,
            "successful_connections": ok,
            "success_rate": ok / total if total else 0.0,
            "total_data_sent": sum(c["sent"] for c in self.connections.values()),
            "total_data_received": sum(c["recv"] for c in self.connections.values()),
            "duration": time.time() - self.start,
        }

    def per_domain(self) -> Dict[str, Dict[str, Any]]:
        out = {}
        for domain, c in self.connections.items():
            out[domain] = {
                "success": c["success"],
                "ip": c["ip"],
                "data_transferred": c["sent"] + c["recv"],
                "latency_ms": (
                    (c["events"][-1][1] - c["events"][0][1]) * 1000
                    if len(c["events"]) > 1
                    else 0
                ),
            }
        return out


class EnhancedPacketCapturer:
    """
    Enhanced packet capturer with strategy-to-packet correlation + offline analysis by time windows.
    """

    def __init__(
        self,
        pcap_file: str = "",
        bpf: Optional[str] = None,
        interface: Optional[str] = None,
        max_packets: int = 0,
        max_seconds: int = 0,
    ):
        self.pcap_file = pcap_file
        self.bpf = bpf
        self.interface = interface
        self.max_packets = max_packets
        self.max_seconds = max_seconds
        self.strategy_markers: Dict[float, Tuple[str, str]] = {}
        self.current_strategy: Optional[str] = None
        self.strategy_packets = defaultdict(list)  # strategy_id -> [packet_indices]
        self.packets = []  # stored scapy packets
        self.running = False
        self._start_time = None
        self._windows: List[Tuple[float, float, str]] = []
        self.logger = logging.getLogger("EnhancedPacketCapturer")

    # Online correlation (marking windows)
    def mark_strategy_start(self, strategy_id: str):
        ts = time.time()
        self.strategy_markers[ts] = ("start", strategy_id)
        self.current_strategy = strategy_id
        self._windows.append([ts, None, strategy_id])

    def mark_strategy_end(self, strategy_id: str):
        ts = time.time()
        self.strategy_markers[ts] = ("end", strategy_id)
        self.current_strategy = None
        for w in reversed(self._windows):
            if w[2] == strategy_id and w[1] is None:
                w[1] = ts
                break

    # Simple live-callback storage (for future live sniff)
    def _packet_callback(self, packet):
        if not SCAPY_AVAILABLE:
            return
        self.packets.append(packet)
        idx = len(self.packets) - 1
        if self.current_strategy:
            self.strategy_packets[self.current_strategy].append(idx)

    def start(self):
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for enhanced packet capture")
        self.running = True
        self._start_time = time.time()
        # Note: live sniff left as TODO; current mode relies on offline analysis of written PCAP

    def stop(self):
        self.running = False
        if SCAPY_AVAILABLE and self.packets and self.pcap_file:
            try:
                wrpcap(self.pcap_file, self.packets)
            except Exception as e:
                self.logger.warning(f"Failed to write PCAP file: {e}")

    def get_capture_stats(self) -> Dict[str, Any]:
        return {
            "total_packets": len(self.packets),
            "strategies_tested": len(self.strategy_packets),
            "capture_duration": time.time() - (self._start_time or time.time()),
            "pcap_file": self.pcap_file,
        }

    def analyze_all_strategies(self) -> Dict[str, Dict[str, Any]]:
        if not SCAPY_AVAILABLE:
            return {"error": "Scapy not available"}
        out = {}
        for sid in self.strategy_packets.keys():
            out[sid] = self.get_strategy_packets(sid)
        return out

    # Per-strategy analysis for captured packets (by indices)
    def get_strategy_packets(self, strategy_id: str) -> Dict[str, Any]:
        if not SCAPY_AVAILABLE:
            return {"error": "Scapy not available"}
        idxs = self.strategy_packets.get(strategy_id, [])
        if not idxs:
            return {"total_packets": 0}
        pkts = [self.packets[i] for i in idxs if i < len(self.packets)]
        return _analyze_packets(pkts)

    # Build time windows from markers
    def _get_strategy_windows(self) -> List[Tuple[str, float, float]]:
        events = sorted(self.strategy_markers.items(), key=lambda kv: kv[0])
        windows: List[Tuple[str, float, float]] = []
        open_map: Dict[str, float] = {}
        last_ts = time.time()
        for ts, (ev, sid) in events:
            last_ts = max(last_ts, ts)
            if ev == "start":
                open_map[sid] = ts
            elif ev == "end":
                st = open_map.pop(sid, None)
                if st is not None and ts > st:
                    windows.append((sid, st, ts))
        for sid, st in open_map.items():
            windows.append((sid, st, last_ts))
        return windows

    # Offline analysis by time windows (for finished PCAPs)
    def analyze_pcap_file(
        self, pcap_file: Optional[str] = None
    ) -> Dict[str, Dict[str, Any]]:
        if not SCAPY_AVAILABLE:
            return {"error": "Scapy not available"}
        path = pcap_file or getattr(self, "pcap_file", "")
        if not path:
            return {"error": "pcap_file is empty"}
        try:
            pkts = rdpcap(path)
        except Exception as e:
            return {"error": f"Failed to read pcap: {e}"}
        windows = self._get_strategy_windows() or [("all", float("-inf"), float("inf"))]
        res: Dict[str, Dict[str, Any]] = {}
        for sid, _, _ in windows:
            res[sid] = {
                "total_packets": 0,
                "syn_packets": 0,
                "rst_packets": 0,
                "tls_clienthellos": 0,
                "tls_serverhellos": 0,
                "data_packets": 0,
                "total_bytes": 0,
                "success_indicator": False,
                "success_score": 0.0,
            }
        for pkt in pkts:
            try:
                ts = float(getattr(pkt, "time", 0.0))
            except Exception:
                ts = 0.0
            for sid, st, en in windows:
                if st <= ts <= en:
                    r = res[sid]
                    r["total_packets"] += 1
                    try:
                        if TCP in pkt:
                            flags = pkt[TCP].flags
                            if flags & 0x02:
                                r["syn_packets"] += 1
                            if flags & 0x04:
                                r["rst_packets"] += 1
                            if Raw in pkt:
                                payload = bytes(pkt[Raw].load)
                                if payload:
                                    r["data_packets"] += 1
                                    r["total_bytes"] += len(payload)
                                    if len(payload) > 5 and payload[0] == 0x16:
                                        if payload[5] == 0x01:
                                            r["tls_clienthellos"] += 1
                                        elif payload[5] == 0x02:
                                            r["tls_serverhellos"] += 1
                    except Exception:
                        pass
                    break
        for sid, r in res.items():
            r["success_indicator"] = r["tls_serverhellos"] > 0
            ch = max(1, r["tls_clienthellos"])
            r["success_score"] = r["tls_serverhellos"] / ch
        return res

    def analyze_all_strategies_offline(
        self, pcap_file: str, window_slack: float = 0.5
    ) -> Dict[str, Dict[str, Any]]:
        # Backward-compatible wrapper retained for callers
        return self.analyze_pcap_file(pcap_file)

    def trigger_pcap_analysis(self, force: bool = False) -> Dict[str, Dict[str, Any]]:
        try:
            return self.analyze_pcap_file(getattr(self, "pcap_file", None))
        except Exception as e:
            self.logger.debug(f"trigger_pcap_analysis failed: {e}")
            return {"error": str(e)}


def _analyze_packets(pkts) -> Dict[str, Any]:
    tls_clienthellos = tls_serverhellos = rst_packets = data_packets = total_bytes = (
        syn_packets
    ) = 0
    for pkt in pkts:
        if TCP in pkt:
            flags = pkt[TCP].flags
            if flags & 0x02:
                syn_packets += 1
            if flags & 0x04:
                rst_packets += 1
            if Raw in pkt:
                payload = bytes(pkt[Raw].load)
                if payload:
                    data_packets += 1
                    total_bytes += len(payload)
                    if len(payload) > 5 and payload[0] == 0x16:
                        if payload[5] == 0x01:
                            tls_clienthellos += 1
                        elif payload[5] == 0x02:
                            tls_serverhellos += 1
    success_indicator = tls_serverhellos > 0
    return {
        "total_packets": len(pkts),
        "tcp_handshakes": syn_packets,
        "tls_clienthellos": tls_clienthellos,
        "tls_serverhellos": tls_serverhellos,
        "rst_packets": rst_packets,
        "data_packets": data_packets,
        "total_bytes": total_bytes,
        "success_indicator": success_indicator,
        "success_score": tls_serverhellos / max(1, tls_clienthellos),
    }


def create_enhanced_packet_capturer(
    pcap_file: str,
    target_ips: Set[str],
    port: int = 443,
    interface: Optional[str] = None,
) -> EnhancedPacketCapturer:
    """
    Factory function to create enhanced packet capturer with appropriate BPF filter.
    """
    ip_list = list(target_ips)[:20]
    if not ip_list:
        bpf = f"tcp port {port} or udp port {port}"
    else:
        clauses = [f"(host {ip} and port {port})" for ip in ip_list if ip]
        bpf = " or ".join(clauses) if clauses else f"tcp port {port}"
    return EnhancedPacketCapturer(
        pcap_file=pcap_file,
        bpf=bpf,
        interface=interface,
        max_packets=10000,
        max_seconds=300,
    )
