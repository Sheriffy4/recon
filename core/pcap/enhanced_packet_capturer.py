from collections import defaultdict
import time
from typing import Dict, List, Optional, Any

try:
    from scapy.all import TCP, Raw, wrpcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class StrategyMetricsCollector:
    """
    Collects detailed metrics for strategy testing with connection tracking.
    """

    def __init__(self, strategy_id: str):
        self.id = strategy_id
        self.connections = {}
        self.start = time.time()

    def start_conn(self, domain: str, ip: str):
        """Start tracking a new connection."""
        self.connections[domain] = {
            "ip": ip,
            "start": time.time(),
            "sent": 0,
            "recv": 0,
            "success": False,
            "events": []
        }
        self.connections[domain]["events"].append(("start", time.time()))

    def sent(self, domain: str, n: int):
        """Record bytes sent for domain."""
        self._mark(domain, "sent", n)

    def recv(self, domain: str, n: int):
        """Record bytes received for domain."""
        self._mark(domain, "recv", n)

    def ok(self, domain: str):
        """Mark connection as successful."""
        self._mark(domain, "ok", 0, success=True)

    def fail(self, domain: str, reason: str):
        """Mark connection as failed with reason."""
        self._mark(domain, f"fail:{reason}", 0)

    def _mark(self, domain: str, event: str, n: int, success: bool = False):
        """Internal method to record event."""
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
        """Aggregate metrics for this strategy."""
        total = len(self.connections)
        ok = sum(1 for c in self.connections.values() if c["success"])
        
        return {
            "total_connections": total,
            "successful_connections": ok,
            "success_rate": ok / total if total else 0.0,
            "total_data_sent": sum(c["sent"] for c in self.connections.values()),
            "total_data_received": sum(c["recv"] for c in self.connections.values()),
            "duration": time.time() - self.start
        }

    def per_domain(self) -> Dict[str, Dict[str, Any]]:
        """Get per-domain breakdown."""
        out = {}
        for domain, c in self.connections.items():
            out[domain] = {
                "success": c["success"],
                "ip": c["ip"],
                "data_transferred": c["sent"] + c["recv"],
                "latency_ms": (c["events"][-1][1] - c["events"][0][1]) * 1000 if len(c["events"]) > 1 else 0
            }
        return out


class EnhancedPacketCapturer:
    """
    Enhanced packet capturer with strategy-to-packet correlation.
    
    Extends basic packet capture to track which strategy generated
    which packets, enabling detailed analysis of strategy effectiveness.
    """

    def __init__(self, pcap_file: str, bpf: Optional[str] = None, 
                 interface: Optional[str] = None, max_packets: int = 0, 
                 max_seconds: int = 0):
        """
        Initialize enhanced packet capturer.
        
        Args:
            pcap_file: Path to write PCAP file
            bpf: Berkeley Packet Filter string
            interface: Network interface to capture on
            max_packets: Maximum packets to capture (0 = unlimited)
            max_seconds: Maximum capture time (0 = unlimited)
        """
        self.pcap_file = pcap_file
        self.bpf = bpf
        self.interface = interface
        self.max_packets = max_packets
        self.max_seconds = max_seconds
        
        # Strategy correlation tracking
        self.strategy_markers = {}  # timestamp -> (event, strategy_id)
        self.current_strategy = None
        self.strategy_packets = defaultdict(list)  # strategy_id -> [packet_indices]
        self.packets = []  # All captured packets
        
        self.running = False
        self._start_time = None

    def mark_strategy_start(self, strategy_id: str):
        """Mark the start of testing a specific strategy."""
        timestamp = time.time()
        self.strategy_markers[timestamp] = ('start', strategy_id)
        self.current_strategy = strategy_id

    def mark_strategy_end(self, strategy_id: str):
        """Mark the end of testing a specific strategy."""
        timestamp = time.time()
        self.strategy_markers[timestamp] = ('end', strategy_id)
        self.current_strategy = None

    def _packet_callback(self, packet):
        """Callback for captured packets."""
        if not SCAPY_AVAILABLE:
            return
            
        # Store packet
        self.packets.append(packet)
        packet_index = len(self.packets) - 1
        
        # Associate with current strategy
        if self.current_strategy:
            self.strategy_packets[self.current_strategy].append(packet_index)

    def get_strategy_packets(self, strategy_id: str) -> Dict[str, Any]:
        """
        Get detailed analysis of packets captured during strategy testing.
        
        Args:
            strategy_id: Strategy identifier
            
        Returns:
            Dictionary with packet analysis results
        """
        if not SCAPY_AVAILABLE:
            return {"error": "Scapy not available for packet analysis"}
            
        packet_indices = self.strategy_packets.get(strategy_id, [])
        if not packet_indices:
            return {"total_packets": 0}
        
        packets = [self.packets[i] for i in packet_indices if i < len(self.packets)]
        
        # Analyze packets
        tls_clienthellos = 0
        tls_serverhellos = 0
        rst_packets = 0
        data_packets = 0
        total_bytes = 0
        syn_packets = 0
        
        for pkt in packets:
            if TCP in pkt:
                flags = pkt[TCP].flags
                
                # Count TCP flags
                if flags & 0x02:  # SYN
                    syn_packets += 1
                if flags & 0x04:  # RST
                    rst_packets += 1
                
                # Analyze payload
                if Raw in pkt:
                    payload = bytes(pkt[Raw])
                    if len(payload) > 5:
                        # TLS detection
                        if payload[0] == 0x16:  # TLS Handshake
                            if len(payload) > 5 and payload[5] == 0x01:  # ClientHello
                                tls_clienthellos += 1
                            elif len(payload) > 5 and payload[5] == 0x02:  # ServerHello
                                tls_serverhellos += 1
                    
                    total_bytes += len(payload)
                    data_packets += 1
        
        # Success indicator: received ServerHello means connection succeeded
        success_indicator = tls_serverhellos > 0
        
        return {
            "total_packets": len(packets),
            "tcp_handshakes": syn_packets,
            "tls_clienthellos": tls_clienthellos,
            "tls_serverhellos": tls_serverhellos,
            "rst_packets": rst_packets,
            "data_packets": data_packets,
            "total_bytes": total_bytes,
            "success_indicator": success_indicator,
            "success_score": tls_serverhellos / max(1, tls_clienthellos)  # ServerHello/ClientHello ratio
        }

    def start(self):
        """Start packet capture."""
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for enhanced packet capture")
            
        self.running = True
        self._start_time = time.time()
        
        # Note: This is a simplified implementation
        # Real implementation would use scapy.sniff() with proper threading
        
    def stop(self):
        """Stop packet capture and write PCAP file."""
        self.running = False
        
        if SCAPY_AVAILABLE and self.packets:
            try:
                wrpcap(self.pcap_file, self.packets)
            except Exception as e:
                print(f"Failed to write PCAP file: {e}")

    def get_capture_stats(self) -> Dict[str, Any]:
        """Get capture statistics."""
        return {
            "total_packets": len(self.packets),
            "strategies_tested": len(self.strategy_packets),
            "capture_duration": time.time() - (self._start_time or time.time()),
            "pcap_file": self.pcap_file
        }

    def analyze_all_strategies(self) -> Dict[str, Dict[str, Any]]:
        """Analyze packets for all tested strategies."""
        analysis = {}
        for strategy_id in self.strategy_packets.keys():
            analysis[strategy_id] = self.get_strategy_packets(strategy_id)
        return analysis


def create_enhanced_capturer(pcap_file: str, target_ips: set, port: int = 443) -> EnhancedPacketCapturer:
    """
    Factory function to create enhanced packet capturer with appropriate BPF filter.
    
    Args:
        pcap_file: Output PCAP file path
        target_ips: Set of target IP addresses
        port: Target port (default 443)
        
    Returns:
        Configured EnhancedPacketCapturer instance
    """
    # Build BPF filter for target IPs
    ip_list = list(target_ips)[:20]  # Limit to avoid filter complexity
    
    if not ip_list:
        bpf = f"tcp port {port} or udp port {port}"
    else:
        clauses = [f"(host {ip} and port {port})" for ip in ip_list if ip]
        bpf = " or ".join(clauses) if clauses else f"tcp port {port}"
    
    return EnhancedPacketCapturer(
        pcap_file=pcap_file,
        bpf=bpf,
        max_packets=10000,  # Reasonable limit
        max_seconds=300     # 5 minute max
    )