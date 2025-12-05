"""
PCAPValidator - PCAP analysis and attack detection.

This module implements PCAP validation with:
- Loading and parsing PCAP files with Scapy
- Grouping packets into TCP streams
- Reassembling fragmented ClientHello packets
- Extracting TLS fields (SNI, versions, extensions)
- Detecting applied attacks (fake, split, disorder)

Requirements: 3.1, 3.3, 3.4, 3.5, 8.1
"""

import logging
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .clienthello_parser import ClientHelloParser, ClientHelloInfo
from .attack_detector import AttackDetector, DetectedAttacks

try:
    from ..metrics.attack_parity_metrics import get_metrics_collector
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class TCPStream:
    """Represents a TCP stream."""
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    packets: List[Any] = field(default_factory=list)

    def key(self) -> Tuple[str, int, str, int]:
        """Return stream key for identification."""
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port)


class PCAPValidator:
    """
    PCAP validator for analyzing network captures and detecting attacks.
    
    Requirements: 3.1, 3.3, 3.4, 3.5, 8.1
    """

    def __init__(self):
        """Initialize PCAP validator."""
        self.streams: Dict[Tuple, TCPStream] = {}
        self.clienthello_cache: Dict[Tuple, bytes] = {}
        self.parser = ClientHelloParser()
        self.detector = AttackDetector()

    def load_pcap(self, path: str) -> List[Any]:
        """Load packets from PCAP file using Scapy."""
        start_time = time.time()
        validation_success = False
        error_type = None
        error_message = None
        packets_count = 0
        
        try:
            from scapy.all import rdpcap
        except ImportError:
            error_type = "ImportError"
            error_message = "Scapy not installed"
            logger.error(error_message)
            self._record_validation_metric(path, validation_success, error_type, error_message, 
                                          packets_count, 0, False, time.time() - start_time)
            return []

        pcap_path = Path(path)
        if not pcap_path.exists():
            error_type = "FileNotFoundError"
            error_message = f"PCAP file not found: {path}"
            self._record_validation_metric(path, validation_success, error_type, error_message,
                                          packets_count, 0, False, time.time() - start_time)
            raise FileNotFoundError(error_message)

        try:
            packets = rdpcap(str(pcap_path))
            packets_count = len(packets)
            validation_success = True
            logger.info(f"Loaded {packets_count} packets from {path}")
            self._record_validation_metric(path, validation_success, error_type, error_message,
                                          packets_count, 0, False, time.time() - start_time)
            return list(packets)
        except Exception as e:
            error_type = type(e).__name__
            error_message = str(e)
            logger.error(f"Failed to load PCAP: {e}")
            self._record_validation_metric(path, validation_success, error_type, error_message,
                                          packets_count, 0, False, time.time() - start_time)
            raise

    def find_streams(self, packets: List[Any], target_ip: Optional[str] = None) -> List[TCPStream]:
        """Group packets into TCP streams."""
        try:
            from scapy.all import IP, TCP
        except ImportError:
            return []

        streams_dict: Dict[Tuple, TCPStream] = {}

        for pkt in packets:
            if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
                continue

            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]

            if target_ip and ip_layer.dst != target_ip and ip_layer.src != target_ip:
                continue

            key1 = (ip_layer.src, tcp_layer.sport, ip_layer.dst, tcp_layer.dport)
            key2 = (ip_layer.dst, tcp_layer.dport, ip_layer.src, tcp_layer.sport)

            if key1 in streams_dict:
                stream_key = key1
            elif key2 in streams_dict:
                stream_key = key2
            else:
                stream_key = key1
                streams_dict[stream_key] = TCPStream(
                    src_ip=ip_layer.src,
                    src_port=tcp_layer.sport,
                    dst_ip=ip_layer.dst,
                    dst_port=tcp_layer.dport
                )

            streams_dict[stream_key].packets.append(pkt)

        return list(streams_dict.values())


    def reassemble_clienthello(self, stream: TCPStream) -> Optional[bytes]:
        """Reassemble fragmented ClientHello from TCP stream."""
        try:
            from scapy.all import TCP, Raw
        except ImportError:
            return None

        cache_key = stream.key()
        if cache_key in self.clienthello_cache:
            return self.clienthello_cache[cache_key]

        tcp_packets = []
        for pkt in stream.packets:
            if pkt.haslayer(TCP):
                # Skip fake packets (low TTL <= 3) during reassembly
                # Fake packets are decoys and should not be part of the real ClientHello
                try:
                    from scapy.all import IP
                    if pkt.haslayer(IP) and pkt[IP].ttl <= 3:
                        logger.debug(f"Skipping fake packet with TTL={pkt[IP].ttl} during reassembly")
                        continue
                except:
                    pass
                
                # Check if packet has payload (either in Raw layer or TCP payload)
                tcp_layer = pkt[TCP]
                has_payload = (pkt.haslayer(Raw) or 
                             (tcp_layer.payload and len(bytes(tcp_layer.payload)) > 0))
                if has_payload:
                    tcp_packets.append(pkt)
                    logger.debug(f"Found TCP packet with payload: seq={tcp_layer.seq}, has_Raw={pkt.haslayer(Raw)}, payload_len={len(bytes(tcp_layer.payload)) if tcp_layer.payload else 0}")

        if not tcp_packets:
            logger.debug(f"No TCP packets with payload found in stream")
            return None
        
        logger.debug(f"Found {len(tcp_packets)} TCP packets with payload for reassembly")

        tcp_packets.sort(key=lambda p: p[TCP].seq)

        reassembled = b""
        expected_seq = None

        for pkt in tcp_packets:
            tcp_layer = pkt[TCP]
            # Get payload from Raw layer if available, otherwise from TCP payload
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
            else:
                payload = bytes(tcp_layer.payload)

            if expected_seq is None:
                expected_seq = tcp_layer.seq

            if tcp_layer.seq == expected_seq:
                reassembled += payload
                expected_seq += len(payload)
            elif tcp_layer.seq < expected_seq:
                overlap = expected_seq - tcp_layer.seq
                if overlap < len(payload):
                    reassembled += payload[overlap:]
                    expected_seq += len(payload) - overlap

        clienthello_data = None
        offset = 0

        while offset < len(reassembled) - 5:
            if reassembled[offset] == 0x16:
                record_len = struct.unpack(">H", reassembled[offset+3:offset+5])[0]
                if offset + 5 < len(reassembled) and reassembled[offset+5] == 0x01:
                    total_len = 5 + record_len
                    if offset + total_len <= len(reassembled):
                        clienthello_data = reassembled[offset:offset+total_len]
                        break
                offset += 5 + record_len
            else:
                offset += 1

        if clienthello_data:
            self.clienthello_cache[cache_key] = clienthello_data

        return clienthello_data


    def parse_clienthello(self, data: bytes) -> ClientHelloInfo:
        """
        Parse ClientHello and extract all TLS fields.
        
        Delegates to ClientHelloParser for actual parsing.
        """
        return self.parser.parse(data)


    def detect_attacks(self, stream: TCPStream, sni_offset: Optional[int] = None) -> DetectedAttacks:
        """
        Detect applied attacks in TCP stream.
        
        Delegates to AttackDetector for actual detection logic.
        """
        try:
            from scapy.all import TCP, Raw
        except ImportError:
            return DetectedAttacks()

        # Get packets with payload
        data_packets = []
        for pkt in stream.packets:
            if pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                # Check if packet has payload (either in Raw layer or TCP payload)
                has_payload = (pkt.haslayer(Raw) or 
                             (tcp_layer.payload and len(bytes(tcp_layer.payload)) > 0))
                if has_payload:
                    data_packets.append(pkt)

        if not data_packets:
            return DetectedAttacks()

        # Delegate to AttackDetector
        detected = self.detector.detect_attacks(data_packets, sni_offset)
        
        # Record attack detection metrics
        if METRICS_AVAILABLE:
            try:
                collector = get_metrics_collector()
                
                # Record fake detection
                if detected.fake:
                    collector.record_attack_detection(
                        attack_type='fake',
                        total_attempts=1,
                        successful_detections=1,
                        failed_detections=0,
                        average_confidence=1.0
                    )
                
                # Record split detection
                if detected.split:
                    attack_type = 'multisplit' if detected.fragment_count > 2 else 'split'
                    collector.record_attack_detection(
                        attack_type=attack_type,
                        total_attempts=1,
                        successful_detections=1,
                        failed_detections=0,
                        average_confidence=1.0
                    )
                
                # Record disorder detection
                if detected.disorder:
                    collector.record_attack_detection(
                        attack_type='disorder',
                        total_attempts=1,
                        successful_detections=1,
                        failed_detections=0,
                        average_confidence=1.0
                    )
            except Exception as e:
                logger.warning(f"Failed to record detection metrics: {e}")
        
        return detected
    
    def _record_validation_metric(self, pcap_file: str, validation_success: bool,
                                  error_type: Optional[str], error_message: Optional[str],
                                  packets_analyzed: int, streams_found: int,
                                  clienthello_found: bool, elapsed_time: float):
        """Record PCAP validation metric."""
        if METRICS_AVAILABLE:
            try:
                collector = get_metrics_collector()
                collector.record_pcap_validation(
                    pcap_file=pcap_file,
                    validation_success=validation_success,
                    error_type=error_type,
                    error_message=error_message,
                    packets_analyzed=packets_analyzed,
                    streams_found=streams_found,
                    clienthello_found=clienthello_found,
                    validation_time_ms=elapsed_time * 1000
                )
            except Exception as e:
                logger.warning(f"Failed to record validation metric: {e}")
