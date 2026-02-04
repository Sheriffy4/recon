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
import hashlib
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
        self.reassembly_stats: Dict[Tuple, Dict[str, Any]] = {}
        self._current_pcap_file: Optional[str] = None
        self.parser = ClientHelloParser()
        self.detector = AttackDetector()

    def load_pcap(self, path: str) -> List[Any]:
        """Load packets from PCAP file using Scapy."""
        start_time = time.time()
        validation_success = False
        error_type = None
        error_message = None
        packets_count = 0
        self._current_pcap_file = path

        try:
            from scapy.all import rdpcap
        except ImportError:
            error_type = "ImportError"
            error_message = "Scapy not installed"
            logger.error(error_message)
            self._record_validation_metric(
                path,
                validation_success,
                error_type,
                error_message,
                packets_count,
                0,
                False,
                time.time() - start_time,
            )
            return []

        pcap_path = Path(path)
        if not pcap_path.exists():
            error_type = "FileNotFoundError"
            error_message = f"PCAP file not found: {path}"
            self._record_validation_metric(
                path,
                validation_success,
                error_type,
                error_message,
                packets_count,
                0,
                False,
                time.time() - start_time,
            )
            raise FileNotFoundError(error_message)

        try:
            packets = rdpcap(str(pcap_path))
            packets_count = len(packets)
            validation_success = True
            logger.info(f"Loaded {packets_count} packets from {path}")
            self._record_validation_metric(
                path,
                validation_success,
                error_type,
                error_message,
                packets_count,
                0,
                False,
                time.time() - start_time,
            )
            return list(packets)
        except Exception as e:
            error_type = type(e).__name__
            error_message = str(e)
            logger.error(f"Failed to load PCAP: {e}")
            self._record_validation_metric(
                path,
                validation_success,
                error_type,
                error_message,
                packets_count,
                0,
                False,
                time.time() - start_time,
            )
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
                    dst_port=tcp_layer.dport,
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
                # Skip fake packets (low TTL <= 5) during reassembly
                # Fake packets are decoys and should not be part of the real ClientHello
                try:
                    from scapy.all import IP, IPv6

                    # Keep threshold consistent with AttackDetector._detect_fake (<=5)
                    is_fake = False
                    if pkt.haslayer(IP) and pkt[IP].ttl <= 5:
                        is_fake = True
                    elif pkt.haslayer(IPv6) and pkt[IPv6].hlim <= 5:
                        is_fake = True

                    if is_fake:
                        logger.debug(
                            "Skipping fake/decoy packet during reassembly (low TTL/HopLimit)"
                        )
                        continue
                except Exception:
                    pass

                # Check if packet has payload (either in Raw layer or TCP payload)
                tcp_layer = pkt[TCP]
                has_payload = pkt.haslayer(Raw) or (
                    tcp_layer.payload and len(bytes(tcp_layer.payload)) > 0
                )
                if has_payload:
                    tcp_packets.append(pkt)
                    logger.debug(
                        f"Found TCP packet with payload: seq={tcp_layer.seq}, has_Raw={pkt.haslayer(Raw)}, payload_len={len(bytes(tcp_layer.payload)) if tcp_layer.payload else 0}"
                    )

        if not tcp_packets:
            logger.debug("No TCP packets with payload found in stream")
            return None

        logger.debug(f"Found {len(tcp_packets)} TCP packets with payload for reassembly")

        tcp_packets.sort(key=lambda p: p[TCP].seq)

        # --------------------------------------------------------------------
        # Filter retransmissions: exact duplicate segments (same seq + same payload)
        # can add noise and, in edge cases, confuse record boundary scanning.
        # We only drop *exact* duplicates to avoid hiding real overlap attacks.
        # --------------------------------------------------------------------
        original_count = len(tcp_packets)
        unique_packets: List[Any] = []
        seen_dupes: set[tuple[int, int, bytes]] = set()
        for pkt in tcp_packets:
            tcp_layer = pkt[TCP]
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
            else:
                payload = bytes(tcp_layer.payload)

            if not payload:
                continue

            # Use a small hash to avoid storing huge payloads in the set
            payload_sig = hashlib.md5(payload, usedforsecurity=False).digest()
            key = (int(tcp_layer.seq), len(payload), payload_sig)
            if key in seen_dupes:
                logger.debug(
                    "Skipping retransmission duplicate during reassembly: seq=%s, len=%s",
                    tcp_layer.seq,
                    len(payload),
                )
                continue
            seen_dupes.add(key)
            unique_packets.append(pkt)

        tcp_packets = unique_packets
        if not tcp_packets:
            logger.debug("No unique TCP packets left after retransmission filtering")
            return None

        duplicates_filtered = max(0, original_count - len(tcp_packets))
        self.reassembly_stats[cache_key] = {
            "retransmission_duplicates_filtered": duplicates_filtered,
            "payload_packets_before_dedup": original_count,
            "payload_packets_after_dedup": len(tcp_packets),
            "reassembly_metric_recorded": False,
        }

        # Record reassembly metric as early as possible (even if detect_attacks is never called).
        # This is best-effort and must not break parsing/reassembly.
        if METRICS_AVAILABLE:
            try:
                collector = get_metrics_collector()
                stats = self.reassembly_stats.get(cache_key) or {}
                collector.record_pcap_reassembly(
                    pcap_file=str(self._current_pcap_file or "unknown"),
                    stream_key=str(cache_key),
                    retransmission_duplicates_filtered=int(
                        stats.get("retransmission_duplicates_filtered", 0)
                    ),
                    payload_packets_before_dedup=int(stats.get("payload_packets_before_dedup", 0)),
                    payload_packets_after_dedup=int(stats.get("payload_packets_after_dedup", 0)),
                )
                # Mark recorded to avoid duplicating the same metric later in detect_attacks()
                self.reassembly_stats[cache_key]["reassembly_metric_recorded"] = True
            except Exception as e:
                logger.debug(f"Failed to record PCAP reassembly metric: {e}")

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
            else:
                # Gap: missing segment(s). Keep scanning; record framing may still be found.
                # We do not advance expected_seq here to avoid inventing bytes.
                continue

        clienthello_data = None
        offset = 0

        while offset < len(reassembled) - 5:
            if reassembled[offset] == 0x16:
                record_len = struct.unpack(">H", reassembled[offset + 3 : offset + 5])[0]
                if offset + 5 < len(reassembled) and reassembled[offset + 5] == 0x01:
                    total_len = 5 + record_len
                    if offset + total_len <= len(reassembled):
                        clienthello_data = reassembled[offset : offset + total_len]
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

    def detect_attacks(
        self, stream: TCPStream, sni_offset: Optional[int] = None
    ) -> DetectedAttacks:
        """
        Detect applied attacks in TCP stream.

        Delegates to AttackDetector for actual detection logic.
        """
        try:
            from scapy.all import TCP, Raw, IP, IPv6
        except ImportError:
            return DetectedAttacks()

        def _is_fake_packet(pkt: Any) -> bool:
            """Fake/decoy heuristic: low TTL (IPv4) or HopLimit (IPv6) <= 5."""
            try:
                if pkt.haslayer(IP):
                    return pkt[IP].ttl <= 5
                if pkt.haslayer(IPv6):
                    return pkt[IPv6].hlim <= 5
            except Exception:
                return False
            return False

        # Get packets with payload
        data_packets: List[Any] = []
        for pkt in stream.packets:
            if pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                # Check if packet has payload (either in Raw layer or TCP payload)
                has_payload = pkt.haslayer(Raw) or (
                    tcp_layer.payload and len(bytes(tcp_layer.payload)) > 0
                )
                if has_payload:
                    data_packets.append(pkt)

        if not data_packets:
            return DetectedAttacks()

        # --------------------------------------------------------------------
        # IMPORTANT:
        # - Fake detection requires decoy packets to be present (TTL/HopLimit low).
        # - Split/disorder analyses should prefer "real" packets to avoid decoy noise.
        #
        # So we:
        #   1) run fake & badsum on all payload packets
        #   2) run split & disorder on "real" payload packets only
        # then merge results into one DetectedAttacks.
        # This keeps interfaces unchanged and improves accuracy.
        # --------------------------------------------------------------------
        real_packets = [p for p in data_packets if not _is_fake_packet(p)]

        detected = DetectedAttacks()

        # fake (needs decoys)
        fake_res = self.detector.detect_fake(data_packets)
        detected.fake = fake_res.fake
        detected.fake_count = fake_res.fake_count
        detected.fake_ttl = fake_res.fake_ttl

        # split/disorder should use real packets only
        split_res = self.detector.detect_split(real_packets, sni_offset)
        detected.split = split_res.split
        detected.fragment_count = split_res.fragment_count
        detected.split_near_sni = split_res.split_near_sni
        detected.split_positions = split_res.split_positions

        disorder_res = self.detector.detect_disorder(real_packets)
        detected.disorder = disorder_res.disorder
        detected.disorder_type = disorder_res.disorder_type

        # badsum/badseq can be part of decoy/fooling; keep on full set
        badsum_res = self.detector.detect_badsum(data_packets)
        detected.badsum = badsum_res.badsum
        detected.badseq = badsum_res.badseq

        # Record attack detection metrics
        if METRICS_AVAILABLE:
            try:
                collector = get_metrics_collector()

                # Record reassembly metric (if not already recorded during reassemble_clienthello()).
                cache_key = stream.key()
                stats = self.reassembly_stats.get(cache_key) or {}
                if stats and not stats.get("reassembly_metric_recorded", False):
                    collector.record_pcap_reassembly(
                        pcap_file=str(self._current_pcap_file or "unknown"),
                        stream_key=str(cache_key),
                        retransmission_duplicates_filtered=int(
                            stats.get("retransmission_duplicates_filtered", 0)
                        ),
                        payload_packets_before_dedup=int(
                            stats.get("payload_packets_before_dedup", 0)
                        ),
                        payload_packets_after_dedup=int(
                            stats.get("payload_packets_after_dedup", 0)
                        ),
                    )
                    # Mark recorded to avoid duplicating metrics on subsequent detect_attacks() calls
                    try:
                        self.reassembly_stats[cache_key]["reassembly_metric_recorded"] = True
                    except Exception:
                        pass

                # Record fake detection
                if detected.fake:
                    collector.record_attack_detection(
                        attack_type="fake",
                        total_attempts=1,
                        successful_detections=1,
                        failed_detections=0,
                        average_confidence=1.0,
                    )

                # Record split detection
                if detected.split:
                    attack_type = "multisplit" if detected.fragment_count > 2 else "split"
                    collector.record_attack_detection(
                        attack_type=attack_type,
                        total_attempts=1,
                        successful_detections=1,
                        failed_detections=0,
                        average_confidence=1.0,
                    )

                # Record disorder detection
                if detected.disorder:
                    collector.record_attack_detection(
                        attack_type="disorder",
                        total_attempts=1,
                        successful_detections=1,
                        failed_detections=0,
                        average_confidence=1.0,
                    )
            except Exception as e:
                logger.warning(f"Failed to record detection metrics: {e}")

        return detected

    def _record_validation_metric(
        self,
        pcap_file: str,
        validation_success: bool,
        error_type: Optional[str],
        error_message: Optional[str],
        packets_analyzed: int,
        streams_found: int,
        clienthello_found: bool,
        elapsed_time: float,
    ):
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
                    validation_time_ms=elapsed_time * 1000,
                )
            except Exception as e:
                logger.warning(f"Failed to record validation metric: {e}")
