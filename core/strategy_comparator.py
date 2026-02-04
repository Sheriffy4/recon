"""
Strategy Comparison Tool - Discovery Mode Capture

This module implements discovery mode capture for comparing strategy application
between discovery mode and service mode.
"""

import json
import logging
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from core.utils.packet_capture import (
    resolve_domain,
    start_packet_capture,
    stop_packet_capture,
)
from core.utils.serialization import save_capture_to_json, save_json_file
from core.utils.network_probe import probe_domain_connection
from core.utils.capture_io import save_strategy_capture, safe_filename_component


def _normalize_parsed_strategy(parsed: Any) -> Dict[str, Any]:
    """
    Normalize parser output to a flat parameter dict used by the comparator.
    Supports:
      - old parsers returning Dict[str, Any]
      - StrategyParserV2 returning ParsedStrategy(dataclass) with .params/.attack_type
    """
    if parsed is None:
        return {}

    if isinstance(parsed, dict):
        params = dict(parsed)
        # Keep compatibility with existing analysis keys
        if "attack_type" in params and "desync_method" not in params:
            params["desync_method"] = params["attack_type"]
        return params

    # ParsedStrategy-like object
    params_obj = getattr(parsed, "params", None)
    params = dict(params_obj or {})
    attack_type = getattr(parsed, "attack_type", None)
    if attack_type is not None:
        params.setdefault("attack_type", attack_type)
        params.setdefault("desync_method", attack_type)
    return params


def _canonicalize_strategy_params(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Canonicalize strategy params for stable comparisons.

    Goals:
      - treat known aliases as the same parameter to avoid duplicate/noisy diffs
      - keep original keys for unknown params untouched

    This does NOT remove data from the original dict; it operates on a copy.
    """
    if not isinstance(params, dict):
        return {}

    p = dict(params)

    # Alias groups: (aliases..., canonical)
    alias_groups = [
        (("attack_type", "desync_method"), "attack_type"),
        (("overlap_size", "split_seqovl"), "overlap_size"),
        (("split_pos", "split_position"), "split_pos"),
        (("fooling", "fooling_methods"), "fooling"),
    ]

    for aliases, canonical in alias_groups:
        # Prefer canonical key if present, else take first found alias.
        canonical_value = None
        canonical_present = canonical in p and p.get(canonical) is not None
        if canonical_present:
            canonical_value = p.get(canonical)
        else:
            for a in aliases:
                if a in p and p.get(a) is not None:
                    canonical_value = p.get(a)
                    break

        if canonical_value is None:
            continue

        # Inject canonical key for comparison
        p[canonical] = canonical_value

        # Keep legacy compatibility keys in the dict (some code reads them),
        # but we will ignore them during comparisons (see StrategyDiff).
        for a in aliases:
            p.setdefault(a, canonical_value)

    return p

try:
    from scapy.all import IP, TCP

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Packet capture will be limited.")


@dataclass
class StrategyCapture:
    """Captured strategy information"""

    mode: str  # 'discovery' or 'service'
    domain: str
    timestamp: str
    strategy_string: str
    parsed_params: Dict[str, Any]
    resolved_ips: List[str] = field(default_factory=list)
    packets_captured: int = 0
    pcap_file: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


class DiscoveryModeCapture:
    """Handles discovery mode capture for strategy comparison"""

    def __init__(self, output_dir: str = "strategy_comparison_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.logger = logging.getLogger(__name__)

    def run_discovery_mode(self, domain: str, timeout: int = 30) -> StrategyCapture:
        """
        Run strategy discovery for a domain and capture results.

        Args:
            domain: Domain to discover strategy for
            timeout: Maximum time to wait for discovery (seconds)

        Returns:
            StrategyCapture object with discovery results
        """
        self.logger.info(f"Starting discovery mode for {domain}")

        timestamp = getattr(self, "_run_id", None) or datetime.now().strftime("%Y%m%d_%H%M%S")
        file_domain = safe_filename_component(domain)
        pcap_file = self.output_dir / f"discovery_{file_domain}_{timestamp}.pcap"

        # Resolve domain to IPs
        resolved_ips = resolve_domain(domain)
        self.logger.info(f"Resolved {domain} to IPs: {resolved_ips}")

        # Start packet capture
        capture_process = start_packet_capture(resolved_ips, str(pcap_file))

        # Best-effort: generate minimal traffic to be captured (does not change public API)
        self._probe_domain(domain)

        # Run discovery mode
        strategy_string, parsed_params = self._execute_discovery(domain, timeout)

        # Stop packet capture
        packets_captured = 0
        if capture_process:
            packets_captured = stop_packet_capture(capture_process, str(pcap_file))

        # Create capture result
        capture = StrategyCapture(
            mode="discovery",
            domain=domain,
            timestamp=timestamp,
            strategy_string=strategy_string,
            parsed_params=parsed_params,
            resolved_ips=resolved_ips,
            packets_captured=packets_captured,
            pcap_file=str(pcap_file) if pcap_file.exists() else None,
        )

        # Save results
        self._save_capture(capture)

        self.logger.info(f"Discovery mode complete for {domain}")
        return capture

    def _probe_domain(self, domain: str):
        """Generate minimal probe traffic for packet capture"""
        probe_domain_connection(domain, port=443, timeout=2.0, logger=self.logger)

    def _execute_discovery(self, domain: str, timeout: int) -> tuple[str, Dict[str, Any]]:
        """
        Execute discovery mode to find working strategy.

        This simulates running the discovery tool and parsing its output.
        In a real implementation, this would call the actual discovery tool.
        """
        self.logger.info(f"Running discovery for {domain} (timeout: {timeout}s)")

        # Try to import and use existing discovery tools
        try:
            from core.strategy_parser_v2 import StrategyParserV2

            # Check if there's a strategies.json with existing strategy
            strategies_file = Path("recon/strategies.json")
            if strategies_file.exists():
                with open(strategies_file, "r", encoding="utf-8") as f:
                    strategies = json.load(f)

                if domain in strategies:
                    strategy_string = strategies[domain]
                    self.logger.info(f"Found existing strategy for {domain}: {strategy_string}")

                    # Parse the strategy
                    parser = StrategyParserV2()
                    parsed_params = _normalize_parsed_strategy(parser.parse(strategy_string))

                    return strategy_string, parsed_params

            # If no existing strategy, return a default discovery result
            self.logger.warning(f"No existing strategy found for {domain}, using default")
            strategy_string = "--dpi-desync=fake --dpi-desync-ttl=4"
            parsed_params = {"attack_type": "fake", "desync_method": "fake", "ttl": 4, "split_pos": 3}

            return strategy_string, parsed_params

        except (ImportError, AttributeError, FileNotFoundError, json.JSONDecodeError, ValueError, OSError) as e:
            self.logger.error(f"Discovery execution failed: {e}")
            # Return minimal default
            return "--dpi-desync=fake", {"attack_type": "fake", "desync_method": "fake"}

    def _save_capture(self, capture: StrategyCapture):
        """Save capture results to JSON file"""
        save_strategy_capture(
            capture_data=capture.to_dict(),
            output_dir=self.output_dir,
            prefix="discovery",
            domain=capture.domain,
            timestamp=capture.timestamp,
        )


@dataclass
class StrategyDifference:
    """Represents a difference between two strategies"""

    parameter: str
    discovery_value: Any
    service_value: Any
    is_critical: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        from core.utils.dataclass_serialization import dataclass_to_dict_with_str_values

        return dataclass_to_dict_with_str_values(
            self, fields_to_stringify=["discovery_value", "service_value"]
        )


@dataclass
class StrategyComparison:
    """Results of comparing discovery and service mode strategies"""

    domain: str
    timestamp: str
    discovery_strategy: str
    service_strategy: str
    differences: List[StrategyDifference] = field(default_factory=list)
    strategies_match: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "domain": self.domain,
            "timestamp": self.timestamp,
            "discovery_strategy": self.discovery_strategy,
            "service_strategy": self.service_strategy,
            "differences": [d.to_dict() for d in self.differences],
            "strategies_match": self.strategies_match,
            "difference_count": len(self.differences),
            "critical_differences": len([d for d in self.differences if d.is_critical]),
        }


class StrategyDiff:
    """Compares strategies between discovery and service modes"""

    # Critical parameters that must match
    CRITICAL_PARAMS = {
        "desync_method",
        "attack_type",
        "ttl",
        "autottl",
        "split_pos",
        "overlap_size",
        "fooling",
    }

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def compare_strategies(
        self, discovery_capture: StrategyCapture, service_capture: StrategyCapture
    ) -> StrategyComparison:
        """
        Compare strategies from discovery and service modes.

        Args:
            discovery_capture: Capture from discovery mode
            service_capture: Capture from service mode

        Returns:
            StrategyComparison with differences highlighted
        """
        self.logger.info(f"Comparing strategies for {discovery_capture.domain}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Find differences in parsed parameters
        differences = self._find_parameter_differences(
            discovery_capture.parsed_params, service_capture.parsed_params
        )

        # Determine if strategies match
        strategies_match = len(differences) == 0

        comparison = StrategyComparison(
            domain=discovery_capture.domain,
            timestamp=timestamp,
            discovery_strategy=discovery_capture.strategy_string,
            service_strategy=service_capture.strategy_string,
            differences=differences,
            strategies_match=strategies_match,
        )

        # Log results
        if strategies_match:
            self.logger.info("✓ Strategies match perfectly")
        else:
            self.logger.warning(f"✗ Found {len(differences)} differences")
            for diff in differences:
                level = "CRITICAL" if diff.is_critical else "INFO"
                self.logger.warning(
                    f"  [{level}] {diff.parameter}: "
                    f"discovery={diff.discovery_value} vs service={diff.service_value}"
                )

        return comparison

    def _find_parameter_differences(
        self, discovery_params: Dict[str, Any], service_params: Dict[str, Any]
    ) -> List[StrategyDifference]:
        """Find differences between parameter dictionaries (alias-aware)."""
        differences = []

        disc = _canonicalize_strategy_params(discovery_params or {})
        svc = _canonicalize_strategy_params(service_params or {})

        # Keys to ignore for diffing because they are aliases of canonical keys.
        # The canonical keys are the ones compared and reported.
        alias_only_keys = {
            "desync_method",      # alias of attack_type
            "split_seqovl",       # alias of overlap_size
            "split_position",     # alias of split_pos
            "fooling_methods",    # alias of fooling
        }

        # Get all unique parameter names after canonicalization, excluding alias-only.
        all_params = (set(disc.keys()) | set(svc.keys())) - alias_only_keys

        for param in all_params:
            discovery_value = disc.get(param)
            service_value = svc.get(param)

            # Check if values differ
            if discovery_value != service_value:
                is_critical = param in self.CRITICAL_PARAMS

                diff = StrategyDifference(
                    parameter=param,
                    discovery_value=discovery_value,
                    service_value=service_value,
                    is_critical=is_critical,
                )
                differences.append(diff)

        return differences

    def highlight_differences(self, comparison: StrategyComparison) -> str:
        """
        Generate a human-readable report of differences.

        Args:
            comparison: StrategyComparison object

        Returns:
            Formatted string report
        """
        from core.reports.strategy_report import StrategyComparisonReporter

        return StrategyComparisonReporter.format_strategy_diff(comparison)


@dataclass
class PacketDifference:
    """Represents a difference between packets"""

    packet_index: int
    field: str
    discovery_value: Any
    service_value: Any
    is_critical: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        from core.utils.dataclass_serialization import dataclass_to_dict_with_str_values

        return dataclass_to_dict_with_str_values(
            self, fields_to_stringify=["discovery_value", "service_value"]
        )


@dataclass
class PacketComparison:
    """Results of comparing packet captures"""

    domain: str
    timestamp: str
    discovery_pcap: Optional[str]
    service_pcap: Optional[str]
    discovery_packet_count: int
    service_packet_count: int
    differences: List[PacketDifference] = field(default_factory=list)
    packets_match: bool = True
    timing_differences: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "domain": self.domain,
            "timestamp": self.timestamp,
            "discovery_pcap": self.discovery_pcap,
            "service_pcap": self.service_pcap,
            "discovery_packet_count": self.discovery_packet_count,
            "service_packet_count": self.service_packet_count,
            "differences": [d.to_dict() for d in self.differences],
            "packets_match": self.packets_match,
            "difference_count": len(self.differences),
            "critical_differences": len([d for d in self.differences if d.is_critical]),
            "timing_differences": self.timing_differences,
        }


class PacketDiff:
    """Compares packet captures between discovery and service modes"""

    # Critical packet fields that must match
    CRITICAL_FIELDS = {"ttl", "flags", "seq", "ack", "payload_len"}

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def compare_packets(
        self, discovery_capture: StrategyCapture, service_capture: StrategyCapture
    ) -> PacketComparison:
        """
        Compare packet captures from discovery and service modes.

        Args:
            discovery_capture: Capture from discovery mode
            service_capture: Capture from service mode

        Returns:
            PacketComparison with differences highlighted
        """
        self.logger.info(f"Comparing packets for {discovery_capture.domain}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Load packets from both captures
        discovery_packets = self._load_capture_packets(discovery_capture)
        service_packets = self._load_capture_packets(service_capture)

        # Analyze differences and timing
        differences, timing_diffs = self._analyze_packet_differences(
            discovery_packets, service_packets
        )

        packets_match = len(differences) == 0

        # Create comparison result
        comparison = self._create_packet_comparison(
            discovery_capture=discovery_capture,
            service_capture=service_capture,
            timestamp=timestamp,
            discovery_packets=discovery_packets,
            service_packets=service_packets,
            differences=differences,
            timing_diffs=timing_diffs,
            packets_match=packets_match,
        )

        # Log results
        self._log_comparison_results(packets_match, len(differences))

        return comparison

    def _load_capture_packets(self, capture: StrategyCapture) -> List[Any]:
        """
        Load packets from a capture's PCAP file.

        Args:
            capture: Strategy capture with pcap_file path

        Returns:
            List of packets or empty list if not available
        """
        if not SCAPY_AVAILABLE:
            return []

        if capture.pcap_file and Path(capture.pcap_file).exists():
            return self._load_packets(capture.pcap_file)

        return []

    def _analyze_packet_differences(
        self, discovery_packets: List[Any], service_packets: List[Any]
    ) -> tuple[List[PacketDifference], Dict[str, float]]:
        """
        Analyze differences and timing between packet sequences.

        Args:
            discovery_packets: Packets from discovery mode
            service_packets: Packets from service mode

        Returns:
            Tuple of (differences list, timing differences dict)
        """
        differences = []
        timing_diffs = {}

        if discovery_packets and service_packets:
            differences = self._find_packet_differences(discovery_packets, service_packets)
            timing_diffs = self._analyze_timing(discovery_packets, service_packets)

        return differences, timing_diffs

    def _create_packet_comparison(
        self,
        discovery_capture: StrategyCapture,
        service_capture: StrategyCapture,
        timestamp: str,
        discovery_packets: List[Any],
        service_packets: List[Any],
        differences: List[PacketDifference],
        timing_diffs: Dict[str, float],
        packets_match: bool,
    ) -> PacketComparison:
        """
        Create PacketComparison object from analysis results.

        Args:
            discovery_capture: Discovery mode capture
            service_capture: Service mode capture
            timestamp: Comparison timestamp
            discovery_packets: Loaded discovery packets
            service_packets: Loaded service packets
            differences: Found packet differences
            timing_diffs: Timing analysis results
            packets_match: Whether packets match

        Returns:
            PacketComparison object
        """
        from core.analysis.packet_analyzer import PacketAnalyzer

        return PacketAnalyzer.create_comparison(
            discovery_capture,
            service_capture,
            timestamp,
            discovery_packets,
            service_packets,
            differences,
            timing_diffs,
            packets_match,
        )

    def _log_comparison_results(self, packets_match: bool, difference_count: int):
        """
        Log packet comparison results.

        Args:
            packets_match: Whether packets match
            difference_count: Number of differences found
        """
        if packets_match:
            self.logger.info("✓ Packets match perfectly")
        else:
            self.logger.warning(f"✗ Found {difference_count} packet differences")

    def _load_packets(self, pcap_file: str) -> List[Any]:
        """Load packets from PCAP file"""
        if not SCAPY_AVAILABLE:
            return []

        try:
            from scapy.all import rdpcap

            packets = rdpcap(pcap_file)
            self.logger.info(f"Loaded {len(packets)} packets from {pcap_file}")
            return packets
        except (ImportError, FileNotFoundError, OSError) as e:
            self.logger.error(f"Failed to load packets from {pcap_file}: {e}")
            return []

    def _find_packet_differences(
        self, discovery_packets: List[Any], service_packets: List[Any]
    ) -> List[PacketDifference]:
        """
        Find differences between packet sequences.

        Args:
            discovery_packets: Packets from discovery mode
            service_packets: Packets from service mode

        Returns:
            List of PacketDifference objects
        """
        differences = []

        # Log packet count mismatch if present
        self._check_packet_count_mismatch(discovery_packets, service_packets)

        # Compare packets pairwise
        min_count = min(len(discovery_packets), len(service_packets))
        for i in range(min_count):
            packet_diffs = self._compare_packet_pair(discovery_packets[i], service_packets[i], i)
            differences.extend(packet_diffs)

        return differences

    def _check_packet_count_mismatch(
        self, discovery_packets: List[Any], service_packets: List[Any]
    ):
        """
        Check and log if packet counts don't match.

        Args:
            discovery_packets: Packets from discovery mode
            service_packets: Packets from service mode
        """
        if len(discovery_packets) != len(service_packets):
            self.logger.warning(
                f"Packet count mismatch: discovery={len(discovery_packets)}, "
                f"service={len(service_packets)}"
            )

    def _compare_packet_pair(
        self, disc_pkt: Any, svc_pkt: Any, packet_index: int
    ) -> List[PacketDifference]:
        """
        Compare a pair of packets and find differences.

        Args:
            disc_pkt: Discovery mode packet
            svc_pkt: Service mode packet
            packet_index: Index of the packet in sequence

        Returns:
            List of differences found in this packet pair
        """
        differences = []

        # Compare IP layer
        ip_diffs = self._compare_ip_layer(disc_pkt, svc_pkt, packet_index)
        differences.extend(ip_diffs)

        # Compare TCP layer
        tcp_diffs = self._compare_tcp_layer(disc_pkt, svc_pkt, packet_index)
        differences.extend(tcp_diffs)

        return differences

    def _compare_ip_layer(
        self, disc_pkt: Any, svc_pkt: Any, packet_index: int
    ) -> List[PacketDifference]:
        """
        Compare IP layer fields between two packets.

        Args:
            disc_pkt: Discovery mode packet
            svc_pkt: Service mode packet
            packet_index: Index of the packet in sequence

        Returns:
            List of IP layer differences
        """
        differences = []

        if disc_pkt.haslayer(IP) and svc_pkt.haslayer(IP):
            disc_ip = disc_pkt[IP]
            svc_ip = svc_pkt[IP]

            # Check TTL
            if disc_ip.ttl != svc_ip.ttl:
                differences.append(
                    PacketDifference(
                        packet_index=packet_index,
                        field="ttl",
                        discovery_value=disc_ip.ttl,
                        service_value=svc_ip.ttl,
                        is_critical=("ttl" in self.CRITICAL_FIELDS),
                    )
                )

        return differences

    def _compare_tcp_layer(
        self, disc_pkt: Any, svc_pkt: Any, packet_index: int
    ) -> List[PacketDifference]:
        """
        Compare TCP layer fields between two packets.

        Args:
            disc_pkt: Discovery mode packet
            svc_pkt: Service mode packet
            packet_index: Index of the packet in sequence

        Returns:
            List of TCP layer differences
        """
        differences = []

        if disc_pkt.haslayer(TCP) and svc_pkt.haslayer(TCP):
            disc_tcp = disc_pkt[TCP]
            svc_tcp = svc_pkt[TCP]

            # Check flags
            if disc_tcp.flags != svc_tcp.flags:
                differences.append(
                    PacketDifference(
                        packet_index=packet_index,
                        field="flags",
                        discovery_value=str(disc_tcp.flags),
                        service_value=str(svc_tcp.flags),
                        is_critical=("flags" in self.CRITICAL_FIELDS),
                    )
                )

            # Check sequence number
            if disc_tcp.seq != svc_tcp.seq:
                differences.append(
                    PacketDifference(
                        packet_index=packet_index,
                        field="seq",
                        discovery_value=disc_tcp.seq,
                        service_value=svc_tcp.seq,
                        is_critical=("seq" in self.CRITICAL_FIELDS),
                    )
                )

            # Check acknowledgement number
            if disc_tcp.ack != svc_tcp.ack:
                differences.append(
                    PacketDifference(
                        packet_index=packet_index,
                        field="ack",
                        discovery_value=disc_tcp.ack,
                        service_value=svc_tcp.ack,
                        is_critical=("ack" in self.CRITICAL_FIELDS),
                    )
                )

            # Check payload length
            disc_payload_len = len(bytes(disc_tcp.payload)) if disc_tcp.payload else 0
            svc_payload_len = len(bytes(svc_tcp.payload)) if svc_tcp.payload else 0

            if disc_payload_len != svc_payload_len:
                differences.append(
                    PacketDifference(
                        packet_index=packet_index,
                        field="payload_len",
                        discovery_value=disc_payload_len,
                        service_value=svc_payload_len,
                        is_critical=("payload_len" in self.CRITICAL_FIELDS),
                    )
                )

        return differences

    def _analyze_timing(
        self, discovery_packets: List[Any], service_packets: List[Any]
    ) -> Dict[str, float]:
        """Analyze timing differences between packet sequences"""
        from core.analysis.packet_analyzer import PacketAnalyzer

        return PacketAnalyzer.analyze_timing(discovery_packets, service_packets)

    def highlight_differences(self, comparison: PacketComparison) -> str:
        """
        Generate a human-readable report of packet differences.

        Args:
            comparison: PacketComparison object

        Returns:
            Formatted string report
        """
        from core.reports.strategy_report import StrategyComparisonReporter

        return StrategyComparisonReporter.format_packet_diff(comparison)


class ServiceModeCapture:
    """Handles service mode capture for strategy comparison"""

    def __init__(self, output_dir: str = "strategy_comparison_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.logger = logging.getLogger(__name__)

    def capture_service_mode(
        self, domain: str, duration: int = 30, service_log_file: Optional[str] = None
    ) -> StrategyCapture:
        """
        Capture strategy application in service mode.

        Args:
            domain: Domain to monitor
            duration: How long to capture (seconds)
            service_log_file: Path to service log file to parse

        Returns:
            StrategyCapture object with service mode results
        """
        self.logger.info(f"Starting service mode capture for {domain}")

        # Prepare capture environment
        timestamp, pcap_file = self._prepare_capture_environment(domain)

        # Resolve domain and get strategy
        resolved_ips = self._resolve_and_log_domain(domain)
        strategy_string, parsed_params = self._get_service_strategy(domain)

        # Perform packet capture
        packets_captured = self._perform_packet_capture(
            resolved_ips, str(pcap_file), duration, domain
        )

        # Parse service logs if provided
        if service_log_file:
            self._parse_service_logs(service_log_file, domain)

        # Create and save capture result
        capture = self._create_capture_result(
            domain=domain,
            timestamp=timestamp,
            pcap_file=pcap_file,
            strategy_string=strategy_string,
            parsed_params=parsed_params,
            resolved_ips=resolved_ips,
            packets_captured=packets_captured,
        )

        self._save_capture(capture)

        self.logger.info(f"Service mode capture complete for {domain}")
        return capture

    def _prepare_capture_environment(self, domain: str) -> tuple[str, Path]:
        """
        Prepare capture environment with timestamp and pcap file path.

        Args:
            domain: Domain being captured

        Returns:
            Tuple of (timestamp, pcap_file_path)
        """
        timestamp = getattr(self, "_run_id", None) or datetime.now().strftime("%Y%m%d_%H%M%S")
        file_domain = safe_filename_component(domain)
        pcap_file = self.output_dir / f"service_{file_domain}_{timestamp}.pcap"
        return timestamp, pcap_file

    def _resolve_and_log_domain(self, domain: str) -> List[str]:
        """
        Resolve domain to IPs and log the result.

        Args:
            domain: Domain to resolve

        Returns:
            List of resolved IP addresses
        """
        resolved_ips = resolve_domain(domain)
        self.logger.info(f"Resolved {domain} to IPs: {resolved_ips}")
        return resolved_ips

    def _perform_packet_capture(
        self, resolved_ips: List[str], pcap_file: str, duration: int, domain: Optional[str] = None
    ) -> int:
        """
        Perform packet capture for specified duration.

        Args:
            resolved_ips: List of IP addresses to capture
            pcap_file: Path to save pcap file
            duration: Duration to capture in seconds
            domain: Optional domain for probe traffic

        Returns:
            Number of packets captured
        """
        # Start packet capture
        capture_process = start_packet_capture(resolved_ips, pcap_file)

        # Best-effort: generate minimal traffic to be captured (does not change public API)
        if domain:
            self._probe_domain(domain)

        # Monitor service for specified duration
        self.logger.info(f"Monitoring service for {duration} seconds...")
        time.sleep(duration)

        # Stop packet capture
        packets_captured = 0
        if capture_process:
            packets_captured = stop_packet_capture(capture_process, pcap_file)

        return packets_captured

    def _probe_domain(self, domain: str):
        """Generate minimal probe traffic for packet capture"""
        probe_domain_connection(domain, port=443, timeout=2.0, logger=self.logger)

    def _create_capture_result(
        self,
        domain: str,
        timestamp: str,
        pcap_file: Path,
        strategy_string: str,
        parsed_params: Dict[str, Any],
        resolved_ips: List[str],
        packets_captured: int,
    ) -> StrategyCapture:
        """
        Create StrategyCapture result object.

        Args:
            domain: Domain captured
            timestamp: Capture timestamp
            pcap_file: Path to pcap file
            strategy_string: Strategy string
            parsed_params: Parsed strategy parameters
            resolved_ips: Resolved IP addresses
            packets_captured: Number of packets captured

        Returns:
            StrategyCapture object
        """
        return StrategyCapture(
            mode="service",
            domain=domain,
            timestamp=timestamp,
            strategy_string=strategy_string,
            parsed_params=parsed_params,
            resolved_ips=resolved_ips,
            packets_captured=packets_captured,
            pcap_file=str(pcap_file) if pcap_file.exists() else None,
        )

    def _get_service_strategy(self, domain: str) -> tuple[str, Dict[str, Any]]:
        """
        Get the strategy that the service is using for a domain.

        This reads from the service's configuration (strategies.json).
        """
        self.logger.info(f"Getting service strategy for {domain}")

        try:
            from core.strategy_parser_v2 import StrategyParserV2

            # Read strategies.json
            strategies_file = Path("recon/strategies.json")
            if not strategies_file.exists():
                strategies_file = Path("strategies.json")

            if strategies_file.exists():
                with open(strategies_file, "r", encoding="utf-8") as f:
                    strategies = json.load(f)

                if domain in strategies:
                    strategy_string = strategies[domain]
                    self.logger.info(f"Found service strategy for {domain}: {strategy_string}")

                    # Parse the strategy
                    parser = StrategyParserV2()
                    parsed_params = parser.parse(strategy_string)

                    return strategy_string, parsed_params

            # If no strategy found, return default
            self.logger.warning(f"No service strategy found for {domain}, using default")
            strategy_string = "--dpi-desync=fake --dpi-desync-ttl=4"
            parsed_params = {"desync_method": "fake", "ttl": 4, "split_pos": 3}

            return strategy_string, parsed_params

        except (ImportError, FileNotFoundError, json.JSONDecodeError, OSError) as e:
            self.logger.error(f"Failed to get service strategy: {e}")
            return "--dpi-desync=fake", {"desync_method": "fake"}

    def _parse_service_logs(self, log_file: str, domain: str):
        """Parse service logs to extract strategy application details"""
        self.logger.info(f"Parsing service logs from {log_file}")

        try:
            with open(log_file, "r", encoding="utf-8") as f:
                for line in f:
                    if domain in line and "strategy" in line.lower():
                        self.logger.info(f"Service log: {line.strip()}")
        except (IOError, OSError, FileNotFoundError) as e:
            self.logger.error(f"Failed to parse service logs: {e}")

    def _save_capture(self, capture: StrategyCapture):
        """Save capture results to JSON file"""
        save_strategy_capture(
            capture_data=capture.to_dict(),
            output_dir=self.output_dir,
            prefix="service",
            domain=capture.domain,
            timestamp=capture.timestamp,
        )


@dataclass
class RootCauseAnalysis:
    """Root cause analysis of strategy/packet differences"""

    domain: str
    timestamp: str
    has_strategy_differences: bool
    has_packet_differences: bool
    root_causes: List[str] = field(default_factory=list)
    code_locations: List[str] = field(default_factory=list)
    fix_recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


class RootCauseAnalyzer:
    """Analyzes root causes of differences between discovery and service modes"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        from core.analysis.parameter_handlers import ParameterDifferenceHandler

        self._param_handler = ParameterDifferenceHandler()

    def analyze(
        self,
        strategy_comparison: StrategyComparison,
        packet_comparison: PacketComparison,
    ) -> RootCauseAnalysis:
        """
        Perform root cause analysis on strategy and packet differences.

        Args:
            strategy_comparison: Strategy comparison results
            packet_comparison: Packet comparison results

        Returns:
            RootCauseAnalysis with identified causes and recommendations
        """
        self.logger.info(f"Performing root cause analysis for {strategy_comparison.domain}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        analysis = RootCauseAnalysis(
            domain=strategy_comparison.domain,
            timestamp=timestamp,
            has_strategy_differences=not strategy_comparison.strategies_match,
            has_packet_differences=not packet_comparison.packets_match,
        )

        # Analyze strategy differences
        if not strategy_comparison.strategies_match:
            self._analyze_strategy_differences(strategy_comparison, analysis)

        # Analyze packet differences
        if not packet_comparison.packets_match:
            self._analyze_packet_differences(packet_comparison, analysis)

        # Correlate findings
        self._correlate_findings(analysis)

        return analysis

    def _analyze_strategy_differences(
        self, comparison: StrategyComparison, analysis: RootCauseAnalysis
    ):
        """
        Analyze strategy differences to identify root causes.

        Args:
            comparison: Strategy comparison results
            analysis: RootCauseAnalysis object to populate
        """
        for diff in comparison.differences:
            self._process_strategy_difference(diff, analysis)

    def _process_strategy_difference(self, diff: StrategyDifference, analysis: RootCauseAnalysis):
        """
        Process a single strategy difference and add findings to analysis.

        Args:
            diff: Strategy difference to process
            analysis: RootCauseAnalysis object to populate
        """
        self._param_handler.handle_difference(diff, analysis)

    def _analyze_packet_differences(
        self, comparison: PacketComparison, analysis: RootCauseAnalysis
    ):
        """Analyze packet differences to identify root causes"""
        from core.analysis.packet_analyzer import PacketAnalyzer

        PacketAnalyzer.analyze_packet_differences_for_root_cause(comparison, analysis)

    def _correlate_findings(self, analysis: RootCauseAnalysis):
        """Correlate strategy and packet differences to identify common root causes"""

        # If both strategy and packet differences exist, look for correlations
        if analysis.has_strategy_differences and analysis.has_packet_differences:
            analysis.root_causes.append(
                "Strategy configuration differences are causing packet differences"
            )
            analysis.fix_recommendations.append(
                "Fix strategy parsing/interpretation first, then verify packets match"
            )

        # Add general recommendations
        if analysis.root_causes:
            analysis.fix_recommendations.append(
                "Review ПОЛНОЕ_РЕШЕНИЕ_ПРОБЛЕМЫ.txt for known fixes"
            )
            analysis.fix_recommendations.append(
                "Run unit tests after applying fixes to verify correctness"
            )

    def generate_report(self, analysis: RootCauseAnalysis) -> str:
        """
        Generate a comprehensive root cause analysis report.

        Args:
            analysis: RootCauseAnalysis object

        Returns:
            Formatted string report
        """
        from core.reports.strategy_report import StrategyComparisonReporter

        return StrategyComparisonReporter.format_root_cause(analysis)


class StrategyComparatorTool:
    """Main tool for comparing strategies between discovery and service modes"""

    def __init__(self, output_dir: str = "strategy_comparison_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.logger = logging.getLogger(__name__)

        self.discovery_capture = DiscoveryModeCapture(output_dir)
        self.service_capture = ServiceModeCapture(output_dir)
        self.strategy_diff = StrategyDiff()
        self.packet_diff = PacketDiff()
        self.root_cause_analyzer = RootCauseAnalyzer()

    def compare_modes(
        self, domain: str, discovery_timeout: int = 30, service_duration: int = 30
    ) -> Dict[str, Any]:
        """
        Complete comparison of discovery vs service mode.

        Args:
            domain: Domain to compare
            discovery_timeout: Timeout for discovery mode
            service_duration: Duration to monitor service mode

        Returns:
            Dictionary with all comparison results
        """
        self.logger.info(f"Starting complete comparison for {domain}")
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Run discovery and service phases
        discovery_result, service_result = self._run_discovery_and_service_phases(
            domain, discovery_timeout, service_duration, run_id
        )

        # Perform comparisons
        strategy_comparison, packet_comparison = self._perform_comparisons(
            discovery_result, service_result
        )

        # Analyze root causes
        root_cause = self._analyze_root_causes(strategy_comparison, packet_comparison)

        # Generate and save reports
        results = self._generate_and_save_reports(
            domain,
            run_id,
            discovery_result,
            service_result,
            strategy_comparison,
            packet_comparison,
            root_cause,
        )

        return results

    def _run_discovery_and_service_phases(
        self, domain: str, discovery_timeout: int, service_duration: int, run_id: str
    ) -> tuple:
        """
        Run discovery and service mode capture phases.

        Args:
            domain: Domain to test
            discovery_timeout: Timeout for discovery mode
            service_duration: Duration to monitor service mode
            run_id: Unique run identifier

        Returns:
            Tuple of (discovery_result, service_result)
        """
        # Private attributes; does not change public API
        self.discovery_capture._run_id = run_id
        self.service_capture._run_id = run_id

        # Run discovery mode
        self.logger.info("Step 1: Running discovery mode...")
        discovery_result = self.discovery_capture.run_discovery_mode(
            domain, timeout=discovery_timeout
        )

        # Run service mode
        self.logger.info("Step 2: Capturing service mode...")
        service_result = self.service_capture.capture_service_mode(
            domain, duration=service_duration
        )

        return discovery_result, service_result

    def _perform_comparisons(self, discovery_result, service_result) -> tuple:
        """
        Perform strategy and packet comparisons.

        Args:
            discovery_result: Discovery mode capture result
            service_result: Service mode capture result

        Returns:
            Tuple of (strategy_comparison, packet_comparison)
        """
        # Compare strategies
        self.logger.info("Step 3: Comparing strategies...")
        strategy_comparison = self.strategy_diff.compare_strategies(
            discovery_result, service_result
        )

        # Compare packets
        self.logger.info("Step 4: Comparing packets...")
        packet_comparison = self.packet_diff.compare_packets(discovery_result, service_result)

        return strategy_comparison, packet_comparison

    def _analyze_root_causes(self, strategy_comparison, packet_comparison):
        """
        Perform root cause analysis on comparison results.

        Args:
            strategy_comparison: Strategy comparison results
            packet_comparison: Packet comparison results

        Returns:
            RootCauseAnalysis object
        """
        self.logger.info("Step 5: Performing root cause analysis...")
        return self.root_cause_analyzer.analyze(strategy_comparison, packet_comparison)

    def _generate_and_save_reports(
        self,
        domain: str,
        run_id: str,
        discovery_result,
        service_result,
        strategy_comparison,
        packet_comparison,
        root_cause,
    ) -> Dict[str, Any]:
        """
        Generate reports and save comprehensive results.

        Args:
            domain: Domain name
            run_id: Unique run identifier
            discovery_result: Discovery mode capture result
            service_result: Service mode capture result
            strategy_comparison: Strategy comparison results
            packet_comparison: Packet comparison results
            root_cause: Root cause analysis results

        Returns:
            Dictionary with all comparison results
        """
        # Generate reports
        strategy_report = self.strategy_diff.highlight_differences(strategy_comparison)
        packet_report = self.packet_diff.highlight_differences(packet_comparison)
        root_cause_report = self.root_cause_analyzer.generate_report(root_cause)

        # Build comprehensive results
        results = {
            "domain": domain,
            "timestamp": run_id,
            "discovery": discovery_result.to_dict(),
            "service": service_result.to_dict(),
            "strategy_comparison": strategy_comparison.to_dict(),
            "packet_comparison": packet_comparison.to_dict(),
            "root_cause_analysis": root_cause.to_dict(),
            "reports": {
                "strategy": strategy_report,
                "packet": packet_report,
                "root_cause": root_cause_report,
            },
        }

        # Save to file (robust serialization)
        output_file = self.output_dir / f"comparison_{domain}_{results['timestamp']}.json"
        save_json_file(
            data=results,
            output_file=output_file,
            description="complete comparison",
            default_handler=str,
        )

        self.logger.info(f"Saved complete comparison to {output_file}")

        # Print reports
        print("\n" + strategy_report)
        print("\n" + packet_report)
        print("\n" + root_cause_report)

        return results


def main():
    """Test complete strategy comparison tool"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Run complete comparison for x.com
    print("\n" + "=" * 80)
    print("STRATEGY COMPARISON TOOL - X.COM")
    print("=" * 80)

    comparator = StrategyComparatorTool()
    results = comparator.compare_modes(domain="x.com", discovery_timeout=30, service_duration=10)

    print("\n" + "=" * 80)
    print("COMPARISON COMPLETE")
    print("=" * 80)
    print("Results saved to: strategy_comparison_results/")
    print(f"Timestamp: {results['timestamp']}")

    # Summary
    strategy_match = results["strategy_comparison"]["strategies_match"]
    packet_match = results["packet_comparison"]["packets_match"]

    print("\nSUMMARY:")
    print(f"  Strategies match: {'✓ YES' if strategy_match else '✗ NO'}")
    print(f"  Packets match: {'✓ YES' if packet_match else '✗ NO'}")

    if not strategy_match or not packet_match:
        print("\n⚠ Differences found! Review the reports above for details.")
    else:
        print("\n✓ Discovery and service modes are identical!")


if __name__ == "__main__":
    main()


@dataclass
class AdvancedRootCauseAnalysis:
    """Advanced root cause analysis results with structured data"""

    domain: str
    timestamp: str
    strategy_differences: List[StrategyDifference]
    packet_differences: List[PacketDifference]
    identified_causes: List[Dict[str, Any]] = field(default_factory=list)
    fix_recommendations: List[Dict[str, Any]] = field(default_factory=list)
    code_locations: List[str] = field(default_factory=list)
    confidence_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "domain": self.domain,
            "timestamp": self.timestamp,
            "strategy_differences": [
                d.to_dict() if hasattr(d, "to_dict") else d for d in self.strategy_differences
            ],
            "packet_differences": [
                d.to_dict() if hasattr(d, "to_dict") else d for d in self.packet_differences
            ],
            "identified_causes": self.identified_causes,
            "fix_recommendations": self.fix_recommendations,
            "code_locations": self.code_locations,
            "confidence_score": self.confidence_score,
            "summary": {
                "total_strategy_differences": len(self.strategy_differences),
                "total_packet_differences": len(self.packet_differences),
                "critical_strategy_differences": len(
                    [
                        d
                        for d in self.strategy_differences
                        if hasattr(d, "is_critical") and d.is_critical
                    ]
                ),
                "critical_packet_differences": len(
                    [
                        d
                        for d in self.packet_differences
                        if hasattr(d, "is_critical") and d.is_critical
                    ]
                ),
                "total_causes_identified": len(self.identified_causes),
                "actionable_fixes": len(self.fix_recommendations),
            },
        }


class AdvancedRootCauseAnalyzer:
    """Analyzes root causes of strategy and packet differences with detailed structured output"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

        # Code location mappings for different issues
        self.code_locations = {
            "strategy_parsing": [
                "recon/core/strategy_parser_v2.py",
                "recon/core/strategy_interpreter.py",
            ],
            "packet_building": [
                "recon/core/bypass/engine/base_engine.py",
                "recon/core/bypass/attacks/tcp/fake_disorder_attack.py",
            ],
            "service_mapping": [
                "recon/recon_service.py",
                "recon/core/bypass_engine.py",
            ],
            "autottl_calculation": ["recon/core/bypass/engine/base_engine.py"],
            "multidisorder_implementation": [
                "recon/core/bypass/attacks/tcp/fake_disorder_attack.py",
                "recon/core/bypass/techniques/primitives.py",
            ],
        }

    def analyze_root_causes(
        self,
        strategy_comparison: StrategyComparison,
        packet_comparison: PacketComparison,
    ) -> AdvancedRootCauseAnalysis:
        """
        Perform comprehensive root cause analysis.

        Args:
            strategy_comparison: Results of strategy comparison
            packet_comparison: Results of packet comparison

        Returns:
            RootCauseAnalysis with identified causes and fix recommendations
        """
        self.logger.info(f"Starting root cause analysis for {strategy_comparison.domain}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Analyze strategy differences
        strategy_causes = self._analyze_strategy_differences(strategy_comparison.differences)

        # Analyze packet differences
        packet_causes = self._analyze_packet_differences(packet_comparison.differences)

        # Correlate strategy and packet differences
        correlated_causes = self._correlate_differences(
            strategy_comparison.differences, packet_comparison.differences
        )

        # Combine all identified causes
        all_causes = strategy_causes + packet_causes + correlated_causes

        # Deduplicate and prioritize causes
        unique_causes = self._deduplicate_causes(all_causes)

        # Generate fix recommendations
        fix_recommendations = self._generate_fix_recommendations(unique_causes)

        # Identify relevant code locations
        code_locations = self._identify_code_locations(unique_causes)

        # Calculate overall confidence score
        confidence_score = self._calculate_confidence_score(unique_causes)

        analysis = AdvancedRootCauseAnalysis(
            domain=strategy_comparison.domain,
            timestamp=timestamp,
            strategy_differences=strategy_comparison.differences,
            packet_differences=packet_comparison.differences,
            identified_causes=unique_causes,
            fix_recommendations=fix_recommendations,
            code_locations=code_locations,
            confidence_score=confidence_score,
        )

        self.logger.info(f"Root cause analysis complete: {len(unique_causes)} causes identified")
        return analysis

    def _analyze_strategy_differences(
        self, differences: List[StrategyDifference]
    ) -> List[Dict[str, Any]]:
        """Analyze root causes from strategy differences"""
        causes = []

        for diff in differences:
            cause = self._create_cause_from_strategy_difference(diff)
            if cause:
                causes.append(cause)

        return causes

    def _create_cause_from_strategy_difference(
        self, diff: StrategyDifference
    ) -> Optional[Dict[str, Any]]:
        """Create root cause from strategy difference"""

        # Map parameter differences to root causes
        if diff.parameter == "desync_method":
            if diff.discovery_value == "multidisorder" and diff.service_value != "multidisorder":
                return {
                    "type": "strategy_interpreter_mapping_error",
                    "description": f"Strategy interpreter incorrectly maps multidisorder to {diff.service_value}",
                    "parameter": diff.parameter,
                    "expected_value": diff.discovery_value,
                    "actual_value": diff.service_value,
                    "severity": "critical" if diff.is_critical else "medium",
                    "confidence": 0.9,
                    "component": "strategy_interpreter",
                    "evidence": {
                        "discovery_strategy_parsed_correctly": True,
                        "service_strategy_mapped_incorrectly": True,
                        "likely_cause": "desync_method check happens after fooling parameter check",
                    },
                }

        elif diff.parameter == "ttl":
            if diff.discovery_value is None and diff.service_value is not None:
                return {
                    "type": "autottl_not_implemented",
                    "description": "AutoTTL parameter not implemented in service mode",
                    "parameter": diff.parameter,
                    "expected_value": "calculated_dynamically",
                    "actual_value": diff.service_value,
                    "severity": "critical" if diff.is_critical else "medium",
                    "confidence": 0.85,
                    "component": "bypass_engine",
                    "evidence": {
                        "discovery_uses_autottl": True,
                        "service_uses_fixed_ttl": True,
                        "autottl_calculation_missing": True,
                    },
                }

        elif diff.parameter == "split_pos":
            if diff.discovery_value != diff.service_value:
                return {
                    "type": "split_position_mismatch",
                    "description": f"Split position differs between modes: discovery={diff.discovery_value}, service={diff.service_value}",
                    "parameter": diff.parameter,
                    "expected_value": diff.discovery_value,
                    "actual_value": diff.service_value,
                    "severity": "high",
                    "confidence": 0.8,
                    "component": "strategy_parser",
                    "evidence": {
                        "parameter_parsing_inconsistent": True,
                        "default_value_used_in_service": diff.service_value in [1, 3],
                    },
                }

        elif diff.parameter == "overlap_size":
            return {
                "type": "sequence_overlap_not_implemented",
                "description": "Sequence overlap (seqovl) parameter not implemented",
                "parameter": diff.parameter,
                "expected_value": diff.discovery_value,
                "actual_value": diff.service_value,
                "severity": "medium",
                "confidence": 0.75,
                "component": "multidisorder_attack",
                "evidence": {
                    "seqovl_parameter_missing": True,
                    "overlap_logic_not_implemented": True,
                },
            }

        elif diff.parameter == "repeats":
            return {
                "type": "repeats_not_implemented",
                "description": "Attack repeats parameter not implemented",
                "parameter": diff.parameter,
                "expected_value": diff.discovery_value,
                "actual_value": diff.service_value,
                "severity": "medium",
                "confidence": 0.7,
                "component": "attack_engine",
                "evidence": {
                    "repeats_parameter_ignored": True,
                    "single_attack_sequence_only": True,
                },
            }

        elif diff.parameter == "fooling":
            return {
                "type": "fooling_method_mismatch",
                "description": f"Fooling methods differ: discovery={diff.discovery_value}, service={diff.service_value}",
                "parameter": diff.parameter,
                "expected_value": diff.discovery_value,
                "actual_value": diff.service_value,
                "severity": "high",
                "confidence": 0.8,
                "component": "strategy_interpreter",
                "evidence": {
                    "fooling_parameter_parsing_error": True,
                    "default_fooling_applied": "badsum" in str(diff.service_value),
                },
            }

        return None

    def _analyze_packet_differences(
        self, differences: List[PacketDifference]
    ) -> List[Dict[str, Any]]:
        """Analyze root causes from packet differences"""
        causes = []

        for diff in differences:
            cause = self._create_cause_from_packet_difference(diff)
            if cause:
                causes.append(cause)

        return causes

    def _create_cause_from_packet_difference(
        self, diff: PacketDifference
    ) -> Optional[Dict[str, Any]]:
        """Create root cause from packet difference"""

        if diff.field == "ttl":
            return {
                "type": "ttl_calculation_error",
                "description": f"TTL values differ in packet {diff.packet_index}: discovery={diff.discovery_value}, service={diff.service_value}",
                "field": diff.field,
                "packet_index": diff.packet_index,
                "expected_value": diff.discovery_value,
                "actual_value": diff.service_value,
                "severity": "critical" if diff.is_critical else "medium",
                "confidence": 0.9,
                "component": "packet_builder",
                "evidence": {
                    "ttl_hardcoded_in_service": int(diff.service_value) in [1, 3, 4, 64],
                    "autottl_not_calculated": True,
                    "packet_construction_uses_wrong_ttl": True,
                },
            }

        elif diff.field == "flags":
            return {
                "type": "tcp_flags_mismatch",
                "description": f"TCP flags differ in packet {diff.packet_index}: discovery={diff.discovery_value}, service={diff.service_value}",
                "field": diff.field,
                "packet_index": diff.packet_index,
                "expected_value": diff.discovery_value,
                "actual_value": diff.service_value,
                "severity": "high",
                "confidence": 0.8,
                "component": "packet_builder",
                "evidence": {
                    "tcp_flags_construction_error": True,
                    "fake_packet_flags_wrong": diff.packet_index == 0,
                },
            }

        elif diff.field == "payload_len":
            return {
                "type": "payload_splitting_error",
                "description": f"Payload length differs in packet {diff.packet_index}: discovery={diff.discovery_value}, service={diff.service_value}",
                "field": diff.field,
                "packet_index": diff.packet_index,
                "expected_value": diff.discovery_value,
                "actual_value": diff.service_value,
                "severity": "medium",
                "confidence": 0.75,
                "component": "payload_splitter",
                "evidence": {
                    "split_position_calculation_error": True,
                    "overlap_size_not_applied": True,
                },
            }

        elif diff.field == "seq":
            return {
                "type": "sequence_number_error",
                "description": f"Sequence number differs in packet {diff.packet_index}: discovery={diff.discovery_value}, service={diff.service_value}",
                "field": diff.field,
                "packet_index": diff.packet_index,
                "expected_value": diff.discovery_value,
                "actual_value": diff.service_value,
                "severity": "medium",
                "confidence": 0.7,
                "component": "sequence_generator",
                "evidence": {
                    "sequence_calculation_error": True,
                    "overlap_sequence_wrong": True,
                },
            }

        return None

    def _correlate_differences(
        self,
        strategy_diffs: List[StrategyDifference],
        packet_diffs: List[PacketDifference],
    ) -> List[Dict[str, Any]]:
        """Correlate strategy and packet differences to identify compound causes"""
        causes = []

        # Look for strategy differences that explain packet differences
        strategy_params = {d.parameter: d for d in strategy_diffs}

        # Check if autottl strategy difference explains TTL packet differences
        if "autottl" in strategy_params or "ttl" in strategy_params:
            ttl_packet_diffs = [d for d in packet_diffs if d.field == "ttl"]
            if ttl_packet_diffs:
                causes.append(
                    {
                        "type": "autottl_strategy_packet_correlation",
                        "description": "AutoTTL strategy difference directly causes TTL packet differences",
                        "strategy_cause": strategy_params.get("autottl")
                        or strategy_params.get("ttl"),
                        "packet_effects": ttl_packet_diffs,
                        "severity": "critical",
                        "confidence": 0.95,
                        "component": "autottl_implementation",
                        "evidence": {
                            "strategy_specifies_autottl": "autottl" in strategy_params,
                            "packets_show_wrong_ttl": len(ttl_packet_diffs) > 0,
                            "correlation_strength": "high",
                        },
                    }
                )

        # Check if desync_method difference explains missing fake packets
        if "desync_method" in strategy_params:
            desync_diff = strategy_params["desync_method"]
            if (
                desync_diff.discovery_value == "multidisorder"
                and desync_diff.service_value != "multidisorder"
            ):

                # Look for evidence of missing fake packets in packet differences
                fake_packet_missing = len(packet_diffs) == 0 or all(
                    d.packet_index > 0 for d in packet_diffs
                )

                if fake_packet_missing:
                    causes.append(
                        {
                            "type": "multidisorder_mapping_causes_missing_fake_packets",
                            "description": "Incorrect multidisorder mapping causes fake packets to not be generated",
                            "strategy_cause": desync_diff,
                            "packet_effects": "no_fake_packets_detected",
                            "severity": "critical",
                            "confidence": 0.9,
                            "component": "strategy_interpreter_and_attack_engine",
                            "evidence": {
                                "multidisorder_mapped_incorrectly": True,
                                "fake_packets_not_generated": True,
                                "attack_type_determines_packet_generation": True,
                            },
                        }
                    )

        # Check if split_pos difference explains payload length differences
        if "split_pos" in strategy_params:
            split_diff = strategy_params["split_pos"]
            payload_diffs = [d for d in packet_diffs if d.field == "payload_len"]
            if payload_diffs:
                causes.append(
                    {
                        "type": "split_position_causes_payload_differences",
                        "description": f"Split position difference ({split_diff.discovery_value} vs {split_diff.service_value}) causes payload length mismatches",
                        "strategy_cause": split_diff,
                        "packet_effects": payload_diffs,
                        "severity": "high",
                        "confidence": 0.85,
                        "component": "payload_splitter",
                        "evidence": {
                            "split_position_differs": True,
                            "payload_lengths_affected": len(payload_diffs) > 0,
                            "split_calculation_error": True,
                        },
                    }
                )

        return causes

    def _deduplicate_causes(self, causes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate causes and merge similar ones"""
        unique_causes = []
        seen_types = set()

        for cause in causes:
            cause_type = cause.get("type", "")

            # Skip if we've already seen this type
            if cause_type in seen_types:
                continue

            seen_types.add(cause_type)
            unique_causes.append(cause)

        # Sort by confidence and severity
        def sort_key(cause):
            severity_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            return (
                severity_weight.get(cause.get("severity", "low"), 1),
                cause.get("confidence", 0.0),
            )

        unique_causes.sort(key=sort_key, reverse=True)
        return unique_causes

    def _generate_fix_recommendations(self, causes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate actionable fix recommendations for identified causes"""
        recommendations = []

        for cause in causes:
            cause_type = cause.get("type", "")

            if cause_type == "strategy_interpreter_mapping_error":
                recommendations.append(
                    {
                        "priority": "critical",
                        "title": "Fix Strategy Interpreter Mapping Logic",
                        "description": "Update strategy interpreter to check desync_method before fooling parameter",
                        "action_items": [
                            "Modify _config_to_strategy_task() in strategy_interpreter.py",
                            "Move desync_method check to top of method",
                            "Ensure multidisorder maps to multidisorder attack type",
                            "Add unit tests for desync_method priority",
                        ],
                        "files_to_modify": ["recon/core/strategy_interpreter.py"],
                        "test_files": ["recon/test_strategy_interpreter_mapping.py"],
                        "validation_steps": [
                            "Run unit tests for strategy interpreter",
                            "Test x.com strategy parsing in isolation",
                            "Verify multidisorder maps correctly",
                        ],
                        "estimated_effort": "low",
                        "cause_addressed": cause_type,
                    }
                )

            elif cause_type == "autottl_not_implemented":
                recommendations.append(
                    {
                        "priority": "critical",
                        "title": "Implement AutoTTL Calculation",
                        "description": "Add dynamic TTL calculation based on network hops",
                        "action_items": [
                            "Add calculate_autottl() method to base_engine.py",
                            "Implement network hop probing using ICMP/TCP",
                            "Update packet building to use calculated TTL",
                            "Add caching for TTL calculations",
                        ],
                        "files_to_modify": [
                            "recon/core/bypass/engine/base_engine.py",
                            "recon/core/bypass/attacks/tcp/fake_disorder_attack.py",
                        ],
                        "test_files": ["recon/test_autottl_calculation.py"],
                        "validation_steps": [
                            "Test TTL calculation with different offsets",
                            "Verify hop count probing works",
                            "Check TTL values in generated packets",
                        ],
                        "estimated_effort": "medium",
                        "cause_addressed": cause_type,
                    }
                )

            elif cause_type == "multidisorder_mapping_causes_missing_fake_packets":
                recommendations.append(
                    {
                        "priority": "critical",
                        "title": "Fix Multidisorder Attack Implementation",
                        "description": "Ensure multidisorder attack generates fake packets correctly",
                        "action_items": [
                            "Fix strategy interpreter mapping (see above)",
                            "Verify multidisorder attack generates fake packets",
                            "Ensure fake packets have correct TTL and checksum",
                            "Test packet sequence order",
                        ],
                        "files_to_modify": [
                            "recon/core/strategy_interpreter.py",
                            "recon/core/bypass/attacks/tcp/fake_disorder_attack.py",
                        ],
                        "test_files": ["recon/test_multidisorder_attack.py"],
                        "validation_steps": [
                            "Capture packets during multidisorder attack",
                            "Verify fake packet is sent first",
                            "Check fake packet has TTL=3 and bad checksum",
                        ],
                        "estimated_effort": "medium",
                        "cause_addressed": cause_type,
                    }
                )

            elif cause_type == "split_position_mismatch":
                recommendations.append(
                    {
                        "priority": "high",
                        "title": "Fix Split Position Parameter Handling",
                        "description": "Ensure split_pos parameter is parsed and applied consistently",
                        "action_items": [
                            "Verify strategy parser handles --dpi-desync-split-pos correctly",
                            "Check strategy interpreter maps split_pos to AttackTask",
                            "Ensure packet builder uses correct split position",
                            "Add validation for split_pos values",
                        ],
                        "files_to_modify": [
                            "recon/core/strategy_parser_v2.py",
                            "recon/core/strategy_interpreter.py",
                        ],
                        "test_files": ["recon/test_strategy_parser_v2.py"],
                        "validation_steps": [
                            "Test parsing of --dpi-desync-split-pos=46",
                            "Verify split_pos=46 is used in packet construction",
                            "Compare payload splitting with zapret",
                        ],
                        "estimated_effort": "low",
                        "cause_addressed": cause_type,
                    }
                )

            elif cause_type == "sequence_overlap_not_implemented":
                recommendations.append(
                    {
                        "priority": "medium",
                        "title": "Implement Sequence Overlap (seqovl)",
                        "description": "Add support for --dpi-desync-split-seqovl parameter",
                        "action_items": [
                            "Add seqovl parsing to strategy_parser_v2.py",
                            "Map seqovl to overlap_size in strategy interpreter",
                            "Implement overlap logic in multidisorder attack",
                            "Test sequence overlap behavior",
                        ],
                        "files_to_modify": [
                            "recon/core/strategy_parser_v2.py",
                            "recon/core/strategy_interpreter.py",
                            "recon/core/bypass/attacks/tcp/fake_disorder_attack.py",
                        ],
                        "test_files": ["recon/test_sequence_overlap.py"],
                        "validation_steps": [
                            "Test seqovl=1 parameter parsing",
                            "Verify overlapping segments are generated",
                            "Compare sequence numbers with zapret",
                        ],
                        "estimated_effort": "medium",
                        "cause_addressed": cause_type,
                    }
                )

            elif cause_type == "repeats_not_implemented":
                recommendations.append(
                    {
                        "priority": "medium",
                        "title": "Implement Attack Repeats",
                        "description": "Add support for --dpi-desync-repeats parameter",
                        "action_items": [
                            "Add repeats parsing to strategy_parser_v2.py",
                            "Update AttackTask to include repeats field",
                            "Implement repeat logic in attack engine",
                            "Add small delay between repeats",
                        ],
                        "files_to_modify": [
                            "recon/core/strategy_parser_v2.py",
                            "recon/core/strategy_interpreter.py",
                            "recon/core/bypass/engine/base_engine.py",
                        ],
                        "test_files": ["recon/test_attack_repeats.py"],
                        "validation_steps": [
                            "Test repeats=2 parameter parsing",
                            "Verify attack sequence is sent twice",
                            "Check timing between repeats",
                        ],
                        "estimated_effort": "low",
                        "cause_addressed": cause_type,
                    }
                )

        return recommendations

    def _identify_code_locations(self, causes: List[Dict[str, Any]]) -> List[str]:
        """Identify relevant code locations for the identified causes"""
        locations = set()

        for cause in causes:
            component = cause.get("component", "")

            if component in self.code_locations:
                locations.update(self.code_locations[component])

            # Add specific locations based on cause type
            cause_type = cause.get("type", "")

            if "strategy" in cause_type.lower():
                locations.update(self.code_locations["strategy_parsing"])

            if "packet" in cause_type.lower() or "ttl" in cause_type.lower():
                locations.update(self.code_locations["packet_building"])

            if "autottl" in cause_type.lower():
                locations.update(self.code_locations["autottl_calculation"])

            if "multidisorder" in cause_type.lower():
                locations.update(self.code_locations["multidisorder_implementation"])

        return sorted(list(locations))

    def _calculate_confidence_score(self, causes: List[Dict[str, Any]]) -> float:
        """Calculate overall confidence score for the analysis"""
        if not causes:
            return 0.0

        # Weight by severity and confidence
        total_weight = 0.0
        weighted_confidence = 0.0

        severity_weights = {"critical": 1.0, "high": 0.8, "medium": 0.6, "low": 0.4}

        for cause in causes:
            severity = cause.get("severity", "low")
            confidence = cause.get("confidence", 0.0)
            weight = severity_weights.get(severity, 0.4)

            weighted_confidence += confidence * weight
            total_weight += weight

        return weighted_confidence / max(1.0, total_weight)

    def generate_report(self, analysis: AdvancedRootCauseAnalysis) -> str:
        """Generate a comprehensive root cause analysis report"""
        lines = []
        lines.append("=" * 100)
        lines.append(f"ROOT CAUSE ANALYSIS REPORT: {analysis.domain}")
        lines.append("=" * 100)
        lines.append(f"Timestamp: {analysis.timestamp}")
        lines.append(f"Overall Confidence: {analysis.confidence_score:.2f}")
        lines.append("")

        # Summary
        summary = analysis.to_dict()["summary"]
        lines.append("ANALYSIS SUMMARY:")
        lines.append(
            f"  • Strategy Differences: {summary['total_strategy_differences']} ({summary['critical_strategy_differences']} critical)"
        )
        lines.append(
            f"  • Packet Differences: {summary['total_packet_differences']} ({summary['critical_packet_differences']} critical)"
        )
        lines.append(f"  • Root Causes Identified: {summary['total_causes_identified']}")
        lines.append(f"  • Actionable Fixes: {summary['actionable_fixes']}")
        lines.append("")

        # Identified causes
        if analysis.identified_causes:
            lines.append("IDENTIFIED ROOT CAUSES:")
            lines.append("")

            for i, cause in enumerate(analysis.identified_causes, 1):
                lines.append(f"{i}. {cause.get('type', 'Unknown').replace('_', ' ').title()}")
                lines.append(f"   Description: {cause.get('description', 'No description')}")
                lines.append(f"   Severity: {cause.get('severity', 'unknown').upper()}")
                lines.append(f"   Confidence: {cause.get('confidence', 0.0):.2f}")
                lines.append(f"   Component: {cause.get('component', 'unknown')}")

                # Evidence
                evidence = cause.get("evidence", {})
                if evidence:
                    lines.append("   Evidence:")
                    for key, value in evidence.items():
                        lines.append(f"     - {key.replace('_', ' ').title()}: {value}")

                lines.append("")

        # Fix recommendations
        if analysis.fix_recommendations:
            lines.append("FIX RECOMMENDATIONS:")
            lines.append("")

            for i, fix in enumerate(analysis.fix_recommendations, 1):
                lines.append(f"{i}. {fix.get('title', 'Unknown Fix')}")
                lines.append(f"   Priority: {fix.get('priority', 'unknown').upper()}")
                lines.append(f"   Description: {fix.get('description', 'No description')}")
                lines.append(
                    f"   Estimated Effort: {fix.get('estimated_effort', 'unknown').upper()}"
                )

                # Action items
                action_items = fix.get("action_items", [])
                if action_items:
                    lines.append("   Action Items:")
                    for item in action_items:
                        lines.append(f"     • {item}")

                # Files to modify
                files = fix.get("files_to_modify", [])
                if files:
                    lines.append("   Files to Modify:")
                    for file in files:
                        lines.append(f"     • {file}")

                # Validation steps
                validation = fix.get("validation_steps", [])
                if validation:
                    lines.append("   Validation Steps:")
                    for step in validation:
                        lines.append(f"     • {step}")

                lines.append("")

        # Code locations
        if analysis.code_locations:
            lines.append("RELEVANT CODE LOCATIONS:")
            for location in analysis.code_locations:
                lines.append(f"  • {location}")
            lines.append("")

        lines.append("=" * 100)

        return "\n".join(lines)


class StrategyComparator:
    """Main class for comparing strategies and performing root cause analysis"""

    def __init__(self, output_dir: str = "strategy_comparison_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.logger = logging.getLogger(__name__)

        # Initialize components
        self.discovery_capture = DiscoveryModeCapture(str(self.output_dir))
        self.service_capture = ServiceModeCapture(str(self.output_dir))
        self.strategy_diff = StrategyDiff()
        self.packet_diff = PacketDiff()
        self.root_cause_analyzer = AdvancedRootCauseAnalyzer()

    def compare_modes(self, domain: str, capture_duration: int = 30) -> Dict[str, Any]:
        """
        Compare strategy application between discovery and service modes.

        Args:
            domain: Domain to analyze
            capture_duration: How long to capture service mode (seconds)

        Returns:
            Complete comparison results with root cause analysis
        """
        self.logger.info(f"Starting comprehensive strategy comparison for {domain}")
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Private attributes; does not change public API
        self.discovery_capture._run_id = run_id
        self.service_capture._run_id = run_id

        try:
            # Run discovery mode
            self.logger.info("Running discovery mode capture...")
            discovery_capture = self.discovery_capture.run_discovery_mode(domain)

            # Run service mode
            self.logger.info("Running service mode capture...")
            service_capture = self.service_capture.capture_service_mode(
                domain, duration=capture_duration
            )

            # Compare strategies
            self.logger.info("Comparing strategies...")
            strategy_comparison = self.strategy_diff.compare_strategies(
                discovery_capture, service_capture
            )

            # Compare packets
            self.logger.info("Comparing packets...")
            packet_comparison = self.packet_diff.compare_packets(discovery_capture, service_capture)

            # Perform root cause analysis
            self.logger.info("Performing root cause analysis...")
            root_cause_analysis = self.root_cause_analyzer.analyze_root_causes(
                strategy_comparison, packet_comparison
            )

            # Generate comprehensive results
            results = {
                "domain": domain,
                "timestamp": run_id,
                "discovery_capture": discovery_capture.to_dict(),
                "service_capture": service_capture.to_dict(),
                "strategy_comparison": strategy_comparison.to_dict(),
                "packet_comparison": packet_comparison.to_dict(),
                "root_cause_analysis": root_cause_analysis.to_dict(),
            }

            # Save results
            self._save_comparison_results(results)

            # Generate and save report
            report = self._generate_comprehensive_report(results)
            self._save_report(report, domain)

            self.logger.info(f"Strategy comparison complete for {domain}")
            return results

        except (ImportError, AttributeError, RuntimeError) as e:
            self.logger.error(f"Strategy comparison failed for {domain}: {e}")
            raise

    def _save_comparison_results(self, results: Dict[str, Any]):
        """Save comparison results to JSON file"""
        timestamp = results["timestamp"]
        domain = results["domain"]
        output_file = self.output_dir / f"comparison_{domain}_{timestamp}.json"

        save_json_file(
            data=results,
            output_file=output_file,
            description="comparison results",
            default_handler=str,
        )

    def _generate_comprehensive_report(self, results: Dict[str, Any]) -> str:
        """Generate comprehensive comparison report"""
        lines = []
        lines.append("=" * 120)
        lines.append(f"COMPREHENSIVE STRATEGY COMPARISON REPORT: {results['domain']}")
        lines.append("=" * 120)
        lines.append(f"Analysis Date: {results['timestamp']}")
        lines.append("")

        # Strategy comparison summary
        strategy_comp = results["strategy_comparison"]
        lines.append("STRATEGY COMPARISON SUMMARY:")
        lines.append(f"  Discovery Strategy: {strategy_comp['discovery_strategy']}")
        lines.append(f"  Service Strategy:   {strategy_comp['service_strategy']}")
        lines.append(f"  Strategies Match:   {'✓' if strategy_comp['strategies_match'] else '✗'}")
        lines.append(f"  Differences Found:  {strategy_comp['difference_count']}")
        lines.append(f"  Critical Issues:    {strategy_comp['critical_differences']}")
        lines.append("")

        # Packet comparison summary
        packet_comp = results["packet_comparison"]
        lines.append("PACKET COMPARISON SUMMARY:")
        lines.append(f"  Discovery Packets: {packet_comp['discovery_packet_count']}")
        lines.append(f"  Service Packets:   {packet_comp['service_packet_count']}")
        lines.append(f"  Packets Match:     {'✓' if packet_comp['packets_match'] else '✗'}")
        lines.append(f"  Differences Found: {packet_comp['difference_count']}")
        lines.append(f"  Critical Issues:   {packet_comp['critical_differences']}")
        lines.append("")

        # Root cause analysis
        rca = results["root_cause_analysis"]
        lines.append("ROOT CAUSE ANALYSIS:")
        lines.append(f"  Overall Confidence: {rca['confidence_score']:.2f}")
        lines.append(f"  Causes Identified:  {len(rca['identified_causes'])}")
        lines.append(f"  Fix Recommendations: {len(rca['fix_recommendations'])}")
        lines.append("")

        # Add detailed root cause analysis report
        rca_obj = AdvancedRootCauseAnalysis(**{k: v for k, v in rca.items() if k != "summary"})
        detailed_rca_report = self.root_cause_analyzer.generate_report(rca_obj)
        lines.append(detailed_rca_report)

        return "\n".join(lines)

    def _save_report(self, report: str, domain: str):
        """Save comprehensive report to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.output_dir / f"report_{domain}_{timestamp}.txt"

        try:
            with open(report_file, "w", encoding="utf-8") as f:
                f.write(report)

            self.logger.info(f"Saved comprehensive report to {report_file}")

        except (IOError, OSError) as e:
            self.logger.error(f"Failed to save report: {e}")
            raise


# Public API exports for backward compatibility
__all__ = [
    # Data classes
    "StrategyCapture",
    "StrategyDifference",
    "StrategyComparison",
    "PacketDifference",
    "PacketComparison",
    "RootCauseAnalysis",
    "AdvancedRootCauseAnalysis",
    # Main classes
    "DiscoveryModeCapture",
    "ServiceModeCapture",
    "StrategyDiff",
    "PacketDiff",
    "RootCauseAnalyzer",
    "AdvancedRootCauseAnalyzer",
    "StrategyComparatorTool",
    "StrategyComparator",
    # Utility re-exports for convenience
    "resolve_domain",
    "start_packet_capture",
    "stop_packet_capture",
    "save_capture_to_json",
    "save_json_file",
]
