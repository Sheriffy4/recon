# recon/core/fingerprint/analyzer.py

"""
Advanced packet and behavior analysis for DPI fingerprinting.
"""

import logging
import statistics
from typing import List, Dict, Optional, Any, Tuple
from collections import defaultdict, deque
from datetime import datetime

from scapy.all import Packet, IP, IPv6, TCP, ICMP

# ИСПРАВЛЕНИЕ 1: Импортируем ProbeConfig и UltimateDPIProber вместо ProbeOrchestrator
from .models import Fingerprint, EnhancedFingerprint, DPIBehaviorProfile, ProbeConfig
from .prober import UltimateDPIProber

# --- КОНЕЦ ИЗМЕНЕНИЙ ---

LOG = logging.getLogger(__name__)


class PacketAnalyzer:
    """
    Analyzes captured packets to extract DPI fingerprint characteristics.
    """

    # ... (содержимое класса PacketAnalyzer остается без изменений) ...

    def __init__(
        self, target_ip: str, target_port: int = 443, domain: Optional[str] = None
    ):
        self.target_ip = target_ip
        self.target_port = target_port
        self.packet_buffer = deque(maxlen=1000)
        self.rst_packets = []
        self.timing_data = []
        self.domain = domain  # Сохраняем domain

    def analyze_packets(self, packets: List[Packet]) -> Fingerprint:
        """
        Analyze packet list to create initial fingerprint.
        """
        # Изменение 2: Передаем domain при создании Fingerprint
        fp = Fingerprint(domain=self.domain or "unknown.domain")

        # Store packets for detailed analysis
        self.packet_buffer.extend(packets)

        # Extract RST packets
        self.rst_packets = self._extract_rst_packets(packets)

        if self.rst_packets:
            fp = self._analyze_rst_characteristics(fp, self.rst_packets)

        # Analyze ICMP packets
        fp = self._analyze_icmp_packets(fp, packets)

        # Analyze timing patterns
        fp = self._analyze_timing_patterns(fp, packets)

        # Analyze TCP behavior
        fp = self._analyze_tcp_behavior(fp, packets)

        return fp

    def _extract_rst_packets(self, packets: List[Packet]) -> List[Packet]:
        """Extract TCP RST packets from packet list."""
        return [p for p in packets if p.haslayer(TCP) and p[TCP].flags.R]

    def _analyze_rst_characteristics(
        self, fp: Fingerprint, rst_packets: List[Packet]
    ) -> Fingerprint:
        """Analyze RST packet characteristics."""
        if not rst_packets:
            return fp

        rst = rst_packets[0]  # Analyze first RST

        # Basic characteristics
        if rst.haslayer(IP):
            fp.rst_ttl = rst[IP].ttl
            fp.rst_from_target = rst[IP].src == self.target_ip
        elif rst.haslayer(IPv6):
            fp.rst_ttl = rst[IPv6].hlim
            fp.rst_from_target = rst[IPv6].src == self.target_ip

        # TCP options analysis
        if rst.haslayer(TCP):
            tcp = rst[TCP]
            fp.tcp_options = tuple(opt[0] for opt in tcp.options)
            fp.timestamp_in_rst = any(opt[0] == "Timestamp" for opt in tcp.options)
            fp.window_size_in_rst = tcp.window

            # Check for specific option patterns
            fp.tcp_timestamps_modified = self._check_timestamp_manipulation(tcp.options)

        # Calculate RST distance
        if fp.rst_ttl:
            fp.rst_distance = self._estimate_hop_distance(fp.rst_ttl)

        # Timing analysis
        if hasattr(rst, "time"):
            fp.rst_latency_ms = self._calculate_rst_latency(rst)

        return fp

    def _analyze_icmp_packets(
        self, fp: Fingerprint, packets: List[Packet]
    ) -> Fingerprint:
        """Analyze ICMP packets for DPI indicators."""
        icmp_packets = [p for p in packets if p.haslayer(ICMP)]

        for pkt in icmp_packets:
            icmp = pkt[ICMP]

            # TTL exceeded
            if icmp.type == 11 and icmp.code == 0:
                fp.icmp_ttl_exceeded = True

                # Extract embedded packet info
                if pkt.haslayer(IP) and len(pkt[IP].payload) > 8:
                    # Analyze the original packet that triggered ICMP
                    pass

        return fp

    def _analyze_timing_patterns(
        self, fp: Fingerprint, packets: List[Packet]
    ) -> Fingerprint:
        """Analyze timing patterns in packet flow."""
        if len(packets) < 2:
            return fp

        # Calculate inter-packet delays
        delays = []
        for i in range(1, len(packets)):
            if hasattr(packets[i], "time") and hasattr(packets[i - 1], "time"):
                delay = packets[i].time - packets[i - 1].time
                delays.append(delay * 1000)  # Convert to ms

        if delays:
            # Store timing statistics
            fp.ml_features["timing_mean"] = statistics.mean(delays)
            fp.ml_features["timing_std"] = (
                statistics.stdev(delays) if len(delays) > 1 else 0
            )
            fp.ml_features["timing_min"] = min(delays)
            fp.ml_features["timing_max"] = max(delays)

        return fp

    def _analyze_tcp_behavior(
        self, fp: Fingerprint, packets: List[Packet]
    ) -> Fingerprint:
        """Analyze TCP-specific behavior."""
        tcp_packets = [p for p in packets if p.haslayer(TCP)]

        if not tcp_packets:
            return fp

        # Analyze TCP flags distribution
        flag_counts = defaultdict(int)
        for pkt in tcp_packets:
            flags = pkt[TCP].flags
            flag_counts[str(flags)] += 1

        # Check for unusual flag combinations
        unusual_flags = ["FPU", "FPUA", "URG"]
        for flag_combo in unusual_flags:
            if flag_combo in flag_counts:
                fp.ml_features[f"tcp_flag_{flag_combo}"] = flag_counts[flag_combo]

        # Analyze sequence numbers
        seq_numbers = [p[TCP].seq for p in tcp_packets if p[TCP].seq]
        if len(seq_numbers) > 1:
            # Check for sequence number randomness
            seq_diffs = [
                seq_numbers[i + 1] - seq_numbers[i] for i in range(len(seq_numbers) - 1)
            ]
            if seq_diffs:
                fp.ml_features["seq_randomness"] = (
                    statistics.stdev(seq_diffs) if len(seq_diffs) > 1 else 0
                )

        return fp

    def _estimate_hop_distance(self, ttl: int) -> int:
        """Estimate hop distance based on TTL."""
        common_initial_ttls = [255, 128, 64, 32]

        for initial_ttl in common_initial_ttls:
            if ttl <= initial_ttl:
                return initial_ttl - ttl

        return 0

    def _calculate_rst_latency(self, rst_packet: Packet) -> float:
        """Calculate RST response latency."""
        # This would need to correlate with the triggering packet
        # For now, return a placeholder
        return 0.0

    def _check_timestamp_manipulation(self, tcp_options: List[Tuple]) -> bool:
        """Check if TCP timestamps show signs of manipulation."""
        for opt_name, opt_value in tcp_options:
            if opt_name == "Timestamp" and opt_value:
                ts_val, ts_ecr = opt_value
                # Check for zeroed or suspicious values
                if ts_val == 0 or ts_ecr == 0:
                    return True
                # Check for non-monotonic timestamps
                # (would need historical data for proper check)

        return False


class BehaviorAnalyzer:
    """
    Analyzes DPI behavioral patterns over time.
    """

    def __init__(self):
        self.session_data = defaultdict(list)
        self.temporal_patterns = defaultdict(deque)
        self.ml_detector = MLAnomalyDetector()

    def analyze_behavior(
        self, fingerprint: EnhancedFingerprint, attack_results: Dict[str, List[float]]
    ) -> DPIBehaviorProfile:
        """
        Create comprehensive behavioral profile from fingerprint and attack results.
        """
        profile = DPIBehaviorProfile(
            dpi_system_id=f"{fingerprint.domain}_{fingerprint.dpi_type}"
        )

        # Analyze detection patterns
        profile.detection_patterns = self._analyze_detection_patterns(fingerprint)

        # Analyze evasion effectiveness
        profile.evasion_effectiveness = attack_results.copy()

        # Analyze temporal patterns
        profile.temporal_patterns = self._analyze_temporal_patterns(
            fingerprint, attack_results
        )

        # Analyze packet size sensitivity
        profile.packet_size_sensitivity = self._analyze_size_sensitivity(fingerprint)

        # Analyze protocol handling
        profile.protocol_handling = self._analyze_protocol_handling(fingerprint)

        # Advanced analysis
        profile.traffic_shaping_detected = self._detect_traffic_shaping(fingerprint)
        profile.qos_manipulation = self._analyze_qos_manipulation(fingerprint)
        profile.ssl_interception_indicators = self._detect_ssl_interception(fingerprint)

        return profile

    def _analyze_detection_patterns(self, fp: EnhancedFingerprint) -> Dict[str, Any]:
        """Analyze how DPI detects different traffic patterns."""
        patterns = {
            "signature_based": False,
            "behavioral_analysis": False,
            "ml_detection": False,
            "statistical_analysis": False,
            "protocol_validation": False,
            "timing_analysis": False,
        }

        # Signature-based detection
        if fp.sni_case_sensitive or fp.ech_blocked:
            patterns["signature_based"] = True

        # Behavioral analysis
        if fp.stateful_inspection and fp.tcp_option_splicing:
            patterns["behavioral_analysis"] = True

        # ML detection
        if fp.ml_detection_blocked:
            patterns["ml_detection"] = True

        # Statistical analysis
        if fp.rate_limiting_detected:
            patterns["statistical_analysis"] = True

        # Protocol validation
        if fp.checksum_validation and not fp.large_payload_bypass:
            patterns["protocol_validation"] = True

        # Timing analysis
        if (
            "timing_sensitivity" in fp.timing_sensitivity
            and fp.timing_sensitivity["timing_sensitivity"] > 0.7
        ):
            patterns["timing_analysis"] = True

        return patterns

    def _analyze_temporal_patterns(
        self, fp: EnhancedFingerprint, attack_results: Dict[str, List[float]]
    ) -> Dict[str, List[float]]:
        """Analyze temporal patterns in DPI behavior."""
        patterns = {
            "hourly_effectiveness": [],
            "burst_tolerance": [],
            "sustained_rate": [],
            "detection_delay": [],
        }

        # Simulate hourly effectiveness variations
        current_hour = datetime.now().hour
        base_effectiveness = 0.6

        for hour in range(24):
            # Model effectiveness based on time of day
            if 9 <= hour <= 17:  # Business hours
                effectiveness = base_effectiveness * 0.8
            elif 0 <= hour <= 6:  # Night hours
                effectiveness = base_effectiveness * 1.2
            else:
                effectiveness = base_effectiveness

            patterns["hourly_effectiveness"].append(min(effectiveness, 1.0))

        # Analyze burst tolerance from attack results
        for technique, results in attack_results.items():
            if len(results) > 10:
                # Check effectiveness during bursts
                burst_results = results[:10]
                sustained_results = (
                    results[10:20] if len(results) > 20 else results[10:]
                )

                burst_effectiveness = (
                    sum(burst_results) / len(burst_results) if burst_results else 0
                )
                sustained_effectiveness = (
                    sum(sustained_results) / len(sustained_results)
                    if sustained_results
                    else 0
                )

                patterns["burst_tolerance"].append(burst_effectiveness)
                patterns["sustained_rate"].append(sustained_effectiveness)

        return patterns

    def _analyze_size_sensitivity(self, fp: EnhancedFingerprint) -> Dict[int, float]:
        """Analyze DPI sensitivity to packet sizes."""
        sensitivity = {}

        # Standard packet sizes to test
        test_sizes = [64, 128, 256, 512, 768, 1024, 1280, 1400, 1500]

        # Base effectiveness from large payload bypass test
        base_effectiveness = 0.5
        if fp.large_payload_bypass:
            base_effectiveness = 0.8

        for size in test_sizes:
            if size < 256:
                # Small packets often scrutinized more
                effectiveness = base_effectiveness * 0.7
            elif size > 1280:
                # Large packets might bypass some checks
                effectiveness = (
                    base_effectiveness * 1.3
                    if fp.large_payload_bypass
                    else base_effectiveness * 0.9
                )
            else:
                effectiveness = base_effectiveness

            sensitivity[size] = min(effectiveness, 1.0)

        return sensitivity

    def _analyze_protocol_handling(self, fp: EnhancedFingerprint) -> Dict[str, str]:
        """Analyze how DPI handles different protocols."""
        handling = {}

        # HTTP/HTTPS
        if fp.http2_support:
            handling["http2"] = "allowed"
        else:
            handling["http2"] = "blocked"

        handling["https"] = (
            "deep_inspection" if fp.sni_case_sensitive else "basic_inspection"
        )

        # QUIC/HTTP3
        if fp.quic_udp_blocked:
            handling["quic"] = "blocked"
            handling["http3"] = "blocked"
        else:
            handling["quic"] = "allowed"
            handling["http3"] = "allowed" if fp.http3_quic_support else "unsupported"

        # DNS
        if fp.dns_over_https_blocked:
            handling["dns_over_https"] = "blocked"
            handling["dns_over_tls"] = "likely_blocked"
        else:
            handling["dns_over_https"] = "allowed"
            handling["dns_over_tls"] = "allowed"

        # VPN protocols
        handling["openvpn"] = "detected" if fp.ml_detection_blocked else "allowed"
        handling["wireguard"] = "detected" if fp.quic_udp_blocked else "allowed"

        return handling

    def _detect_traffic_shaping(self, fp: EnhancedFingerprint) -> bool:
        """Detect if DPI performs traffic shaping."""
        indicators = [
            fp.rate_limiting_detected,
            fp.timing_sensitivity.get("burst_tolerance", 1.0) < 0.5,
            "qos" in str(fp.classification_reasons).lower(),
        ]

        return sum(indicators) >= 2

    def _analyze_qos_manipulation(self, fp: EnhancedFingerprint) -> Dict[str, Any]:
        """Analyze Quality of Service manipulation."""
        qos_data = {"detected": False, "methods": [], "affected_protocols": []}

        if fp.rate_limiting_detected:
            qos_data["detected"] = True
            qos_data["methods"].append("rate_limiting")

        if fp.packet_processing_stats.get("delayed_packets", 0) > 0:
            qos_data["detected"] = True
            qos_data["methods"].append("packet_delay")

        # Check which protocols are affected
        if fp.quic_udp_blocked:
            qos_data["affected_protocols"].append("quic")

        if not fp.http2_support:
            qos_data["affected_protocols"].append("http2")

        return qos_data

    def _detect_ssl_interception(self, fp: EnhancedFingerprint) -> List[str]:
        """Detect indicators of SSL/TLS interception."""
        indicators = []

        # Check for MITM indicators
        if fp.sni_case_sensitive:
            indicators.append("sni_validation")

        if fp.ech_blocked and fp.esni_support is False:
            indicators.append("encrypted_sni_blocked")

        if fp.tls13_0rtt_blocked:
            indicators.append("tls13_early_data_blocked")

        if fp.checksum_validation and fp.tcp_timestamps_modified:
            indicators.append("packet_modification_detected")

        # Check for certificate validation behavior
        if fp.tls_fingerprint and "intercepted" in fp.tls_fingerprint:
            indicators.append("tls_fingerprint_mismatch")

        return indicators


class MLAnomalyDetector:
    """
    Machine Learning based anomaly detection for DPI behavior.
    """

    def __init__(self):
        self.baseline_profiles = {}
        self.anomaly_threshold = 2.0  # Standard deviations

    def detect_anomalies(self, profile: DPIBehaviorProfile) -> Dict[str, float]:
        """
        Detect anomalies in DPI behavior compared to baseline.
        """
        anomalies = {}

        # Get or create baseline for this DPI type
        baseline = self.baseline_profiles.get(profile.dpi_system_id, {})

        if not baseline:
            # First time seeing this DPI, establish baseline
            self._update_baseline(profile)
            return anomalies

        # Compare current profile to baseline
        # Check evasion effectiveness
        for technique, effectiveness in profile.evasion_effectiveness.items():
            if technique in baseline.get("evasion_effectiveness", {}):
                baseline_eff = baseline["evasion_effectiveness"][technique]["mean"]
                baseline_std = baseline["evasion_effectiveness"][technique]["std"]

                if baseline_std > 0:
                    z_score = abs(effectiveness - baseline_eff) / baseline_std
                    if z_score > self.anomaly_threshold:
                        anomalies[f"evasion_{technique}"] = z_score

        # Check temporal patterns
        if "hourly_effectiveness" in profile.temporal_patterns:
            current_pattern = profile.temporal_patterns["hourly_effectiveness"]
            baseline_pattern = baseline.get("temporal_pattern", [])

            if baseline_pattern and len(current_pattern) == len(baseline_pattern):
                pattern_diff = sum(
                    abs(c - b) for c, b in zip(current_pattern, baseline_pattern)
                )
                pattern_diff_normalized = pattern_diff / len(current_pattern)

                if pattern_diff_normalized > 0.2:  # 20% deviation
                    anomalies["temporal_pattern_shift"] = pattern_diff_normalized

        return anomalies

    def _update_baseline(self, profile: DPIBehaviorProfile):
        """Update baseline profile with new data."""
        baseline = self.baseline_profiles.setdefault(profile.dpi_system_id, {})

        # Update evasion effectiveness baseline
        if "evasion_effectiveness" not in baseline:
            baseline["evasion_effectiveness"] = {}

        for technique, effectiveness in profile.evasion_effectiveness.items():
            if technique not in baseline["evasion_effectiveness"]:
                baseline["evasion_effectiveness"][technique] = {
                    "values": [],
                    "mean": 0,
                    "std": 0,
                }

            tech_baseline = baseline["evasion_effectiveness"][technique]
            tech_baseline["values"].append(effectiveness)

            # Keep only recent values (last 100)
            if len(tech_baseline["values"]) > 100:
                tech_baseline["values"] = tech_baseline["values"][-100:]

            # Recalculate statistics
            if len(tech_baseline["values"]) > 1:
                tech_baseline["mean"] = statistics.mean(tech_baseline["values"])
                tech_baseline["std"] = statistics.stdev(tech_baseline["values"])

        # Update temporal pattern baseline
        if "hourly_effectiveness" in profile.temporal_patterns:
            baseline["temporal_pattern"] = profile.temporal_patterns[
                "hourly_effectiveness"
            ]


async def comprehensive_analysis(
    target_ip: str,
    target_port: int = 443,
    packets: List[Packet] = None,
    domain: str = None,
) -> EnhancedFingerprint:
    """
    Perform comprehensive DPI analysis combining all techniques.
    """
    LOG.info(f"Starting comprehensive DPI analysis for {target_ip}:{target_port}")

    # Изменение 3: Передаем domain в конструктор PacketAnalyzer
    packet_analyzer = PacketAnalyzer(target_ip, target_port, domain=domain)

    # ИСПРАВЛЕНИЕ 2: Заменяем ProbeOrchestrator на UltimateDPIProber
    probe_config = ProbeConfig(target_ip=target_ip, port=target_port)
    prober = UltimateDPIProber(probe_config)
    classifier = DPIClassifier()

    # Create enhanced fingerprint
    efp = EnhancedFingerprint(
        domain=domain or target_ip, ip_addresses=[target_ip], timestamp=datetime.now()
    )

    # Phase 1: Packet analysis (if packets provided)
    if packets:
        LOG.info("Analyzing captured packets...")
        basic_fp = packet_analyzer.analyze_packets(packets)

        # Copy basic fingerprint data to enhanced fingerprint
        for attr in dir(basic_fp):
            if not attr.startswith("_") and hasattr(efp, attr):
                setattr(efp, attr, getattr(basic_fp, attr))

    # Phase 2: Active probing
    LOG.info("Performing active DPI probing...")
    # ИСПРАВЛЕНИЕ 3: Вызываем новый метод run_probes
    probed_fp_dict = await prober.run_probes(domain, force_all=True)

    # Merge probed data
    for attr, value in probed_fp_dict.items():
        if hasattr(efp, attr):
            if value is not None:
                setattr(efp, attr, value)

    # Phase 3: Classification
    LOG.info("Classifying DPI system...")
    classification = classifier.classify(efp)

    # Phase 4: Generate recommendations
    efp.technique_success_rates = {
        "tcp_segmentation": 0.7 if not efp.stateful_inspection else 0.4,
        "ip_fragmentation": 0.8 if efp.supports_ip_frag else 0.1,
        "payload_encryption": 0.9 if not efp.ml_detection_blocked else 0.6,
        "timing_evasion": 0.6 if efp.rate_limiting_detected else 0.8,
        "checksum_confusion": 0.9 if not efp.checksum_validation else 0.0,
    }

    # Phase 5: Network topology analysis
    efp.network_path = _trace_network_path(target_ip)
    efp.asn_info = _get_asn_info(target_ip)

    LOG.info(
        f"Comprehensive analysis complete: {classification.dpi_type} [{classification.confidence:.0%}]"
    )

    return efp


def _trace_network_path(target_ip: str) -> List[str]:
    """Trace network path to target (simplified)."""
    # This would use traceroute functionality
    # For now, return placeholder
    return ["gateway", "isp_router", "dpi_box", target_ip]


def _get_asn_info(ip: str) -> Dict[str, Any]:
    """Get ASN information for IP (simplified)."""
    # This would query ASN databases
    # For now, return placeholder
    return {"asn": "AS12345", "name": "Example ISP", "country": "US"}


# --- ИСПРАВЛЕНИЕ 4: Добавляем недостающую функцию apply_probe_results ---
def apply_probe_results(probe_results: Dict[str, Any], fp: EnhancedFingerprint):
    """Applies the results from probing to the fingerprint object."""
    for key, value in probe_results.items():
        if hasattr(fp, key):
            setattr(fp, key, value)
