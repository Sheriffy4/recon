"""
Fingerprint Processing Methods Module
Extracted from AdvancedFingerprinter for better organization and maintainability

This module contains all methods that process and manipulate DPI fingerprints,
including applying metrics, generating hints, and making predictions.
"""

import hashlib
from typing import Dict, List, Any
from core.fingerprint.advanced_models import DPIFingerprint, DPIType
from core.protocols.tls import ClientHelloInfo


class FingerprintProcessor:
    """
    Centralized fingerprint processing methods
    """

    def __init__(self, logger):
        """
        Initialize Fingerprint Processor

        Args:
            logger: Logger instance
        """
        self.logger = logger

    def apply_extended_metrics_to_fingerprint(
        self, fingerprint: DPIFingerprint, extended: Dict[str, Any]
    ):
        """
        Apply extended metrics to fingerprint

        Integrates extended metrics collected from various sources into
        the fingerprint object.

        Args:
            fingerprint: DPI fingerprint to update
            extended: Extended metrics dictionary
        """
        if not extended or "error" in extended:
            return

        rm = fingerprint.raw_metrics
        rm["extended_metrics"] = extended

        # Map key metrics
        https_metrics = extended.get("https", extended)

        if "baseline_block_type" in https_metrics:
            if not fingerprint.block_type or fingerprint.block_type == "unknown":
                fingerprint.block_type = https_metrics["baseline_block_type"]

        if "rst_ttl_distance" in https_metrics:
            rm.setdefault("rst_ttl_stats", {})["distance"] = https_metrics["rst_ttl_distance"]

        # Protocol support
        for proto in ["http2_support", "quic_support", "ech_support"]:
            if proto in https_metrics:
                rm[proto] = https_metrics[proto]

        # Additional protocol features
        if "http3_support" in https_metrics:
            rm["http3_support"] = bool(https_metrics["http3_support"])
        if "ech_present" in https_metrics:
            rm["ech_present"] = bool(https_metrics["ech_present"])
        if "ech_blocked" in https_metrics:
            rm["ech_blocked"] = bool(https_metrics["ech_blocked"])

        # SNI consistency
        if "sni_consistency_blocked" in https_metrics:
            rm.setdefault("sni_sensitivity", {})["consistency_blocked"] = https_metrics[
                "sni_consistency_blocked"
            ]

        # Content filtering indicators
        cfi = https_metrics.get("content_filtering_indicators", {})
        if cfi:
            fingerprint.content_inspection_depth = max(
                getattr(fingerprint, "content_inspection_depth", 0),
                len(cfi) * 100,  # Rough estimate
            )

    def apply_behavioral_metrics_to_fingerprint(
        self, fingerprint: DPIFingerprint, behavioral_metrics: Dict[str, Any]
    ):
        """
        Apply behavioral metrics to fingerprint

        Integrates behavioral analysis results into the fingerprint.

        Args:
            fingerprint: DPI fingerprint to update
            behavioral_metrics: Behavioral metrics dictionary
        """
        if not behavioral_metrics or "error" in behavioral_metrics:
            return

        # Reordering tolerance
        reordering = behavioral_metrics.get("reordering_tolerance", {})
        if reordering.get("tolerates_reordering"):
            fingerprint.raw_metrics["packet_reordering_tolerant"] = True
            fingerprint.raw_metrics["max_reorder_distance"] = reordering.get(
                "max_reorder_distance", 0
            )

        # Fragmentation
        frag = behavioral_metrics.get("fragmentation_handling", {})
        if frag.get("supports_ip_fragmentation"):
            setattr(fingerprint, "supports_ip_frag", True)
            fingerprint.raw_metrics["min_fragment_size"] = frag.get("min_fragment_size")

        # Timing patterns
        timing = behavioral_metrics.get("timing_patterns", {})
        if "connect_time_ms" in timing:
            fingerprint.connection_latency = timing["connect_time_ms"]
        if "tls_handshake_ms" in timing:
            fingerprint.raw_metrics["tls_handshake_latency"] = timing["tls_handshake_ms"]

        # Packet size limits
        limits = behavioral_metrics.get("packet_size_limits", {})
        if limits.get("max_tcp_payload"):
            fingerprint.packet_size_limitations = limits["max_tcp_payload"]
        if limits.get("jumbo_frames_supported"):
            fingerprint.raw_metrics["jumbo_frames_supported"] = True

    def generate_strategy_hints(self, fingerprint: DPIFingerprint) -> List[str]:
        """
        Generate strategy hints based on collected data

        Analyzes fingerprint data to generate actionable hints for
        bypass strategy selection.

        Args:
            fingerprint: DPI fingerprint with collected metrics

        Returns:
            List of strategy hint strings
        """
        hints = []
        rm = fingerprint.raw_metrics

        # QUIC blocking
        if rm.get("quic_probe", {}).get("blocked") or not rm.get("quic_support"):
            hints.append("disable_quic")

        # SNI sensitivity
        if rm.get("sni_sensitivity", {}).get("likely") or rm.get("sni_sensitivity", {}).get(
            "confirmed"
        ):
            hints.append("split_tls_sni")
            if rm.get("sni_probe", {}).get("sni_validation_type") == "strict_domain":
                hints.append("use_domain_fronting")

        # Protocol preferences
        if not rm.get("http2_support"):
            hints.append("prefer_http11")
        elif rm.get("http2_support") and not rm.get("alpn_h2_supported"):
            hints.append("force_http2_prior_knowledge")

        # CDN detection
        cdn_markers = ["cloudflare", "fastly", "akamai", "cloudfront"]
        if any(m in fingerprint.target.lower() for m in cdn_markers):
            hints.append("cdn_aware_strategy")

        # Fragmentation support
        if getattr(fingerprint, "supports_ip_frag", False):
            hints.append("use_fragmentation")

        # Timing sensitivity
        if rm.get("timing_probe", {}).get("timing_sensitive"):
            hints.append("use_timing_attacks")

        # Packet reordering
        if rm.get("packet_reordering_tolerant"):
            hints.append("tcp_segment_reordering")

        # RST injection
        if fingerprint.rst_injection_detected:
            hints.append("tcp_disorder_defense")

        return hints

    def populate_coherent_fingerprint_features(
        self, fingerprint: DPIFingerprint, client_hello_info: ClientHelloInfo
    ):
        """
        Populate fingerprint with ClientHello features

        Extracts TLS features from ClientHello for coherent mimicry.

        Args:
            fingerprint: DPI fingerprint to update
            client_hello_info: Parsed ClientHello information
        """
        if not client_hello_info:
            return

        # Map ClientHello info to fingerprint attributes if they exist
        if hasattr(fingerprint, "cipher_suites_order"):
            fingerprint.cipher_suites_order = client_hello_info.cipher_suites
        if hasattr(fingerprint, "extensions_order"):
            fingerprint.extensions_order = client_hello_info.extensions_order
        if hasattr(fingerprint, "supported_groups"):
            fingerprint.supported_groups = client_hello_info.supported_groups
        if hasattr(fingerprint, "signature_algorithms"):
            fingerprint.signature_algorithms = client_hello_info.signature_algorithms
        if hasattr(fingerprint, "ec_point_formats"):
            fingerprint.ec_point_formats = client_hello_info.ec_point_formats
        if hasattr(fingerprint, "alpn_protocols"):
            fingerprint.alpn_protocols = client_hello_info.alpn_protocols

    def integrate_analysis_result(
        self, fingerprint: DPIFingerprint, task_name: str, result: Dict[str, Any]
    ):
        """
        Integrate analysis results into fingerprint

        Processes results from various analyzers and integrates them
        into the fingerprint object.

        Args:
            fingerprint: DPI fingerprint to update
            task_name: Name of the analysis task
            result: Analysis result dictionary
        """
        if task_name == "tcp_analysis" and result:
            fingerprint.rst_injection_detected = result.get("rst_injection_detected", False)
            fingerprint.rst_source_analysis = result.get("rst_source_analysis", "unknown")
            fingerprint.tcp_window_manipulation = result.get("tcp_window_manipulation", False)
            fingerprint.sequence_number_anomalies = result.get("sequence_number_anomalies", False)
            fingerprint.handshake_anomalies = result.get("handshake_anomalies", [])
            fingerprint.tcp_options_filtering = bool(result.get("tcp_options_filtering", []))

            # Optional TCP attributes
            for attr in [
                "tcp_window_size",
                "tcp_mss",
                "tcp_sack_permitted",
                "tcp_timestamps_enabled",
                "syn_ack_to_client_hello_delta",
            ]:
                if attr in result:
                    setattr(fingerprint, attr, result[attr])

        elif task_name == "http_analysis" and result:
            fingerprint.http_header_filtering = result.get("http_header_filtering", False)
            fingerprint.content_inspection_depth = result.get("content_inspection_depth", 0)
            fingerprint.user_agent_filtering = result.get("user_agent_filtering", False)
            fingerprint.host_header_manipulation = result.get("host_header_manipulation", False)
            fingerprint.http_method_restrictions = result.get("http_method_restrictions", [])
            fingerprint.content_type_filtering = result.get("content_type_filtering", False)
            fingerprint.redirect_injection = result.get("redirect_injection", False)
            fingerprint.http_response_modification = result.get("http_response_modification", False)
            fingerprint.keep_alive_manipulation = result.get("keep_alive_manipulation", False)

        elif task_name == "dns_analysis" and result:
            fingerprint.dns_hijacking_detected = result.get("dns_hijacking_detected", False)
            fingerprint.dns_response_modification = result.get("dns_response_modification", False)
            fingerprint.dns_query_filtering = result.get("dns_query_filtering", False)
            fingerprint.doh_blocking = result.get("doh_blocking", False)
            fingerprint.dot_blocking = result.get("dot_blocking", False)
            fingerprint.dns_cache_poisoning = result.get("dns_cache_poisoning", False)
            fingerprint.dns_timeout_manipulation = result.get("dns_timeout_manipulation", False)
            fingerprint.recursive_resolver_blocking = result.get(
                "recursive_resolver_blocking", False
            )
            fingerprint.dns_over_tcp_blocking = result.get("dns_over_tcp_blocking", False)
            fingerprint.edns_support = result.get("edns_support", False)

        # Store raw result
        fingerprint.raw_metrics[task_name] = result

    def extract_ml_features(self, fingerprint: DPIFingerprint) -> Dict[str, Any]:
        """
        Extract ML features from fingerprint

        Converts fingerprint data into feature vector for ML classification.

        Args:
            fingerprint: DPI fingerprint with collected metrics

        Returns:
            Dictionary of ML features
        """
        features = {}

        # Binary features
        binary_attrs = [
            "rst_injection_detected",
            "tcp_window_manipulation",
            "sequence_number_anomalies",
            "tcp_options_filtering",
            "mss_clamping_detected",
            "tcp_timestamp_manipulation",
            "http_header_filtering",
            "user_agent_filtering",
            "host_header_manipulation",
            "content_type_filtering",
            "redirect_injection",
            "http_response_modification",
            "keep_alive_manipulation",
            "dns_hijacking_detected",
            "dns_response_modification",
            "dns_query_filtering",
            "doh_blocking",
            "dot_blocking",
            "dns_cache_poisoning",
            "dns_timeout_manipulation",
            "recursive_resolver_blocking",
            "dns_over_tcp_blocking",
            "edns_support",
            "supports_ipv6",
            "geographic_restrictions",
            "time_based_filtering",
        ]

        for attr in binary_attrs:
            features[attr] = 1 if getattr(fingerprint, attr, False) else 0

        # Numeric features
        features["connection_reset_timing"] = getattr(fingerprint, "connection_reset_timing", 0.0)
        features["handshake_anomalies_count"] = len(getattr(fingerprint, "handshake_anomalies", []))
        features["content_inspection_depth"] = getattr(fingerprint, "content_inspection_depth", 0)
        features["http_method_restrictions_count"] = len(
            getattr(fingerprint, "http_method_restrictions", [])
        )
        features["packet_size_limitations"] = getattr(fingerprint, "packet_size_limitations", 0)
        features["protocol_whitelist_count"] = len(getattr(fingerprint, "protocol_whitelist", []))
        features["analysis_duration"] = getattr(fingerprint, "analysis_duration", 0.0)

        return features

    def predict_weaknesses(self, fingerprint: DPIFingerprint) -> List[str]:
        """
        Predict DPI weaknesses based on fingerprint

        Analyzes fingerprint to identify potential DPI weaknesses that
        can be exploited for bypass.

        Args:
            fingerprint: DPI fingerprint with collected metrics

        Returns:
            List of weakness descriptions
        """
        weaknesses = []

        if getattr(fingerprint, "supports_ip_frag", False):
            weaknesses.append("Vulnerable to IP fragmentation attacks")

        if not getattr(fingerprint, "checksum_validation", True):
            weaknesses.append("No checksum validation - checksum attacks possible")

        if getattr(fingerprint, "large_payload_bypass", False):
            weaknesses.append("Large payloads can bypass inspection")

        if not fingerprint.raw_metrics.get("ml_detection_indicators", False):
            weaknesses.append("No ML-based anomaly detection")

        if getattr(fingerprint, "rate_limiting_detected", False):
            weaknesses.append("Rate limiting detected - timing attacks possible")

        if fingerprint.raw_metrics.get("packet_reordering_tolerant"):
            weaknesses.append("Tolerates packet reordering - sequence attacks viable")

        if fingerprint.content_inspection_depth and fingerprint.content_inspection_depth < 1500:
            weaknesses.append(
                f"Limited inspection depth ({fingerprint.content_inspection_depth} bytes)"
            )

        return list(set(weaknesses))

    def predict_best_attacks(self, fingerprint: DPIFingerprint) -> List[Dict[str, Any]]:
        """
        Predict most effective attacks based on fingerprint

        Analyzes fingerprint to recommend the most likely successful
        bypass techniques.

        Args:
            fingerprint: DPI fingerprint with collected metrics

        Returns:
            List of attack predictions with scores
        """
        predictions = []
        weaknesses = self.predict_weaknesses(fingerprint)

        # Map weaknesses to attacks
        if "Vulnerable to IP fragmentation attacks" in weaknesses:
            predictions.append({"technique": "ip_fragmentation", "score": 0.9})

        if "No checksum validation" in weaknesses:
            predictions.append({"technique": "bad_checksum", "score": 0.85})

        if fingerprint.rst_injection_detected:
            predictions.append({"technique": "tcp_fakeddisorder", "score": 0.8})
            predictions.append({"technique": "tcp_multisplit", "score": 0.75})

        if fingerprint.dns_hijacking_detected:
            predictions.append({"technique": "dns_over_https", "score": 0.7})

        if fingerprint.http_header_filtering:
            predictions.append({"technique": "http_header_obfuscation", "score": 0.65})

        # Generic fallbacks
        if not predictions:
            predictions.append({"technique": "tcp_multisplit", "score": 0.5})
            predictions.append({"technique": "tcp_fakeddisorder", "score": 0.45})

        predictions.sort(key=lambda x: x["score"], reverse=True)
        return predictions[:10]

    def infer_sni_sensitivity(self, fingerprint: DPIFingerprint) -> bool:
        """
        Infer SNI sensitivity from fingerprint data

        Uses heuristics to determine if DPI is sensitive to SNI field.

        Args:
            fingerprint: DPI fingerprint with collected metrics

        Returns:
            Boolean indicating SNI sensitivity
        """
        try:
            # Check direct SNI probe results
            if fingerprint.raw_metrics.get("sni_probe", {}).get("sni_sensitive"):
                return True

            # Heuristic: RST injection + HTTP filtering often means SNI sensitivity
            if (
                fingerprint.rst_injection_detected
                and fingerprint.http_header_filtering
                and not fingerprint.dns_hijacking_detected
            ):
                return True

            # Check if SNI validation detected
            if (
                fingerprint.raw_metrics.get("sni_probe", {}).get("sni_validation_type")
                == "strict_domain"
            ):
                return True

            return False
        except Exception:
            return False

    def compute_ja3(self, client_hello_bytes: bytes) -> Dict[str, Any]:
        """
        Compute JA3 hash from ClientHello bytes

        Generates JA3 fingerprint hash for TLS client identification.

        Args:
            client_hello_bytes: Raw ClientHello packet bytes

        Returns:
            Dictionary with JA3 hash or error
        """
        try:
            # Simple MD5 hash of ClientHello bytes
            md5_hash = hashlib.md5(client_hello_bytes).hexdigest()
            return {"ja3_hash": md5_hash}
        except Exception as e:
            return {"ja3_hash": None, "error": str(e)}

    def create_fallback_fingerprint(self, target: str, error_msg: str) -> DPIFingerprint:
        """
        Create fallback fingerprint when analysis fails

        Generates a minimal fingerprint when full analysis cannot be completed.

        Args:
            target: Target domain/IP
            error_msg: Error message describing failure

        Returns:
            Fallback DPIFingerprint object
        """
        fp = DPIFingerprint(
            target=target,
            analysis_duration=0.0,
            reliability_score=0.0,
            dpi_type=DPIType.UNKNOWN,
            confidence=0.0,
        )
        fp.analysis_methods_used.append("fallback")
        fp.raw_metrics["error"] = error_msg
        return fp
