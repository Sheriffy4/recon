from __future__ import annotations
import logging
from typing import List, Optional
import numpy as np
import joblib
import os

try:
    from sklearn.ensemble import RandomForestClassifier

    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

    class RandomForestClassifier:
        pass


from core.fingerprint.models import Fingerprint, DPIClassification, DPIFamily

LOG = logging.getLogger("ultimate_classifier")


class UltimateDPIClassifier:
    """
    Ultimate DPI classifier combining all expert signatures with ML enhancement
    """

    DPI_SIGNATURES = {
        "TSPU": {
            "vendor": "TSPU/Beeline",
            "family": DPIFamily.INLINE_FAST,
            "confidence": 0.95,
            "conditions": [
                (
                    lambda fp: 60 <= (fp.rst_ttl or 0) <= 64,
                    "RST TTL in Linux range",
                    0.12,
                ),
                (lambda fp: fp.timestamp_in_rst is True, "Timestamp in RST", 0.08),
                (
                    lambda fp: fp.stateful_inspection is True,
                    "Stateful inspection",
                    0.12,
                ),
                (lambda fp: fp.ech_blocked is True, "ECH blocked", 0.08),
                (
                    lambda fp: fp.tcp_option_splicing is True,
                    "TCP option splicing sensitive",
                    0.08,
                ),
                (
                    lambda fp: (fp.dpi_hop_distance or 99) <= 5,
                    "DPI close (≤5 hops)",
                    0.08,
                ),
                (lambda fp: fp.ecn_support is False, "ECN stripped", 0.04),
                (lambda fp: fp.rate_limiting_detected is True, "Rate limiting", 0.08),
                (
                    lambda fp: fp.tls_version_sensitivity == "blocks_tls13",
                    "Blocks TLS 1.3",
                    0.08,
                ),
                (lambda fp: fp.zero_rtt_blocked is True, "0-RTT blocked", 0.04),
                (
                    lambda fp: hasattr(fp, "rst_ttl_distance")
                    and (fp.rst_ttl_distance or 0) > 10,
                    "High RST TTL distance",
                    0.08,
                ),
                (
                    lambda fp: hasattr(fp, "baseline_block_type")
                    and fp.baseline_block_type == "RST",
                    "RST-based blocking",
                    0.06,
                ),
                (
                    lambda fp: hasattr(fp, "sni_consistency_blocked")
                    and fp.sni_consistency_blocked is True,
                    "SNI consistency blocking",
                    0.06,
                ),
                (
                    lambda fp: hasattr(fp, "primary_block_method")
                    and fp.primary_block_method == "rst",
                    "Primary RST blocking",
                    0.04,
                ),
            ],
        },
        "Roskomnadzor": {
            "vendor": "RKN",
            "family": DPIFamily.NATIONAL,
            "confidence": 0.92,
            "conditions": [
                (lambda fp: fp.ip_level_blocked is True, "IP-level blocking", 0.3),
                (lambda fp: (fp.dpi_hop_distance or 99) <= 3, "Very close DPI", 0.2),
                (lambda fp: fp.quic_udp_blocked is True, "QUIC blocked", 0.15),
                (lambda fp: fp.supports_ip_frag is False, "IP frag blocked", 0.1),
                (lambda fp: fp.stateful_inspection is True, "Stateful", 0.1),
                (lambda fp: fp.dns_over_https_blocked is True, "DoH blocked", 0.1),
                (lambda fp: fp.esni_support is False, "ESNI blocked", 0.05),
            ],
        },
        "GFW": {
            "vendor": "Great Firewall",
            "family": DPIFamily.NATIONAL,
            "confidence": 0.93,
            "conditions": [
                (
                    lambda fp: 30 <= (fp.rst_ttl or 0) <= 50,
                    "RST TTL in GFW range",
                    0.18,
                ),
                (lambda fp: fp.quic_udp_blocked is True, "QUIC blocked", 0.13),
                (lambda fp: fp.supports_ip_frag is False, "IP frag blocked", 0.09),
                (
                    lambda fp: fp.large_payload_bypass is False,
                    "Large payload blocked",
                    0.09,
                ),
                (
                    lambda fp: fp.tcp_option_splicing is True,
                    "TCP splicing sensitive",
                    0.09,
                ),
                (lambda fp: fp.mptcp_support is False, "MPTCP blocked", 0.04),
                (lambda fp: fp.zero_rtt_blocked is True, "0-RTT blocked", 0.09),
                (lambda fp: fp.esni_support is False, "ESNI blocked", 0.09),
                (
                    lambda fp: fp.vpn_detection.get("openvpn", False),
                    "OpenVPN detected",
                    0.09,
                ),
                (
                    lambda fp: hasattr(fp, "rst_ttl_distance")
                    and (fp.rst_ttl_distance or 0) > 15,
                    "Very high RST TTL distance",
                    0.05,
                ),
                (
                    lambda fp: hasattr(fp, "timing_attack_vulnerable")
                    and fp.timing_attack_vulnerable is False,
                    "Timing attack resistant",
                    0.03,
                ),
                (
                    lambda fp: hasattr(fp, "quic_support") and fp.quic_support is False,
                    "No QUIC support",
                    0.02,
                ),
            ],
        },
        "Iran_NIN": {
            "vendor": "Iran National Internet",
            "family": DPIFamily.NATIONAL,
            "confidence": 0.88,
            "conditions": [
                (lambda fp: fp.esni_support is False, "ESNI blocked", 0.2),
                (lambda fp: fp.ech_blocked is True, "ECH blocked", 0.2),
                (lambda fp: fp.quic_udp_blocked is True, "QUIC blocked", 0.15),
                (lambda fp: fp.ml_detection_blocked is True, "ML detection", 0.15),
                (lambda fp: (fp.dpi_hop_distance or 99) <= 4, "Close DPI", 0.1),
                (
                    lambda fp: fp.vpn_detection.get("wireguard", False),
                    "WireGuard detected",
                    0.1,
                ),
                (lambda fp: fp.dns_over_https_blocked is True, "DoH blocked", 0.1),
            ],
        },
        "Sandvine": {
            "vendor": "Sandvine/Procera",
            "family": DPIFamily.MIDDLEBOX_HEAVY,
            "confidence": 0.9,
            "conditions": [
                (lambda fp: fp.checksum_validation is True, "Checksum validation", 0.2),
                (lambda fp: fp.quic_udp_blocked is True, "QUIC blocked", 0.15),
                (
                    lambda fp: (fp.tcp_option_len_limit or 40) < 20,
                    "TCP option limited",
                    0.15,
                ),
                (lambda fp: fp.stateful_inspection is True, "Stateful", 0.15),
                (lambda fp: fp.http2_detection is True, "HTTP/2 detection", 0.1),
                (lambda fp: fp.rate_limiting_detected is True, "Rate limiting", 0.15),
                (lambda fp: fp.ml_detection_blocked is True, "ML detection", 0.1),
            ],
        },
        "PaloAlto": {
            "vendor": "Palo Alto Networks",
            "family": DPIFamily.NGFW,
            "confidence": 0.91,
            "conditions": [
                (lambda fp: fp.ml_detection_blocked is True, "ML detection", 0.22),
                (
                    lambda fp: fp.tls_version_sensitivity == "blocks_tls13",
                    "Blocks TLS 1.3",
                    0.13,
                ),
                (lambda fp: fp.ech_blocked is True, "ECH blocked", 0.09),
                (lambda fp: fp.rate_limiting_detected is True, "Rate limiting", 0.09),
                (lambda fp: fp.http2_detection is True, "HTTP/2 detection", 0.09),
                (
                    lambda fp: (fp.payload_entropy_sensitivity or 0.0) > 0.7,
                    "High entropy sensitive",
                    0.13,
                ),
                (lambda fp: fp.websocket_blocked is True, "WebSocket blocked", 0.09),
                (lambda fp: 120 <= (fp.rst_ttl or 0) <= 128, "RST TTL near 128", 0.04),
                (
                    lambda fp: hasattr(fp, "http2_support")
                    and fp.http2_support is True,
                    "HTTP/2 support detected",
                    0.04,
                ),
                (
                    lambda fp: hasattr(fp, "ech_support") and fp.ech_support is False,
                    "ECH not supported",
                    0.04,
                ),
                (
                    lambda fp: hasattr(fp, "content_filtering_indicators")
                    and any(fp.content_filtering_indicators.values()),
                    "Content filtering active",
                    0.04,
                ),
            ],
        },
        "FortiGate": {
            "vendor": "Fortinet",
            "family": DPIFamily.ENTERPRISE,
            "confidence": 0.87,
            "conditions": [
                (lambda fp: 250 <= (fp.rst_ttl or 0) <= 255, "High RST TTL", 0.25),
                (lambda fp: fp.ech_grease_blocked is True, "ECH GREASE blocked", 0.15),
                (lambda fp: fp.ech_blocked is True, "ECH blocked", 0.15),
                (
                    lambda fp: fp.checksum_validation is True,
                    "Checksum validation",
                    0.15,
                ),
                (
                    lambda fp: fp.tcp_keepalive_handling == "reset",
                    "Resets on keepalive",
                    0.1,
                ),
                (
                    lambda fp: fp.tls_version_sensitivity
                    in ["blocks_tls12", "blocks_tls13"],
                    "TLS version sensitive",
                    0.1,
                ),
                (lambda fp: fp.certificate_validation is True, "Cert validation", 0.1),
            ],
        },
        "Cisco_ASA": {
            "vendor": "Cisco",
            "family": DPIFamily.ENTERPRISE,
            "confidence": 0.85,
            "conditions": [
                (lambda fp: fp.ipv6_handling == "throttled", "IPv6 throttled", 0.2),
                (lambda fp: fp.dns_over_https_blocked is True, "DoH blocked", 0.15),
                (
                    lambda fp: getattr(fp, "ipsec_detection", False) is True,
                    "IPSec detection",
                    0.15,
                ),
                (lambda fp: fp.stateful_inspection is True, "Stateful", 0.15),
                (
                    lambda fp: fp.tcp_option_len_limit is not None,
                    "TCP option limit",
                    0.1,
                ),
                (lambda fp: fp.ssh_blocked is True, "SSH blocked", 0.15),
                (lambda fp: fp.grpc_blocked is True, "gRPC blocked", 0.1),
            ],
        },
        "Cloudflare": {
            "vendor": "Cloudflare",
            "family": DPIFamily.CDN_EDGE,
            "confidence": 0.88,
            "conditions": [
                (lambda fp: (fp.rst_latency_ms or 0) > 100, "High latency", 0.2),
                (lambda fp: (fp.window_size_in_rst or 0) > 60000, "Large window", 0.15),
                (lambda fp: fp.large_payload_bypass is True, "Large payload OK", 0.15),
                (lambda fp: fp.http2_detection is True, "HTTP/2 support", 0.1),
                (lambda fp: fp.http3_support is True, "HTTP/3 support", 0.1),
                (lambda fp: fp.tcp_fast_open_support is True, "TFO support", 0.1),
                (lambda fp: fp.zero_rtt_blocked is False, "0-RTT allowed", 0.1),
                (lambda fp: fp.websocket_blocked is False, "WebSocket allowed", 0.1),
            ],
        },
        "Akamai": {
            "vendor": "Akamai",
            "family": DPIFamily.CDN_EDGE,
            "confidence": 0.86,
            "conditions": [
                (lambda fp: fp.http3_support is True, "HTTP/3 support", 0.2),
                (
                    lambda fp: (fp.payload_entropy_sensitivity or 0.0) > 0.7,
                    "Entropy sensitive",
                    0.15,
                ),
                (
                    lambda fp: fp.quic_version_negotiation is True,
                    "QUIC version neg",
                    0.15,
                ),
                (lambda fp: fp.tcp_fast_open_support is True, "TFO support", 0.1),
                (lambda fp: fp.ecn_support is True, "ECN support", 0.1),
                (lambda fp: (fp.rst_latency_ms or 0) > 80, "High latency", 0.15),
                (lambda fp: fp.large_payload_bypass is True, "Large payload OK", 0.15),
            ],
        },
        "Zscaler": {
            "vendor": "Zscaler",
            "family": DPIFamily.CLOUD_SECURITY,
            "confidence": 0.84,
            "conditions": [
                (lambda fp: (fp.rst_latency_ms or 0) > 80, "Cloud latency", 0.2),
                (lambda fp: fp.dns_over_https_blocked is True, "DoH blocked", 0.15),
                (lambda fp: fp.esni_support is False, "ESNI blocked", 0.15),
                (
                    lambda fp: fp.checksum_validation is True,
                    "Checksum validation",
                    0.15,
                ),
                (lambda fp: fp.http2_detection is True, "HTTP/2 detection", 0.1),
                (lambda fp: fp.ml_detection_blocked is True, "ML detection", 0.15),
                (lambda fp: fp.certificate_validation is True, "Cert validation", 0.1),
            ],
        },
        "Cisco_Umbrella": {
            "vendor": "Cisco",
            "family": DPIFamily.CLOUD_SECURITY,
            "confidence": 0.83,
            "conditions": [
                (lambda fp: fp.dpi_hop_distance is None, "Cloud-based", 0.2),
                (lambda fp: fp.rst_from_target is False, "RST from middlebox", 0.15),
                (lambda fp: fp.quic_udp_blocked is True, "QUIC blocked", 0.15),
                (lambda fp: fp.ech_blocked is True, "ECH blocked", 0.15),
                (lambda fp: fp.dns_over_https_blocked is True, "DoH blocked", 0.2),
                (lambda fp: fp.dns_over_tls_blocked is True, "DoT blocked", 0.15),
            ],
        },
        "OpenDPI": {
            "vendor": "OpenDPI/nDPI",
            "family": DPIFamily.OPEN_SOURCE,
            "confidence": 0.75,
            "conditions": [
                (lambda fp: 60 <= (fp.rst_ttl or 0) <= 64, "Linux TTL", 0.2),
                (lambda fp: fp.stateful_inspection is True, "Stateful", 0.25),
                (lambda fp: fp.checksum_validation is False, "No checksum check", 0.2),
                (lambda fp: fp.tcp_fast_open_support is False, "No TFO", 0.15),
                (lambda fp: fp.rate_limiting_detected is False, "No rate limit", 0.1),
                (lambda fp: fp.ml_detection_blocked is False, "No ML detection", 0.1),
            ],
        },
        "Generic_DPI": {
            "vendor": "Unknown",
            "family": DPIFamily.UNKNOWN,
            "confidence": 0.6,
            "conditions": [
                (lambda fp: fp.rst_from_target is False, "RST from middlebox", 0.35),
                (lambda fp: fp.icmp_ttl_exceeded is True, "ICMP TTL exceeded", 0.25),
                (lambda fp: fp.stateful_inspection is True, "Stateful", 0.25),
                (lambda fp: fp.rate_limiting_detected is True, "Rate limiting", 0.15),
            ],
        },
    }

    def __init__(self, ml_enabled: bool = True, debug: bool = False):
        self.ml_enabled = ml_enabled and SKLEARN_AVAILABLE
        self.debug = debug
        self.ml_model = None
        self.feature_names = []
        self.is_model_fitted = False
        if self.debug:
            LOG.setLevel(logging.DEBUG)
        if self.ml_enabled:
            self._load_or_train_ml_model()

    def classify(self, fp: Fingerprint) -> DPIClassification:
        sig_classification = self._signature_classify(fp)
        if self.ml_enabled and self.is_model_fitted:
            ml_classification = self._ml_classify(fp)
            if (
                ml_classification
                and ml_classification.confidence > sig_classification.confidence
            ):
                LOG.info(
                    f"ML override: {sig_classification.dpi_type} → {ml_classification.dpi_type}"
                )
                classification = ml_classification
                classification.classification_method = "ml_enhanced"
            else:
                classification = sig_classification
        else:
            classification = sig_classification
        classification.recommended_techniques = self._get_recommendations(
            classification.dpi_type, fp
        )
        fp.dpi_type = classification.dpi_type
        fp.dpi_vendor = classification.vendor
        if isinstance(classification.family, str):
            try:
                fp.dpi_family = DPIFamily(classification.family)
            except (ValueError, KeyError):
                for family in DPIFamily:
                    if family.value == classification.family:
                        fp.dpi_family = family
                        break
                else:
                    fp.dpi_family = classification.family
        else:
            fp.dpi_family = classification.family
        fp.confidence = classification.confidence
        fp.classification_reasons = classification.classification_reasons
        LOG.info(
            f"DPI Classification: {classification.dpi_type} ({classification.vendor}) [{classification.confidence:.0%}]"
        )
        return classification

    def _signature_classify(self, fp: Fingerprint) -> DPIClassification:
        matches = []
        for dpi_type, sig in self.DPI_SIGNATURES.items():
            score = 0.0
            matched_conditions = []
            total_weight = sum((w for _, _, w in sig["conditions"]))
            for condition, reason, weight in sig["conditions"]:
                try:
                    if condition(fp):
                        score += weight
                        matched_conditions.append(reason)
                except Exception as e:
                    LOG.debug(f"Condition failed for {dpi_type}: {e}")
            if total_weight > 0:
                normalized_score = score / total_weight
                confidence = normalized_score * sig["confidence"]
                if confidence > 0:
                    matches.append((dpi_type, confidence, matched_conditions, sig))
        matches.sort(key=lambda x: x[1], reverse=True)
        if matches:
            dpi_type, confidence, reasons, sig = matches[0]
            classification = DPIClassification(
                dpi_type=dpi_type,
                vendor=sig["vendor"],
                family=(
                    sig["family"].value
                    if hasattr(sig["family"], "value")
                    else str(sig["family"])
                ),
                confidence=confidence,
                classification_method="signature",
                classification_reasons=reasons,
            )
            if len(matches) > 1:
                classification.alternative_classifications = [
                    (m[0], m[1]) for m in matches[1:4]
                ]
            return classification
        return DPIClassification(
            dpi_type="Unknown",
            vendor="Unknown",
            family=DPIFamily.UNKNOWN.value,
            confidence=0.0,
            classification_method="signature",
            classification_reasons=["No matching signatures"],
        )

    def _ml_classify(self, fp: Fingerprint) -> Optional[DPIClassification]:
        """ML-based classification"""
        try:
            features = self._extract_features(fp)
            probabilities = self.ml_model.predict_proba([features])[0]
            predicted_idx = np.argmax(probabilities)
            predicted_type = self.ml_model.classes_[predicted_idx]
            confidence = probabilities[predicted_idx]
            if confidence > 0.6:
                sig = self.DPI_SIGNATURES.get(predicted_type, {})
                return DPIClassification(
                    dpi_type=predicted_type,
                    vendor=sig.get("vendor", "Unknown"),
                    family=(
                        sig.get("family", DPIFamily.UNKNOWN).value
                        if hasattr(sig.get("family"), "value")
                        else "Unknown"
                    ),
                    confidence=confidence,
                    classification_method="ml",
                    classification_reasons=["ML model prediction"],
                    ml_features={
                        name: value for name, value in zip(self.feature_names, features)
                    },
                )
        except Exception as e:
            LOG.error(f"ML classification failed: {e}")
        return None

    def _extract_features(self, fp: Fingerprint) -> np.ndarray:
        """Extract numerical features for ML including new extended features"""
        features = []
        features.extend(
            [
                fp.rst_ttl or -1,
                fp.rst_latency_ms or -1,
                fp.rst_distance or -1,
                fp.tcp_option_len_limit or -1,
                fp.window_size_in_rst or -1,
                fp.dpi_hop_distance or -1,
                fp.payload_entropy_sensitivity or -1,
                fp.connection_latency if hasattr(fp, "connection_latency") else -1,
            ]
        )
        features.extend(
            [
                getattr(fp, "rst_ttl_distance", None) or -1,
                getattr(fp, "connection_timeout_ms", None) or -1,
            ]
        )
        bool_features = [
            "rst_from_target",
            "icmp_ttl_exceeded",
            "supports_ip_frag",
            "checksum_validation",
            "quic_udp_blocked",
            "sni_case_sensitive",
            "ech_grease_blocked",
            "timestamp_in_rst",
            "stateful_inspection",
            "rate_limiting_detected",
            "ml_detection_blocked",
            "ip_level_blocked",
            "ech_blocked",
            "tcp_option_splicing",
            "large_payload_bypass",
            "ecn_support",
            "mptcp_support",
            "tcp_fast_open_support",
            "http2_detection",
            "http3_support",
            "esni_support",
            "zero_rtt_blocked",
            "dns_over_https_blocked",
            "websocket_blocked",
            "grpc_blocked",
            "ssh_blocked",
            "tls13_downgrade",
        ]
        extended_bool_features = [
            "sni_consistency_blocked",
            "http2_support",
            "quic_support",
            "ech_support",
            "timing_attack_vulnerable",
        ]
        for feat in bool_features:
            value = getattr(fp, feat, None)
            features.append(1 if value is True else 0 if value is False else -1)
        for feat in extended_bool_features:
            value = getattr(fp, feat, None)
            features.append(1 if value is True else 0 if value is False else -1)
        features.append(self._encode_tls_sensitivity(fp.tls_version_sensitivity))
        features.append(self._encode_ipv6_handling(fp.ipv6_handling))
        features.append(self._encode_tcp_keepalive(fp.tcp_keepalive_handling))
        features.append(
            self._encode_baseline_block_type(getattr(fp, "baseline_block_type", None))
        )
        features.append(
            self._encode_primary_block_method(getattr(fp, "primary_block_method", None))
        )
        timing_patterns = getattr(fp, "response_timing_patterns", {})
        if timing_patterns:
            jitter_measurements = timing_patterns.get("jitter_measurements", [])
            avg_jitter = (
                sum(jitter_measurements) / len(jitter_measurements)
                if jitter_measurements
                else -1
            )
            features.append(avg_jitter)
            connection_times = timing_patterns.get("connection_times", [])
            avg_connection_time = (
                sum(connection_times) / len(connection_times)
                if connection_times
                else -1
            )
            features.append(avg_connection_time)
        else:
            features.extend([-1, -1])
        content_indicators = getattr(fp, "content_filtering_indicators", {})
        active_filters = (
            sum((1 for v in content_indicators.values() if v))
            if content_indicators
            else 0
        )
        features.append(active_filters)
        return np.array(features)

    def _encode_baseline_block_type(self, value: Optional[str]) -> int:
        """Encode baseline block type for ML features"""
        mapping = {
            "RST": 3,
            "TIMEOUT": 2,
            "CONTENT": 1,
            "CONNECTION_REFUSED": 4,
            "none": 0,
        }
        return mapping.get(value, -1)

    def _encode_primary_block_method(self, value: Optional[str]) -> int:
        """Encode primary block method for ML features"""
        mapping = {"rst": 3, "timeout": 2, "content": 1, "mixed": 4, "none": 0}
        return mapping.get(value, -1)

    def _encode_tls_sensitivity(self, value: Optional[str]) -> int:
        mapping = {
            "blocks_tls13": 3,
            "blocks_tls12": 2,
            "blocks_tls11": 1,
            "blocks_all_tls": 4,
            "no_version_preference": 0,
        }
        return mapping.get(value, -1)

    def _encode_ipv6_handling(self, value: Optional[str]) -> int:
        mapping = {"blocked": 2, "throttled": 1, "allowed": 0, "not_applicable": -1}
        return mapping.get(value, -1)

    def _encode_tcp_keepalive(self, value: Optional[str]) -> int:
        mapping = {"reset": 2, "strip": 1, "forward": 0}
        return mapping.get(value, -1)

    def _get_recommendations(self, dpi_type: str, fp: Fingerprint) -> List[str]:
        recommendations = []
        type_recommendations = {
            "TSPU": [
                "payload_encryption",
                "payload_tunneling_combo",
                "tls_record_fragmentation",
                "http_header_injection",
                "timing_channel_steganography",
            ],
            "GFW": [
                "tcp_fakeddisorder",
                "timing_based_evasion",
                "sni_manipulation",
                "protocol_tunneling",
                "dns_subdomain_tunneling",
            ],
            "Cloudflare": [
                "payload_obfuscation",
                "http_path_obfuscation",
                "tcp_fast_open",
                "websocket_tunneling",
            ],
            "FortiGate": [
                "ip_fragmentation_random",
                "http_header_manipulation",
                "tls_version_confusion",
                "protocol_confusion",
            ],
            "PaloAlto": [
                "noise_injection",
                "adaptive_multi_layer",
                "http_tunneling",
                "timing_channel_steganography",
            ],
            "Sandvine": [
                "tcp_window_scaling",
                "payload_padding",
                "payload_obfuscation",
                "burst_timing_evasion",
            ],
        }
        recommendations.extend(type_recommendations.get(dpi_type, []))
        if fp.supports_ip_frag:
            recommendations.extend(["ip_fragmentation_disorder", "tcp_multisplit"])
        if not fp.checksum_validation:
            recommendations.extend(["badsum_race", "md5sig_fooling"])
        if fp.stateful_inspection:
            recommendations.extend(["tcp_window_scaling", "badseq_fooling"])
        if fp.ml_detection_blocked:
            recommendations.extend(["adaptive_multi_layer", "noise_injection"])
        if fp.large_payload_bypass:
            recommendations.extend(["payload_padding", "tcp_multisplit"])
        if not fp.zero_rtt_blocked:
            recommendations.extend(["tls13_0rtt_tunnel", "early_data_smuggling"])
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        return unique_recommendations[:10]

    def _load_or_train_ml_model(self):
        """Load pre-trained model or train new one"""
        model_path = "data/ml_models/dpi_classifier.pkl"
        if os.path.exists(model_path):
            try:
                self.ml_model = joblib.load(model_path)
                self.feature_names = joblib.load(
                    model_path.replace(".pkl", "_features.pkl")
                )
                self.is_model_fitted = True
                LOG.info("Loaded pre-trained ML model")
            except Exception as e:
                LOG.error(f"Failed to load ML model: {e}")
                self._train_new_model()
        else:
            self._train_new_model()

    def _train_new_model(self):
        """Train new ML model (placeholder - needs training data)"""
        LOG.info("Training new ML model...")
        self.ml_model = RandomForestClassifier(
            n_estimators=100, max_depth=10, random_state=42
        )
        self.feature_names = (
            [
                "rst_ttl",
                "rst_latency_ms",
                "rst_distance",
                "tcp_option_len_limit",
                "window_size_in_rst",
                "dpi_hop_distance",
                "payload_entropy_sensitivity",
                "connection_latency",
            ]
            + ["rst_from_target", "icmp_ttl_exceeded", "supports_ip_frag"]
            + [
                "tls_version_sensitivity_encoded",
                "ipv6_handling_encoded",
                "tcp_keepalive_handling_encoded",
            ]
        )
        self.is_model_fitted = False
        LOG.info("ML model created (placeholder). Needs training data to be fitted.")

    def update_model_with_feedback(
        self, fp: Fingerprint, actual_dpi_type: str, confidence: float = 1.0
    ):
        """Update ML model with new labeled data (online learning)"""
        if not self.ml_enabled or not self.ml_model:
            return
        try:
            features = self._extract_features(fp)
            X = [features]
            y = [actual_dpi_type]
            if hasattr(self.ml_model, "partial_fit"):
                self.ml_model.partial_fit(
                    X, y, classes=list(self.DPI_SIGNATURES.keys())
                )
                self.is_model_fitted = True
            LOG.info(f"Updated ML model with feedback: {actual_dpi_type}")
        except Exception as e:
            LOG.error(f"Failed to update ML model: {e}")


DPIClassifier = UltimateDPIClassifier
