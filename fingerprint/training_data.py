# recon/core/fingerprint/training_data.py
"""
Training data preparation and feature engineering for DPI ML classifier.
Implements comprehensive training dataset with known DPI types and their metrics.
"""

from __future__ import annotations
import logging
import json
import os
from typing import Dict, List, Any
import numpy as np
from dataclasses import dataclass, asdict

LOG = logging.getLogger("training_data")


@dataclass
class TrainingExample:
    """Single training example with metrics and DPI type."""

    dpi_type: str
    confidence: float
    metrics: Dict[str, Any]
    source: str  # Where this example came from
    description: str  # Human-readable description

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TrainingExample":
        """Create from dictionary."""
        return cls(**data)


class TrainingDataGenerator:
    """
    Generates comprehensive training dataset with known DPI types.
    Creates synthetic and real-world examples for ML training.
    """

    def __init__(self):
        self.training_examples: List[TrainingExample] = []
        self._initialize_base_examples()

    def _initialize_base_examples(self):
        """Initialize base training examples for each DPI type."""

        # ROSKOMNADZOR_TSPU examples
        self.training_examples.extend(
            [
                TrainingExample(
                    dpi_type="ROSKOMNADZOR_TSPU",
                    confidence=0.95,
                    source="real_world_analysis",
                    description="Typical TSPU behavior with TTL 63 RST injection",
                    metrics={
                        "rst_ttl": 63,
                        "rst_latency_ms": 15.2,
                        "rst_from_target": False,
                        "connection_latency_ms": 45.8,
                        "dns_resolution_time_ms": 12.3,
                        "handshake_time_ms": 89.4,
                        "rst_distance": 8,
                        "window_size_in_rst": 0,
                        "tcp_option_len_limit": 40,
                        "dpi_hop_distance": 7,
                        "icmp_ttl_exceeded": False,
                        "supports_ip_frag": True,
                        "checksum_validation": True,
                        "quic_udp_blocked": True,
                        "stateful_inspection": True,
                        "rate_limiting_detected": False,
                        "ml_detection_blocked": False,
                        "ip_level_blocked": False,
                        "ech_blocked": True,
                        "tcp_option_splicing": False,
                        "large_payload_bypass": True,
                        "ecn_support": False,
                        "http2_detection": True,
                        "http3_support": False,
                        "esni_support": False,
                        "zero_rtt_blocked": True,
                        "dns_over_https_blocked": True,
                        "websocket_blocked": False,
                        "tls_version_sensitivity": "blocks_tls13",
                        "ipv6_handling": "throttled",
                        "tcp_keepalive_handling": "strip",
                    },
                ),
                TrainingExample(
                    dpi_type="ROSKOMNADZOR_TSPU",
                    confidence=0.92,
                    source="synthetic",
                    description="TSPU with slight variations in timing",
                    metrics={
                        "rst_ttl": 62,
                        "rst_latency_ms": 18.7,
                        "rst_from_target": False,
                        "connection_latency_ms": 52.1,
                        "dns_resolution_time_ms": 15.8,
                        "handshake_time_ms": 95.2,
                        "rst_distance": 9,
                        "window_size_in_rst": 0,
                        "tcp_option_len_limit": 40,
                        "dpi_hop_distance": 8,
                        "icmp_ttl_exceeded": False,
                        "supports_ip_frag": True,
                        "checksum_validation": True,
                        "quic_udp_blocked": True,
                        "stateful_inspection": True,
                        "rate_limiting_detected": False,
                        "ml_detection_blocked": False,
                        "ip_level_blocked": False,
                        "ech_blocked": True,
                        "tcp_option_splicing": False,
                        "large_payload_bypass": True,
                        "ecn_support": False,
                        "http2_detection": True,
                        "http3_support": False,
                        "esni_support": False,
                        "zero_rtt_blocked": True,
                        "dns_over_https_blocked": True,
                        "websocket_blocked": False,
                        "tls_version_sensitivity": "blocks_tls13",
                        "ipv6_handling": "throttled",
                        "tcp_keepalive_handling": "strip",
                    },
                ),
            ]
        )

        # ROSKOMNADZOR_DPI examples
        self.training_examples.extend(
            [
                TrainingExample(
                    dpi_type="ROSKOMNADZOR_DPI",
                    confidence=0.88,
                    source="real_world_analysis",
                    description="Deep packet inspection with content analysis",
                    metrics={
                        "rst_ttl": 64,
                        "rst_latency_ms": 25.4,
                        "rst_from_target": False,
                        "connection_latency_ms": 78.3,
                        "dns_resolution_time_ms": 8.9,
                        "handshake_time_ms": 156.7,
                        "rst_distance": 12,
                        "window_size_in_rst": 8192,
                        "tcp_option_len_limit": 20,
                        "dpi_hop_distance": 11,
                        "icmp_ttl_exceeded": False,
                        "supports_ip_frag": False,
                        "checksum_validation": True,
                        "quic_udp_blocked": True,
                        "stateful_inspection": True,
                        "rate_limiting_detected": True,
                        "ml_detection_blocked": True,
                        "ip_level_blocked": False,
                        "ech_blocked": True,
                        "tcp_option_splicing": True,
                        "large_payload_bypass": False,
                        "ecn_support": False,
                        "http2_detection": True,
                        "http3_support": False,
                        "esni_support": False,
                        "zero_rtt_blocked": True,
                        "dns_over_https_blocked": True,
                        "websocket_blocked": True,
                        "tls_version_sensitivity": "blocks_all_tls",
                        "ipv6_handling": "blocked",
                        "tcp_keepalive_handling": "reset",
                    },
                )
            ]
        )

        # COMMERCIAL_DPI examples
        self.training_examples.extend(
            [
                TrainingExample(
                    dpi_type="COMMERCIAL_DPI",
                    confidence=0.91,
                    source="vendor_documentation",
                    description="Commercial DPI with ML-based detection",
                    metrics={
                        "rst_ttl": 255,
                        "rst_latency_ms": 5.2,
                        "rst_from_target": False,
                        "connection_latency_ms": 23.1,
                        "dns_resolution_time_ms": 3.4,
                        "handshake_time_ms": 45.6,
                        "rst_distance": 2,
                        "window_size_in_rst": 65535,
                        "tcp_option_len_limit": 60,
                        "dpi_hop_distance": 1,
                        "icmp_ttl_exceeded": False,
                        "supports_ip_frag": True,
                        "checksum_validation": True,
                        "quic_udp_blocked": False,
                        "stateful_inspection": True,
                        "rate_limiting_detected": True,
                        "ml_detection_blocked": True,
                        "ip_level_blocked": False,
                        "ech_blocked": False,
                        "tcp_option_splicing": False,
                        "large_payload_bypass": False,
                        "ecn_support": True,
                        "http2_detection": True,
                        "http3_support": True,
                        "esni_support": True,
                        "zero_rtt_blocked": False,
                        "dns_over_https_blocked": False,
                        "websocket_blocked": False,
                        "tls_version_sensitivity": "no_version_preference",
                        "ipv6_handling": "allowed",
                        "tcp_keepalive_handling": "forward",
                    },
                )
            ]
        )

        # FIREWALL_BASED examples
        self.training_examples.extend(
            [
                TrainingExample(
                    dpi_type="FIREWALL_BASED",
                    confidence=0.85,
                    source="network_analysis",
                    description="Traditional firewall with basic DPI",
                    metrics={
                        "rst_ttl": 64,
                        "rst_latency_ms": 1.8,
                        "rst_from_target": False,
                        "connection_latency_ms": 12.4,
                        "dns_resolution_time_ms": 5.7,
                        "handshake_time_ms": 28.9,
                        "rst_distance": 1,
                        "window_size_in_rst": 0,
                        "tcp_option_len_limit": 20,
                        "dpi_hop_distance": 0,
                        "icmp_ttl_exceeded": True,
                        "supports_ip_frag": True,
                        "checksum_validation": False,
                        "quic_udp_blocked": True,
                        "stateful_inspection": False,
                        "rate_limiting_detected": True,
                        "ml_detection_blocked": False,
                        "ip_level_blocked": True,
                        "ech_blocked": False,
                        "tcp_option_splicing": False,
                        "large_payload_bypass": True,
                        "ecn_support": False,
                        "http2_detection": False,
                        "http3_support": False,
                        "esni_support": False,
                        "zero_rtt_blocked": True,
                        "dns_over_https_blocked": False,
                        "websocket_blocked": False,
                        "tls_version_sensitivity": "blocks_tls11",
                        "ipv6_handling": "blocked",
                        "tcp_keepalive_handling": "reset",
                    },
                )
            ]
        )

        # ISP_TRANSPARENT_PROXY examples
        self.training_examples.extend(
            [
                TrainingExample(
                    dpi_type="ISP_TRANSPARENT_PROXY",
                    confidence=0.79,
                    source="isp_analysis",
                    description="ISP transparent proxy with caching",
                    metrics={
                        "rst_ttl": 64,
                        "rst_latency_ms": 35.6,
                        "rst_from_target": True,
                        "connection_latency_ms": 89.2,
                        "dns_resolution_time_ms": 25.1,
                        "handshake_time_ms": 134.7,
                        "rst_distance": 15,
                        "window_size_in_rst": 32768,
                        "tcp_option_len_limit": 40,
                        "dpi_hop_distance": 14,
                        "icmp_ttl_exceeded": False,
                        "supports_ip_frag": True,
                        "checksum_validation": False,
                        "quic_udp_blocked": False,
                        "stateful_inspection": False,
                        "rate_limiting_detected": True,
                        "ml_detection_blocked": False,
                        "ip_level_blocked": False,
                        "ech_blocked": False,
                        "tcp_option_splicing": False,
                        "large_payload_bypass": True,
                        "ecn_support": True,
                        "http2_detection": False,
                        "http3_support": False,
                        "esni_support": False,
                        "zero_rtt_blocked": False,
                        "dns_over_https_blocked": False,
                        "websocket_blocked": False,
                        "tls_version_sensitivity": "no_version_preference",
                        "ipv6_handling": "allowed",
                        "tcp_keepalive_handling": "forward",
                    },
                )
            ]
        )

        # CLOUDFLARE_PROTECTION examples
        self.training_examples.extend(
            [
                TrainingExample(
                    dpi_type="CLOUDFLARE_PROTECTION",
                    confidence=0.93,
                    source="cloudflare_analysis",
                    description="Cloudflare DDoS protection and filtering",
                    metrics={
                        "rst_ttl": 64,
                        "rst_latency_ms": 125.3,
                        "rst_from_target": True,
                        "connection_latency_ms": 156.8,
                        "dns_resolution_time_ms": 45.2,
                        "handshake_time_ms": 234.1,
                        "rst_distance": 25,
                        "window_size_in_rst": 65535,
                        "tcp_option_len_limit": 60,
                        "dpi_hop_distance": 24,
                        "icmp_ttl_exceeded": False,
                        "supports_ip_frag": True,
                        "checksum_validation": True,
                        "quic_udp_blocked": False,
                        "stateful_inspection": True,
                        "rate_limiting_detected": True,
                        "ml_detection_blocked": True,
                        "ip_level_blocked": False,
                        "ech_blocked": False,
                        "tcp_option_splicing": False,
                        "large_payload_bypass": False,
                        "ecn_support": True,
                        "http2_detection": True,
                        "http3_support": True,
                        "esni_support": True,
                        "zero_rtt_blocked": False,
                        "dns_over_https_blocked": False,
                        "websocket_blocked": False,
                        "tls_version_sensitivity": "no_version_preference",
                        "ipv6_handling": "allowed",
                        "tcp_keepalive_handling": "forward",
                    },
                )
            ]
        )

        # GOVERNMENT_CENSORSHIP examples
        self.training_examples.extend(
            [
                TrainingExample(
                    dpi_type="GOVERNMENT_CENSORSHIP",
                    confidence=0.96,
                    source="censorship_analysis",
                    description="Government-level censorship with IP blocking",
                    metrics={
                        "rst_ttl": 64,
                        "rst_latency_ms": 0.0,  # Immediate block
                        "rst_from_target": False,
                        "connection_latency_ms": 0.0,
                        "dns_resolution_time_ms": 1000.0,  # Timeout
                        "handshake_time_ms": 0.0,
                        "rst_distance": 0,
                        "window_size_in_rst": 0,
                        "tcp_option_len_limit": 0,
                        "dpi_hop_distance": 0,
                        "icmp_ttl_exceeded": False,
                        "supports_ip_frag": False,
                        "checksum_validation": False,
                        "quic_udp_blocked": True,
                        "stateful_inspection": False,
                        "rate_limiting_detected": False,
                        "ml_detection_blocked": False,
                        "ip_level_blocked": True,
                        "ech_blocked": True,
                        "tcp_option_splicing": False,
                        "large_payload_bypass": False,
                        "ecn_support": False,
                        "http2_detection": False,
                        "http3_support": False,
                        "esni_support": False,
                        "zero_rtt_blocked": True,
                        "dns_over_https_blocked": True,
                        "websocket_blocked": True,
                        "tls_version_sensitivity": "blocks_all_tls",
                        "ipv6_handling": "blocked",
                        "tcp_keepalive_handling": "reset",
                    },
                )
            ]
        )

        # UNKNOWN examples (for cases where classification is uncertain)
        self.training_examples.extend(
            [
                TrainingExample(
                    dpi_type="UNKNOWN",
                    confidence=0.3,
                    source="mixed_signals",
                    description="Mixed signals, unclear DPI type",
                    metrics={
                        "rst_ttl": 128,
                        "rst_latency_ms": 67.4,
                        "rst_from_target": True,
                        "connection_latency_ms": 123.5,
                        "dns_resolution_time_ms": 34.2,
                        "handshake_time_ms": 189.3,
                        "rst_distance": 18,
                        "window_size_in_rst": 16384,
                        "tcp_option_len_limit": 30,
                        "dpi_hop_distance": 17,
                        "icmp_ttl_exceeded": False,
                        "supports_ip_frag": True,
                        "checksum_validation": True,
                        "quic_udp_blocked": False,
                        "stateful_inspection": True,
                        "rate_limiting_detected": False,
                        "ml_detection_blocked": False,
                        "ip_level_blocked": False,
                        "ech_blocked": False,
                        "tcp_option_splicing": False,
                        "large_payload_bypass": True,
                        "ecn_support": True,
                        "http2_detection": False,
                        "http3_support": False,
                        "esni_support": False,
                        "zero_rtt_blocked": False,
                        "dns_over_https_blocked": False,
                        "websocket_blocked": False,
                        "tls_version_sensitivity": "no_version_preference",
                        "ipv6_handling": "allowed",
                        "tcp_keepalive_handling": "forward",
                    },
                )
            ]
        )

    def generate_synthetic_variations(
        self, base_examples: int = 5
    ) -> List[TrainingExample]:
        """
        Generate synthetic variations of existing examples.

        Args:
            base_examples: Number of base examples to use for variation generation

        Returns:
            List of synthetic training examples
        """
        synthetic_examples = []

        for base_example in self.training_examples[:base_examples]:
            # Generate 3-5 variations per base example
            for i in range(np.random.randint(3, 6)):
                variation = self._create_variation(base_example, variation_id=i)
                synthetic_examples.append(variation)

        return synthetic_examples

    def _create_variation(
        self, base_example: TrainingExample, variation_id: int
    ) -> TrainingExample:
        """Create a synthetic variation of a base example."""
        new_metrics = base_example.metrics.copy()

        # Add noise to numerical values
        numerical_keys = [
            "rst_ttl",
            "rst_latency_ms",
            "connection_latency_ms",
            "dns_resolution_time_ms",
            "handshake_time_ms",
            "rst_distance",
            "window_size_in_rst",
            "tcp_option_len_limit",
            "dpi_hop_distance",
        ]

        for key in numerical_keys:
            if key in new_metrics and new_metrics[key] is not None:
                original_value = new_metrics[key]
                # Add 5-15% noise
                noise_factor = np.random.uniform(0.95, 1.15)
                new_metrics[key] = max(0, original_value * noise_factor)

        # Occasionally flip some boolean values (10% chance)
        boolean_keys = [k for k, v in new_metrics.items() if isinstance(v, bool)]
        for key in boolean_keys:
            if np.random.random() < 0.1:
                new_metrics[key] = not new_metrics[key]

        # Reduce confidence slightly for synthetic examples
        new_confidence = max(
            0.1, base_example.confidence - np.random.uniform(0.05, 0.15)
        )

        return TrainingExample(
            dpi_type=base_example.dpi_type,
            confidence=new_confidence,
            source="synthetic_variation",
            description=f"Synthetic variation {variation_id} of {base_example.description}",
            metrics=new_metrics,
        )

    def get_training_data(self, include_synthetic: bool = True) -> List[Dict[str, Any]]:
        """
        Get training data in format expected by MLClassifier.

        Args:
            include_synthetic: Whether to include synthetic variations

        Returns:
            List of training examples as dictionaries
        """
        examples = self.training_examples.copy()

        if include_synthetic:
            synthetic = self.generate_synthetic_variations()
            examples.extend(synthetic)
            LOG.info(f"Generated {len(synthetic)} synthetic examples")

        # Convert to format expected by MLClassifier
        training_data = []
        for example in examples:
            training_data.append(
                {
                    "metrics": example.metrics,
                    "dpi_type": example.dpi_type,
                    "confidence": example.confidence,
                }
            )

        LOG.info(f"Prepared {len(training_data)} training examples")
        return training_data

    def save_training_data(self, filepath: str, include_synthetic: bool = True):
        """Save training data to JSON file."""
        training_data = self.get_training_data(include_synthetic)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(training_data, f, indent=2, ensure_ascii=False)

        LOG.info(f"Training data saved to {filepath}")

    def load_training_data(self, filepath: str) -> List[Dict[str, Any]]:
        """Load training data from JSON file."""
        if not os.path.exists(filepath):
            LOG.warning(f"Training data file {filepath} not found")
            return []

        with open(filepath, "r", encoding="utf-8") as f:
            training_data = json.load(f)

        LOG.info(f"Loaded {len(training_data)} training examples from {filepath}")
        return training_data

    def get_class_distribution(self) -> Dict[str, int]:
        """Get distribution of classes in training data."""
        distribution = {}
        for example in self.training_examples:
            distribution[example.dpi_type] = distribution.get(example.dpi_type, 0) + 1
        return distribution

    def validate_training_data(self) -> Dict[str, Any]:
        """Validate training data quality and completeness."""
        validation_results = {
            "total_examples": len(self.training_examples),
            "class_distribution": self.get_class_distribution(),
            "missing_features": [],
            "invalid_examples": [],
            "feature_coverage": {},
        }

        # Check for required features
        required_features = [
            "rst_ttl",
            "rst_latency_ms",
            "connection_latency_ms",
            "dns_resolution_time_ms",
            "handshake_time_ms",
        ]

        feature_counts = {}
        for example in self.training_examples:
            for feature in required_features:
                if feature not in example.metrics:
                    if feature not in validation_results["missing_features"]:
                        validation_results["missing_features"].append(feature)
                else:
                    feature_counts[feature] = feature_counts.get(feature, 0) + 1

        validation_results["feature_coverage"] = {
            feature: count / len(self.training_examples)
            for feature, count in feature_counts.items()
        }

        return validation_results


class FeatureEngineer:
    """
    Feature engineering pipeline for converting raw metrics to ML features.
    Handles normalization, encoding, and feature selection.
    """

    def __init__(self):
        self.feature_stats = {}
        self.is_fitted = False

    def fit(self, training_data: List[Dict[str, Any]]):
        """
        Fit the feature engineering pipeline on training data.

        Args:
            training_data: List of training examples with metrics
        """
        # Collect statistics for normalization
        all_metrics = [example["metrics"] for example in training_data]

        # Calculate statistics for numerical features
        numerical_features = [
            "rst_ttl",
            "rst_latency_ms",
            "connection_latency_ms",
            "dns_resolution_time_ms",
            "handshake_time_ms",
            "rst_distance",
            "window_size_in_rst",
            "tcp_option_len_limit",
            "dpi_hop_distance",
        ]

        for feature in numerical_features:
            values = []
            for metrics in all_metrics:
                if feature in metrics and metrics[feature] is not None:
                    values.append(float(metrics[feature]))

            if values:
                self.feature_stats[feature] = {
                    "mean": np.mean(values),
                    "std": np.std(values),
                    "min": np.min(values),
                    "max": np.max(values),
                }

        self.is_fitted = True
        LOG.info(
            f"Feature engineering pipeline fitted on {len(training_data)} examples"
        )

    def transform(self, metrics: Dict[str, Any]) -> Dict[str, float]:
        """
        Transform raw metrics to engineered features.

        Args:
            metrics: Raw DPI metrics

        Returns:
            Dictionary of engineered features
        """
        if not self.is_fitted:
            LOG.warning("Feature engineering pipeline not fitted, using raw features")
            return self._extract_raw_features(metrics)

        engineered_features = {}

        # Normalize numerical features
        numerical_features = [
            "rst_ttl",
            "rst_latency_ms",
            "connection_latency_ms",
            "dns_resolution_time_ms",
            "handshake_time_ms",
            "rst_distance",
            "window_size_in_rst",
            "tcp_option_len_limit",
            "dpi_hop_distance",
        ]

        for feature in numerical_features:
            if feature in metrics and feature in self.feature_stats:
                value = metrics[feature]
                if value is not None:
                    stats = self.feature_stats[feature]
                    # Z-score normalization
                    if stats["std"] > 0:
                        normalized = (float(value) - stats["mean"]) / stats["std"]
                    else:
                        normalized = 0.0
                    engineered_features[f"{feature}_normalized"] = normalized

                    # Min-max normalization
                    if stats["max"] > stats["min"]:
                        minmax = (float(value) - stats["min"]) / (
                            stats["max"] - stats["min"]
                        )
                    else:
                        minmax = 0.0
                    engineered_features[f"{feature}_minmax"] = minmax

        # Boolean features (as is)
        boolean_features = [
            "rst_from_target",
            "icmp_ttl_exceeded",
            "supports_ip_frag",
            "checksum_validation",
            "quic_udp_blocked",
            "stateful_inspection",
            "rate_limiting_detected",
            "ml_detection_blocked",
            "ip_level_blocked",
            "ech_blocked",
            "tcp_option_splicing",
            "large_payload_bypass",
            "ecn_support",
            "http2_detection",
            "http3_support",
            "esni_support",
            "zero_rtt_blocked",
            "dns_over_https_blocked",
            "websocket_blocked",
        ]

        for feature in boolean_features:
            if feature in metrics:
                value = metrics[feature]
                engineered_features[feature] = (
                    1.0 if value is True else 0.0 if value is False else -1.0
                )

        # Categorical features (encoded)
        categorical_mappings = {
            "tls_version_sensitivity": {
                "blocks_tls13": 3.0,
                "blocks_tls12": 2.0,
                "blocks_tls11": 1.0,
                "blocks_all_tls": 4.0,
                "no_version_preference": 0.0,
            },
            "ipv6_handling": {
                "blocked": 2.0,
                "throttled": 1.0,
                "allowed": 0.0,
                "not_applicable": -1.0,
            },
            "tcp_keepalive_handling": {"reset": 2.0, "strip": 1.0, "forward": 0.0},
        }

        for feature, mapping in categorical_mappings.items():
            if feature in metrics:
                value = metrics[feature]
                engineered_features[feature] = mapping.get(value, -1.0)

        # Derived features
        engineered_features.update(self._create_derived_features(metrics))

        return engineered_features

    def _extract_raw_features(self, metrics: Dict[str, Any]) -> Dict[str, float]:
        """Extract raw features without normalization."""
        features = {}

        # Simple extraction for fallback
        for key, value in metrics.items():
            if isinstance(value, (int, float)):
                features[key] = float(value)
            elif isinstance(value, bool):
                features[key] = 1.0 if value else 0.0

        return features

    def _create_derived_features(self, metrics: Dict[str, Any]) -> Dict[str, float]:
        """Create derived features from raw metrics."""
        derived = {}

        # Latency ratios
        if metrics.get("rst_latency_ms") and metrics.get("connection_latency_ms"):
            rst_lat = metrics["rst_latency_ms"]
            conn_lat = metrics["connection_latency_ms"]
            if conn_lat > 0:
                derived["rst_to_connection_ratio"] = rst_lat / conn_lat

        # TTL analysis
        if metrics.get("rst_ttl"):
            ttl = metrics["rst_ttl"]
            # Common TTL values indicate different systems
            derived["ttl_is_common"] = 1.0 if ttl in [63, 64, 128, 255] else 0.0
            derived["ttl_category"] = self._categorize_ttl(ttl)

        # Blocking intensity score
        blocking_indicators = [
            "quic_udp_blocked",
            "ech_blocked",
            "zero_rtt_blocked",
            "dns_over_https_blocked",
            "websocket_blocked",
            "ip_level_blocked",
        ]
        blocking_count = sum(
            1 for indicator in blocking_indicators if metrics.get(indicator) is True
        )
        derived["blocking_intensity"] = blocking_count / len(blocking_indicators)

        # Technology support score
        tech_indicators = [
            "http2_detection",
            "http3_support",
            "esni_support",
            "ecn_support",
        ]
        tech_count = sum(
            1 for indicator in tech_indicators if metrics.get(indicator) is True
        )
        derived["technology_support"] = tech_count / len(tech_indicators)

        return derived

    def _categorize_ttl(self, ttl: int) -> float:
        """Categorize TTL values into common ranges."""
        if ttl <= 32:
            return 1.0  # Very low
        elif ttl <= 64:
            return 2.0  # Low-medium
        elif ttl <= 128:
            return 3.0  # Medium-high
        else:
            return 4.0  # High
