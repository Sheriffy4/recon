#!/usr/bin/env python3
# recon/core/fingerprint/ml_classifier_demo.py
"""
Demo script for MLClassifier functionality.
Shows training, classification, and model persistence.
"""

import os
import sys
import tempfile
import logging

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../.."))

from core.fingerprint.ml_classifier import MLClassifier, MLClassificationError

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
LOG = logging.getLogger(__name__)


def create_sample_training_data():
    """Create sample training data for demonstration."""
    return [
        # ROSKOMNADZOR_TSPU examples
        {
            "metrics": {
                "rst_ttl": 63,
                "rst_latency_ms": 50,
                "stateful_inspection": True,
                "ip_level_blocked": False,
                "ml_detection_blocked": False,
                "rate_limiting_detected": True,
                "rst_from_target": False,
                "tls_version_sensitivity": "blocks_tls13",
                "ipv6_handling": "allowed",
                "tcp_keepalive_handling": "forward",
                "ech_blocked": True,
                "tcp_option_splicing": True,
            },
            "dpi_type": "ROSKOMNADZOR_TSPU",
        },
        {
            "metrics": {
                "rst_ttl": 61,
                "rst_latency_ms": 45,
                "stateful_inspection": True,
                "ip_level_blocked": False,
                "ml_detection_blocked": False,
                "rate_limiting_detected": True,
                "rst_from_target": False,
                "tls_version_sensitivity": "blocks_tls13",
                "ipv6_handling": "allowed",
                "tcp_keepalive_handling": "forward",
                "ech_blocked": True,
                "tcp_option_splicing": True,
            },
            "dpi_type": "ROSKOMNADZOR_TSPU",
        },
        # GOVERNMENT_CENSORSHIP examples
        {
            "metrics": {
                "rst_ttl": 128,
                "rst_latency_ms": 120,
                "stateful_inspection": False,
                "ip_level_blocked": True,
                "ml_detection_blocked": False,
                "rate_limiting_detected": False,
                "rst_from_target": False,
                "tls_version_sensitivity": "blocks_all_tls",
                "ipv6_handling": "blocked",
                "tcp_keepalive_handling": "reset",
                "ech_blocked": True,
                "dns_over_https_blocked": True,
            },
            "dpi_type": "GOVERNMENT_CENSORSHIP",
        },
        {
            "metrics": {
                "rst_ttl": 125,
                "rst_latency_ms": 110,
                "stateful_inspection": False,
                "ip_level_blocked": True,
                "ml_detection_blocked": False,
                "rate_limiting_detected": False,
                "rst_from_target": False,
                "tls_version_sensitivity": "blocks_all_tls",
                "ipv6_handling": "blocked",
                "tcp_keepalive_handling": "reset",
                "ech_blocked": True,
                "dns_over_https_blocked": True,
            },
            "dpi_type": "GOVERNMENT_CENSORSHIP",
        },
        # COMMERCIAL_DPI examples
        {
            "metrics": {
                "rst_ttl": 255,
                "rst_latency_ms": 30,
                "stateful_inspection": True,
                "ip_level_blocked": False,
                "ml_detection_blocked": True,
                "rate_limiting_detected": True,
                "rst_from_target": False,
                "tls_version_sensitivity": "blocks_tls12",
                "ipv6_handling": "throttled",
                "tcp_keepalive_handling": "strip",
                "http2_detection": True,
                "websocket_blocked": False,
            },
            "dpi_type": "COMMERCIAL_DPI",
        },
        {
            "metrics": {
                "rst_ttl": 250,
                "rst_latency_ms": 25,
                "stateful_inspection": True,
                "ip_level_blocked": False,
                "ml_detection_blocked": True,
                "rate_limiting_detected": True,
                "rst_from_target": False,
                "tls_version_sensitivity": "blocks_tls12",
                "ipv6_handling": "throttled",
                "tcp_keepalive_handling": "strip",
                "http2_detection": True,
                "websocket_blocked": False,
            },
            "dpi_type": "COMMERCIAL_DPI",
        },
        # CLOUDFLARE_PROTECTION examples
        {
            "metrics": {
                "rst_ttl": 200,
                "rst_latency_ms": 150,
                "stateful_inspection": False,
                "ip_level_blocked": False,
                "ml_detection_blocked": False,
                "rate_limiting_detected": False,
                "rst_from_target": True,
                "tls_version_sensitivity": "no_version_preference",
                "ipv6_handling": "allowed",
                "tcp_keepalive_handling": "forward",
                "http3_support": True,
                "large_payload_bypass": True,
            },
            "dpi_type": "CLOUDFLARE_PROTECTION",
        },
        {
            "metrics": {
                "rst_ttl": 195,
                "rst_latency_ms": 140,
                "stateful_inspection": False,
                "ip_level_blocked": False,
                "ml_detection_blocked": False,
                "rate_limiting_detected": False,
                "rst_from_target": True,
                "tls_version_sensitivity": "no_version_preference",
                "ipv6_handling": "allowed",
                "tcp_keepalive_handling": "forward",
                "http3_support": True,
                "large_payload_bypass": True,
            },
            "dpi_type": "CLOUDFLARE_PROTECTION",
        },
        # FIREWALL_BASED examples
        {
            "metrics": {
                "rst_ttl": 100,
                "rst_latency_ms": 80,
                "stateful_inspection": True,
                "ip_level_blocked": False,
                "ml_detection_blocked": False,
                "rate_limiting_detected": True,
                "rst_from_target": False,
                "tls_version_sensitivity": "blocks_tls12",
                "ipv6_handling": "throttled",
                "tcp_keepalive_handling": "strip",
                "checksum_validation": True,
            },
            "dpi_type": "FIREWALL_BASED",
        },
        {
            "metrics": {
                "rst_ttl": 105,
                "rst_latency_ms": 75,
                "stateful_inspection": True,
                "ip_level_blocked": False,
                "ml_detection_blocked": False,
                "rate_limiting_detected": True,
                "rst_from_target": False,
                "tls_version_sensitivity": "blocks_tls12",
                "ipv6_handling": "throttled",
                "tcp_keepalive_handling": "strip",
                "checksum_validation": True,
            },
            "dpi_type": "FIREWALL_BASED",
        },
    ]


def demo_ml_classifier():
    """Demonstrate MLClassifier functionality."""
    print("=== MLClassifier Demo ===\n")

    # Create temporary model file
    temp_dir = tempfile.mkdtemp()
    model_path = os.path.join(temp_dir, "demo_model.joblib")

    try:
        # 1. Initialize classifier
        print("1. Initializing MLClassifier...")
        classifier = MLClassifier(model_path=model_path)

        info = classifier.get_model_info()
        print(f"   sklearn available: {info['sklearn_available']}")
        print(f"   Model trained: {info['is_trained']}")
        print(f"   DPI types: {len(info['dpi_types'])}")
        print()

        if not classifier.sklearn_available:
            print("   sklearn not available, demonstrating fallback mode only")

            # Test fallback classification
            test_metrics = {
                "ip_level_blocked": True,
                "rst_ttl": 128,
                "stateful_inspection": False,
            }

            dpi_type, confidence = classifier.classify_dpi(test_metrics)
            print(
                f"   Fallback classification: {dpi_type} (confidence: {confidence:.3f})"
            )
            return

        # 2. Create training data
        print("2. Creating training data...")
        training_data = create_sample_training_data()
        print(f"   Created {len(training_data)} training examples")

        # Show distribution
        type_counts = {}
        for example in training_data:
            dpi_type = example["dpi_type"]
            type_counts[dpi_type] = type_counts.get(dpi_type, 0) + 1

        for dpi_type, count in type_counts.items():
            print(f"   - {dpi_type}: {count} examples")
        print()

        # 3. Train model
        print("3. Training ML model...")
        try:
            accuracy = classifier.train_model(training_data)
            print(f"   Training completed with accuracy: {accuracy:.3f}")
            print(f"   Model features: {len(classifier.feature_names)}")
            print()
        except MLClassificationError as e:
            print(f"   Training failed: {e}")
            return

        # 4. Test classification
        print("4. Testing classification...")

        test_cases = [
            {
                "name": "ROSKOMNADZOR_TSPU-like",
                "metrics": {
                    "rst_ttl": 62,
                    "rst_latency_ms": 48,
                    "stateful_inspection": True,
                    "rate_limiting_detected": True,
                    "tls_version_sensitivity": "blocks_tls13",
                    "ech_blocked": True,
                },
            },
            {
                "name": "GOVERNMENT_CENSORSHIP-like",
                "metrics": {
                    "rst_ttl": 127,
                    "rst_latency_ms": 115,
                    "ip_level_blocked": True,
                    "tls_version_sensitivity": "blocks_all_tls",
                    "ipv6_handling": "blocked",
                },
            },
            {
                "name": "COMMERCIAL_DPI-like",
                "metrics": {
                    "rst_ttl": 252,
                    "rst_latency_ms": 28,
                    "ml_detection_blocked": True,
                    "rate_limiting_detected": True,
                    "http2_detection": True,
                },
            },
            {
                "name": "CLOUDFLARE_PROTECTION-like",
                "metrics": {
                    "rst_ttl": 198,
                    "rst_latency_ms": 145,
                    "rst_from_target": True,
                    "http3_support": True,
                    "large_payload_bypass": True,
                },
            },
        ]

        for test_case in test_cases:
            dpi_type, confidence = classifier.classify_dpi(test_case["metrics"])
            print(f"   {test_case['name']}: {dpi_type} (confidence: {confidence:.3f})")
        print()

        # 5. Test model persistence
        print("5. Testing model persistence...")
        print(f"   Model file exists: {os.path.exists(model_path)}")

        # Create new classifier and load model
        classifier2 = MLClassifier(model_path=model_path)
        loaded = classifier2.load_model()
        print(f"   Model loaded successfully: {loaded}")

        if loaded:
            # Test classification with loaded model
            test_metrics = test_cases[0]["metrics"]
            dpi_type, confidence = classifier2.classify_dpi(test_metrics)
            print(
                f"   Classification with loaded model: {dpi_type} (confidence: {confidence:.3f})"
            )
        print()

        # 6. Test model update
        print("6. Testing model update...")
        new_data = {
            "metrics": {
                "rst_ttl": 90,
                "rst_latency_ms": 60,
                "rate_limiting_detected": True,
                "stateful_inspection": True,
            }
        }
        classifier.update_model(new_data, "FIREWALL_BASED")
        print("   Model update completed (logged for future retraining)")
        print()

        # 7. Show final model info
        print("7. Final model information:")
        final_info = classifier.get_model_info()
        for key, value in final_info.items():
            print(f"   {key}: {value}")

    except Exception as e:
        LOG.error(f"Demo failed: {e}")
        import traceback

        traceback.print_exc()

    finally:
        # Cleanup
        try:
            if os.path.exists(model_path):
                os.remove(model_path)
            os.rmdir(temp_dir)
        except:
            pass

    print("\n=== Demo completed ===")


if __name__ == "__main__":
    demo_ml_classifier()
