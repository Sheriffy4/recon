# recon/core/fingerprint/ml_classifier.py
"""
ML-based DPI classifier using sklearn RandomForest.
Implements the design specification for advanced DPI fingerprinting.
"""

from __future__ import annotations
import logging
import os
from typing import Dict, List, Tuple, Optional, Any
import numpy as np

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, classification_report
    import joblib

    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

    # Mock classes for graceful fallback
    class RandomForestClassifier:
        pass


LOG = logging.getLogger("ml_classifier")


class MLClassificationError(Exception):
    """Exception raised for ML classification errors."""

    pass


class MLClassifier:
    """
    ML-классификатор типов DPI на основе sklearn RandomForest.
    Обучается на собранных метриках и классифицирует DPI-системы.
    """

    def __init__(self, model_path: str = "demo_dpi_classifier.joblib"):
        self.model = None
        self.model_path = model_path
        self.feature_names = []
        self.is_trained = False
        self.sklearn_available = SKLEARN_AVAILABLE

        # DPI types as defined in the design specification
        self.dpi_types = [
            "UNKNOWN",
            "ROSKOMNADZOR_TSPU",
            "ROSKOMNADZOR_DPI",
            "COMMERCIAL_DPI",
            "FIREWALL_BASED",
            "ISP_TRANSPARENT_PROXY",
            "CLOUDFLARE_PROTECTION",
            "GOVERNMENT_CENSORSHIP",
        ]

        if not self.sklearn_available:
            LOG.warning("sklearn not available, ML classification will be disabled")
            return

        # Initialize the RandomForest model
        self.model = RandomForestClassifier(
            n_estimators=100, max_depth=10, random_state=42, class_weight="balanced"
        )

        # Try to load existing model
        self.load_model()

    def train_model(self, training_data: List[Dict]) -> float:
        """
        Обучает модель на предоставленных данных.

        Args:
            training_data: List of training examples with 'metrics' and 'dpi_type' keys

        Returns:
            float: Accuracy score of the trained model

        Raises:
            MLClassificationError: If sklearn is not available or training fails
        """
        if not self.sklearn_available:
            raise MLClassificationError("sklearn not available for ML training")

        if not training_data:
            raise MLClassificationError("No training data provided")

        try:
            # Extract features and labels
            X = []
            y = []

            for example in training_data:
                if "metrics" not in example or "dpi_type" not in example:
                    LOG.warning(
                        "Skipping invalid training example: missing 'metrics' or 'dpi_type'"
                    )
                    continue

                features = self._extract_features_from_metrics(example["metrics"])
                X.append(features)
                y.append(example["dpi_type"])

            if not X:
                raise MLClassificationError("No valid training examples found")

            X = np.array(X)
            y = np.array(y)

            # Split data for validation
            if len(X) > 10:  # Only split if we have enough data
                X_train, X_test, y_train, y_test = train_test_split(
                    X, y, test_size=0.2, random_state=42, stratify=y
                )
            else:
                X_train, X_test, y_train, y_test = X, X, y, y

            # Train the model
            self.model.fit(X_train, y_train)
            self.is_trained = True

            # Calculate accuracy
            y_pred = self.model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)

            LOG.info(f"Model trained with accuracy: {accuracy:.3f}")
            LOG.debug(
                f"Classification report:\n{classification_report(y_test, y_pred)}"
            )

            # Save the trained model
            self.save_model()

            return accuracy

        except Exception as e:
            LOG.error(f"Model training failed: {e}")
            raise MLClassificationError(f"Model training failed: {e}")

    def classify_dpi(self, metrics: Dict[str, Any]) -> Tuple[str, float]:
        """
        Классифицирует DPI и возвращает тип с уверенностью.

        Args:
            metrics: Dictionary of DPI metrics

        Returns:
            Tuple[str, float]: (dpi_type, confidence_score)

        Raises:
            MLClassificationError: If classification fails
        """
        if not self.sklearn_available:
            LOG.debug("sklearn not available, returning fallback classification")
            return self._fallback_classification(metrics)

        if not self.is_trained:
            LOG.debug("Model not trained, returning fallback classification")
            return self._fallback_classification(metrics)

        try:
            features = self._extract_features_from_metrics(metrics)
            features = np.array(features).reshape(1, -1)

            # Get prediction probabilities
            probabilities = self.model.predict_proba(features)[0]
            predicted_idx = np.argmax(probabilities)
            predicted_type = self.model.classes_[predicted_idx]
            confidence = probabilities[predicted_idx]

            LOG.debug(
                f"ML classification: {predicted_type} (confidence: {confidence:.3f})"
            )

            return predicted_type, float(confidence)

        except Exception as e:
            LOG.error(f"ML classification failed: {e}")
            return self._fallback_classification(metrics)

    def update_model(self, new_data: Dict, actual_type: str):
        """
        Обновляет модель новыми данными (online learning).

        Args:
            new_data: Dictionary containing 'metrics' key with DPI metrics
            actual_type: The actual DPI type for this example
        """
        if not self.sklearn_available or not self.is_trained:
            LOG.debug("Cannot update model: sklearn unavailable or model not trained")
            return

        try:
            # Store the new data for batch retraining
            LOG.info(f"Received new training example: {actual_type}")

            # In a production system with online learning, this would:
            # 1. Add to online learning system buffer
            # 2. Trigger incremental updates based on confidence
            # 3. Monitor performance and trigger retraining if needed

            # For now, we'll just log the update
            # The actual online learning is handled by OnlineLearningSystem

        except Exception as e:
            LOG.error(f"Model update failed: {e}")

    def get_prediction_with_alternatives(
        self, metrics: Dict[str, Any]
    ) -> Tuple[str, float, List[Tuple[str, float]]]:
        """
        Enhanced classification that returns top predictions with confidence scores.

        Args:
            metrics: Dictionary of DPI metrics

        Returns:
            Tuple[str, float, List[Tuple[str, float]]]: (top_prediction, confidence, alternatives)
        """
        if not self.sklearn_available or not self.is_trained:
            result = self._fallback_classification(metrics)
            return result[0], result[1], []

        try:
            features = self._extract_features_from_metrics(metrics)
            features = np.array(features).reshape(1, -1)

            # Get prediction probabilities for all classes
            probabilities = self.model.predict_proba(features)[0]

            # Sort by probability (descending)
            class_probs = list(zip(self.model.classes_, probabilities))
            class_probs.sort(key=lambda x: x[1], reverse=True)

            # Top prediction
            top_prediction = class_probs[0][0]
            top_confidence = float(class_probs[0][1])

            # Alternative predictions (top 3 excluding the top one)
            alternatives = [(cls, float(prob)) for cls, prob in class_probs[1:4]]

            LOG.debug(
                f"ML classification: {top_prediction} (confidence: {top_confidence:.3f})"
            )
            LOG.debug(f"Alternatives: {alternatives}")

            return top_prediction, top_confidence, alternatives

        except Exception as e:
            LOG.error(f"Enhanced ML classification failed: {e}")
            result = self._fallback_classification(metrics)
            return result[0], result[1], []

    def save_model(self):
        """Сохраняет обученную модель."""
        if not self.sklearn_available or not self.is_trained:
            LOG.debug("Cannot save model: sklearn unavailable or model not trained")
            return

        try:
            model_data = {
                "model": self.model,
                "feature_names": self.feature_names,
                "dpi_types": self.dpi_types,
                "is_trained": self.is_trained,
            }

            joblib.dump(model_data, self.model_path)
            LOG.info(f"Model saved to {self.model_path}")

        except Exception as e:
            LOG.error(f"Failed to save model: {e}")

    def load_model(self) -> bool:
        """
        Загружает сохраненную модель.

        Returns:
            bool: True if model was loaded successfully, False otherwise
        """
        if not self.sklearn_available:
            LOG.debug("sklearn not available, cannot load model")
            return False

        if not os.path.exists(self.model_path):
            LOG.debug(f"Model file {self.model_path} does not exist")
            return False

        try:
            model_data = joblib.load(self.model_path)

            self.model = model_data["model"]
            self.feature_names = model_data.get("feature_names", [])
            self.dpi_types = model_data.get("dpi_types", self.dpi_types)
            self.is_trained = model_data.get("is_trained", False)

            LOG.info(f"Model loaded from {self.model_path}")
            return True

        except Exception as e:
            LOG.error(f"Failed to load model: {e}")
            return False

    def _extract_features_from_metrics(self, metrics: Dict[str, Any]) -> List[float]:
        """
        Extract numerical features from DPI metrics for ML classification.

        Args:
            metrics: Dictionary of DPI metrics

        Returns:
            List[float]: Extracted features as a list of numbers
        """
        features = []

        # Define the feature extraction mapping
        # This should match the metrics collected by MetricsCollector
        feature_mapping = {
            # Timing metrics
            "rst_latency_ms": lambda x: float(x) if x is not None else -1.0,
            "connection_latency_ms": lambda x: float(x) if x is not None else -1.0,
            "dns_resolution_time_ms": lambda x: float(x) if x is not None else -1.0,
            "handshake_time_ms": lambda x: float(x) if x is not None else -1.0,
            # TCP metrics
            "rst_ttl": lambda x: float(x) if x is not None else -1.0,
            "rst_distance": lambda x: float(x) if x is not None else -1.0,
            "window_size_in_rst": lambda x: float(x) if x is not None else -1.0,
            "tcp_option_len_limit": lambda x: float(x) if x is not None else -1.0,
            "dpi_hop_distance": lambda x: float(x) if x is not None else -1.0,
            # Boolean features (converted to 0/1)
            "rst_from_target": lambda x: (
                1.0 if x is True else 0.0 if x is False else -1.0
            ),
            "icmp_ttl_exceeded": lambda x: (
                1.0 if x is True else 0.0 if x is False else -1.0
            ),
            "supports_ip_frag": lambda x: (
                1.0 if x is True else 0.0 if x is False else -1.0
            ),
            "checksum_validation": lambda x: (
                1.0 if x is True else 0.0 if x is False else -1.0
            ),
            "quic_udp_blocked": lambda x: (
                1.0 if x is True else 0.0 if x is False else -1.0
            ),
            "stateful_inspection": lambda x: (
                1.0 if x is True else 0.0 if x is False else -1.0
            ),
            "rate_limiting_detected": lambda x: (
                1.0 if x is True else 0.0 if x is False else -1.0
            ),
            "ml_detection_blocked": lambda x: (
                1.0 if x is True else 0.0 if x is False else -1.0
            ),
            "ip_level_blocked": lambda x: (
                1.0 if x is True else 0.0 if x is False else -1.0
            ),
            "ech_blocked": lambda x: 1.0 if x is True else 0.0 if x is False else -1.0,
            "tcp_option_splicing": lambda x: (
                1.0 if x is True else 0.0 if x is False else -1.0
            ),
            "large_payload_bypass": lambda x: (
                1.0 if x is True else 0.0 if x is False else -1.0
            ),
            "ecn_support": lambda x: 1.0 if x is True else 0.0 if x is False else -1.0,
            "http2_detection": lambda x: (
                1.0 if x is True else 0.0 if x is False else -1.0
            ),
            "http3_support": lambda x: (
                1.0 if x is True else 0.0 if x is False else -1.0
            ),
            "esni_support": lambda x: 1.0 if x is True else 0.0 if x is False else -1.0,
            "zero_rtt_blocked": lambda x: (
                1.0 if x is True else 0.0 if x is False else -1.0
            ),
            "dns_over_https_blocked": lambda x: (
                1.0 if x is True else 0.0 if x is False else -1.0
            ),
            "websocket_blocked": lambda x: (
                1.0 if x is True else 0.0 if x is False else -1.0
            ),
            # Categorical features (encoded as numbers)
            "tls_version_sensitivity": self._encode_tls_sensitivity,
            "ipv6_handling": self._encode_ipv6_handling,
            "tcp_keepalive_handling": self._encode_tcp_keepalive,
        }

        # Store feature names for the first time
        if not self.feature_names:
            self.feature_names = list(feature_mapping.keys())

        # Extract features in consistent order
        for feature_name in self.feature_names:
            if feature_name in feature_mapping:
                extractor = feature_mapping[feature_name]
                value = metrics.get(feature_name)
                features.append(extractor(value))
            else:
                features.append(-1.0)  # Missing feature

        return features

    def _encode_tls_sensitivity(self, value: Optional[str]) -> float:
        """Encode TLS version sensitivity as a number."""
        mapping = {
            "blocks_tls13": 3.0,
            "blocks_tls12": 2.0,
            "blocks_tls11": 1.0,
            "blocks_all_tls": 4.0,
            "no_version_preference": 0.0,
        }
        return mapping.get(value, -1.0)

    def _encode_ipv6_handling(self, value: Optional[str]) -> float:
        """Encode IPv6 handling as a number."""
        mapping = {
            "blocked": 2.0,
            "throttled": 1.0,
            "allowed": 0.0,
            "not_applicable": -1.0,
        }
        return mapping.get(value, -1.0)

    def _encode_tcp_keepalive(self, value: Optional[str]) -> float:
        """Encode TCP keepalive handling as a number."""
        mapping = {"reset": 2.0, "strip": 1.0, "forward": 0.0}
        return mapping.get(value, -1.0)

    def _fallback_classification(self, metrics: Dict[str, Any]) -> Tuple[str, float]:
        """
        Fallback classification when ML is not available.
        Uses simple heuristics based on key metrics.

        Args:
            metrics: Dictionary of DPI metrics

        Returns:
            Tuple[str, float]: (dpi_type, confidence_score)
        """
        # Simple heuristic-based classification
        if metrics.get("ip_level_blocked"):
            return "GOVERNMENT_CENSORSHIP", 0.7

        if metrics.get("rst_ttl") and 60 <= metrics["rst_ttl"] <= 64:
            if metrics.get("stateful_inspection"):
                return "ROSKOMNADZOR_TSPU", 0.6

        if metrics.get("ml_detection_blocked"):
            return "COMMERCIAL_DPI", 0.6

        if metrics.get("rate_limiting_detected"):
            return "FIREWALL_BASED", 0.5

        if metrics.get("rst_latency_ms", 0) > 100:
            return "CLOUDFLARE_PROTECTION", 0.5

        return "UNKNOWN", 0.3

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the classifier."""
        return self.get_model_info()

    def is_healthy(self) -> bool:
        """Check if the classifier is healthy."""
        return self.sklearn_available and self.is_trained

    def get_model_info(self) -> Dict[str, Any]:
        """
        Get information about the current model state.

        Returns:
            Dict with model information
        """
        return {
            "sklearn_available": self.sklearn_available,
            "is_trained": self.is_trained,
            "model_path": self.model_path,
            "feature_count": len(self.feature_names),
            "dpi_types": self.dpi_types,
            "model_exists": (
                os.path.exists(self.model_path) if self.model_path else False
            ),
        }
