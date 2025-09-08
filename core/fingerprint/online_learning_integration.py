"""
Integration module for online learning with existing DPI fingerprinting system.
Provides seamless integration between AdvancedFingerprinter and OnlineLearningSystem.
"""

from __future__ import annotations
import logging
import time
from typing import Dict, Any, Tuple, List
from dataclasses import dataclass
from core.fingerprint.online_learning import (
    OnlineLearningSystem,
    LearningMode,
    ABTestConfig,
)
from core.fingerprint.ml_classifier import MLClassifier
from core.fingerprint.advanced_models import DPIFingerprint

LOG = logging.getLogger("online_learning_integration")


@dataclass
class FeedbackData:
    """User feedback data for online learning."""

    target: str
    fingerprint: DPIFingerprint
    user_reported_type: str
    confidence_in_feedback: float
    feedback_source: str
    timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "fingerprint": self.fingerprint.to_dict(),
            "user_reported_type": self.user_reported_type,
            "confidence_in_feedback": self.confidence_in_feedback,
            "feedback_source": self.feedback_source,
            "timestamp": self.timestamp,
        }


class OnlineLearningIntegrator:
    """
    Integrates online learning capabilities with the existing DPI fingerprinting system.

    This class acts as a bridge between:
    - AdvancedFingerprinter (main fingerprinting system)
    - OnlineLearningSystem (online learning capabilities)
    - User feedback and validation systems
    """

    def __init__(
        self,
        ml_classifier: MLClassifier,
        learning_mode: LearningMode = LearningMode.MODERATE,
        enable_online_learning: bool = True,
    ):
        """
        Initialize the online learning integrator.

        Args:
            ml_classifier: The ML classifier to enhance
            learning_mode: Initial learning mode
            enable_online_learning: Whether to enable online learning
        """
        self.ml_classifier = ml_classifier
        self.enable_online_learning = enable_online_learning
        if self.enable_online_learning:
            self.online_learning = OnlineLearningSystem(
                ml_classifier=ml_classifier,
                learning_mode=learning_mode,
                buffer_size=500,
                min_confidence_threshold=0.75,
                performance_window_size=50,
                retraining_threshold=0.08,
            )
        else:
            self.online_learning = None
        self.stats = {
            "fingerprints_processed": 0,
            "feedback_received": 0,
            "learning_examples_added": 0,
            "ab_tests_run": 0,
            "model_improvements_detected": 0,
        }
        LOG.info(
            f"Online learning integrator initialized (enabled: {enable_online_learning})"
        )

    def classify_with_learning(
        self, metrics: Dict[str, Any], target: str = None
    ) -> Tuple[str, float, List[Tuple[str, float]]]:
        """
        Classify DPI with online learning integration.

        Args:
            metrics: DPI metrics for classification
            target: Optional target identifier for tracking

        Returns:
            Tuple[str, float, List[Tuple[str, float]]]: (dpi_type, confidence, alternatives)
        """
        self.stats["fingerprints_processed"] += 1
        if self.online_learning and self.online_learning.active_ab_test:
            dpi_type, confidence, model_used = (
                self.online_learning.classify_with_ab_test(metrics)
            )
            alternatives = []
            LOG.debug(
                f"A/B test classification: {dpi_type} (confidence: {confidence:.3f}, model: {model_used})"
            )
        else:
            dpi_type, confidence, alternatives = (
                self.ml_classifier.get_prediction_with_alternatives(metrics)
            )
        return (dpi_type, confidence, alternatives)

    def add_user_feedback(self, feedback: FeedbackData) -> bool:
        """
        Add user feedback for online learning.

        Args:
            feedback: User feedback data

        Returns:
            bool: True if feedback was processed successfully
        """
        if not self.enable_online_learning or not self.online_learning:
            LOG.debug("Online learning disabled, ignoring feedback")
            return False
        self.stats["feedback_received"] += 1
        try:
            metrics = self._extract_metrics_from_fingerprint(feedback.fingerprint)
            predicted_type, confidence, _ = (
                self.ml_classifier.get_prediction_with_alternatives(metrics)
            )
            adjusted_confidence = min(confidence, feedback.confidence_in_feedback)
            learned = self.online_learning.add_learning_example(
                metrics=metrics,
                predicted_type=predicted_type,
                actual_type=feedback.user_reported_type,
                confidence=adjusted_confidence,
                source=feedback.feedback_source,
            )
            if learned:
                self.stats["learning_examples_added"] += 1
                LOG.info(
                    f"User feedback processed: {predicted_type} -> {feedback.user_reported_type} for target {feedback.target}"
                )
            if self.online_learning.active_ab_test:
                self.online_learning.record_ab_test_result(
                    metrics=metrics,
                    predicted_type=predicted_type,
                    actual_type=feedback.user_reported_type,
                    confidence=adjusted_confidence,
                    model_used="control",
                )
            return learned
        except Exception as e:
            LOG.error(f"Failed to process user feedback: {e}")
            return False

    def add_validation_result(
        self,
        target: str,
        metrics: Dict[str, Any],
        predicted_type: str,
        validated_type: str,
        confidence: float,
        validation_method: str = "automated",
    ) -> bool:
        """
        Add validation result for online learning.

        Args:
            target: Target that was validated
            metrics: DPI metrics used for prediction
            predicted_type: What the model predicted
            validated_type: Validated/correct DPI type
            confidence: Confidence in the prediction
            validation_method: Method used for validation

        Returns:
            bool: True if validation result was processed
        """
        if not self.enable_online_learning or not self.online_learning:
            return False
        try:
            learned = self.online_learning.add_learning_example(
                metrics=metrics,
                predicted_type=predicted_type,
                actual_type=validated_type,
                confidence=confidence,
                source=f"validation_{validation_method}",
            )
            if learned:
                self.stats["learning_examples_added"] += 1
                LOG.debug(
                    f"Validation result processed: {predicted_type} -> {validated_type} for {target}"
                )
            return learned
        except Exception as e:
            LOG.error(f"Failed to process validation result: {e}")
            return False

    def start_model_ab_test(
        self,
        test_model_path: str,
        test_name: str = None,
        traffic_split: float = 0.1,
        min_samples: int = 100,
        success_threshold: float = 0.05,
    ) -> bool:
        """
        Start an A/B test for model improvement.

        Args:
            test_model_path: Path to the test model
            test_name: Name for the test (auto-generated if None)
            traffic_split: Fraction of traffic to send to test model
            min_samples: Minimum samples before concluding test
            success_threshold: Minimum improvement threshold

        Returns:
            bool: True if A/B test started successfully
        """
        if not self.enable_online_learning or not self.online_learning:
            LOG.warning("Cannot start A/B test: online learning disabled")
            return False
        if test_name is None:
            test_name = f"model_test_{int(time.time())}"
        config = ABTestConfig(
            test_name=test_name,
            control_model_path=self.ml_classifier.model_path,
            test_model_path=test_model_path,
            traffic_split=traffic_split,
            min_samples=min_samples,
            max_duration_hours=72,
            success_threshold=success_threshold,
        )
        success = self.online_learning.start_ab_test(config)
        if success:
            self.stats["ab_tests_run"] += 1
            LOG.info(
                f"Started A/B test '{test_name}' with {traffic_split:.1%} traffic split"
            )
        return success

    def get_learning_insights(self) -> Dict[str, Any]:
        """
        Get insights about the online learning performance.

        Returns:
            Dictionary with learning insights and recommendations
        """
        if not self.enable_online_learning or not self.online_learning:
            return {"online_learning_enabled": False}
        learning_stats = self.online_learning.get_learning_statistics()
        total_examples = learning_stats["statistics"]["total_examples_received"]
        learned_examples = learning_stats["statistics"]["examples_learned_from"]
        learning_efficiency = (
            learned_examples / total_examples if total_examples > 0 else 0
        )
        performance_trend = "stable"
        if (
            learning_stats["baseline_performance"]
            and len(self.online_learning.performance_history) > 10
        ):
            recent_accuracy = (
                sum(
                    (
                        1
                        for ex in list(self.online_learning.performance_history)[-10:]
                        if ex.predicted_type == ex.actual_type
                    )
                )
                / 10
            )
            baseline_accuracy = learning_stats["baseline_performance"]["accuracy"]
            if recent_accuracy > baseline_accuracy + 0.05:
                performance_trend = "improving"
            elif recent_accuracy < baseline_accuracy - 0.05:
                performance_trend = "degrading"
        recommendations = []
        if learning_efficiency < 0.3:
            recommendations.append(
                "Consider lowering confidence threshold or switching to aggressive learning mode"
            )
        if learning_stats["statistics"]["retraining_events"] > 3:
            recommendations.append(
                "Frequent retraining detected - consider reviewing data quality"
            )
        if performance_trend == "degrading":
            recommendations.append(
                "Performance degradation detected - manual review recommended"
            )
        if total_examples > 1000 and learned_examples < 100:
            recommendations.append(
                "Low learning rate - consider adjusting learning mode or thresholds"
            )
        return {
            "online_learning_enabled": True,
            "learning_mode": learning_stats["learning_mode"],
            "learning_efficiency": learning_efficiency,
            "performance_trend": performance_trend,
            "total_examples_processed": total_examples,
            "examples_learned_from": learned_examples,
            "retraining_events": learning_stats["statistics"]["retraining_events"],
            "active_ab_test": learning_stats["active_ab_test"],
            "buffer_utilization": learning_stats["buffer_size"]
            / learning_stats["buffer_capacity"],
            "recommendations": recommendations,
            "integration_stats": self.stats.copy(),
        }

    def set_learning_mode(self, mode: LearningMode) -> bool:
        """
        Change the learning mode.

        Args:
            mode: New learning mode

        Returns:
            bool: True if mode was changed successfully
        """
        if not self.enable_online_learning or not self.online_learning:
            return False
        old_mode = self.online_learning.learning_mode
        self.online_learning.set_learning_mode(mode)
        LOG.info(f"Learning mode changed from {old_mode.value} to {mode.value}")
        return True

    def enable_online_learning(
        self, learning_mode: LearningMode = LearningMode.MODERATE
    ) -> bool:
        """
        Enable online learning if it was disabled.

        Args:
            learning_mode: Learning mode to use

        Returns:
            bool: True if online learning was enabled
        """
        if self.enable_online_learning and self.online_learning:
            LOG.debug("Online learning already enabled")
            return True
        try:
            self.online_learning = OnlineLearningSystem(
                ml_classifier=self.ml_classifier,
                learning_mode=learning_mode,
                buffer_size=500,
                min_confidence_threshold=0.75,
                performance_window_size=50,
                retraining_threshold=0.08,
            )
            self.enable_online_learning = True
            LOG.info("Online learning enabled")
            return True
        except Exception as e:
            LOG.error(f"Failed to enable online learning: {e}")
            return False

    def disable_online_learning(self) -> bool:
        """
        Disable online learning.

        Returns:
            bool: True if online learning was disabled
        """
        if not self.enable_online_learning:
            LOG.debug("Online learning already disabled")
            return True
        if self.online_learning:
            self.online_learning._save_state()
        self.online_learning = None
        self.enable_online_learning = False
        LOG.info("Online learning disabled")
        return True

    def _extract_metrics_from_fingerprint(
        self, fingerprint: DPIFingerprint
    ) -> Dict[str, Any]:
        """
        Extract metrics dictionary from DPI fingerprint.

        Args:
            fingerprint: DPI fingerprint object

        Returns:
            Dictionary of metrics suitable for ML classification
        """
        metrics = {
            "rst_latency_ms": getattr(fingerprint, "connection_reset_timing", 0.0)
            * 1000,
            "connection_latency_ms": getattr(fingerprint, "analysis_duration", 0.0)
            * 1000,
            "dns_resolution_time_ms": 30.0,
            "handshake_time_ms": 80.0,
            "rst_ttl": 63,
            "rst_distance": 10,
            "window_size_in_rst": 0,
            "tcp_option_len_limit": 40,
            "dpi_hop_distance": 8,
            "rst_from_target": getattr(fingerprint, "rst_injection_detected", False),
            "icmp_ttl_exceeded": False,
            "supports_ip_frag": getattr(fingerprint, "supports_ipv6", True),
            "checksum_validation": True,
            "quic_udp_blocked": False,
            "stateful_inspection": getattr(
                fingerprint, "tcp_window_manipulation", False
            ),
            "rate_limiting_detected": False,
            "ml_detection_blocked": getattr(fingerprint, "content_inspection_depth", 0)
            > 5,
            "ip_level_blocked": getattr(fingerprint, "geographic_restrictions", False),
            "ech_blocked": False,
            "tcp_option_splicing": getattr(fingerprint, "tcp_options_filtering", False),
            "large_payload_bypass": True,
            "ecn_support": True,
            "http2_detection": getattr(fingerprint, "http_method_restrictions", [])
            != [],
            "http3_support": False,
            "esni_support": False,
            "zero_rtt_blocked": False,
            "dns_over_https_blocked": getattr(fingerprint, "doh_blocking", False),
            "websocket_blocked": False,
            "tls_version_sensitivity": (
                "blocks_tls13"
                if getattr(fingerprint, "http_header_filtering", False)
                else "no_version_preference"
            ),
            "ipv6_handling": (
                "allowed" if getattr(fingerprint, "supports_ipv6", True) else "blocked"
            ),
            "tcp_keepalive_handling": "forward",
        }
        return metrics


def create_online_learning_integrator(
    ml_classifier: MLClassifier,
    enable_online_learning: bool = True,
    learning_mode: LearningMode = LearningMode.MODERATE,
) -> OnlineLearningIntegrator:
    """
    Factory function to create an online learning integrator.

    Args:
        ml_classifier: ML classifier to enhance
        enable_online_learning: Whether to enable online learning
        learning_mode: Initial learning mode

    Returns:
        OnlineLearningIntegrator instance
    """
    return OnlineLearningIntegrator(
        ml_classifier=ml_classifier,
        learning_mode=learning_mode,
        enable_online_learning=enable_online_learning,
    )
