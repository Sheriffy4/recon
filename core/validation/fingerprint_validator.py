from __future__ import annotations

"""
Fingerprint Validator for Results Validation System.

Extracted from results_validation_system.py to reduce god class complexity.
Handles DPI fingerprint validation, accuracy metrics, and confidence calibration.
"""

import asyncio
import statistics
import logging
import random
from typing import List, Dict, Any

LOG = logging.getLogger("FingerprintValidator")


class FingerprintValidator:
    """Validates DPI fingerprints and calculates accuracy metrics."""

    @staticmethod
    def predict_dpi_behavior(fingerprint_domain: str, test_domain: str) -> Dict[str, Any]:
        """
        Predict DPI behavior based on fingerprint.

        Args:
            fingerprint_domain: Domain of the fingerprint
            test_domain: Domain to test prediction on

        Returns:
            Dictionary with prediction results
        """
        # Simple heuristic based on fingerprint characteristics
        block_probability = 0.3

        # Increase probability for known blocked domains
        blocked_patterns = ["twitter", "x.com", "facebook", "instagram", "youtube"]
        if any(pattern in test_domain.lower() for pattern in blocked_patterns):
            block_probability += 0.4

        # If testing same domain as fingerprint
        if test_domain == fingerprint_domain:
            block_probability += 0.3

        block_probability = max(0.0, min(1.0, block_probability))

        return {
            "blocked": block_probability > 0.5,
            "confidence": 0.7,
            "block_probability": block_probability,
        }

    @staticmethod
    async def test_domain_blocking(domain: str) -> bool:
        """
        Test real domain blocking (connectivity-level semantics).

        Semantics is unified with CurlResponseAnalyzer:
        - Any HTTP response code (including 4xx/5xx) => accessible => NOT blocked.
        - "blocked" means: connection cannot be established / timeout / DNS failure.

        Args:
            domain: Domain to test

        Returns:
            True if domain is blocked, False otherwise
        """
        try:
            import aiohttp
            from aiohttp import ClientConnectorError, ClientError

            timeout = aiohttp.ClientTimeout(total=5.0)

            async with aiohttp.ClientSession(timeout=timeout) as session:
                try:
                    # GET is more compatible than HEAD (some endpoints reject HEAD)
                    async with session.get(f"https://{domain}", ssl=False) as response:
                        # Any HTTP response code means the server is reachable.
                        # (Even 403/404/500 => connectivity established)
                        _ = response.status
                        return False
                except (asyncio.TimeoutError, aiohttp.ClientTimeout):
                    return True
                except (ClientConnectorError, OSError):
                    return True
                except ClientError:
                    return True
                except Exception:
                    return True

        except Exception:
            # Deterministic fallback: TCP connect to 443 (no HTTP needed)
            try:
                import socket

                def _tcp_probe() -> bool:
                    try:
                        infos = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
                        if not infos:
                            return False
                        family, socktype, proto, _, sockaddr = infos[0]
                        s = socket.socket(family, socktype, proto)
                        s.settimeout(5.0)
                        try:
                            s.connect(sockaddr)
                            return True
                        finally:
                            try:
                                s.close()
                            except Exception:
                                pass
                    except Exception:
                        return False

                ok = await asyncio.to_thread(_tcp_probe)
                return not ok
            except Exception:
                # Last resort (kept for backward-compat "demo" behavior)
                return random.random() > 0.6

    @staticmethod
    def calculate_accuracy_metrics(predictions: List[bool], actual: List[bool]) -> Dict[str, float]:
        """
        Calculate prediction accuracy metrics.

        Args:
            predictions: List of predicted values
            actual: List of actual values

        Returns:
            Dictionary with accuracy metrics
        """
        if len(predictions) != len(actual) or not predictions:
            return {
                "accuracy": 0.0,
                "precision": 0.0,
                "recall": 0.0,
                "f1_score": 0.0,
                "false_positive_rate": 1.0,
                "false_negative_rate": 1.0,
            }

        # Calculate basic metrics
        tp = sum(1 for p, a in zip(predictions, actual) if p and a)  # True Positive
        fp = sum(1 for p, a in zip(predictions, actual) if p and not a)  # False Positive
        tn = sum(1 for p, a in zip(predictions, actual) if not p and not a)  # True Negative
        fn = sum(1 for p, a in zip(predictions, actual) if not p and a)  # False Negative

        total = len(predictions)

        # Calculate metrics
        accuracy = (tp + tn) / total if total > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1_score = (
            2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        )

        false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        false_negative_rate = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "false_positive_rate": false_positive_rate,
            "false_negative_rate": false_negative_rate,
            "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        }

    @staticmethod
    def calculate_confidence_calibration(
        predictions: List[bool], actual: List[bool], confidences: List[float]
    ) -> float:
        """
        Calculate confidence calibration score.

        Args:
            predictions: List of predicted values
            actual: List of actual values
            confidences: List of confidence scores

        Returns:
            Calibration score between 0.0 and 1.0
        """
        if len(predictions) != len(actual) or len(predictions) != len(confidences):
            return 0.0

        # Group predictions by confidence levels
        confidence_bins = [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]
        calibration_errors = []

        for i in range(len(confidence_bins) - 1):
            bin_min, bin_max = confidence_bins[i], confidence_bins[i + 1]

            # Find predictions in this confidence range
            bin_indices = [j for j, conf in enumerate(confidences) if bin_min <= conf < bin_max]

            if not bin_indices:
                continue

            # Average confidence in bin
            avg_confidence = statistics.mean([confidences[j] for j in bin_indices])

            # Actual accuracy in bin
            bin_accuracy = statistics.mean(
                [1 if predictions[j] == actual[j] else 0 for j in bin_indices]
            )

            # Calibration error for this bin
            calibration_error = abs(avg_confidence - bin_accuracy)
            calibration_errors.append(calibration_error)

        # Overall calibration error
        if calibration_errors:
            avg_calibration_error = statistics.mean(calibration_errors)
            return max(0.0, 1.0 - avg_calibration_error)
        else:
            return 0.5  # Neutral score when no data
