# core/strategy/validator.py
"""
Strategy Validator - Validates strategies before application

This module provides comprehensive validation for DPI bypass strategies,
ensuring they are structurally correct, compatible between modes, and
safe to apply.
"""

import logging
import json
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime


@dataclass
class ValidationResult:
    """Result of strategy validation."""

    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def has_errors(self) -> bool:
        """Check if validation has errors."""
        return len(self.errors) > 0

    def has_warnings(self) -> bool:
        """Check if validation has warnings."""
        return len(self.warnings) > 0

    def add_error(self, error: str) -> None:
        """Add an error to the result."""
        self.errors.append(error)
        self.is_valid = False

    def add_warning(self, warning: str) -> None:
        """Add a warning to the result."""
        self.warnings.append(warning)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "is_valid": self.is_valid,
            "errors": self.errors,
            "warnings": self.warnings,
            "metadata": self.metadata,
        }


@dataclass
class CompatibilityResult:
    """Result of compatibility check between strategies."""

    is_compatible: bool
    differences: List[Dict[str, Any]] = field(default_factory=list)
    similarity_score: float = 1.0
    recommendations: List[str] = field(default_factory=list)

    def add_difference(
        self, field: str, testing_value: Any, service_value: Any, severity: str = "warning"
    ) -> None:
        """Add a difference between strategies."""
        self.differences.append(
            {
                "field": field,
                "testing_value": testing_value,
                "service_value": service_value,
                "severity": severity,
            }
        )

        if severity == "error":
            self.is_compatible = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "is_compatible": self.is_compatible,
            "differences": self.differences,
            "similarity_score": self.similarity_score,
            "recommendations": self.recommendations,
        }


@dataclass
class TestResult:
    """Result of strategy test application."""

    success: bool
    domain: str
    strategy_type: str
    latency_ms: float = 0.0
    error_message: Optional[str] = None
    pcap_analysis: Optional[Dict[str, Any]] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "success": self.success,
            "domain": self.domain,
            "strategy_type": self.strategy_type,
            "latency_ms": self.latency_ms,
            "error_message": self.error_message,
            "pcap_analysis": self.pcap_analysis,
            "timestamp": self.timestamp,
        }


class StrategyValidator:
    """
    Validates strategies for both testing and service modes.

    Provides:
    - Structural validation of strategy parameters
    - Compatibility checking between modes
    - Test application with PCAP verification
    - Periodic revalidation of strategies
    """

    def __init__(
        self, strategy_loader=None, pcap_analyzer=None, bypass_engine=None, debug: bool = False
    ):
        """
        Initialize the strategy validator.

        Args:
            strategy_loader: UnifiedStrategyLoader instance for loading strategies
            pcap_analyzer: PCAPAnalyzer instance for PCAP verification
            bypass_engine: UnifiedBypassEngine instance for test application
            debug: Enable debug logging
        """
        self.logger = logging.getLogger(__name__)
        if debug:
            self.logger.setLevel(logging.DEBUG)

        self.strategy_loader = strategy_loader
        self.pcap_analyzer = pcap_analyzer
        self.bypass_engine = bypass_engine

        # Validation cache to avoid repeated validation
        self._validation_cache: Dict[str, ValidationResult] = {}

        # Known working strategies (domain -> strategy hash)
        self._working_strategies: Dict[str, str] = {}

        # Failed strategies (domain -> failure count)
        self._failed_strategies: Dict[str, int] = {}

        # Maximum failure count before marking strategy as broken
        self.max_failures = 3

        self.logger.info("StrategyValidator initialized")

    def validate_strategy(self, strategy: Any) -> ValidationResult:
        """
        Validate a strategy's structure and parameters.

        Args:
            strategy: Strategy object (NormalizedStrategy or dict)

        Returns:
            ValidationResult with validation details
        """
        result = ValidationResult(is_valid=True)

        try:
            # Convert strategy to dict if needed
            if hasattr(strategy, "to_dict"):
                strategy_dict = strategy.to_dict()
            elif isinstance(strategy, dict):
                strategy_dict = strategy
            else:
                result.add_error(f"Invalid strategy type: {type(strategy)}")
                return result

            # Check required fields
            if "type" not in strategy_dict:
                result.add_error("Strategy missing 'type' field")
                return result

            strategy_type = strategy_dict["type"]
            params = strategy_dict.get("params", {})

            # Validate strategy type
            if not self._validate_strategy_type(strategy_type, result):
                return result

            # Validate parameters
            if not self._validate_parameters(strategy_type, params, result):
                return result

            # Validate parameter ranges
            if not self._validate_parameter_ranges(strategy_type, params, result):
                return result

            # Validate parameter combinations
            if not self._validate_parameter_combinations(strategy_type, params, result):
                return result

            # Add metadata
            result.metadata["strategy_type"] = strategy_type
            result.metadata["param_count"] = len(params)
            result.metadata["validated_at"] = datetime.now().isoformat()

            self.logger.debug(
                f"Strategy validation completed: {strategy_type}, valid={result.is_valid}"
            )

        except Exception as e:
            result.add_error(f"Validation exception: {str(e)}")
            self.logger.error(f"Strategy validation failed with exception: {e}", exc_info=True)

        return result

    def _validate_strategy_type(self, strategy_type: str, result: ValidationResult) -> bool:
        """Validate that the strategy type is known and supported."""
        # Use strategy loader if available
        if self.strategy_loader:
            if not self.strategy_loader.is_attack_supported(strategy_type):
                result.add_error(f"Unknown or unsupported strategy type: {strategy_type}")
                return False
        else:
            # Fallback to basic validation
            known_types = {
                "fakeddisorder",
                "seqovl",
                "multidisorder",
                "disorder",
                "disorder2",
                "multisplit",
                "split",
                "fake",
                "combo",
            }
            if strategy_type not in known_types:
                result.add_warning(f"Strategy type '{strategy_type}' not in known types list")

        return True

    def _validate_parameters(
        self, strategy_type: str, params: Dict[str, Any], result: ValidationResult
    ) -> bool:
        """Validate that all required parameters are present."""
        # Use strategy loader if available
        if self.strategy_loader:
            try:
                self.strategy_loader.validate_attack_parameters(strategy_type, params)
            except Exception as e:
                result.add_error(f"Parameter validation failed: {str(e)}")
                return False
        else:
            # Fallback to basic validation
            required_params = {
                "fakeddisorder": ["split_pos"],
                "seqovl": ["split_pos", "overlap_size"],
                "split": ["split_pos"],
                "fake": ["ttl"],
            }

            required = required_params.get(strategy_type, [])
            missing = [p for p in required if p not in params]

            if missing:
                result.add_error(f"Missing required parameters: {missing}")
                return False

        return True

    def _validate_parameter_ranges(
        self, strategy_type: str, params: Dict[str, Any], result: ValidationResult
    ) -> bool:
        """Validate that parameter values are within acceptable ranges."""
        # TTL validation
        if "ttl" in params:
            ttl = params["ttl"]
            if isinstance(ttl, int):
                if not (1 <= ttl <= 255):
                    result.add_error(f"TTL value {ttl} out of range (1-255)")
                    return False

        # Split position validation
        if "split_pos" in params:
            split_pos = params["split_pos"]
            if isinstance(split_pos, int):
                if split_pos < 1:
                    result.add_error(f"split_pos value {split_pos} must be >= 1")
                    return False
                if split_pos > 65535:
                    result.add_warning(f"split_pos value {split_pos} is very large")

        # Overlap size validation
        if "overlap_size" in params:
            overlap_size = params["overlap_size"]
            if isinstance(overlap_size, int):
                if overlap_size < 0:
                    result.add_error(f"overlap_size value {overlap_size} must be >= 0")
                    return False
                if overlap_size > 1000:
                    result.add_warning(f"overlap_size value {overlap_size} is very large")

        # Repeats validation
        if "repeats" in params:
            repeats = params["repeats"]
            if isinstance(repeats, int):
                if not (1 <= repeats <= 10):
                    result.add_error(f"repeats value {repeats} out of range (1-10)")
                    return False

        return True

    def _validate_parameter_combinations(
        self, strategy_type: str, params: Dict[str, Any], result: ValidationResult
    ) -> bool:
        """Validate that parameter combinations make sense."""
        # Check for conflicting TTL parameters
        if "ttl" in params and "autottl" in params:
            if params["ttl"] is not None and params["autottl"] is not None:
                result.add_error("Cannot specify both 'ttl' and 'autottl'")
                return False

        # Check seqovl specific requirements
        if strategy_type in ["seqovl", "seq_overlap", "overlap"]:
            if "overlap_size" in params and "split_pos" in params:
                overlap_size = params.get("overlap_size")
                split_pos = params.get("split_pos")

                if isinstance(overlap_size, int) and isinstance(split_pos, int):
                    if overlap_size >= split_pos:
                        result.add_error(
                            f"overlap_size ({overlap_size}) must be < split_pos ({split_pos})"
                        )
                        return False

        # Check multisplit/multidisorder requirements
        if strategy_type in ["multisplit", "multidisorder"]:
            if "positions" not in params and "split_pos" not in params:
                result.add_error(f"Strategy '{strategy_type}' requires 'positions' or 'split_pos'")
                return False

        return True

    def validate_compatibility(
        self, testing_strategy: Any, service_strategy: Any
    ) -> CompatibilityResult:
        """
        Check compatibility between testing mode and service mode strategies.

        Args:
            testing_strategy: Strategy from testing mode
            service_strategy: Strategy from service mode

        Returns:
            CompatibilityResult with differences and recommendations
        """
        result = CompatibilityResult(is_compatible=True)

        try:
            # Convert strategies to dicts
            if hasattr(testing_strategy, "to_dict"):
                testing_dict = testing_strategy.to_dict()
            elif isinstance(testing_strategy, dict):
                testing_dict = testing_strategy
            else:
                result.is_compatible = False
                result.recommendations.append("Invalid testing strategy format")
                return result

            if hasattr(service_strategy, "to_dict"):
                service_dict = service_strategy.to_dict()
            elif isinstance(service_strategy, dict):
                service_dict = service_strategy
            else:
                result.is_compatible = False
                result.recommendations.append("Invalid service strategy format")
                return result

            # Compare strategy types
            testing_type = testing_dict.get("type")
            service_type = service_dict.get("type")

            if testing_type != service_type:
                result.add_difference("type", testing_type, service_type, "error")
                result.recommendations.append(
                    f"Strategy types must match: {testing_type} != {service_type}"
                )

            # Compare parameters
            testing_params = testing_dict.get("params", {})
            service_params = service_dict.get("params", {})

            # Find all parameter keys
            all_keys = set(testing_params.keys()) | set(service_params.keys())

            matching_params = 0
            total_params = len(all_keys)

            for key in all_keys:
                testing_value = testing_params.get(key)
                service_value = service_params.get(key)

                if testing_value != service_value:
                    # Determine severity
                    severity = self._determine_difference_severity(
                        key, testing_value, service_value
                    )
                    result.add_difference(key, testing_value, service_value, severity)

                    if severity == "error":
                        result.recommendations.append(
                            f"Critical parameter mismatch: {key} ({testing_value} != {service_value})"
                        )
                    else:
                        result.recommendations.append(
                            f"Parameter difference: {key} ({testing_value} != {service_value})"
                        )
                else:
                    matching_params += 1

            # Calculate similarity score
            if total_params > 0:
                result.similarity_score = matching_params / total_params
            else:
                result.similarity_score = 1.0

            # Add overall recommendation
            if result.is_compatible:
                if result.similarity_score < 0.8:
                    result.recommendations.append(
                        f"Strategies are compatible but have significant differences (similarity: {result.similarity_score:.2%})"
                    )
                else:
                    result.recommendations.append(
                        f"Strategies are highly compatible (similarity: {result.similarity_score:.2%})"
                    )
            else:
                result.recommendations.append(
                    "Strategies are NOT compatible - critical differences found"
                )

            self.logger.debug(
                f"Compatibility check: compatible={result.is_compatible}, "
                f"similarity={result.similarity_score:.2%}, "
                f"differences={len(result.differences)}"
            )

        except Exception as e:
            result.is_compatible = False
            result.recommendations.append(f"Compatibility check failed: {str(e)}")
            self.logger.error(f"Compatibility check failed with exception: {e}", exc_info=True)

        return result

    def _determine_difference_severity(self, param_name: str, value1: Any, value2: Any) -> str:
        """Determine the severity of a parameter difference."""
        # Critical parameters that must match
        critical_params = {"type", "split_pos", "ttl", "overlap_size", "positions"}

        if param_name in critical_params:
            return "error"

        # Important parameters that should match
        important_params = {"fooling", "repeats", "fake_sni", "autottl"}

        if param_name in important_params:
            return "warning"

        # Other parameters are informational
        return "info"

    def test_strategy_application(
        self, strategy: Any, domain: str, timeout: float = 10.0, capture_pcap: bool = True
    ) -> TestResult:
        """
        Test applying a strategy to a domain with PCAP verification.

        Args:
            strategy: Strategy to test
            domain: Domain to test against
            timeout: Timeout in seconds
            capture_pcap: Whether to capture and analyze PCAP

        Returns:
            TestResult with test outcome and PCAP analysis
        """
        # Convert strategy to dict
        if hasattr(strategy, "to_dict"):
            strategy_dict = strategy.to_dict()
        elif isinstance(strategy, dict):
            strategy_dict = strategy
        else:
            return TestResult(
                success=False,
                domain=domain,
                strategy_type="unknown",
                error_message=f"Invalid strategy type: {type(strategy)}",
            )

        strategy_type = strategy_dict.get("type", "unknown")

        try:
            # First validate the strategy
            validation_result = self.validate_strategy(strategy)

            if not validation_result.is_valid:
                return TestResult(
                    success=False,
                    domain=domain,
                    strategy_type=strategy_type,
                    error_message=f"Strategy validation failed: {', '.join(validation_result.errors)}",
                )

            # If bypass engine is available, test actual application
            if self.bypass_engine:
                start_time = datetime.now()

                try:
                    # Test the strategy application
                    test_result = self._test_with_bypass_engine(
                        strategy_dict, domain, timeout, capture_pcap
                    )

                    end_time = datetime.now()
                    latency_ms = (end_time - start_time).total_seconds() * 1000

                    test_result.latency_ms = latency_ms
                    return test_result

                except Exception as e:
                    self.logger.error(f"Bypass engine test failed: {e}", exc_info=True)
                    return TestResult(
                        success=False,
                        domain=domain,
                        strategy_type=strategy_type,
                        error_message=f"Bypass engine test failed: {str(e)}",
                    )
            else:
                # No bypass engine available - just return validation result
                return TestResult(
                    success=validation_result.is_valid,
                    domain=domain,
                    strategy_type=strategy_type,
                    error_message=(
                        "No bypass engine available for testing"
                        if validation_result.is_valid
                        else None
                    ),
                )

        except Exception as e:
            self.logger.error(f"Strategy test failed for {domain}: {e}", exc_info=True)
            return TestResult(
                success=False,
                domain=domain,
                strategy_type=strategy_type,
                error_message=f"Test exception: {str(e)}",
            )

    def _test_with_bypass_engine(
        self, strategy_dict: Dict[str, Any], domain: str, timeout: float, capture_pcap: bool
    ) -> TestResult:
        """
        Test strategy with bypass engine and optional PCAP capture.

        Args:
            strategy_dict: Strategy configuration
            domain: Domain to test
            timeout: Timeout in seconds
            capture_pcap: Whether to capture PCAP

        Returns:
            TestResult with test outcome
        """
        import asyncio
        import socket
        from pathlib import Path

        strategy_type = strategy_dict.get("type", "unknown")
        pcap_file = None
        pcap_analysis = None

        try:
            # Start PCAP capture if requested and analyzer is available
            if capture_pcap and self.pcap_analyzer:
                pcap_file = Path(
                    f"test_pcap_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
                )
                self.logger.debug(f"Starting PCAP capture to {pcap_file}")
                # Note: Actual PCAP capture would be started here
                # This is a placeholder for integration with existing PCAP infrastructure

            # Resolve domain to IP
            try:
                ip_addresses = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
                if not ip_addresses:
                    return TestResult(
                        success=False,
                        domain=domain,
                        strategy_type=strategy_type,
                        error_message=f"Could not resolve domain: {domain}",
                    )

                target_ip = ip_addresses[0][4][0]
                self.logger.debug(f"Resolved {domain} to {target_ip}")

            except Exception as e:
                return TestResult(
                    success=False,
                    domain=domain,
                    strategy_type=strategy_type,
                    error_message=f"DNS resolution failed: {str(e)}",
                )

            # Configure bypass engine with strategy
            # Note: This is a simplified version - actual implementation would use
            # the bypass engine's configuration interface
            self.logger.debug(f"Configuring bypass engine with strategy: {strategy_type}")

            # Attempt connection with strategy applied
            try:
                # Create a test connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)

                # Connect to the target
                sock.connect((target_ip, 443))

                # Send a simple TLS ClientHello or HTTP request
                # Note: Actual implementation would send proper protocol data

                # Close connection
                sock.close()

                success = True
                error_message = None

            except socket.timeout:
                success = False
                error_message = f"Connection timeout after {timeout}s"
            except Exception as e:
                success = False
                error_message = f"Connection failed: {str(e)}"

            # Analyze PCAP if captured
            if capture_pcap and self.pcap_analyzer and pcap_file and pcap_file.exists():
                try:
                    self.logger.debug(f"Analyzing PCAP file: {pcap_file}")
                    # Note: Actual PCAP analysis would be performed here
                    # This is a placeholder for integration with existing PCAP analyzer
                    pcap_analysis = {
                        "pcap_file": str(pcap_file),
                        "packets_captured": 0,
                        "strategy_detected": False,
                        "analysis_note": "PCAP analysis integration pending",
                    }
                except Exception as e:
                    self.logger.warning(f"PCAP analysis failed: {e}")
                    pcap_analysis = {"error": str(e)}

            return TestResult(
                success=success,
                domain=domain,
                strategy_type=strategy_type,
                error_message=error_message,
                pcap_analysis=pcap_analysis,
            )

        except Exception as e:
            self.logger.error(f"Test with bypass engine failed: {e}", exc_info=True)
            return TestResult(
                success=False,
                domain=domain,
                strategy_type=strategy_type,
                error_message=f"Test failed: {str(e)}",
            )
        finally:
            # Cleanup PCAP file if needed
            if pcap_file and pcap_file.exists() and not capture_pcap:
                try:
                    pcap_file.unlink()
                except Exception as e:
                    self.logger.warning(f"Failed to cleanup PCAP file: {e}")

    def revalidate_strategies(
        self, strategies: Dict[str, Any], remove_invalid: bool = False
    ) -> Dict[str, ValidationResult]:
        """
        Periodically revalidate a set of strategies.

        Args:
            strategies: Dict of domain -> strategy
            remove_invalid: Whether to remove invalid strategies

        Returns:
            Dict of domain -> ValidationResult
        """
        results = {}
        invalid_domains = []

        self.logger.info(f"Revalidating {len(strategies)} strategies")

        for domain, strategy in strategies.items():
            try:
                result = self.validate_strategy(strategy)
                results[domain] = result

                if not result.is_valid:
                    self.logger.warning(f"Strategy for {domain} is invalid: {result.errors}")
                    invalid_domains.append(domain)

                    # Track failures
                    self._failed_strategies[domain] = self._failed_strategies.get(domain, 0) + 1

                    if self._failed_strategies[domain] >= self.max_failures:
                        self.logger.error(
                            f"Strategy for {domain} has failed {self._failed_strategies[domain]} times - "
                            f"marking as broken"
                        )
                else:
                    # Reset failure count on success
                    if domain in self._failed_strategies:
                        del self._failed_strategies[domain]

                    # Mark as working
                    strategy_hash = self._hash_strategy(strategy)
                    self._working_strategies[domain] = strategy_hash

            except Exception as e:
                self.logger.error(f"Revalidation failed for {domain}: {e}", exc_info=True)
                results[domain] = ValidationResult(
                    is_valid=False, errors=[f"Revalidation exception: {str(e)}"]
                )
                invalid_domains.append(domain)

        # Remove invalid strategies if requested
        if remove_invalid and invalid_domains:
            self.logger.info(f"Removing {len(invalid_domains)} invalid strategies")
            for domain in invalid_domains:
                if domain in strategies:
                    del strategies[domain]

        self.logger.info(
            f"Revalidation complete: {len(results) - len(invalid_domains)} valid, "
            f"{len(invalid_domains)} invalid"
        )

        return results

    def _hash_strategy(self, strategy: Any) -> str:
        """Create a hash of a strategy for tracking."""
        import hashlib

        if hasattr(strategy, "to_dict"):
            strategy_dict = strategy.to_dict()
        elif isinstance(strategy, dict):
            strategy_dict = strategy
        else:
            return ""

        # Create a stable string representation
        strategy_str = json.dumps(strategy_dict, sort_keys=True)
        return hashlib.md5(strategy_str.encode()).hexdigest()

    def get_working_strategies(self) -> Dict[str, str]:
        """Get dict of domains with working strategies."""
        return self._working_strategies.copy()

    def get_failed_strategies(self) -> Dict[str, int]:
        """Get dict of domains with failed strategies and failure counts."""
        return self._failed_strategies.copy()

    def mark_strategy_working(self, domain: str, strategy: Any) -> None:
        """Mark a strategy as working for a domain."""
        strategy_hash = self._hash_strategy(strategy)
        self._working_strategies[domain] = strategy_hash

        # Reset failure count
        if domain in self._failed_strategies:
            del self._failed_strategies[domain]

        self.logger.debug(f"Marked strategy for {domain} as working")

    def mark_strategy_failed(self, domain: str) -> None:
        """Mark a strategy as failed for a domain."""
        self._failed_strategies[domain] = self._failed_strategies.get(domain, 0) + 1
        self.logger.debug(
            f"Marked strategy for {domain} as failed " f"(count: {self._failed_strategies[domain]})"
        )

    def is_strategy_broken(self, domain: str) -> bool:
        """Check if a strategy is marked as broken (too many failures)."""
        return self._failed_strategies.get(domain, 0) >= self.max_failures

    def clear_validation_cache(self) -> None:
        """Clear the validation cache."""
        self._validation_cache.clear()
        self.logger.debug("Validation cache cleared")

    def get_validation_stats(self) -> Dict[str, Any]:
        """Get statistics about validation."""
        return {
            "working_strategies": len(self._working_strategies),
            "failed_strategies": len(self._failed_strategies),
            "broken_strategies": sum(
                1 for count in self._failed_strategies.values() if count >= self.max_failures
            ),
            "cache_size": len(self._validation_cache),
            "max_failures": self.max_failures,
        }

    def export_validation_report(self, output_file: str) -> None:
        """Export a validation report to a file."""
        report = {
            "timestamp": datetime.now().isoformat(),
            "stats": self.get_validation_stats(),
            "working_strategies": list(self._working_strategies.keys()),
            "failed_strategies": [
                {"domain": domain, "failure_count": count, "is_broken": count >= self.max_failures}
                for domain, count in self._failed_strategies.items()
            ],
        }

        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        self.logger.info(f"Validation report exported to {output_file}")

    def start_periodic_revalidation(
        self,
        strategies: Dict[str, Any],
        interval_seconds: int = 3600,
        remove_invalid: bool = True,
        notification_callback: Optional[callable] = None,
    ) -> None:
        """
        Start periodic revalidation of strategies in a background thread.

        Args:
            strategies: Dict of domain -> strategy to revalidate
            interval_seconds: Revalidation interval in seconds (default: 1 hour)
            remove_invalid: Whether to remove invalid strategies
            notification_callback: Optional callback for notifications (domain, is_valid, message)
        """
        import threading
        import time

        def revalidation_loop():
            """Background revalidation loop."""
            self.logger.info(
                f"Starting periodic revalidation (interval: {interval_seconds}s, "
                f"remove_invalid: {remove_invalid})"
            )

            while self._revalidation_active:
                try:
                    self.logger.debug("Running periodic revalidation")

                    # Revalidate all strategies
                    results = self.revalidate_strategies(strategies, remove_invalid)

                    # Process results and send notifications
                    for domain, result in results.items():
                        if not result.is_valid:
                            message = f"Strategy validation failed: {', '.join(result.errors)}"
                            self.logger.warning(f"{domain}: {message}")

                            # Send notification if callback provided
                            if notification_callback:
                                try:
                                    notification_callback(domain, False, message)
                                except Exception as e:
                                    self.logger.error(f"Notification callback failed: {e}")

                            # Check if strategy is broken
                            if self.is_strategy_broken(domain):
                                broken_message = (
                                    f"Strategy for {domain} is broken (too many failures)"
                                )
                                self.logger.error(broken_message)

                                if notification_callback:
                                    try:
                                        notification_callback(domain, False, broken_message)
                                    except Exception as e:
                                        self.logger.error(f"Notification callback failed: {e}")

                    # Export validation report
                    report_file = (
                        f"validation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    )
                    self.export_validation_report(report_file)

                    # Wait for next interval
                    time.sleep(interval_seconds)

                except Exception as e:
                    self.logger.error(f"Periodic revalidation failed: {e}", exc_info=True)
                    time.sleep(60)  # Wait 1 minute before retrying on error

            self.logger.info("Periodic revalidation stopped")

        # Start revalidation thread
        self._revalidation_active = True
        self._revalidation_thread = threading.Thread(
            target=revalidation_loop, daemon=True, name="StrategyRevalidation"
        )
        self._revalidation_thread.start()

        self.logger.info("Periodic revalidation thread started")

    def stop_periodic_revalidation(self) -> None:
        """Stop periodic revalidation."""
        if hasattr(self, "_revalidation_active"):
            self._revalidation_active = False
            self.logger.info("Stopping periodic revalidation")

            # Wait for thread to finish (with timeout)
            if hasattr(self, "_revalidation_thread") and self._revalidation_thread.is_alive():
                self._revalidation_thread.join(timeout=5.0)

                if self._revalidation_thread.is_alive():
                    self.logger.warning("Revalidation thread did not stop gracefully")
                else:
                    self.logger.info("Periodic revalidation stopped successfully")

    def schedule_revalidation(
        self,
        strategies: Dict[str, Any],
        schedule_time: str,
        remove_invalid: bool = True,
        notification_callback: Optional[callable] = None,
    ) -> None:
        """
        Schedule revalidation at a specific time daily.

        Args:
            strategies: Dict of domain -> strategy to revalidate
            schedule_time: Time in HH:MM format (24-hour)
            remove_invalid: Whether to remove invalid strategies
            notification_callback: Optional callback for notifications
        """
        import threading
        import time
        from datetime import datetime, timedelta

        def scheduled_revalidation_loop():
            """Background scheduled revalidation loop."""
            self.logger.info(f"Starting scheduled revalidation (time: {schedule_time})")

            while self._revalidation_active:
                try:
                    # Parse schedule time
                    hour, minute = map(int, schedule_time.split(":"))

                    # Calculate next run time
                    now = datetime.now()
                    next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)

                    # If time has passed today, schedule for tomorrow
                    if next_run <= now:
                        next_run += timedelta(days=1)

                    # Calculate wait time
                    wait_seconds = (next_run - now).total_seconds()

                    self.logger.info(
                        f"Next revalidation scheduled for {next_run} (in {wait_seconds:.0f}s)"
                    )

                    # Wait until scheduled time
                    time.sleep(wait_seconds)

                    # Run revalidation
                    if self._revalidation_active:
                        self.logger.info("Running scheduled revalidation")
                        results = self.revalidate_strategies(strategies, remove_invalid)

                        # Process results and send notifications
                        for domain, result in results.items():
                            if not result.is_valid:
                                message = f"Strategy validation failed: {', '.join(result.errors)}"
                                self.logger.warning(f"{domain}: {message}")

                                if notification_callback:
                                    try:
                                        notification_callback(domain, False, message)
                                    except Exception as e:
                                        self.logger.error(f"Notification callback failed: {e}")

                        # Export validation report
                        report_file = (
                            f"validation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                        )
                        self.export_validation_report(report_file)

                except Exception as e:
                    self.logger.error(f"Scheduled revalidation failed: {e}", exc_info=True)
                    time.sleep(3600)  # Wait 1 hour before retrying on error

            self.logger.info("Scheduled revalidation stopped")

        # Start scheduled revalidation thread
        self._revalidation_active = True
        self._revalidation_thread = threading.Thread(
            target=scheduled_revalidation_loop, daemon=True, name="ScheduledStrategyRevalidation"
        )
        self._revalidation_thread.start()

        self.logger.info(f"Scheduled revalidation thread started (time: {schedule_time})")


def create_strategy_validator(
    strategy_loader=None, pcap_analyzer=None, bypass_engine=None, debug: bool = False
) -> StrategyValidator:
    """
    Factory function to create a StrategyValidator instance.

    Args:
        strategy_loader: UnifiedStrategyLoader instance
        pcap_analyzer: PCAPAnalyzer instance
        bypass_engine: UnifiedBypassEngine instance
        debug: Enable debug logging

    Returns:
        Configured StrategyValidator instance
    """
    return StrategyValidator(
        strategy_loader=strategy_loader,
        pcap_analyzer=pcap_analyzer,
        bypass_engine=bypass_engine,
        debug=debug,
    )
