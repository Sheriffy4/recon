#!/usr/bin/env python3
"""
Comprehensive Reliability Validation System for Bypass Engine Modernization.

This module provides multi-level validation of bypass strategies with enhanced
reliability checking, false positive detection, and comprehensive effectiveness scoring.
"""

import asyncio
import logging
import time
import statistics
from typing import Dict, Any, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

# Import types from separate module
from .types import (
    ValidationMethod,
    ReliabilityLevel,
    AccessibilityStatus,
    ValidationResult,
    AccessibilityResult,
    StrategyEffectivenessResult,
)

# Import validation functions
from . import validators
from . import reliability_calculator as calc
from . import report_generator


class ReliabilityValidator:
    """
    Comprehensive reliability validation system for bypass strategies.

    Provides:
    - Multi-level accessibility checking with multiple validation methods
    - False positive detection and prevention
    - Strategy effectiveness scoring with detailed metrics
    - Consistency validation across multiple test runs
    - Performance-aware reliability assessment
    """

    def __init__(self, max_concurrent_tests: int = 10, timeout: float = 30.0):
        self.logger = logging.getLogger(__name__)
        self.max_concurrent_tests = max_concurrent_tests
        self.timeout = timeout

        # Validation configuration
        self.validation_methods = [
            ValidationMethod.HTTP_RESPONSE,
            ValidationMethod.CONTENT_CHECK,
            ValidationMethod.TIMING_ANALYSIS,
            ValidationMethod.DNS_RESOLUTION,
        ]

        # False positive detection thresholds
        self.false_positive_thresholds = {
            "response_time_variance": 2.0,  # Standard deviations
            "content_similarity": 0.8,  # Minimum similarity for consistency
            "status_code_consistency": 0.9,  # Minimum consistency rate
            "dns_consistency": 0.95,  # DNS resolution consistency
        }

        # Performance baselines
        self.performance_baselines = {
            "max_response_time": 10.0,  # Maximum acceptable response time
            "min_success_rate": 0.7,  # Minimum success rate for reliability
            "consistency_threshold": 0.8,  # Minimum consistency for reliability
        }

        # Thread pool for concurrent operations
        self._thread_pool = ThreadPoolExecutor(max_workers=max_concurrent_tests)

        # Cache for DNS resolutions and baseline measurements (with thread safety)
        self._dns_cache: Dict[str, str] = {}
        self._dns_cache_lock = Lock()  # Thread-safe access to DNS cache
        self._baseline_cache: Dict[str, Dict[str, Any]] = {}
        self._baseline_cache_lock = Lock()  # Thread-safe access to baseline cache

    async def validate_strategy_effectiveness(
        self, strategy_id: str, domain: str, port: int = 443, test_iterations: int = 5
    ) -> StrategyEffectivenessResult:
        """
        Validate the effectiveness of a bypass strategy for a specific domain.

        Args:
            strategy_id: Identifier of the strategy being tested
            domain: Target domain to test
            port: Target port (default 443 for HTTPS)
            test_iterations: Number of test iterations for consistency checking

        Returns:
            Comprehensive strategy effectiveness result
        """
        self.logger.info(f"Validating strategy {strategy_id} for {domain}:{port}")

        # Collect baseline measurements without bypass
        baseline_result = await self._collect_baseline_measurements(domain, port)

        # Run multiple accessibility tests with the strategy
        accessibility_results = []
        for iteration in range(test_iterations):
            result = await self.multi_level_accessibility_check(domain, port)
            accessibility_results.append(result)

            # Add small delay between iterations
            await asyncio.sleep(0.5)

        # Calculate effectiveness metrics
        effectiveness_score = calc.calculate_effectiveness_score(
            accessibility_results, baseline_result
        )

        # Detect false positives
        false_positive_rate = calc.detect_false_positives(
            accessibility_results,
            baseline_result,
            self.false_positive_thresholds["response_time_variance"],
        )

        # Calculate consistency score
        consistency_score = calc.calculate_consistency_score(accessibility_results)

        # Calculate performance score
        performance_score = calc.calculate_performance_score(
            accessibility_results, self.performance_baselines["max_response_time"]
        )

        # Determine reliability level
        reliability_level = calc.determine_reliability_level(
            effectiveness_score, consistency_score, false_positive_rate
        )

        # Generate recommendation
        recommendation = calc.generate_strategy_recommendation(
            reliability_level,
            false_positive_rate,
            consistency_score,
            performance_score,
        )

        return StrategyEffectivenessResult(
            strategy_id=strategy_id,
            domain=domain,
            port=port,
            effectiveness_score=effectiveness_score,
            reliability_level=reliability_level,
            accessibility_results=accessibility_results,
            false_positive_rate=false_positive_rate,
            consistency_score=consistency_score,
            performance_score=performance_score,
            recommendation=recommendation,
            metadata={
                "baseline_result": baseline_result,
                "test_iterations": test_iterations,
                "validation_timestamp": time.time(),
            },
        )

    async def multi_level_accessibility_check(
        self, domain: str, port: int = 443
    ) -> AccessibilityResult:
        """
        Perform multi-level accessibility checking using various validation methods.

        Args:
            domain: Target domain
            port: Target port

        Returns:
            Comprehensive accessibility result
        """
        self.logger.debug(f"Multi-level accessibility check for {domain}:{port}")

        # Run all validation methods concurrently
        validation_tasks = []
        for method in self.validation_methods:
            task = asyncio.create_task(self._run_validation_method(method, domain, port))
            validation_tasks.append(task)

        # Wait for all validations to complete
        validation_results = await asyncio.gather(*validation_tasks, return_exceptions=True)

        # Filter out exceptions and create ValidationResult objects
        valid_results = []
        for i, result in enumerate(validation_results):
            if isinstance(result, Exception):
                self.logger.warning(
                    f"Validation method {self.validation_methods[i]} failed: {result}"
                )
                # Create failed validation result
                valid_results.append(
                    ValidationResult(
                        method=self.validation_methods[i],
                        success=False,
                        response_time=self.timeout,
                        error_message=str(result),
                    )
                )
            else:
                valid_results.append(result)

        # Analyze results
        successful_tests = sum(1 for r in valid_results if r.success)
        total_tests = len(valid_results)

        # Calculate metrics
        reliability_score = calc.calculate_reliability_score(
            valid_results, self.performance_baselines["max_response_time"]
        )
        false_positive_detected = calc.detect_false_positive_in_results(
            valid_results, self.false_positive_thresholds["status_code_consistency"]
        )
        bypass_effectiveness = successful_tests / total_tests if total_tests > 0 else 0.0

        # Determine accessibility status
        status = calc.determine_accessibility_status(valid_results, reliability_score)

        # Calculate average response time
        response_times = [
            r.response_time for r in valid_results if r.success and r.response_time > 0
        ]
        average_response_time = statistics.mean(response_times) if response_times else 0.0

        return AccessibilityResult(
            domain=domain,
            port=port,
            status=status,
            validation_results=valid_results,
            reliability_score=reliability_score,
            false_positive_detected=false_positive_detected,
            bypass_effectiveness=bypass_effectiveness,
            total_tests=total_tests,
            successful_tests=successful_tests,
            average_response_time=average_response_time,
            metadata={
                "validation_timestamp": time.time(),
                "method_count": len(self.validation_methods),
            },
        )

    async def _run_validation_method(
        self, method: ValidationMethod, domain: str, port: int
    ) -> ValidationResult:
        """Run a specific validation method using dispatch table."""
        # Dispatch table mapping methods to validator functions and their arguments
        dispatch_table = {
            ValidationMethod.HTTP_RESPONSE: (
                validators.validate_http_response,
                (domain, port, self.timeout),
            ),
            ValidationMethod.CONTENT_CHECK: (
                validators.validate_content_check,
                (
                    domain,
                    port,
                    self.timeout,
                    self.false_positive_thresholds["content_similarity"],
                ),
            ),
            ValidationMethod.TIMING_ANALYSIS: (
                validators.validate_timing_analysis,
                (domain, port, self.timeout, self.performance_baselines["max_response_time"]),
            ),
            ValidationMethod.MULTI_REQUEST: (
                validators.validate_multi_request,
                (domain, port, self.timeout, self.performance_baselines["min_success_rate"]),
            ),
            ValidationMethod.DNS_RESOLUTION: (
                validators.validate_dns_resolution,
                (domain, self.timeout, self._dns_cache, self._thread_pool, self._dns_cache_lock),
            ),
            ValidationMethod.SSL_HANDSHAKE: (
                validators.validate_ssl_handshake,
                (domain, port, self.timeout, self._thread_pool),
            ),
            ValidationMethod.HEADER_ANALYSIS: (
                validators.validate_header_analysis,
                (domain, port, self.timeout),
            ),
            ValidationMethod.PAYLOAD_VERIFICATION: (
                validators.validate_payload_verification,
                (domain, port, self.timeout),
            ),
        }

        try:
            if method not in dispatch_table:
                raise ValueError(f"Unknown validation method: {method}")

            validator_func, args = dispatch_table[method]
            return await validator_func(*args)

        except Exception as e:
            return ValidationResult(
                method=method,
                success=False,
                response_time=self.timeout,
                error_message=str(e),
            )

    async def _collect_baseline_measurements(self, domain: str, port: int) -> Dict[str, Any]:
        """Collect baseline measurements without bypass for comparison (thread-safe)."""
        cache_key = f"{domain}:{port}"

        # Check cache (thread-safe)
        with self._baseline_cache_lock:
            if cache_key in self._baseline_cache:
                return self._baseline_cache[cache_key]

        self.logger.debug(f"Collecting baseline measurements for {domain}:{port}")

        # Run basic accessibility check without bypass
        baseline_result = await self.multi_level_accessibility_check(domain, port)

        baseline_data = {
            "accessibility_status": baseline_result.status.value,
            "reliability_score": baseline_result.reliability_score,
            "average_response_time": baseline_result.average_response_time,
            "successful_tests": baseline_result.successful_tests,
            "total_tests": baseline_result.total_tests,
            "timestamp": time.time(),
        }

        # Cache the baseline (thread-safe)
        with self._baseline_cache_lock:
            self._baseline_cache[cache_key] = baseline_data

        return baseline_data

    async def batch_validate_strategies(
        self,
        strategy_domain_pairs: List[Tuple[str, str, int]],
        test_iterations: int = 3,
    ) -> List[StrategyEffectivenessResult]:
        """
        Validate multiple strategies in batch for efficiency.

        Args:
            strategy_domain_pairs: List of (strategy_id, domain, port) tuples
            test_iterations: Number of test iterations per strategy

        Returns:
            List of strategy effectiveness results
        """
        self.logger.info(f"Batch validating {len(strategy_domain_pairs)} strategy-domain pairs")

        # Create semaphore to limit concurrent validations
        semaphore = asyncio.Semaphore(self.max_concurrent_tests)

        async def validate_single(strategy_id: str, domain: str, port: int):
            async with semaphore:
                return await self.validate_strategy_effectiveness(
                    strategy_id, domain, port, test_iterations
                )

        # Run all validations concurrently
        tasks = [
            validate_single(strategy_id, domain, port)
            for strategy_id, domain, port in strategy_domain_pairs
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                strategy_id, domain, port = strategy_domain_pairs[i]
                self.logger.error(
                    f"Validation failed for {strategy_id} on {domain}:{port}: {result}"
                )
            else:
                valid_results.append(result)

        return valid_results

    def generate_reliability_report(
        self, results: List[StrategyEffectivenessResult]
    ) -> Dict[str, Any]:
        """Generate comprehensive reliability report (delegates to report_generator)."""
        return report_generator.generate_reliability_report(results)

    def cleanup(self):
        """Clean up resources."""
        if self._thread_pool:
            self._thread_pool.shutdown(wait=True)

        # Clear caches
        self._dns_cache.clear()
        self._baseline_cache.clear()

        self.logger.info("Reliability validator cleaned up")


# Global validator instance
_global_reliability_validator: Optional[ReliabilityValidator] = None


def get_global_reliability_validator() -> ReliabilityValidator:
    """Get or create global reliability validator."""
    global _global_reliability_validator
    if _global_reliability_validator is None:
        _global_reliability_validator = ReliabilityValidator()
    return _global_reliability_validator


async def validate_domain_accessibility(domain: str, port: int = 443) -> AccessibilityResult:
    """
    Convenience function to validate domain accessibility.

    Args:
        domain: Target domain
        port: Target port

    Returns:
        AccessibilityResult
    """
    validator = get_global_reliability_validator()
    return await validator.multi_level_accessibility_check(domain, port)


async def validate_strategy_reliability(
    strategy_id: str, domain: str, port: int = 443, iterations: int = 5
) -> StrategyEffectivenessResult:
    """
    Convenience function to validate strategy reliability.

    Args:
        strategy_id: Strategy identifier
        domain: Target domain
        port: Target port
        iterations: Number of test iterations

    Returns:
        StrategyEffectivenessResult
    """
    validator = get_global_reliability_validator()
    return await validator.validate_strategy_effectiveness(strategy_id, domain, port, iterations)
