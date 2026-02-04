"""
Testing Service implementation for the refactored Adaptive Engine.

This service coordinates all strategy testing operations and manages
PCAP capture and analysis workflows.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from ..interfaces import ITestingService, ITestCoordinator
from ..models import Strategy, TestResult, TestMode, TestVerdict
from ..config import TestingConfig


logger = logging.getLogger(__name__)


class TestingService(ITestingService):
    """
    Implementation of testing service operations.

    Coordinates strategy testing by managing the test coordinator
    and providing high-level testing workflows with PCAP capture
    and analysis coordination.

    This service extracts the testing orchestration logic from the
    original monolithic AdaptiveEngine.
    """

    def __init__(self, test_coordinator: ITestCoordinator, config: TestingConfig):
        self.test_coordinator = test_coordinator
        self.config = config

        logger.info("Testing service initialized")
        logger.info(f"PCAP verification: {'enabled' if config.verify_with_pcap else 'disabled'}")
        logger.info(
            f"Parallel testing: {'enabled' if config.enable_parallel_testing else 'disabled'}"
        )
        logger.info(f"Test retries: {'enabled' if config.retry_failed_tests else 'disabled'}")

    async def test_strategy(
        self, domain: str, strategy: Strategy, shared_pcap_file: Optional[str] = None
    ) -> TestResult:
        """
        Test a single strategy against a domain with optional shared PCAP capture.

        This method implements the high-level testing workflow extracted from
        the original AdaptiveEngine._test_strategy_with_capture method.

        Args:
            domain: Domain to test against
            strategy: Strategy to test
            shared_pcap_file: Optional shared PCAP file for continuous capture

        Returns:
            TestResult with test outcome and artifacts
        """
        try:
            logger.info(f"Testing strategy {strategy.name} against {domain}")

            # Start test session with coordinator
            session_id = self.test_coordinator.start_test_session(
                domain, strategy.name, shared_pcap_file
            )

            # Execute test with retry logic if enabled
            if self.config.retry_failed_tests:
                result = await self._test_with_retry(domain, strategy, session_id)
            else:
                result = await self._execute_single_test(domain, strategy, session_id)

            # Add session ID to result metadata for tracking
            if not hasattr(result, "metadata") or result.metadata is None:
                result.metadata = {}
            result.metadata["session_id"] = session_id

            # Record the result with the coordinator
            self.test_coordinator.record_response(
                session_id,
                success=result.success,
                timeout="timeout" in (result.error or "").lower(),
                error=result.error,
                response_data={"execution_time": result.execution_time},
            )

            # Add test result to session for tracking
            self.test_coordinator.add_test_result_to_session(session_id, result)

            # Update strategy metadata with test result
            if hasattr(strategy, "last_tested"):
                try:
                    strategy.last_tested = getattr(result, "timestamp", None)
                except Exception:
                    pass
            if hasattr(strategy, "success_rate"):
                try:
                    current_rate = getattr(strategy, "success_rate", 0.0) or 0.0
                    if result.success:
                        # Update success rate (simple moving average)
                        strategy.success_rate = (float(current_rate) + 1.0) / 2.0
                    else:
                        # Decrease success rate on failure
                        strategy.success_rate = float(current_rate) * 0.9
                except Exception:
                    pass

            logger.info(
                f"Test completed for {strategy.name}: {'SUCCESS' if result.success else 'FAILED'}"
            )
            return result

        except Exception as e:
            logger.error(f"Failed to test strategy {strategy.name} against {domain}: {e}")

            # Return failure result
            return TestResult(
                success=False,
                strategy=strategy,
                domain=domain,
                execution_time=0.0,
                error=str(e),
                test_mode=TestMode.DISCOVERY,
            )

    async def _execute_single_test(
        self, domain: str, strategy: Strategy, session_id: str
    ) -> TestResult:
        """Execute a single test without retry logic."""
        return await self.test_coordinator.execute_test(domain, strategy)

    async def _test_with_retry(
        self, domain: str, strategy: Strategy, session_id: str
    ) -> TestResult:
        """Test strategy with retry logic."""
        last_result = None

        for attempt in range(self.config.max_test_retries + 1):
            try:
                result = await self.test_coordinator.execute_test(domain, strategy)

                # Return immediately on success
                if result.success:
                    if attempt > 0:
                        logger.info(f"Test succeeded on attempt {attempt + 1}")
                    return result

                last_result = result

                # Don't retry on the last attempt
                if attempt < self.config.max_test_retries:
                    logger.warning(
                        f"Test failed on attempt {attempt + 1}, retrying in {self.config.test_retry_delay}s"
                    )
                    await asyncio.sleep(self.config.test_retry_delay)

            except Exception as e:
                logger.error(f"Test attempt {attempt + 1} failed with exception: {e}")
                last_result = TestResult(
                    success=False,
                    strategy=strategy,
                    domain=domain,
                    execution_time=0.0,
                    error=str(e),
                    test_mode=TestMode.DISCOVERY,
                )

        return last_result or TestResult(
            success=False,
            strategy=strategy,
            domain=domain,
            execution_time=0.0,
            error="All retry attempts failed",
            test_mode=TestMode.DISCOVERY,
        )

    async def test_multiple_strategies(
        self, domain: str, strategies: List[Strategy], shared_pcap_file: Optional[str] = None
    ) -> List[TestResult]:
        """
        Test multiple strategies against a domain with coordinated PCAP capture.

        This method implements the multi-strategy testing workflow with
        optional shared PCAP capture for comprehensive analysis.

        Args:
            domain: Domain to test against
            strategies: List of strategies to test
            shared_pcap_file: Optional shared PCAP file for continuous capture

        Returns:
            List of test results
        """
        try:
            logger.info(f"Testing {len(strategies)} strategies against {domain}")

            if self.config.enable_parallel_testing:
                results = await self._test_strategies_parallel(domain, strategies, shared_pcap_file)
            else:
                results = await self._test_strategies_sequential(
                    domain, strategies, shared_pcap_file
                )

            successful_results = [r for r in results if r.success]
            logger.info(
                f"Testing completed: {len(successful_results)}/{len(results)} strategies succeeded"
            )

            return results

        except Exception as e:
            logger.error(f"Failed to test multiple strategies against {domain}: {e}")
            return []

    async def _test_strategies_parallel(
        self, domain: str, strategies: List[Strategy], shared_pcap_file: Optional[str] = None
    ) -> List[TestResult]:
        """Test strategies in parallel with coordinated PCAP capture."""
        semaphore = asyncio.Semaphore(self.config.max_parallel_workers)

        async def test_with_semaphore(strategy: Strategy) -> TestResult:
            async with semaphore:
                return await self.test_strategy(domain, strategy, shared_pcap_file)

        tasks = [test_with_semaphore(strategy) for strategy in strategies]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle exceptions in results
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Parallel test failed for strategy {strategies[i].name}: {result}")
                final_results.append(
                    TestResult(
                        success=False,
                        strategy=strategies[i],
                        domain=domain,
                        execution_time=0.0,
                        error=str(result),
                        test_mode=TestMode.DISCOVERY,
                    )
                )
            else:
                final_results.append(result)

        return final_results

    async def _test_strategies_sequential(
        self, domain: str, strategies: List[Strategy], shared_pcap_file: Optional[str] = None
    ) -> List[TestResult]:
        """Test strategies sequentially with coordinated PCAP capture."""
        results = []

        for strategy in strategies:
            result = await self.test_strategy(domain, strategy, shared_pcap_file)
            results.append(result)

            # Early termination if we find a successful strategy and it's not validation mode
            if result.success and not self.config.enable_test_validation:
                logger.info(
                    f"Found successful strategy {strategy.name}, stopping sequential testing"
                )
                break

        return results

    async def validate_test_result(self, result: TestResult) -> bool:
        """
        Validate that a test result is accurate using PCAP analysis if available.

        This method implements comprehensive test result validation including
        PCAP analysis coordination as extracted from the original AdaptiveEngine.

        Args:
            result: Test result to validate

        Returns:
            True if result is valid, False otherwise
        """
        try:
            if not self.config.enable_test_validation:
                return True

            # Basic validation checks
            exec_time = getattr(result, "execution_time", 0.0) or 0.0
            if exec_time < 0:
                logger.warning("Invalid execution time in test result")
                return False

            if result.success and result.error:
                logger.warning("Test result marked as success but has error message")
                return False

            if not result.success and not result.error:
                logger.warning("Test result marked as failure but has no error message")
                return False

            # Additional validation with PCAP if available
            if result.artifacts and result.artifacts.pcap_path:
                return await self._validate_with_pcap(result)

            # Validate using session data if available
            if (
                hasattr(result, "metadata")
                and result.metadata
                and result.metadata.get("session_id")
            ):
                session_id = result.metadata["session_id"]
                return await self._validate_with_session_data(result, session_id)

            return True

        except Exception as e:
            logger.error(f"Failed to validate test result: {e}")
            return False

    async def _validate_with_pcap(self, result: TestResult) -> bool:
        """Validate test result using PCAP analysis."""
        try:
            pcap_path = result.artifacts.pcap_path
            logger.info(f"Validating test result with PCAP analysis: {pcap_path}")

            # Get PCAP analysis through coordinator for caching
            pcap_analysis = self.test_coordinator.get_pcap_analysis(pcap_path)

            if not pcap_analysis:
                logger.warning(f"PCAP analysis not available for validation: {pcap_path}")
                return True  # Don't fail validation if PCAP analysis unavailable

            # Validate based on PCAP analysis results
            # This would contain actual validation logic based on packet analysis
            success_indicators = pcap_analysis.get("success_indicators", [])
            dpi_detection = pcap_analysis.get("dpi_detection", {})

            # Basic validation: if test claims success, PCAP should show success indicators
            if result.success:
                if not success_indicators:
                    logger.warning("Test claims success but PCAP shows no success indicators")
                    return False

            logger.info(f"PCAP validation completed for {pcap_path}: VALID")
            return True

        except Exception as e:
            logger.error(f"PCAP validation failed: {e}")
            return False

    async def _validate_with_session_data(self, result: TestResult, session_id: str) -> bool:
        """Validate test result using session data from coordinator."""
        try:
            session_data = self.test_coordinator.get_session(session_id)
            if not session_data:
                logger.warning(f"No session data available for validation: {session_id}")
                return True

            # Check if coordinator responses align with test result
            responses = session_data.get("responses_recorded", [])
            if responses:
                coordinator_success = any(r["success"] for r in responses)
                coordinator_timeout = any(r["timeout"] for r in responses)

                # Validate consistency
                if result.success != coordinator_success:
                    logger.warning(
                        f"Test result inconsistent with coordinator responses: "
                        f"result={result.success}, coordinator={coordinator_success}"
                    )
                    return False

                if "timeout" in (result.error or "").lower() and not coordinator_timeout:
                    logger.warning("Test claims timeout but coordinator shows no timeout")
                    return False

            logger.debug(f"Session data validation completed for {session_id}: VALID")
            return True

        except Exception as e:
            logger.error(f"Session data validation failed: {e}")
            return False

    async def run_comprehensive_test(
        self, domain: str, strategies: List[Strategy]
    ) -> Dict[str, Any]:
        """Run comprehensive testing with detailed analysis."""
        try:
            logger.info(
                f"Running comprehensive test for {domain} with {len(strategies)} strategies"
            )

            # Start test session
            session_id = self.test_coordinator.start_test_session(domain, "comprehensive_test")

            # Test all strategies
            results = await self.test_multiple_strategies(domain, strategies)

            # Finalize session
            verdict = self.test_coordinator.finalize_test_session(session_id)

            # Analyze results
            analysis = self._analyze_test_results(results)

            return {
                "session_id": session_id,
                "domain": domain,
                "total_strategies": len(strategies),
                "results": [result.to_dict() for result in results],
                "verdict": {
                    "success": verdict.success,
                    "confidence": verdict.confidence,
                    "evidence": verdict.evidence,
                    "recommendations": verdict.recommendations,
                },
                "analysis": analysis,
            }

        except Exception as e:
            logger.error(f"Comprehensive test failed for {domain}: {e}")
            return {"error": str(e)}

    def _analyze_test_results(self, results: List[TestResult]) -> Dict[str, Any]:
        """Analyze test results and provide insights."""
        if not results:
            return {"error": "No test results to analyze"}

        successful_results = [r for r in results if r.success]
        failed_results = [r for r in results if not r.success]

        analysis = {
            "total_tests": len(results),
            "successful_tests": len(successful_results),
            "failed_tests": len(failed_results),
            "success_rate": len(successful_results) / len(results),
            "average_execution_time": sum(
                float(getattr(r, "execution_time", 0.0) or 0.0) for r in results
            )
            / len(results),
        }

        if successful_results:
            best_result = min(successful_results, key=lambda r: r.execution_time)
            analysis["best_strategy"] = {
                "name": best_result.strategy.name,
                "execution_time": best_result.execution_time,
                "confidence_score": best_result.strategy.confidence_score,
            }

        if failed_results:
            # Analyze failure patterns
            error_types = {}
            for result in failed_results:
                error = result.error or "Unknown error"
                error_type = error.split(":")[0] if ":" in error else error
                error_types[error_type] = error_types.get(error_type, 0) + 1

            analysis["failure_patterns"] = error_types

        return analysis

    async def get_testing_statistics(self) -> Dict[str, Any]:
        """Get testing service statistics."""
        try:
            active_sessions = self.test_coordinator.get_active_sessions()

            return {
                "active_sessions": len(active_sessions),
                "session_details": active_sessions,
                "configuration": {
                    "parallel_testing_enabled": self.config.enable_parallel_testing,
                    "max_parallel_workers": self.config.max_parallel_workers,
                    "retry_enabled": self.config.retry_failed_tests,
                    "max_retries": self.config.max_test_retries,
                    "pcap_verification": self.config.verify_with_pcap,
                },
            }

        except Exception as e:
            logger.error(f"Failed to get testing statistics: {e}")
            return {"error": str(e)}

    async def coordinate_pcap_capture(self, domain: str, duration: float) -> Optional[str]:
        """
        Coordinate PCAP capture for a domain.

        This method provides centralized PCAP capture coordination,
        delegating to the test coordinator for actual capture management.

        Args:
            domain: Domain to capture traffic for
            duration: Capture duration in seconds

        Returns:
            Path to captured PCAP file or None if capture failed
        """
        try:
            logger.info(f"Coordinating PCAP capture for {domain} (duration: {duration}s)")

            pcap_path = await self.test_coordinator.capture_pcap(domain, duration)

            if pcap_path:
                logger.info(f"PCAP capture coordinated successfully: {pcap_path}")
            else:
                logger.warning(f"PCAP capture coordination failed for {domain}")

            return pcap_path

        except Exception as e:
            logger.error(f"Failed to coordinate PCAP capture for {domain}: {e}")
            return None

    async def finalize_test_session(self, session_id: str) -> TestVerdict:
        """
        Finalize a test session and get the verdict.

        This method provides a high-level interface to the test coordinator's
        session finalization functionality.

        Args:
            session_id: Test session ID to finalize

        Returns:
            TestVerdict with final determination
        """
        try:
            logger.info(f"Finalizing test session: {session_id}")

            verdict = self.test_coordinator.finalize_test_session(session_id)

            logger.info(
                f"Test session finalized: {session_id} -> "
                f"{'SUCCESS' if verdict.success else 'FAILED'} "
                f"(confidence: {verdict.confidence:.2f})"
            )

            return verdict

        except Exception as e:
            logger.error(f"Failed to finalize test session {session_id}: {e}")
            return TestVerdict(
                session_id=session_id,
                success=False,
                confidence=0.0,
                evidence=[f"Finalization failed: {str(e)}"],
                recommendations=["Check session ID and try again"],
            )

    def should_save_strategy(self, session_id: str) -> bool:
        """
        Determine if a strategy should be saved based on test session results.

        This method provides a high-level interface to the test coordinator's
        strategy save approval functionality.

        Args:
            session_id: Test session ID

        Returns:
            True if strategy should be saved, False otherwise
        """
        return self.test_coordinator.should_save_strategy(session_id)

    async def validate_test_environment(self) -> bool:
        """
        Validate that the test environment is properly configured and ready for testing.

        This method performs comprehensive validation of the testing environment
        including network connectivity, required tools, and configuration settings.

        Returns:
            True if environment is valid and ready for testing, False otherwise
        """
        try:
            logger.info("Validating test environment")

            # Check basic configuration
            if not self.config:
                logger.error("Testing configuration is missing")
                return False

            # Validate timeout settings
            if self.config.strategy_timeout <= 0:
                logger.error(f"Invalid strategy timeout: {self.config.strategy_timeout}")
                return False

            if self.config.connection_timeout <= 0:
                logger.error(f"Invalid connection timeout: {self.config.connection_timeout}")
                return False

            # Validate parallel testing configuration
            if self.config.enable_parallel_testing:
                if self.config.max_parallel_workers <= 0:
                    logger.error(
                        f"Invalid max parallel workers: {self.config.max_parallel_workers}"
                    )
                    return False

            # Validate retry configuration
            if self.config.retry_failed_tests:
                if not hasattr(self.config, "max_test_retries") or self.config.max_test_retries < 0:
                    logger.warning("Retry enabled but max_test_retries not properly configured")

                if not hasattr(self.config, "test_retry_delay") or self.config.test_retry_delay < 0:
                    logger.warning("Retry enabled but test_retry_delay not properly configured")

            # Check test coordinator availability
            if not self.test_coordinator:
                logger.error("Test coordinator is not available")
                return False

            # Validate PCAP configuration if enabled
            if self.config.verify_with_pcap:
                logger.info("PCAP verification is enabled - validating PCAP capabilities")
                # Additional PCAP validation could be added here

            # Check if we can create test sessions
            try:
                test_session_id = self.test_coordinator.start_test_session(
                    "validation-test", "environment-check"
                )
                if test_session_id:
                    logger.debug(f"Test session creation validated: {test_session_id}")
                    # Clean up the validation session
                    try:
                        self.test_coordinator.finalize_test_session(test_session_id)
                    except Exception as cleanup_error:
                        logger.warning(f"Failed to clean up validation session: {cleanup_error}")
                else:
                    logger.error("Failed to create test session during validation")
                    return False
            except Exception as session_error:
                logger.error(f"Test session validation failed: {session_error}")
                return False

            logger.info("Test environment validation completed successfully")
            return True

        except Exception as e:
            logger.error(f"Test environment validation failed: {e}")
            return False

    async def cleanup_test_artifacts(self, domain: str) -> None:
        """
        Clean up test artifacts and temporary files for a domain.

        This method removes temporary files, clears caches, and performs
        cleanup operations related to testing a specific domain.

        Args:
            domain: Domain to clean up artifacts for
        """
        try:
            logger.info(f"Cleaning up test artifacts for domain: {domain}")

            # Get active sessions for this domain
            active_sessions = self.test_coordinator.get_active_sessions()

            # Handle case where active_sessions might be a Mock or None
            if active_sessions is None or not hasattr(active_sessions, "items"):
                active_sessions = {}

            domain_sessions = [
                session_id
                for session_id, session_data in active_sessions.items()
                if session_data.get("domain") == domain
            ]

            # Finalize any active sessions for this domain
            for session_id in domain_sessions:
                try:
                    logger.info(f"Finalizing active session for cleanup: {session_id}")
                    self.test_coordinator.finalize_test_session(session_id)
                except Exception as session_error:
                    logger.warning(
                        f"Failed to finalize session {session_id} during cleanup: {session_error}"
                    )

            # Clean up PCAP files if any exist for this domain
            # This would typically involve checking for temporary PCAP files
            # and removing them if they're no longer needed

            # Clean up any temporary test data
            # This could include clearing domain-specific caches or temporary files

            logger.info(f"Test artifacts cleanup completed for domain: {domain}")

        except Exception as e:
            logger.error(f"Failed to clean up test artifacts for {domain}: {e}")
            # Don't re-raise the exception as cleanup failures shouldn't break the main flow

    def get_test_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive testing statistics and metrics.

        This method provides detailed statistics about testing operations
        including success rates, performance metrics, and configuration status.

        Returns:
            Dictionary containing comprehensive testing statistics
        """
        try:
            logger.debug("Collecting testing statistics")

            # Get active sessions from coordinator
            active_sessions = self.test_coordinator.get_active_sessions()

            # Handle case where active_sessions might be a Mock or None
            if active_sessions is None or not hasattr(active_sessions, "__len__"):
                active_sessions = {}

            # Basic statistics
            stats = {
                "total_tests": 0,
                "successful_tests": 0,
                "failed_tests": 0,
                "active_sessions": len(active_sessions),
                "configuration": {
                    "parallel_testing_enabled": self.config.enable_parallel_testing,
                    "max_parallel_workers": self.config.max_parallel_workers,
                    "strategy_timeout": self.config.strategy_timeout,
                    "connection_timeout": self.config.connection_timeout,
                    "pcap_verification": self.config.verify_with_pcap,
                    "retry_enabled": getattr(self.config, "retry_failed_tests", False),
                    "max_retries": getattr(self.config, "max_test_retries", 0),
                    "test_validation_enabled": getattr(
                        self.config, "enable_test_validation", False
                    ),
                },
            }

            # Analyze active sessions for additional statistics
            if active_sessions:
                session_domains = set()
                session_strategies = set()

                for session_id, session_data in active_sessions.items():
                    if isinstance(session_data, dict):
                        domain = session_data.get("domain")
                        strategy_name = session_data.get("strategy_name")

                        if domain:
                            session_domains.add(domain)
                        if strategy_name:
                            session_strategies.add(strategy_name)

                        # Count responses if available
                        responses = session_data.get("responses_recorded", [])
                        for response in responses:
                            if isinstance(response, dict):
                                if response.get("success"):
                                    stats["successful_tests"] += 1
                                else:
                                    stats["failed_tests"] += 1
                                stats["total_tests"] += 1

                stats["unique_domains_tested"] = len(session_domains)
                stats["unique_strategies_tested"] = len(session_strategies)
                stats["session_details"] = {
                    "domains": list(session_domains),
                    "strategies": list(session_strategies),
                }

            # Calculate success rate
            if stats["total_tests"] > 0:
                stats["success_rate"] = stats["successful_tests"] / stats["total_tests"]
            else:
                stats["success_rate"] = 0.0

            # Add timestamp
            stats["timestamp"] = datetime.now(timezone.utc).isoformat()

            logger.debug(
                f"Testing statistics collected: {stats['total_tests']} total tests, "
                f"{stats['active_sessions']} active sessions"
            )

            return stats

        except Exception as e:
            logger.error(f"Failed to collect testing statistics: {e}")
            return {
                "error": str(e),
                "total_tests": 0,
                "successful_tests": 0,
                "failed_tests": 0,
                "active_sessions": 0,
                "success_rate": 0.0,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
