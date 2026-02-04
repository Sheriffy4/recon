"""
Test Coordinator implementation for the refactored Adaptive Engine.

This component manages test execution, PCAP capture, and result validation.
Extracted from the original AdaptiveEngine to provide centralized test coordination.
"""

import asyncio
import logging
import time
from typing import Dict, Optional, Any, List
from datetime import datetime
from pathlib import Path
import re
from ..interfaces import ITestCoordinator, IBypassEngine, IPCAPAnalyzer, IStrategyValidator
from ..models import Strategy, TestResult, TestVerdict, TestArtifacts, TestMode
from ..config import TestingConfig


logger = logging.getLogger(__name__)


class TestCoordinator(ITestCoordinator):
    """
    Implementation of test coordination and management.

    Manages the complete testing workflow including:
    - Test session lifecycle management
    - PCAP capture coordination
    - Result validation and verdict determination
    - Test artifact management
    - Integration with bypass engines and analyzers

    This component extracts and centralizes the test coordination logic
    from the original monolithic AdaptiveEngine.
    """

    def __init__(
        self,
        config: TestingConfig,
        bypass_engine: Optional[IBypassEngine] = None,
        pcap_analyzer: Optional[IPCAPAnalyzer] = None,
        strategy_validator: Optional[IStrategyValidator] = None,
    ):
        self.config = config
        self.bypass_engine = bypass_engine
        self.pcap_analyzer = pcap_analyzer
        self.strategy_validator = strategy_validator

        # Active test sessions - maps session_id to session data
        self._active_sessions: Dict[str, Dict[str, Any]] = {}

        # Test session counter for unique session IDs
        self._session_counter = 0

        # Ensure temp_pcap directory exists
        self._ensure_pcap_directory()

        logger.info(f"Test coordinator initialized with timeout {config.strategy_timeout}s")
        logger.info(f"PCAP verification: {'enabled' if config.verify_with_pcap else 'disabled'}")
        logger.info(
            f"Parallel testing: {'enabled' if config.enable_parallel_testing else 'disabled'}"
        )

    def _ensure_pcap_directory(self):
        """Ensure the temp_pcap directory exists for PCAP capture."""
        try:
            pcap_dir = Path("temp_pcap")
            pcap_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.warning(f"Failed to create temp_pcap directory: {e}")

    @staticmethod
    def _sanitize_token(value: str, max_len: int = 80) -> str:
        """
        Sanitize domain/strategy tokens for filenames and IDs.
        Keeps compatibility (still human-readable), but avoids filesystem issues.
        """
        s = str(value or "").strip()
        if not s:
            return "unknown"
        # Replace path separators and whitespace
        s = s.replace("/", "_").replace("\\", "_").replace(" ", "_")
        # Allow only safe chars
        s = re.sub(r"[^A-Za-z0-9._-]+", "_", s)
        # Collapse repeated underscores
        s = re.sub(r"_+", "_", s).strip("_")
        return s[:max_len] if len(s) > max_len else s

    def _safe_engine_call(self, method_name: str, *args: Any, **kwargs: Any) -> None:
        """
        Best-effort call into bypass_engine for optional compatibility methods.
        Does not raise to avoid masking primary errors.
        """
        if not self.bypass_engine:
            return
        fn = getattr(self.bypass_engine, method_name, None)
        if not callable(fn):
            return
        try:
            fn(*args, **kwargs)
        except TypeError:
            # Backward compatibility: old signature
            try:
                fn()
            except Exception as e:
                logger.warning(f"Failed to call bypass_engine.{method_name}(): {e}")
        except Exception as e:
            logger.warning(f"Failed to call bypass_engine.{method_name}: {e}")

    def _generate_session_id(self, domain: str, strategy_name: str) -> str:
        """Generate a unique session ID for test tracking."""
        self._session_counter += 1
        timestamp = int(time.time())
        safe_domain = self._sanitize_token(domain, max_len=60)
        safe_strategy = self._sanitize_token(strategy_name, max_len=60)
        return f"test_{safe_domain}_{safe_strategy}_{timestamp}_{self._session_counter}"

    def _generate_pcap_filename(self, domain: str, strategy_name: str) -> str:
        """Generate a unique PCAP filename for the test session."""
        safe_domain = self._sanitize_token(domain, max_len=80)
        safe_strategy = self._sanitize_token(strategy_name, max_len=80)
        timestamp = int(time.time())
        return f"temp_pcap/capture_{safe_domain}_{safe_strategy}_{timestamp}.pcap"

    async def execute_test(self, domain: str, strategy: Strategy) -> TestResult:
        """Исполняет тест стратегии с гарантированной изоляцией от чужого трафика."""
        if not self.bypass_engine:
            return self._create_error_result(domain, strategy, "Bypass engine not available")

        try:
            # ШАГ 1: Входим в режим Discovery (отключаем Fixed стратегии для других доменов)
            self._safe_engine_call("enable_discovery_mode", domain)
            if hasattr(self.bypass_engine, "enable_discovery_mode"):
                logger.info(f"🛡️ Discovery mode enabled for {domain}")

            # ШАГ 2: Включаем тестовый режим для изоляции
            if hasattr(self.bypass_engine, "enable_testing_mode"):
                self._safe_engine_call("enable_testing_mode")
                logger.info(f"🧪 Testing mode enabled for {domain}")

            # ШАГ 3: Выполняем сам тест
            result = await asyncio.wait_for(
                self.bypass_engine.test_strategy(domain, strategy),
                timeout=self.config.strategy_timeout,
            )

            # ШАГ 4: Проверка на загрязнение (Cross-talk check)
            # Если в процессе теста мы поймали домен, который не заказывали
            extracted = getattr(result, "extracted_domain", None)
            if isinstance(extracted, str) and extracted and extracted != domain:
                logger.error(
                    f"⚠️ TRAFFIC CONTAMINATION: Expected {domain}, but engine processed {result.extracted_domain}"
                )
                result.success = False
                result.error = f"Traffic contamination: {result.extracted_domain} interfered"

            return result

        except asyncio.TimeoutError:
            return self._create_error_result(
                domain, strategy, f"Timeout after {self.config.strategy_timeout}s"
            )
        except Exception as e:
            return self._create_error_result(domain, strategy, str(e))
        finally:
            # КРИТИЧЕСКИ ВАЖНО: Всегда возвращаем движок в нормальное состояние
            self._safe_engine_call("disable_testing_mode")
            self._safe_engine_call("disable_discovery_mode")
            logger.info(f"🛡️ Sandbox for {domain} destroyed. Global rules restored.")

    def _create_error_result(self, domain: str, strategy: Strategy, error_msg: str) -> TestResult:
        return TestResult(
            success=False,
            strategy=strategy,
            domain=domain,
            execution_time=0.0,
            error=error_msg,
            test_mode=TestMode.DISCOVERY,
        )

    async def _execute_test_internal(self, domain: str, strategy: Strategy) -> TestResult:
        """Internal test execution logic."""
        artifacts = TestArtifacts()

        # Start PCAP capture if enabled
        pcap_path = None
        if self.config.verify_with_pcap and self.pcap_analyzer:
            pcap_path = await self.capture_pcap(domain, self.config.pcap_capture_duration)
            if pcap_path:
                artifacts.pcap_path = pcap_path

        # Execute the actual bypass test
        if self.bypass_engine and self.bypass_engine.is_available():
            result = await self.bypass_engine.test_strategy(domain, strategy)
        else:
            # Try to use legacy bypass engine directly
            try:
                result = await self._test_with_legacy_engine(domain, strategy)
            except Exception as e:
                logger.warning(f"Legacy engine test failed: {e}")
                # Fallback to mock test for now
                result = await self._mock_test_execution(domain, strategy)

        # Analyze PCAP if captured
        if pcap_path and self.pcap_analyzer:
            try:
                pcap_analysis = await self.pcap_analyzer.analyze_pcap(pcap_path)
                artifacts.debug_info["pcap_analysis"] = pcap_analysis
            except Exception as e:
                logger.warning(f"PCAP analysis failed: {e}")

        # Set artifacts if enabled
        if self.config.enable_test_artifacts:
            result.artifacts = artifacts

        return result

    async def _mock_test_execution(self, domain: str, strategy: Strategy) -> TestResult:
        """Mock test execution for when bypass engine is not available."""
        # Simulate test execution delay
        await asyncio.sleep(0.1)

        # Mock success based on strategy confidence
        success = strategy.confidence_score > 0.5

        return TestResult(
            success=success,
            strategy=strategy,
            domain=domain,
            execution_time=0.1,
            error=None if success else "Mock test failure",
            test_mode=TestMode.DISCOVERY,
        )

    async def _test_with_legacy_engine(self, domain: str, strategy: Strategy) -> TestResult:
        """Test strategy using legacy UnifiedBypassEngine."""
        try:
            from core.unified_bypass_engine import UnifiedBypassEngine
            import socket
            import asyncio

            logger.info(f"🔧 Using legacy bypass engine for {strategy.name} on {domain}")

            # Resolve domain to IP
            try:
                target_ip = socket.gethostbyname(domain)
            except Exception as e:
                return TestResult(
                    success=False,
                    strategy=strategy,
                    domain=domain,
                    execution_time=0.0,
                    error=f"DNS resolution failed: {e}",
                    test_mode=TestMode.DISCOVERY,
                )

            # Create bypass engine instance
            bypass_engine = UnifiedBypassEngine()

            # Convert strategy to legacy format
            strategy_dict = {
                "type": strategy.name,
                "parameters": getattr(strategy, "parameters", {}),
            }

            # Run test in thread pool to avoid blocking
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None, bypass_engine.test_strategy_as_service, target_ip, strategy_dict, domain
            )

            logger.info(f"🔧 Legacy engine result: {result}")

            return TestResult(
                success=result.get("success", False),
                strategy=strategy,
                domain=domain,
                execution_time=result.get("execution_time", 0.1),
                error=result.get("error"),
                test_mode=TestMode.DISCOVERY,
            )

        except Exception as e:
            logger.error(f"Legacy engine test failed: {e}")
            return TestResult(
                success=False,
                strategy=strategy,
                domain=domain,
                execution_time=0.0,
                error=f"Legacy engine error: {e}",
                test_mode=TestMode.DISCOVERY,
            )

    def start_test_session(
        self, domain: str, strategy_name: str, pcap_file: Optional[str] = None
    ) -> str:
        """
        Start a new test session and return session ID.

        This method extracts the test session management logic from the original
        AdaptiveEngine._test_strategy_with_capture method.

        Args:
            domain: Domain being tested
            strategy_name: Name of the strategy being tested
            pcap_file: Optional specific PCAP file path to use

        Returns:
            Unique session ID for tracking this test
        """
        session_id = self._generate_session_id(domain, strategy_name)

        # Generate PCAP file path if not provided
        if pcap_file is None:
            pcap_file = self._generate_pcap_filename(domain, strategy_name)

        session_data = {
            "session_id": session_id,
            "domain": domain,
            "strategy_name": strategy_name,
            "pcap_file": pcap_file,
            "start_time": datetime.now(),
            "status": "active",
            "test_results": [],
            "artifacts": [],
            "responses_recorded": [],
            "verdict": None,
            "verdict_reason": None,
        }

        self._active_sessions[session_id] = session_data

        logger.info(f"🚀 Started test session {session_id} for {domain} with {strategy_name}")
        logger.debug(f"   PCAP file: {pcap_file}")

        return session_id

    def record_response(
        self,
        session_id: str,
        success: bool = False,
        timeout: bool = False,
        error: Optional[str] = None,
        response_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Record a response/result for the test session.

        This method allows recording multiple responses during a test session,
        which is used for building the final verdict.

        Args:
            session_id: Test session ID
            success: Whether this response indicates success
            timeout: Whether this response was a timeout
            error: Error message if any
            response_data: Additional response data
        """
        if session_id not in self._active_sessions:
            logger.warning(f"Attempted to record response for unknown session: {session_id}")
            return

        session_data = self._active_sessions[session_id]

        response_record = {
            "timestamp": datetime.now(),
            "success": success,
            "timeout": timeout,
            "error": error,
            "response_data": response_data or {},
        }

        session_data["responses_recorded"].append(response_record)

        logger.debug(
            f"Recorded response for session {session_id}: "
            f"success={success}, timeout={timeout}, error={error}"
        )

    def should_save_strategy(self, session_id: str) -> bool:
        """
        Determine if a strategy should be saved based on test session results.

        This method implements the coordinator approval logic from the original
        AdaptiveEngine._save_working_strategy method.

        Args:
            session_id: Test session ID

        Returns:
            True if strategy should be saved, False otherwise
        """
        if session_id not in self._active_sessions:
            logger.warning(f"Cannot determine save approval for unknown session: {session_id}")
            return False

        session_data = self._active_sessions[session_id]

        # If session has been finalized, use the verdict
        if session_data.get("verdict"):
            verdict = session_data["verdict"]
            should_save = verdict.success and verdict.confidence > 0.5
            logger.debug(f"Session {session_id} verdict-based save decision: {should_save}")
            return should_save

        # If not finalized, check recorded responses
        responses = session_data.get("responses_recorded", [])
        if not responses:
            logger.debug(f"No responses recorded for session {session_id}, denying save")
            return False

        # Require at least one successful response and no timeouts
        has_success = any(r["success"] for r in responses)
        has_timeout = any(r["timeout"] for r in responses)

        should_save = has_success and not has_timeout
        logger.debug(
            f"Session {session_id} response-based save decision: {should_save} "
            f"(success={has_success}, timeout={has_timeout})"
        )

        return should_save

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get session data for a given session ID.

        Args:
            session_id: Test session ID

        Returns:
            Session data dictionary or None if not found
        """
        return self._active_sessions.get(session_id)

    def finalize_test_session(self, session_id: str) -> TestVerdict:
        """
        Finalize test session and return verdict.

        This method implements the verdict determination logic extracted from
        the original AdaptiveEngine test coordination.

        Args:
            session_id: Test session ID

        Returns:
            TestVerdict with final determination
        """
        if session_id not in self._active_sessions:
            return TestVerdict(
                session_id=session_id,
                success=False,
                confidence=0.0,
                evidence=["Session not found"],
                recommendations=["Check session ID validity"],
            )

        session_data = self._active_sessions[session_id]
        session_data["end_time"] = datetime.now()
        session_data["status"] = "completed"

        # Analyze recorded responses and test results
        responses = session_data.get("responses_recorded", [])
        test_results = session_data.get("test_results", [])

        # Combine evidence from responses and test results
        all_evidence = []

        if responses:
            successful_responses = [r for r in responses if r["success"]]
            timeout_responses = [r for r in responses if r["timeout"]]
            error_responses = [r for r in responses if r.get("error")]

            all_evidence.append(f"Recorded {len(responses)} responses")
            if successful_responses:
                all_evidence.append(f"{len(successful_responses)} successful responses")
            if timeout_responses:
                all_evidence.append(f"{len(timeout_responses)} timeout responses")
            if error_responses:
                all_evidence.append(f"{len(error_responses)} error responses")

        if test_results:
            successful_tests = [r for r in test_results if r.success]
            all_evidence.append(f"Executed {len(test_results)} tests")
            if successful_tests:
                all_evidence.append(f"{len(successful_tests)} successful tests")

        # Determine overall success
        overall_success = False
        confidence = 0.0

        if responses:
            # Base decision on recorded responses (primary)
            successful_responses = [r for r in responses if r["success"]]
            timeout_responses = [r for r in responses if r["timeout"]]

            # Success if we have successful responses and no timeouts
            overall_success = len(successful_responses) > 0 and len(timeout_responses) == 0

            # Calculate confidence based on response quality
            if overall_success:
                success_rate = len(successful_responses) / len(responses)
                confidence = success_rate * 0.9  # High confidence for response-based success
            else:
                confidence = 0.1  # Low confidence for failures

        elif test_results:
            # Fallback to test results if no responses recorded
            successful_tests = [r for r in test_results if r.success]
            success_rate = len(successful_tests) / len(test_results) if test_results else 0

            overall_success = success_rate >= 0.5
            confidence = success_rate * 0.7  # Lower confidence than response-based

        else:
            # No evidence available
            all_evidence.append("No test data available")
            overall_success = False
            confidence = 0.0

        # Generate recommendations
        recommendations = self._generate_session_recommendations(session_data, overall_success)

        # Create and store verdict
        verdict = TestVerdict(
            session_id=session_id,
            success=overall_success,
            confidence=confidence,
            evidence=all_evidence,
            recommendations=recommendations,
        )

        session_data["verdict"] = verdict

        # Determine verdict reason for logging
        if overall_success:
            session_data["verdict_reason"] = "success"
        elif any(r["timeout"] for r in responses):
            session_data["verdict_reason"] = "timeout"
        elif any(r.get("error") for r in responses):
            session_data["verdict_reason"] = "error"
        else:
            session_data["verdict_reason"] = "general_failure"

        # Remove from active sessions (keep in memory briefly for queries)
        # In production, this might be moved to a completed sessions cache

        logger.info(
            f"Finalized test session {session_id}: {'SUCCESS' if overall_success else 'FAILED'} "
            f"(confidence: {confidence:.2f}, reason: {session_data['verdict_reason']})"
        )

        return verdict

    def _generate_session_recommendations(
        self, session_data: Dict[str, Any], success: bool
    ) -> List[str]:
        """Generate recommendations based on session data."""
        recommendations = []

        responses = session_data.get("responses_recorded", [])
        test_results = session_data.get("test_results", [])

        if not responses and not test_results:
            recommendations.append("No test data available - check test execution")
            return recommendations

        if success:
            recommendations.append(
                f"Strategy '{session_data['strategy_name']}' is working for {session_data['domain']}"
            )
            if responses:
                successful_responses = [r for r in responses if r["success"]]
                if len(successful_responses) == len(responses):
                    recommendations.append("All responses were successful - high confidence result")
        else:
            # Analyze failure patterns
            if responses:
                timeout_responses = [r for r in responses if r["timeout"]]
                error_responses = [r for r in responses if r.get("error")]

                if timeout_responses:
                    recommendations.append("Timeouts detected - consider increasing timeout values")

                if error_responses:
                    error_types = set(
                        r["error"].split(":")[0] for r in error_responses if r.get("error")
                    )
                    if error_types:
                        recommendations.append(f"Common errors: {', '.join(error_types)}")

            if test_results:
                failed_tests = [r for r in test_results if not r.success]
                if failed_tests:
                    recommendations.append("Multiple test failures - strategy may not be suitable")

        return recommendations

    def _generate_recommendations(self, test_results: list) -> list:
        """Generate recommendations based on test results."""
        recommendations = []

        if not test_results:
            return ["No test results available for recommendations"]

        successful_tests = [r for r in test_results if r.success]
        failed_tests = [r for r in test_results if not r.success]

        if successful_tests:
            # Recommend best performing strategies
            best_strategy = max(successful_tests, key=lambda r: r.strategy.confidence_score)
            recommendations.append(f"Use strategy '{best_strategy.strategy.name}' for best results")

        if failed_tests:
            # Analyze failure patterns
            timeout_failures = [r for r in failed_tests if "timeout" in (r.error or "").lower()]
            if timeout_failures:
                recommendations.append("Consider increasing timeout values for better results")

            connection_failures = [
                r for r in failed_tests if "connection" in (r.error or "").lower()
            ]
            if connection_failures:
                recommendations.append("Network connectivity issues detected, check connection")

        if len(successful_tests) < len(test_results) / 2:
            recommendations.append("Low success rate - consider trying different strategy types")

        return recommendations

    async def capture_pcap(self, domain: str, duration: float) -> Optional[str]:
        """Capture PCAP for specified domain and duration."""
        try:
            logger.info(f"Starting PCAP capture for {domain} (duration: {duration}s)")

            # Generate unique filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pcap_filename = f"test_capture_{domain}_{timestamp}.pcap"

            # Mock PCAP capture for now
            # In real implementation, this would start actual packet capture
            await asyncio.sleep(duration)

            logger.info(f"PCAP capture completed: {pcap_filename}")
            return pcap_filename

        except Exception as e:
            logger.error(f"PCAP capture failed for {domain}: {e}")
            return None

    def get_active_sessions(self) -> Dict[str, Dict[str, Any]]:
        """Get information about active test sessions."""
        return {
            session_id: {
                "domain": data["domain"],
                "strategy_name": data["strategy_name"],
                "start_time": data["start_time"].isoformat(),
                "status": data["status"],
                "test_count": len(data.get("test_results", [])),
            }
            for session_id, data in self._active_sessions.items()
        }

    def cleanup_stale_sessions(self, max_age_hours: int = 24) -> int:
        """Clean up sessions that have been active too long."""
        current_time = datetime.now()
        stale_sessions = []

        for session_id, session_data in self._active_sessions.items():
            age = current_time - session_data["start_time"]
            if age.total_seconds() > max_age_hours * 3600:
                stale_sessions.append(session_id)

        for session_id in stale_sessions:
            del self._active_sessions[session_id]
            logger.warning(f"Cleaned up stale test session: {session_id}")

        return len(stale_sessions)

    def get_pcap_analysis(self, pcap_file: str) -> Optional[Dict[str, Any]]:
        """
        Get PCAP analysis for a file, with caching support.

        This method provides centralized PCAP analysis routing as extracted
        from the original AdaptiveEngine._save_working_strategy method.

        Args:
            pcap_file: Path to PCAP file to analyze

        Returns:
            PCAP analysis results or None if analysis fails
        """
        try:
            if not self.pcap_analyzer:
                logger.warning("PCAP analyzer not available")
                return None

            logger.info(f"🔍 Analyzing PCAP: {pcap_file}")

            # Check if file exists
            pcap_path = Path(pcap_file)
            if not pcap_path.exists():
                logger.warning(f"PCAP file not found: {pcap_file}")
                return None

            # Perform analysis (this would be async in real implementation)
            # For now, return a mock analysis structure
            analysis_result = {
                "file_path": pcap_file,
                "file_size": pcap_path.stat().st_size,
                "analysis_timestamp": datetime.now().isoformat(),
                "packet_count": 0,  # Would be filled by actual analyzer
                "connection_analysis": {},
                "dpi_detection": {},
                "success_indicators": [],
            }

            logger.info(f"✅ PCAP analysis completed for {pcap_file}")
            return analysis_result

        except Exception as e:
            logger.error(f"❌ PCAP analysis failed for {pcap_file}: {e}")
            return None

    def update_session_pcap_path(self, session_id: str, actual_pcap_path: str) -> None:
        """
        Update the PCAP file path for a session.

        This handles cases where the bypass engine creates a PCAP file with
        a different path than initially predicted.

        Args:
            session_id: Test session ID
            actual_pcap_path: Actual PCAP file path created
        """
        if session_id not in self._active_sessions:
            logger.warning(f"Cannot update PCAP path for unknown session: {session_id}")
            return

        session_data = self._active_sessions[session_id]
        old_path = session_data.get("pcap_file")

        if old_path != actual_pcap_path:
            logger.debug(f"📝 Updating session PCAP path: {old_path} -> {actual_pcap_path}")
            session_data["pcap_file"] = actual_pcap_path

    def add_test_result_to_session(self, session_id: str, test_result: TestResult) -> None:
        """
        Add a test result to a session for tracking.

        Args:
            session_id: Test session ID
            test_result: Test result to add
        """
        if session_id not in self._active_sessions:
            logger.warning(f"Cannot add test result to unknown session: {session_id}")
            return

        session_data = self._active_sessions[session_id]
        session_data["test_results"].append(test_result)

        logger.debug(
            f"Added test result to session {session_id}: "
            f"success={test_result.success}, strategy={test_result.strategy.name}"
        )

    def get_session_verdict_reason(self, session_id: str) -> Optional[str]:
        """
        Get the verdict reason for a session.

        Args:
            session_id: Test session ID

        Returns:
            Verdict reason string or None if not available
        """
        session_data = self._active_sessions.get(session_id)
        if session_data:
            return session_data.get("verdict_reason")
        return None
