"""
Test Result Coordinator - Central authority for test result determination.

This module provides the TestResultCoordinator class which enforces consistency
between test execution, validation, and saving operations. It serves as the
single source of truth for test outcomes.

Feature: strategy-testing-production-parity
Requirements: 1.1, 1.2, 1.4, 1.5, 6.1, 6.2, 6.3, 8.1, 8.2, 8.5, 9.1, 9.2, 9.3, 9.4
"""

import logging
import time
import uuid
from typing import Dict, Optional
from pathlib import Path

from core.test_result_models import (
    TestSession,
    TestVerdict,
    PCAPAnalysisResult,
    ValidationResult
)

LOG = logging.getLogger(__name__)


class TestResultCoordinator:
    """
    Central authority for test result determination.
    
    Enforces consistency between test execution, validation, and saving.
    Collects evidence from all sources (retransmissions, PCAP, responses)
    and applies decision logic to determine SUCCESS/FAIL.
    
    Requirements: 9.1, 9.2, 9.3, 9.4
    """
    
    def __init__(self, pcap_analyzer=None, strategy_validator=None):
        """
        Initialize the coordinator.
        
        Args:
            pcap_analyzer: PCAPAnalyzer instance for PCAP analysis
            strategy_validator: StrategyValidator instance for validation
        """
        self.logger = LOG
        self.pcap_analyzer = pcap_analyzer
        self.strategy_validator = strategy_validator
        
        # Session tracking
        self.test_sessions: Dict[str, TestSession] = {}
        
        # PCAP analysis cache (ensures analysis runs exactly once per file)
        self.pcap_cache: Dict[str, PCAPAnalysisResult] = {}
        
        self.logger.info("✅ TestResultCoordinator initialized")
    
    def start_test(self, domain: str, strategy_name: str, pcap_file: str) -> str:
        """
        Start a new test session.
        
        Creates a unique session ID and initializes a TestSession object
        to track all test data.
        
        Args:
            domain: Target domain being tested
            strategy_name: Name of strategy being tested
            pcap_file: Path to PCAP file for this test
            
        Returns:
            session_id: Unique identifier for this test session
            
        Requirements: 9.1
        """
        # Generate unique session ID
        session_id = str(uuid.uuid4())
        
        # Initialize test session
        session = TestSession(
            session_id=session_id,
            domain=domain,
            strategy_name=strategy_name,
            pcap_file=pcap_file,
            start_time=time.time()
        )
        
        # Track session
        self.test_sessions[session_id] = session
        
        # Log in consistent format (Requirement 10.1)
        self.logger.info(f"Starting test: [{strategy_name}] for [{domain}]")
        self.logger.debug(f"Session ID: {session_id}")
        
        # Save metadata for PCAP validation (single source of truth)
        # This ensures the declared strategy is used for validation, not PCAP-detected attacks
        try:
            from core.pcap.metadata_saver import save_pcap_metadata
            from core.strategy.strategy_decomposer import StrategyDecomposer
            
            # Decompose strategy name to get attacks list
            decomposer = StrategyDecomposer()
            attacks = decomposer.decompose_strategy(strategy_name)
            executed_attacks = ",".join(attacks) if attacks else strategy_name
            
            # Save metadata with test start timestamp for PCAP filtering
            save_pcap_metadata(
                pcap_file=pcap_file,
                executed_attacks=executed_attacks,
                strategy_name=strategy_name,
                strategy_id=session_id,
                domain=domain,
                additional_data={
                    'test_start_time': session.start_time,
                    'test_start_timestamp': int(session.start_time)
                }
            )
            self.logger.debug(f"📝 Saved PCAP metadata: executed_attacks={executed_attacks}")
        except Exception as e:
            self.logger.debug(f"⚠️ Failed to save PCAP metadata: {e}")
        
        return session_id
    
    def record_retransmission(self, session_id: str, count: int) -> None:
        """
        Record retransmission count from bypass engine.
        
        Retransmissions are the primary indicator of strategy failure.
        
        Args:
            session_id: Test session identifier
            count: Number of retransmissions detected
            
        Requirements: 9.1
        """
        if session_id not in self.test_sessions:
            self.logger.warning(f"⚠️ Unknown session ID: {session_id}")
            return
        
        session = self.test_sessions[session_id]
        session.retransmission_count = count
        
        if count > 0:
            self.logger.warning(f"⚠️ Retransmissions detected: {count} for session {session_id}")
        else:
            self.logger.debug(f"✅ No retransmissions for session {session_id}")
    
    def record_response(self, session_id: str, response_status: Optional[int] = None, 
                       timeout: bool = False) -> None:
        """
        Record server response.
        
        Args:
            session_id: Test session identifier
            response_status: HTTP response status code (if received)
            timeout: Whether the request timed out
            
        Requirements: 9.1
        """
        if session_id not in self.test_sessions:
            self.logger.warning(f"⚠️ Unknown session ID: {session_id}")
            return
        
        session = self.test_sessions[session_id]
        
        if timeout:
            session.timeout = True
            session.response_received = False
            self.logger.warning(f"⏱️ Request timeout for session {session_id}")
        elif response_status is not None:
            session.response_received = True
            session.response_status = response_status
            self.logger.info(f"✅ Response received: {response_status} for session {session_id}")
        else:
            session.response_received = False
            self.logger.debug(f"❌ No response for session {session_id}")
    
    def record_error(self, session_id: str, error_type: str, error_message: str) -> None:
        """
        Record test execution error.
        
        This method handles various test execution errors including:
        - Network timeout
        - Connection refused
        - Packet send failure
        
        Args:
            session_id: Test session identifier
            error_type: Type of error (timeout, connection_refused, packet_send_error, etc.)
            error_message: Detailed error message
            
        Requirements: 8.4 (Task 8.1)
        """
        if session_id not in self.test_sessions:
            self.logger.warning(f"⚠️ Unknown session ID: {session_id}")
            return
        
        session = self.test_sessions[session_id]
        session.error = error_message
        
        # Log error with context (Requirement 10.5)
        self.logger.error(
            f"Error during test execution: component=TestResultCoordinator, "
            f"operation=test_execution, strategy=[{session.strategy_name}], "
            f"domain=[{session.domain}], error_type={error_type}, error={error_message}"
        )
        
        # Handle specific error types (Task 8.1)
        if error_type == "timeout":
            session.timeout = True
            session.response_received = False
            self.logger.warning(f"⏱️ Network timeout for session {session_id}")
        elif error_type == "connection_refused":
            session.response_received = False
            self.logger.warning(f"🚫 Connection refused for session {session_id}")
        elif error_type == "packet_send_error":
            session.response_received = False
            self.logger.warning(f"📤 Packet send failure for session {session_id}")
        else:
            # Generic error handling
            session.response_received = False
            self.logger.warning(f"❌ Test execution error ({error_type}) for session {session_id}")
    
    def get_pcap_analysis(self, pcap_file: str, test_start_time: Optional[float] = None) -> Optional[PCAPAnalysisResult]:
        """
        Get PCAP analysis, using cache if available.
        
        Ensures PCAP is analyzed exactly once per file. This is critical
        for performance and consistency.
        
        Args:
            pcap_file: Path to PCAP file
            test_start_time: Timestamp of test start for packet filtering (optional)
            
        Returns:
            PCAPAnalysisResult or None if analysis fails
            
        Requirements: 6.1, 6.2, 6.3
        """
        # Check cache first (include test_start_time in cache key for unique caching per test)
        cache_key = f"{pcap_file}_{test_start_time}" if test_start_time else pcap_file
        if cache_key in self.pcap_cache:
            self.logger.debug(f"📋 Using cached PCAP analysis for {pcap_file}")
            return self.pcap_cache[cache_key]
        
        # Check if file exists
        if not Path(pcap_file).exists():
            self.logger.warning(f"⚠️ PCAP file not found: {pcap_file}")
            return None
        
        # Analyze PCAP (Requirement 10.3)
        self.logger.info(f"Analyzing PCAP: [{pcap_file}]")
        
        if self.pcap_analyzer is None:
            self.logger.error("❌ No PCAP analyzer configured")
            return None
        
        try:
            # Use analyze_pcap which returns PCAPAnalysisResult directly (Task 3.4)
            # Pass test_start_time for timestamp filtering
            pcap_result = self.pcap_analyzer.analyze_pcap(
                pcap_file,
                test_start_time=test_start_time
            )
            
            # Cache result with unique key
            self.pcap_cache[cache_key] = pcap_result
            
            # Log completion (handle case where detected_attacks might be a mock)
            try:
                attack_count = len(pcap_result.detected_attacks) if hasattr(pcap_result, 'detected_attacks') else 0
                self.logger.info(f"✅ PCAP analysis complete: {attack_count} attacks detected")
            except (TypeError, AttributeError):
                self.logger.info(f"✅ PCAP analysis complete")
            
            return pcap_result
            
        except Exception as e:
            # Log error with context (Requirement 10.5)
            self.logger.error(
                f"Error analyzing PCAP: component=TestResultCoordinator, "
                f"operation=get_pcap_analysis, file=[{pcap_file}], error={e}",
                exc_info=True
            )
            return None
    
    def finalize_test(self, session_id: str) -> TestVerdict:
        """
        Analyze all evidence and make final verdict.
        
        Decision logic (in priority order):
        1. If retransmissions >= 3: FAIL
        2. If no PCAP file: INCONCLUSIVE
        3. If PCAP shows incomplete strategy: PARTIAL_SUCCESS
        4. If declared != applied strategy: MISMATCH
        5. If all checks pass: SUCCESS
        
        Args:
            session_id: Test session identifier
            
        Returns:
            TestVerdict: Final verdict for this test
            
        Requirements: 1.1, 1.2, 8.1, 8.2, 8.5
        """
        if session_id not in self.test_sessions:
            self.logger.error(f"❌ Unknown session ID: {session_id}")
            return TestVerdict.INCONCLUSIVE
        
        session = self.test_sessions[session_id]
        session.end_time = time.time()
        
        self.logger.info(f"🔍 Finalizing test for session {session_id}")
        
        # Priority 1: Check for test execution errors (Task 8.1)
        # Handle network timeout → FAIL verdict
        # Handle connection refused → FAIL verdict
        # Handle packet send failure → FAIL verdict
        if session.error:
            session.verdict = TestVerdict.FAIL
            session.verdict_reason = f"Test execution error: {session.error}"
            self.logger.warning(f"❌ Test FAIL: {session.verdict_reason}")
            # Log test result in consistent format (Requirement 10.2)
            self.logger.info(f"Test result: {session.verdict.value.upper()} for [{session.strategy_name}]")
            return session.verdict
        
        # Priority 2: Check if PCAP exists (need it for MISMATCH detection)
        # Task 8.2: Handle PCAP file not found → INCONCLUSIVE verdict
        pcap_file_to_use = session.pcap_file
        
        if not Path(session.pcap_file).exists():
            # If we have high retransmissions but no PCAP, still return FAIL
            if session.retransmission_count >= 3:
                session.verdict = TestVerdict.FAIL
                session.verdict_reason = f"High retransmission count: {session.retransmission_count} (no PCAP)"
                self.logger.warning(f"❌ Test FAIL: {session.verdict_reason}")
                self.logger.info(f"Test result: {session.verdict.value.upper()} for [{session.strategy_name}]")
                return session.verdict
            
            session.verdict = TestVerdict.INCONCLUSIVE
            session.verdict_reason = "PCAP file not found"
            self.logger.warning(f"⚠️ Test INCONCLUSIVE: {session.verdict_reason}")
            # Log test result in consistent format (Requirement 10.2)
            self.logger.info(f"Test result: {session.verdict.value.upper()} for [{session.strategy_name}]")
            return session.verdict
        
        # FIX: Check if individual PCAP is empty, fallback to shared PCAP
        # In --verify-with-pcap mode, individual PCAP files are often empty (0 packets)
        # but shared PCAP file contains all packets from all tests
        file_size = Path(session.pcap_file).stat().st_size
        if file_size <= 24:  # PCAP header is 24 bytes, so ≤24 means empty
            self.logger.warning(f"⚠️ Individual PCAP is empty ({file_size} bytes), looking for shared PCAP")
            
            # Try to find shared PCAP file
            pcap_dir = Path(session.pcap_file).parent
            domain_part = session.domain.replace('.', '_')
            
            # Look for shared PCAP: capture_{domain}_{timestamp}.pcap
            # Shared PCAP has format: capture_pagead2_googlesyndication_com_1764933300.pcap
            # Individual PCAP has format: capture_pagead2.googlesyndication.com_1764933302.pcap (with dots!)
            shared_pcaps = list(pcap_dir.glob(f"capture_{domain_part}_*.pcap"))
            
            # Find the most recent non-empty PCAP (by timestamp in filename)
            if shared_pcaps:
                # Filter out empty PCAPs
                non_empty_pcaps = [p for p in shared_pcaps if p.stat().st_size > 24]
                
                if non_empty_pcaps:
                    # Extract timestamp from filename and find the most recent
                    # Format: capture_domain_TIMESTAMP.pcap
                    def get_timestamp(pcap_path):
                        try:
                            # Extract timestamp from filename
                            name = pcap_path.stem  # Remove .pcap extension
                            parts = name.split('_')
                            # Last part should be timestamp
                            return int(parts[-1])
                        except (ValueError, IndexError):
                            return 0
                    
                    # Sort by timestamp (most recent first)
                    non_empty_pcaps.sort(key=get_timestamp, reverse=True)
                    most_recent_pcap = non_empty_pcaps[0]
                    pcap_size = most_recent_pcap.stat().st_size
                    pcap_timestamp = get_timestamp(most_recent_pcap)
                    
                    self.logger.info(f"✅ Found shared PCAP: {most_recent_pcap.name} ({pcap_size} bytes, timestamp={pcap_timestamp})")
                    pcap_file_to_use = str(most_recent_pcap)
                    # Update session to use shared PCAP
                    session.pcap_file = pcap_file_to_use
                else:
                    self.logger.warning(f"⚠️ No non-empty shared PCAP found (all {len(shared_pcaps)} files are empty)")
            else:
                self.logger.warning(f"⚠️ No shared PCAP files found in {pcap_dir}")
        
        # Priority 3: Analyze PCAP to detect MISMATCH (before checking retransmissions)
        # This is important because MISMATCH is more specific than FAIL
        # Use pcap_file_to_use which may be shared PCAP if individual is empty
        # Pass test_start_time from session for timestamp filtering
        pcap_analysis = self.get_pcap_analysis(pcap_file_to_use, test_start_time=session.start_time)
        session.pcap_analysis = pcap_analysis
        
        if pcap_analysis is None:
            session.verdict = TestVerdict.INCONCLUSIVE
            session.verdict_reason = "PCAP analysis failed"
            self.logger.warning(f"⚠️ Test INCONCLUSIVE: {session.verdict_reason}")
            # Log test result in consistent format (Requirement 10.2)
            self.logger.info(f"Test result: {session.verdict.value.upper()} for [{session.strategy_name}]")
            return session.verdict
        
        # Task 8.2: Check for PCAP analysis errors
        # Handle PCAP file not found → INCONCLUSIVE verdict
        # Handle PCAP file corrupted → INCONCLUSIVE verdict
        # Handle empty PCAP → INCONCLUSIVE verdict
        if pcap_analysis.errors:
            session.verdict = TestVerdict.INCONCLUSIVE
            session.verdict_reason = f"PCAP analysis errors: {'; '.join(pcap_analysis.errors)}"
            self.logger.warning(f"⚠️ Test INCONCLUSIVE: {session.verdict_reason}")
            # Log test result in consistent format (Requirement 10.2)
            self.logger.info(f"Test result: {session.verdict.value.upper()} for [{session.strategy_name}]")
            return session.verdict
        
        # Priority 5: Check if PCAP is empty
        if pcap_analysis.packet_count == 0:
            session.verdict = TestVerdict.INCONCLUSIVE
            session.verdict_reason = "Empty PCAP file"
            self.logger.warning(f"⚠️ Test INCONCLUSIVE: {session.verdict_reason}")
            # Log test result in consistent format (Requirement 10.2)
            self.logger.info(f"Test result: {session.verdict.value.upper()} for [{session.strategy_name}]")
            return session.verdict
        
        # Priority 6: Check for incomplete strategy application
        if not pcap_analysis.detected_attacks:
            session.verdict = TestVerdict.PARTIAL_SUCCESS
            session.verdict_reason = "No attacks detected in PCAP"
            self.logger.warning(f"⚠️ Test PARTIAL_SUCCESS: {session.verdict_reason}")
            # Log test result in consistent format (Requirement 10.2)
            self.logger.info(f"Test result: {session.verdict.value.upper()} for [{session.strategy_name}]")
            return session.verdict
        
        # Priority 7: Validate strategy completeness (if validator available)
        if self.strategy_validator is not None:
            try:
                validation_result = self.strategy_validator.validate(
                    session.strategy_name,
                    pcap_analysis
                )
                session.validation_result = validation_result
                
                if not validation_result.is_valid:
                    if not validation_result.strategy_match:
                        session.verdict = TestVerdict.MISMATCH
                        session.verdict_reason = f"Strategy mismatch: declared={validation_result.declared_strategy}, applied={validation_result.applied_strategy}"
                        self.logger.warning(f"⚠️ Test MISMATCH: {session.verdict_reason}")
                        # Log test result in consistent format (Requirement 10.2)
                        self.logger.info(f"Test result: {session.verdict.value.upper()} for [{session.strategy_name}]")
                        return session.verdict
                    
                    if not validation_result.all_attacks_applied:
                        session.verdict = TestVerdict.PARTIAL_SUCCESS
                        session.verdict_reason = f"Incomplete strategy application: missing {validation_result.missing_components}"
                        self.logger.warning(f"⚠️ Test PARTIAL_SUCCESS: {session.verdict_reason}")
                        # Log test result in consistent format (Requirement 10.2)
                        self.logger.info(f"Test result: {session.verdict.value.upper()} for [{session.strategy_name}]")
                        return session.verdict
            except Exception as e:
                # Log error with context (Requirement 10.5)
                self.logger.warning(
                    f"Error during validation: component=TestResultCoordinator, "
                    f"operation=finalize_test, strategy=[{session.strategy_name}], "
                    f"domain=[{session.domain}], error={e}"
                )
                # Continue without validation
        
        # Priority 8: Check retransmissions (after MISMATCH detection)
        # High retransmissions indicate strategy failure, but MISMATCH is more specific
        if session.retransmission_count >= 3:
            session.verdict = TestVerdict.FAIL
            session.verdict_reason = f"High retransmission count: {session.retransmission_count}"
            self.logger.warning(f"❌ Test FAIL: {session.verdict_reason}")
            # Log test result in consistent format (Requirement 10.2)
            self.logger.info(f"Test result: {session.verdict.value.upper()} for [{session.strategy_name}]")
            return session.verdict
        
        # Priority 9: Check for timeout
        if session.timeout:
            session.verdict = TestVerdict.FAIL
            session.verdict_reason = "Request timeout"
            self.logger.warning(f"❌ Test FAIL: {session.verdict_reason}")
            # Log test result in consistent format (Requirement 10.2)
            self.logger.info(f"Test result: {session.verdict.value.upper()} for [{session.strategy_name}]")
            return session.verdict
        
        # Priority 10: Check if response was received
        if not session.response_received:
            session.verdict = TestVerdict.FAIL
            session.verdict_reason = "No response received"
            self.logger.warning(f"❌ Test FAIL: {session.verdict_reason}")
            # Log test result in consistent format (Requirement 10.2)
            self.logger.info(f"Test result: {session.verdict.value.upper()} for [{session.strategy_name}]")
            return session.verdict
        
        # All checks passed - SUCCESS!
        session.verdict = TestVerdict.SUCCESS
        session.verdict_reason = "All checks passed"
        self.logger.info(f"✅ Test SUCCESS: {session.verdict_reason}")
        
        # Log test result in consistent format (Requirement 10.2)
        self.logger.info(f"Test result: {session.verdict.value.upper()} for [{session.strategy_name}]")
        
        return session.verdict
    
    def should_save_strategy(self, session_id: str) -> bool:
        """
        Determine if strategy should be saved.
        
        Only returns True for SUCCESS verdict. This prevents false positives
        from being saved to the knowledge base.
        
        Args:
            session_id: Test session identifier
            
        Returns:
            bool: True if strategy should be saved, False otherwise
            
        Requirements: 1.4, 1.5, 9.4
        """
        if session_id not in self.test_sessions:
            self.logger.warning(f"⚠️ Unknown session ID: {session_id}")
            return False
        
        session = self.test_sessions[session_id]
        
        # Only save if verdict is SUCCESS
        should_save = session.verdict == TestVerdict.SUCCESS
        
        if should_save:
            self.logger.info(f"✅ Strategy approved for saving: {session.strategy_name}")
        else:
            self.logger.info(f"🚫 Strategy blocked from saving: {session.strategy_name} (verdict: {session.verdict})")
        
        return should_save
    
    def get_session(self, session_id: str) -> Optional[TestSession]:
        """
        Get test session by ID.
        
        Args:
            session_id: Test session identifier
            
        Returns:
            TestSession or None if not found
        """
        return self.test_sessions.get(session_id)
    
    def clear_session(self, session_id: str) -> None:
        """
        Clear test session from memory.
        
        Args:
            session_id: Test session identifier
        """
        if session_id in self.test_sessions:
            del self.test_sessions[session_id]
            self.logger.debug(f"🧹 Cleared session {session_id}")
    
    def clear_all_sessions(self) -> None:
        """Clear all test sessions from memory."""
        count = len(self.test_sessions)
        self.test_sessions.clear()
        self.logger.info(f"🧹 Cleared {count} test sessions")
    
    def clear_pcap_cache(self) -> None:
        """Clear PCAP analysis cache."""
        count = len(self.pcap_cache)
        self.pcap_cache.clear()
        self.logger.info(f"🧹 Cleared {count} cached PCAP analyses")
    

