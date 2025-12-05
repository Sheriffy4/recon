# path: core/bypass/engine/enhanced_bypass_adapter.py
"""
Enhanced adapter for WindowsBypassEngine with PCAP capture and artifact collection.

This module provides enhanced integration with WindowsBypassEngine for the adaptive
monitoring system, adding support for:
- PCAP capture during strategy testing
- Artifact collection (logs, network events)
- Enhanced result reporting with failure analysis data
- Backward compatibility with existing API
"""

import logging
import time
import threading
from typing import Dict, Any, Optional, List, Set
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .base_engine import WindowsBypassEngine
from .attack_dispatcher import AttackDispatcher
from ..attacks.metadata import ValidationResult
from ...pcap.temporary_capturer import TemporaryPCAPCapturer, CaptureSession


@dataclass
class TrialArtifacts:
    """Artifacts collected during strategy testing"""
    pcap_file: Optional[str] = None
    engine_logs: List[str] = field(default_factory=list)
    network_events: List[Dict[str, Any]] = field(default_factory=list)
    attack_metadata: Dict[str, Any] = field(default_factory=dict)
    capture_session_id: Optional[str] = None
    packets_captured: int = 0
    capture_duration: float = 0.0


@dataclass
class EnhancedTestResult:
    """Enhanced test result with comprehensive artifact collection"""
    success: bool
    domain: str
    strategy: Dict[str, Any]
    response_time: float
    error: Optional[str] = None
    artifacts: Optional[TrialArtifacts] = None
    timestamp: str = ""
    validation_result: Optional[ValidationResult] = None
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
        if self.artifacts is None:
            self.artifacts = TrialArtifacts()


class EnhancedBypassEngineAdapter:
    """
    Enhanced adapter for WindowsBypassEngine with artifact collection capabilities.
    
    This adapter extends the functionality of WindowsBypassEngine to support:
    - Automatic PCAP capture during strategy testing
    - Comprehensive artifact collection for failure analysis
    - Enhanced logging and monitoring
    - Backward compatibility with existing API
    """
    
    def __init__(self, bypass_engine: WindowsBypassEngine, enable_traffic_analysis: bool = True):
        """
        Initialize the enhanced bypass engine adapter.
        
        Args:
            bypass_engine: WindowsBypassEngine instance
            enable_traffic_analysis: Whether to enable PCAP capture and traffic analysis
        """
        self.bypass_engine = bypass_engine
        self.logger = logging.getLogger("EnhancedBypassEngineAdapter")
        
        # Traffic analysis configuration
        self.enable_traffic_analysis = enable_traffic_analysis
        self.pcap_capturer = None
        
        if enable_traffic_analysis:
            try:
                self.pcap_capturer = TemporaryPCAPCapturer()
                if self.pcap_capturer.is_capture_available():
                    self.logger.info("✅ Traffic analysis enabled with PCAP capture")
                else:
                    self.logger.warning("⚠️ PCAP capture unavailable, traffic analysis disabled")
                    self.enable_traffic_analysis = False
            except Exception as e:
                self.logger.warning(f"⚠️ Failed to initialize PCAP capturer: {e}")
                self.enable_traffic_analysis = False
        
        # Artifact collection
        self._log_buffer = []
        self._log_buffer_lock = threading.Lock()
        self._setup_log_capture()
        
        # Statistics
        self.stats = {
            "tests_performed": 0,
            "successful_tests": 0,
            "failed_tests": 0,
            "artifacts_collected": 0,
            "pcap_files_created": 0
        }
    
    def test_strategy_with_artifacts(self, 
                                   domain: str, 
                                   strategy: Dict[str, Any],
                                   capture_timeout: float = 15.0,
                                   include_validation: bool = True) -> EnhancedTestResult:
        """
        Test a strategy with comprehensive artifact collection.
        
        Args:
            domain: Target domain to test
            strategy: Strategy configuration dictionary
            capture_timeout: Maximum time for PCAP capture (seconds)
            include_validation: Whether to validate strategy parameters
            
        Returns:
            EnhancedTestResult with comprehensive artifacts
        """
        start_time = time.time()
        self.stats["tests_performed"] += 1
        
        self.logger.info(f"🧪 Testing strategy for {domain}: {strategy}")
        
        # Validate strategy parameters if requested
        validation_result = None
        if include_validation:
            validation_result = self._validate_strategy_parameters(strategy)
            if not validation_result.is_valid:
                self.logger.warning(f"⚠️ Strategy validation failed: {validation_result.error_message}")
        
        # Initialize artifacts
        artifacts = TrialArtifacts()
        artifacts.attack_metadata = self._extract_attack_metadata(strategy)
        
        # Clear log buffer
        with self._log_buffer_lock:
            self._log_buffer.clear()
        
        try:
            if self.enable_traffic_analysis and self.pcap_capturer:
                # Test with PCAP capture
                result = self._test_with_capture(domain, strategy, capture_timeout, artifacts)
            else:
                # Test without capture (fallback mode)
                result = self._test_without_capture(domain, strategy, artifacts)
            
            # Collect engine logs
            with self._log_buffer_lock:
                artifacts.engine_logs = self._log_buffer.copy()
            
            # Update statistics
            if result.success:
                self.stats["successful_tests"] += 1
            else:
                self.stats["failed_tests"] += 1
            
            if artifacts.pcap_file:
                self.stats["pcap_files_created"] += 1
            
            self.stats["artifacts_collected"] += 1
            
            return EnhancedTestResult(
                success=result.success,
                domain=domain,
                strategy=strategy,
                response_time=time.time() - start_time,
                error=result.error,
                artifacts=artifacts,
                validation_result=validation_result
            )
            
        except Exception as e:
            self.logger.error(f"❌ Strategy test failed with exception: {e}")
            self.stats["failed_tests"] += 1
            
            return EnhancedTestResult(
                success=False,
                domain=domain,
                strategy=strategy,
                response_time=time.time() - start_time,
                error=str(e),
                artifacts=artifacts,
                validation_result=validation_result
            )
    
    def _test_with_capture(self, 
                          domain: str, 
                          strategy: Dict[str, Any], 
                          timeout: float,
                          artifacts: TrialArtifacts) -> EnhancedTestResult:
        """Test strategy with PCAP capture enabled"""
        
        try:
            with self.pcap_capturer.capture_session(domain) as session:
                capture_start = time.time()
                
                # Give capture time to initialize
                time.sleep(0.5)
                
                # Execute the strategy test
                success, error = self._execute_strategy_test(domain, strategy, timeout - 0.5)
                
                # Update artifacts with capture information
                artifacts.pcap_file = session.pcap_file if session.packets_captured > 0 else None
                artifacts.capture_session_id = session.session_id
                artifacts.packets_captured = session.packets_captured
                artifacts.capture_duration = time.time() - capture_start
                
                # Collect network events from capture session
                artifacts.network_events = self._extract_network_events(session)
                
                self.logger.info(f"📊 Capture completed: {session.packets_captured} packets in {artifacts.capture_duration:.2f}s")
                
                return EnhancedTestResult(success=success, domain=domain, strategy=strategy, 
                                        response_time=0, error=error)
                
        except Exception as e:
            self.logger.error(f"❌ PCAP capture failed: {e}")
            # Fall back to test without capture
            return self._test_without_capture(domain, strategy, artifacts)
    
    def _test_without_capture(self, 
                            domain: str, 
                            strategy: Dict[str, Any],
                            artifacts: TrialArtifacts) -> EnhancedTestResult:
        """Test strategy without PCAP capture (fallback mode)"""
        
        try:
            success, error = self._execute_strategy_test(domain, strategy, 10.0)
            
            # Collect basic network information without PCAP
            artifacts.network_events = [
                {
                    "type": "strategy_test",
                    "domain": domain,
                    "timestamp": datetime.now().isoformat(),
                    "capture_mode": "fallback"
                }
            ]
            
            return EnhancedTestResult(success=success, domain=domain, strategy=strategy,
                                    response_time=0, error=error)
            
        except Exception as e:
            return EnhancedTestResult(success=False, domain=domain, strategy=strategy,
                                    response_time=0, error=str(e))
    
    def _execute_strategy_test(self, domain: str, strategy: Dict[str, Any], timeout: float) -> tuple[bool, Optional[str]]:
        """
        Execute the actual strategy test using the bypass engine.
        
        This method integrates with the existing WindowsBypassEngine to perform
        the strategy test by:
        1. Setting up the strategy override
        2. Starting the bypass engine
        3. Testing connectivity to the domain
        4. Returning success/failure result
        """
        try:
            # Convert strategy to bypass engine format
            strategy_task = self._convert_strategy_to_task(strategy)
            
            # Set strategy override on the bypass engine
            self.bypass_engine.set_strategy_override(strategy_task)
            
            # Test connectivity with the strategy applied
            success = self._test_domain_connectivity(domain, timeout)
            
            # Clear strategy override
            self.bypass_engine.clear_strategy_override()
            
            return success, None if success else "Connection failed with strategy"
            
        except Exception as e:
            self.logger.error(f"Strategy execution failed: {e}")
            # Ensure strategy override is cleared
            try:
                self.bypass_engine.clear_strategy_override()
            except:
                pass
            return False, str(e)
    
    def _convert_strategy_to_task(self, strategy: Dict[str, Any]) -> Dict[str, Any]:
        """Convert strategy format to bypass engine task format"""
        
        # Extract attack type and parameters
        attack_type = strategy.get("attack", strategy.get("type", "fake"))
        params = strategy.get("parameters", strategy.get("params", {}))
        
        # Convert to bypass engine task format
        task = {
            "type": attack_type,
            "params": params.copy(),
            "forced": True,
            "no_fallbacks": True
        }
        
        # Ensure required parameters are present
        if "fooling" not in task["params"]:
            task["params"]["fooling"] = "badsum"
        
        return task
    
    def _test_domain_connectivity(self, domain: str, timeout: float) -> bool:
        """Test connectivity to domain with current bypass engine configuration"""
        
        try:
            import requests
            import urllib3
            
            # Disable SSL warnings for testing
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            # Test HTTPS connectivity
            response = requests.get(
                f"https://{domain}",
                timeout=timeout,
                verify=False,
                allow_redirects=True
            )
            
            # Consider 2xx and 3xx as success
            success = 200 <= response.status_code < 400
            
            self.logger.debug(f"Connectivity test: {domain} -> HTTP {response.status_code}")
            return success
            
        except Exception as e:
            self.logger.debug(f"Connectivity test failed: {domain} -> {e}")
            return False
    
    def _validate_strategy_parameters(self, strategy: Dict[str, Any]) -> ValidationResult:
        """Validate strategy parameters using attack dispatcher"""
        
        try:
            attack_type = strategy.get("attack", strategy.get("type", "fake"))
            params = strategy.get("parameters", strategy.get("params", {}))
            
            # Use attack dispatcher for validation
            dispatcher = getattr(self.bypass_engine, '_attack_dispatcher', None)
            if dispatcher and hasattr(dispatcher, 'validate_attack_parameters'):
                return dispatcher.validate_attack_parameters(attack_type, params)
            else:
                # Fallback validation
                return ValidationResult(is_valid=True, error_message=None)
                
        except Exception as e:
            return ValidationResult(is_valid=False, error_message=str(e))
    
    def _extract_attack_metadata(self, strategy: Dict[str, Any]) -> Dict[str, Any]:
        """Extract metadata about the attack for analysis"""
        
        return {
            "attack_type": strategy.get("attack", strategy.get("type", "unknown")),
            "parameter_count": len(strategy.get("parameters", strategy.get("params", {}))),
            "has_custom_sni": "custom_sni" in strategy.get("parameters", {}),
            "has_ttl_setting": "ttl" in strategy.get("parameters", {}),
            "strategy_source": strategy.get("source", "unknown")
        }
    
    def _extract_network_events(self, session: CaptureSession) -> List[Dict[str, Any]]:
        """Extract network events from capture session"""
        
        events = []
        
        # Basic session information
        events.append({
            "type": "capture_session",
            "session_id": session.session_id,
            "packets_captured": session.packets_captured,
            "pcap_file": session.pcap_file,
            "timestamp": datetime.now().isoformat()
        })
        
        # Add any additional events from the session
        if hasattr(session, 'events'):
            events.extend(session.events)
        
        return events
    
    def _setup_log_capture(self):
        """Setup log capture for collecting engine logs"""
        
        class LogCapture(logging.Handler):
            def __init__(self, buffer, lock):
                super().__init__()
                self.buffer = buffer
                self.lock = lock
            
            def emit(self, record):
                with self.lock:
                    self.buffer.append(self.format(record))
        
        # Add log handler to capture bypass engine logs
        log_handler = LogCapture(self._log_buffer, self._log_buffer_lock)
        log_handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        ))
        
        # Attach to bypass engine logger
        bypass_logger = logging.getLogger("BypassEngine")
        bypass_logger.addHandler(log_handler)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get adapter statistics"""
        
        stats = self.stats.copy()
        stats.update({
            "traffic_analysis_enabled": self.enable_traffic_analysis,
            "pcap_capture_available": self.pcap_capturer is not None and self.pcap_capturer.is_capture_available() if self.pcap_capturer else False,
            "success_rate": self.stats["successful_tests"] / max(1, self.stats["tests_performed"]),
        })
        
        if self.pcap_capturer:
            stats.update(self.pcap_capturer.get_statistics())
        
        return stats
    
    def cleanup_artifacts(self):
        """Clean up temporary artifacts"""
        
        if self.pcap_capturer:
            self.pcap_capturer.cleanup_all_temp_files()
            self.logger.info("🗑️ Cleaned up temporary PCAP files")
    
    def __getattr__(self, name):
        """Delegate unknown attributes to the wrapped bypass engine"""
        return getattr(self.bypass_engine, name)


def create_enhanced_bypass_adapter(bypass_engine: WindowsBypassEngine, 
                                 enable_traffic_analysis: bool = True) -> EnhancedBypassEngineAdapter:
    """
    Factory function to create an enhanced bypass engine adapter.
    
    Args:
        bypass_engine: Existing WindowsBypassEngine instance
        enable_traffic_analysis: Whether to enable traffic analysis and PCAP capture
        
    Returns:
        EnhancedBypassEngineAdapter instance
    """
    return EnhancedBypassEngineAdapter(bypass_engine, enable_traffic_analysis)