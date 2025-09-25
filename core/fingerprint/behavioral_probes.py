"""
Behavioral & Timing Probes for DPI Detection - Task 23 Implementation
Implements behavioral and timing-based probes to detect DPI behavior patterns.

This module implements behavioral probing techniques:
- Timing analysis for DPI detection
- Session fingerprinting analysis
- DPI adaptation testing
- Connection pattern analysis
"""

import asyncio
import socket
import time
import random
import logging
import statistics
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import deque, defaultdict

try:
    from scapy.all import (
        IP, TCP, Raw, sr1, send, sr, 
        conf, get_if_list, get_if_addr
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

LOG = logging.getLogger(__name__)


@dataclass
class BehavioralProbeResult:
    """Results from behavioral and timing probing"""
    
    target: str
    port: int
    timestamp: float = field(default_factory=time.time)
    
    # Timing Analysis
    connection_timing_patterns: Dict[str, Any] = field(default_factory=dict)
    dpi_processing_delay: Optional[float] = None
    timing_variance_detected: bool = False
    
    # Session Fingerprinting
    session_tracking_detected: bool = False
    connection_correlation_detected: bool = False
    ip_based_tracking: bool = False
    port_based_tracking: bool = False
    
    # DPI Adaptation Testing
    dpi_learning_detected: bool = False
    adaptation_time_window: Optional[float] = None
    bypass_degradation_detected: bool = False
    
    # Connection Pattern Analysis
    concurrent_connection_limit: Optional[int] = None
    rate_limiting_detected: bool = False
    connection_fingerprinting: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}


class BehavioralProber:
    """
    Behavioral and timing-based probing for sophisticated DPI detection.
    
    This class implements behavioral probing techniques to detect DPI behavior:
    - Timing analysis for DPI detection
    - Session fingerprinting analysis
    - DPI adaptation testing
    - Connection pattern analysis
    """
    
    def __init__(self, timeout: float = 10.0, max_attempts: int = 3):
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.logger = logging.getLogger(__name__)
        self.is_available = SCAPY_AVAILABLE
        
        # Timing measurement storage
        self.timing_measurements = deque(maxlen=100)
        self.connection_history = deque(maxlen=50)
        
        if not self.is_available:
            self.logger.warning("Scapy not available - behavioral probes disabled")
    
    async def run_behavioral_probes(self, target: str, port: int = 443) -> Dict[str, Any]:
        """
        Run all behavioral and timing probes against the target.
        
        Args:
            target: Target hostname or IP
            port: Target port (default 443 for HTTPS)
            
        Returns:
            Dictionary with probe results
        """
        if not self.is_available:
            return {}
            
        self.logger.info(f"Starting behavioral probes for {target}:{port}")
        
        result = BehavioralProbeResult(target=target, port=port)
        
        try:
            target_ip = await self._resolve_target(target)
            
            # Run all probe categories
            await asyncio.gather(
                self._probe_timing_analysis(result, target_ip, port),
                self._probe_session_fingerprinting(result, target_ip, port),
                self._probe_dpi_adaptation(result, target_ip, port),
                self._probe_connection_patterns(result, target_ip, port),
                return_exceptions=True
            )
            self.logger.info(f"Behavioral probes for {target}:{port} completed. Session tracking detected: {result.session_tracking_detected}")
        except Exception as e:
            self.logger.error(f"Behavioral probes failed for {target}: {e}", exc_info=True)

        return result.to_dict()
    
    async def _resolve_target(self, target: str) -> str:
        """Resolve hostname to IP address"""
        try:
            loop = asyncio.get_event_loop()
            addr_info = await loop.getaddrinfo(target, None, family=socket.AF_INET)
            return addr_info[0][4][0]
        except Exception as e:
            self.logger.debug(f"DNS resolution failed for {target}: {e}")
            return target  # Assume it's already an IP
    
    async def _probe_timing_analysis(self, result: BehavioralProbeResult, 
                                   target_ip: str, port: int):
        """
        Analyze timing patterns to detect DPI processing delays.
        
        DPI systems often introduce measurable delays due to deep packet inspection.
        This probe measures connection timing patterns to detect DPI presence.
        """
        
        def probe():
            try:
                timing_samples = []
                
                # Collect multiple timing samples
                for i in range(20):
                    try:
                        start_time = time.perf_counter()
                        
                        # Test basic TCP connection
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(self.timeout)
                        
                        connect_start = time.perf_counter()
                        sock.connect((target_ip, port))
                        connect_end = time.perf_counter()
                        
                        # Send a simple HTTP request
                        request = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n".encode()
                        send_start = time.perf_counter()
                        sock.send(request)
                        
                        # Measure response time
                        response = sock.recv(1024)
                        response_end = time.perf_counter()
                        
                        sock.close()
                        
                        # Calculate timing metrics
                        connect_time = (connect_end - connect_start) * 1000  # ms
                        response_time = (response_end - send_start) * 1000   # ms
                        total_time = (response_end - start_time) * 1000      # ms
                        
                        timing_samples.append({
                            'connect_time': connect_time,
                            'response_time': response_time,
                            'total_time': total_time,
                            'success': len(response) > 0
                        })
                        
                        # Small delay between measurements
                        time.sleep(0.1)
                        
                    except Exception as e:
                        timing_samples.append({
                            'connect_time': None,
                            'response_time': None,
                            'total_time': None,
                            'success': False,
                            'error': str(e)
                        })
                        self.logger.debug(f"Timing sample {i} failed: {e}")
                
                # Analyze timing patterns
                successful_samples = [s for s in timing_samples if s['success']]
                
                if len(successful_samples) >= 5:
                    connect_times = [s['connect_time'] for s in successful_samples]
                    response_times = [s['response_time'] for s in successful_samples]
                    
                    # Calculate statistics
                    avg_connect = statistics.mean(connect_times)
                    std_connect = statistics.stdev(connect_times) if len(connect_times) > 1 else 0
                    avg_response = statistics.mean(response_times)
                    std_response = statistics.stdev(response_times) if len(response_times) > 1 else 0
                    
                    result.connection_timing_patterns = {
                        'avg_connect_time_ms': avg_connect,
                        'std_connect_time_ms': std_connect,
                        'avg_response_time_ms': avg_response,
                        'std_response_time_ms': std_response,
                        'samples_count': len(successful_samples),
                        'success_rate': len(successful_samples) / len(timing_samples)
                    }
                    
                    # Detect DPI processing delay
                    # DPI typically adds 1-50ms of processing delay
                    if avg_connect > 50 or avg_response > 100:
                        result.dpi_processing_delay = max(avg_connect, avg_response)
                    
                    # Detect timing variance (inconsistent DPI behavior)
                    cv_connect = (std_connect / avg_connect) if avg_connect > 0 else 0
                    cv_response = (std_response / avg_response) if avg_response > 0 else 0
                    
                    if cv_connect > 0.5 or cv_response > 0.5:
                        result.timing_variance_detected = True
                    
                    self.logger.debug(f"Timing analysis: avg_connect={avg_connect:.2f}ms, "
                                    f"avg_response={avg_response:.2f}ms, "
                                    f"variance_detected={result.timing_variance_detected}")
                
            except Exception as e:
                self.logger.debug(f"Timing analysis probe failed: {e}")
        
        await asyncio.get_event_loop().run_in_executor(None, probe)
    
    async def _probe_session_fingerprinting(self, result: BehavioralProbeResult, 
                                          target_ip: str, port: int):
        """
        Test for session tracking and connection correlation by DPI.
        
        Many DPI systems track connections and sessions to build behavioral profiles.
        This probe tests various tracking mechanisms.
        """
        
        def probe():
            try:
                # Test 1: IP-based tracking
                # Make multiple connections from same IP with different source ports
                ip_tracking_results = []
                
                for i in range(5):
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(self.timeout)
                        
                        # Bind to specific source port to test port-based tracking
                        source_port = 20000 + i
                        try:
                            sock.bind(('', source_port))
                        except:
                            pass  # If bind fails, use random port
                        
                        start_time = time.perf_counter()
                        sock.connect((target_ip, port))
                        connect_time = time.perf_counter() - start_time
                        
                        # Send identical request
                        request = f"GET /test{i} HTTP/1.1\r\nHost: {target_ip}\r\n\r\n".encode()
                        sock.send(request)
                        response = sock.recv(1024)
                        
                        sock.close()
                        
                        ip_tracking_results.append({
                            'source_port': source_port,
                            'connect_time': connect_time * 1000,
                            'response_received': len(response) > 0,
                            'response_size': len(response)
                        })
                        
                        time.sleep(0.2)
                        
                    except Exception as e:
                        ip_tracking_results.append({
                            'source_port': source_port,
                            'error': str(e)
                        })
                
                # Analyze for tracking patterns
                successful_connections = [r for r in ip_tracking_results if 'error' not in r]
                
                if len(successful_connections) >= 3:
                    connect_times = [r['connect_time'] for r in successful_connections]
                    
                    # If connection times increase significantly, might indicate tracking
                    if len(connect_times) > 1:
                        time_trend = connect_times[-1] - connect_times[0]
                        if time_trend > 50:  # 50ms increase suggests processing overhead
                            result.session_tracking_detected = True
                    
                    # Check for port-based patterns
                    response_sizes = [r['response_size'] for r in successful_connections]
                    if len(set(response_sizes)) == 1 and response_sizes[0] > 0:
                        # Identical responses might indicate caching/tracking
                        result.ip_based_tracking = True
                
                # Test 2: Connection correlation
                # Make rapid successive connections to see if DPI correlates them
                correlation_results = []
                
                for i in range(3):
                    try:
                        # Make 2 rapid connections
                        sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        
                        sock1.settimeout(self.timeout)
                        sock2.settimeout(self.timeout)
                        
                        # Connect almost simultaneously
                        start_time = time.perf_counter()
                        sock1.connect((target_ip, port))
                        sock2.connect((target_ip, port))
                        
                        # Send different requests
                        req1 = f"GET /corr1_{i} HTTP/1.1\r\nHost: {target_ip}\r\n\r\n".encode()
                        req2 = f"GET /corr2_{i} HTTP/1.1\r\nHost: {target_ip}\r\n\r\n".encode()
                        
                        sock1.send(req1)
                        sock2.send(req2)
                        
                        resp1 = sock1.recv(1024)
                        resp2 = sock2.recv(1024)
                        
                        sock1.close()
                        sock2.close()
                        
                        correlation_results.append({
                            'both_successful': len(resp1) > 0 and len(resp2) > 0,
                            'response_similarity': self._calculate_response_similarity(resp1, resp2)
                        })
                        
                        time.sleep(0.5)
                        
                    except Exception as e:
                        correlation_results.append({'error': str(e)})
                
                # Analyze correlation results
                successful_correlations = [r for r in correlation_results if 'error' not in r]
                if successful_correlations:
                    avg_similarity = statistics.mean([r['response_similarity'] 
                                                    for r in successful_correlations])
                    if avg_similarity > 0.8:  # High similarity suggests correlation
                        result.connection_correlation_detected = True
                
                self.logger.debug(f"Session fingerprinting: tracking={result.session_tracking_detected}, "
                                f"ip_tracking={result.ip_based_tracking}, "
                                f"correlation={result.connection_correlation_detected}")
                
            except Exception as e:
                self.logger.debug(f"Session fingerprinting probe failed: {e}")
        
        await asyncio.get_event_loop().run_in_executor(None, probe)
    
    def _calculate_response_similarity(self, resp1: bytes, resp2: bytes) -> float:
        """Calculate similarity between two responses (0.0 to 1.0)"""
        if not resp1 or not resp2:
            return 0.0
        
        # Simple similarity based on response length and common bytes
        len_similarity = 1.0 - abs(len(resp1) - len(resp2)) / max(len(resp1), len(resp2))
        
        # Check for common patterns (HTTP status codes, headers)
        common_patterns = [b'HTTP/', b'200', b'404', b'Content-Length', b'Server']
        pattern_matches = 0
        
        for pattern in common_patterns:
            if pattern in resp1 and pattern in resp2:
                pattern_matches += 1
        
        pattern_similarity = pattern_matches / len(common_patterns)
        
        return (len_similarity + pattern_similarity) / 2
    
    async def _probe_dpi_adaptation(self, result: BehavioralProbeResult, 
                                  target_ip: str, port: int):
        """
        Test for DPI learning and adaptation behavior.
        
        Advanced DPI systems can learn from bypass attempts and adapt their detection.
        This probe tests if the DPI system changes behavior over time.
        """
        
        def probe():
            try:
                # Test DPI learning by repeating the same "suspicious" pattern
                learning_results = []
                
                # Create a pattern that might trigger DPI learning
                suspicious_pattern = b"GET /admin HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n"
                suspicious_pattern += b"User-Agent: sqlmap/1.0\r\n"  # Suspicious user agent
                suspicious_pattern += b"X-Forwarded-For: 127.0.0.1\r\n\r\n"
                
                # Send the pattern multiple times and measure response
                for attempt in range(10):
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(self.timeout)
                        
                        start_time = time.perf_counter()
                        sock.connect((target_ip, port))
                        connect_time = time.perf_counter() - start_time
                        
                        send_start = time.perf_counter()
                        sock.send(suspicious_pattern)
                        
                        try:
                            response = sock.recv(4096)
                            response_time = time.perf_counter() - send_start
                            
                            learning_results.append({
                                'attempt': attempt,
                                'connect_time': connect_time * 1000,
                                'response_time': response_time * 1000,
                                'response_size': len(response),
                                'blocked': b'403' in response or b'blocked' in response.lower(),
                                'success': len(response) > 0
                            })
                            
                        except socket.timeout:
                            learning_results.append({
                                'attempt': attempt,
                                'connect_time': connect_time * 1000,
                                'timeout': True,
                                'success': False
                            })
                        
                        sock.close()
                        time.sleep(1.0)  # Wait between attempts to allow DPI processing
                        
                    except Exception as e:
                        learning_results.append({
                            'attempt': attempt,
                            'error': str(e),
                            'success': False
                        })
                
                # Analyze for learning patterns
                successful_attempts = [r for r in learning_results if r.get('success', False)]
                
                if len(successful_attempts) >= 5:
                    # Check if response times increase over time (DPI learning overhead)
                    response_times = [r['response_time'] for r in successful_attempts 
                                    if 'response_time' in r]
                    
                    if len(response_times) >= 5:
                        early_avg = statistics.mean(response_times[:3])
                        late_avg = statistics.mean(response_times[-3:])
                        
                        if late_avg > early_avg * 1.5:  # 50% increase suggests learning
                            result.dpi_learning_detected = True
                            result.adaptation_time_window = len(successful_attempts) * 1.0  # seconds
                    
                    # Check for increasing block rate
                    blocked_attempts = [r for r in successful_attempts if r.get('blocked', False)]
                    if len(blocked_attempts) > 0:
                        # If blocking increases over time, suggests adaptation
                        block_positions = [r['attempt'] for r in blocked_attempts]
                        if block_positions and statistics.mean(block_positions) > 5:
                            result.bypass_degradation_detected = True
                
                # Test bypass degradation with a known working pattern
                # First establish a working baseline
                baseline_pattern = b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n"
                
                baseline_success = False
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((target_ip, port))
                    sock.send(baseline_pattern)
                    response = sock.recv(1024)
                    baseline_success = len(response) > 0 and b'200' in response
                    sock.close()
                except:
                    pass
                
                # If baseline works, test if it degrades after suspicious activity
                if baseline_success:
                    # Send more suspicious patterns
                    for _ in range(5):
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(2.0)
                            sock.connect((target_ip, port))
                            sock.send(suspicious_pattern)
                            sock.recv(1024)
                            sock.close()
                            time.sleep(0.5)
                        except:
                            pass
                    
                    # Test baseline again
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(self.timeout)
                        sock.connect((target_ip, port))
                        sock.send(baseline_pattern)
                        response = sock.recv(1024)
                        post_baseline_success = len(response) > 0 and b'200' in response
                        sock.close()
                        
                        if baseline_success and not post_baseline_success:
                            result.bypass_degradation_detected = True
                    except:
                        pass
                
                self.logger.debug(f"DPI adaptation: learning={result.dpi_learning_detected}, "
                                f"degradation={result.bypass_degradation_detected}")
                
            except Exception as e:
                self.logger.debug(f"DPI adaptation probe failed: {e}")
        
        await asyncio.get_event_loop().run_in_executor(None, probe)
    
    async def _probe_connection_patterns(self, result: BehavioralProbeResult, 
                                       target_ip: str, port: int):
        """
        Analyze connection patterns and rate limiting behavior.
        
        Tests for DPI rate limiting, concurrent connection limits,
        and connection fingerprinting techniques.
        """
        
        def probe():
            try:
                # Test 1: Concurrent connection limits
                max_concurrent = 0
                concurrent_sockets = []
                
                try:
                    for i in range(20):  # Try up to 20 concurrent connections
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(5.0)
                        
                        try:
                            sock.connect((target_ip, port))
                            concurrent_sockets.append(sock)
                            max_concurrent = i + 1
                            time.sleep(0.1)  # Small delay between connections
                        except Exception as e:
                            # Connection failed - might have hit limit
                            sock.close()
                            break
                    
                    result.concurrent_connection_limit = max_concurrent
                    
                    # Clean up sockets
                    for sock in concurrent_sockets:
                        try:
                            sock.close()
                        except:
                            pass
                    
                except Exception as e:
                    self.logger.debug(f"Concurrent connection test failed: {e}")
                
                # Test 2: Rate limiting detection
                rate_limit_results = []
                
                # Make rapid successive connections
                for i in range(15):
                    try:
                        start_time = time.perf_counter()
                        
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(3.0)
                        sock.connect((target_ip, port))
                        
                        connect_time = time.perf_counter() - start_time
                        
                        # Send simple request
                        request = f"GET /rate{i} HTTP/1.1\r\nHost: {target_ip}\r\n\r\n".encode()
                        sock.send(request)
                        
                        try:
                            response = sock.recv(1024)
                            rate_limit_results.append({
                                'attempt': i,
                                'connect_time': connect_time * 1000,
                                'success': len(response) > 0,
                                'rate_limited': b'429' in response or b'rate' in response.lower()
                            })
                        except socket.timeout:
                            rate_limit_results.append({
                                'attempt': i,
                                'connect_time': connect_time * 1000,
                                'success': False,
                                'timeout': True
                            })
                        
                        sock.close()
                        
                        # No delay - test rapid connections
                        
                    except Exception as e:
                        rate_limit_results.append({
                            'attempt': i,
                            'error': str(e),
                            'success': False
                        })
                
                # Analyze rate limiting
                successful_rate_tests = [r for r in rate_limit_results if r.get('success', False)]
                rate_limited_responses = [r for r in successful_rate_tests if r.get('rate_limited', False)]
                timeout_responses = [r for r in rate_limit_results if r.get('timeout', False)]
                
                if rate_limited_responses or len(timeout_responses) > 5:
                    result.rate_limiting_detected = True
                
                # Test 3: Connection fingerprinting
                # Test different connection patterns to see if DPI fingerprints them
                fingerprint_tests = {
                    'normal': {'delay': 0.0, 'user_agent': 'Mozilla/5.0'},
                    'fast': {'delay': 0.0, 'user_agent': 'curl/7.68.0'},
                    'slow': {'delay': 2.0, 'user_agent': 'wget/1.20.3'},
                    'automated': {'delay': 0.1, 'user_agent': 'python-requests/2.25.1'},
                }
                
                fingerprint_results = {}
                
                for test_name, config in fingerprint_tests.items():
                    try:
                        time.sleep(config['delay'])
                        
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(self.timeout)
                        
                        start_time = time.perf_counter()
                        sock.connect((target_ip, port))
                        connect_time = time.perf_counter() - start_time
                        
                        request = f"GET /fp_{test_name} HTTP/1.1\r\n"
                        request += f"Host: {target_ip}\r\n"
                        request += f"User-Agent: {config['user_agent']}\r\n\r\n"
                        
                        sock.send(request.encode())
                        response = sock.recv(4096)
                        sock.close()
                        
                        fingerprint_results[test_name] = {
                            'connect_time': connect_time * 1000,
                            'response_size': len(response),
                            'blocked': b'403' in response or b'blocked' in response.lower(),
                            'success': len(response) > 0
                        }
                        
                        time.sleep(1.0)  # Delay between fingerprint tests
                        
                    except Exception as e:
                        fingerprint_results[test_name] = {
                            'error': str(e),
                            'success': False
                        }
                
                result.connection_fingerprinting = fingerprint_results
                
                self.logger.debug(f"Connection patterns: max_concurrent={max_concurrent}, "
                                f"rate_limiting={result.rate_limiting_detected}, "
                                f"fingerprint_tests={len(fingerprint_results)}")
                
            except Exception as e:
                self.logger.debug(f"Connection patterns probe failed: {e}")
        
        await asyncio.get_event_loop().run_in_executor(None, probe)