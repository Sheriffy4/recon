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
import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple, Union, Set
from enum import Enum
import aiohttp
import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import ssl
import dns.resolver
import random


class ValidationMethod(Enum):
    """Validation methods for reliability checking."""
    HTTP_RESPONSE = "http_response"
    CONTENT_CHECK = "content_check"
    TIMING_ANALYSIS = "timing_analysis"
    MULTI_REQUEST = "multi_request"
    DEEP_INSPECTION = "deep_inspection"
    DNS_RESOLUTION = "dns_resolution"
    SSL_HANDSHAKE = "ssl_handshake"
    HEADER_ANALYSIS = "header_analysis"
    PAYLOAD_VERIFICATION = "payload_verification"


class ReliabilityLevel(Enum):
    """Reliability levels for validation results."""
    EXCELLENT = "excellent"      # 95-100% reliability
    VERY_GOOD = "very_good"     # 85-94% reliability
    GOOD = "good"               # 70-84% reliability
    MODERATE = "moderate"       # 50-69% reliability
    POOR = "poor"              # 30-49% reliability
    UNRELIABLE = "unreliable"   # 0-29% reliability


class AccessibilityStatus(Enum):
    """Status of domain accessibility."""
    ACCESSIBLE = "accessible"
    BLOCKED = "blocked"
    PARTIALLY_BLOCKED = "partially_blocked"
    TIMEOUT = "timeout"
    DNS_ERROR = "dns_error"
    SSL_ERROR = "ssl_error"
    UNKNOWN = "unknown"


@dataclass
class ValidationResult:
    """Result of a single validation method."""
    method: ValidationMethod
    success: bool
    response_time: float
    status_code: Optional[int] = None
    content_length: Optional[int] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class AccessibilityResult:
    """Result of multi-level accessibility checking."""
    domain: str
    port: int
    status: AccessibilityStatus
    validation_results: List[ValidationResult]
    reliability_score: float
    false_positive_detected: bool
    bypass_effectiveness: float
    total_tests: int
    successful_tests: int
    average_response_time: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StrategyEffectivenessResult:
    """Result of strategy effectiveness evaluation."""
    strategy_id: str
    domain: str
    port: int
    effectiveness_score: float
    reliability_level: ReliabilityLevel
    accessibility_results: List[AccessibilityResult]
    false_positive_rate: float
    consistency_score: float
    performance_score: float
    recommendation: str
    metadata: Dict[str, Any] = field(default_factory=dict)


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
            ValidationMethod.DNS_RESOLUTION
        ]
        
        # False positive detection thresholds
        self.false_positive_thresholds = {
            'response_time_variance': 2.0,  # Standard deviations
            'content_similarity': 0.8,      # Minimum similarity for consistency
            'status_code_consistency': 0.9,  # Minimum consistency rate
            'dns_consistency': 0.95         # DNS resolution consistency
        }
        
        # Performance baselines
        self.performance_baselines = {
            'max_response_time': 10.0,      # Maximum acceptable response time
            'min_success_rate': 0.7,        # Minimum success rate for reliability
            'consistency_threshold': 0.8     # Minimum consistency for reliability
        }
        
        # Thread pool for concurrent operations
        self._thread_pool = ThreadPoolExecutor(max_workers=max_concurrent_tests)
        
        # Cache for DNS resolutions and baseline measurements
        self._dns_cache: Dict[str, str] = {}
        self._baseline_cache: Dict[str, Dict[str, Any]] = {}
    
    async def validate_strategy_effectiveness(self, 
                                            strategy_id: str,
                                            domain: str,
                                            port: int = 443,
                                            test_iterations: int = 5) -> StrategyEffectivenessResult:
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
        effectiveness_score = self._calculate_effectiveness_score(
            accessibility_results, baseline_result
        )
        
        # Detect false positives
        false_positive_rate = self._detect_false_positives(
            accessibility_results, baseline_result
        )
        
        # Calculate consistency score
        consistency_score = self._calculate_consistency_score(accessibility_results)
        
        # Calculate performance score
        performance_score = self._calculate_performance_score(accessibility_results)
        
        # Determine reliability level
        reliability_level = self._determine_reliability_level(
            effectiveness_score, consistency_score, false_positive_rate
        )
        
        # Generate recommendation
        recommendation = self._generate_strategy_recommendation(
            effectiveness_score, reliability_level, false_positive_rate, 
            consistency_score, performance_score
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
                'baseline_result': baseline_result,
                'test_iterations': test_iterations,
                'validation_timestamp': time.time()
            }
        )
    
    async def multi_level_accessibility_check(self, 
                                            domain: str, 
                                            port: int = 443) -> AccessibilityResult:
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
            task = asyncio.create_task(
                self._run_validation_method(method, domain, port)
            )
            validation_tasks.append(task)
        
        # Wait for all validations to complete
        validation_results = await asyncio.gather(*validation_tasks, return_exceptions=True)
        
        # Filter out exceptions and create ValidationResult objects
        valid_results = []
        for i, result in enumerate(validation_results):
            if isinstance(result, Exception):
                self.logger.warning(f"Validation method {self.validation_methods[i]} failed: {result}")
                # Create failed validation result
                valid_results.append(ValidationResult(
                    method=self.validation_methods[i],
                    success=False,
                    response_time=self.timeout,
                    error_message=str(result)
                ))
            else:
                valid_results.append(result)
        
        # Analyze results
        successful_tests = sum(1 for r in valid_results if r.success)
        total_tests = len(valid_results)
        
        # Calculate metrics
        reliability_score = self._calculate_reliability_score(valid_results)
        false_positive_detected = self._detect_false_positive_in_results(valid_results)
        bypass_effectiveness = successful_tests / total_tests if total_tests > 0 else 0.0
        
        # Determine accessibility status
        status = self._determine_accessibility_status(valid_results, reliability_score)
        
        # Calculate average response time
        response_times = [r.response_time for r in valid_results if r.success and r.response_time > 0]
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
                'validation_timestamp': time.time(),
                'method_count': len(self.validation_methods)
            }
        )
    
    async def _run_validation_method(self, 
                                   method: ValidationMethod, 
                                   domain: str, 
                                   port: int) -> ValidationResult:
        """Run a specific validation method."""
        start_time = time.time()
        
        try:
            if method == ValidationMethod.HTTP_RESPONSE:
                return await self._validate_http_response(domain, port, start_time)
            elif method == ValidationMethod.CONTENT_CHECK:
                return await self._validate_content_check(domain, port, start_time)
            elif method == ValidationMethod.TIMING_ANALYSIS:
                return await self._validate_timing_analysis(domain, port, start_time)
            elif method == ValidationMethod.MULTI_REQUEST:
                return await self._validate_multi_request(domain, port, start_time)
            elif method == ValidationMethod.DNS_RESOLUTION:
                return await self._validate_dns_resolution(domain, start_time)
            elif method == ValidationMethod.SSL_HANDSHAKE:
                return await self._validate_ssl_handshake(domain, port, start_time)
            elif method == ValidationMethod.HEADER_ANALYSIS:
                return await self._validate_header_analysis(domain, port, start_time)
            elif method == ValidationMethod.PAYLOAD_VERIFICATION:
                return await self._validate_payload_verification(domain, port, start_time)
            else:
                raise ValueError(f"Unknown validation method: {method}")
                
        except Exception as e:
            response_time = time.time() - start_time
            return ValidationResult(
                method=method,
                success=False,
                response_time=response_time,
                error_message=str(e)
            )
    
    async def _validate_http_response(self, domain: str, port: int, start_time: float) -> ValidationResult:
        """Validate HTTP response accessibility."""
        url = f"{'https' if port == 443 else 'http'}://{domain}"
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as response:
                    content = await response.text()
                    response_time = time.time() - start_time
                    
                    # Check for blocking indicators
                    blocking_indicators = [
                        'blocked', 'forbidden', 'access denied', 'not available',
                        'restricted', 'censored', 'filtered'
                    ]
                    
                    content_lower = content.lower()
                    is_blocked = any(indicator in content_lower for indicator in blocking_indicators)
                    
                    success = response.status == 200 and not is_blocked and len(content) > 100
                    
                    return ValidationResult(
                        method=ValidationMethod.HTTP_RESPONSE,
                        success=success,
                        response_time=response_time,
                        status_code=response.status,
                        content_length=len(content),
                        metadata={
                            'headers': dict(response.headers),
                            'content_hash': hashlib.md5(content.encode()).hexdigest()[:16],
                            'blocking_detected': is_blocked
                        }
                    )
                    
        except asyncio.TimeoutError:
            response_time = time.time() - start_time
            return ValidationResult(
                method=ValidationMethod.HTTP_RESPONSE,
                success=False,
                response_time=response_time,
                error_message="Request timeout"
            )
        except Exception as e:
            response_time = time.time() - start_time
            return ValidationResult(
                method=ValidationMethod.HTTP_RESPONSE,
                success=False,
                response_time=response_time,
                error_message=str(e)
            )
    
    async def _validate_content_check(self, domain: str, port: int, start_time: float) -> ValidationResult:
        """Validate content consistency and authenticity."""
        url = f"{'https' if port == 443 else 'http'}://{domain}"
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Make multiple requests to check consistency
                contents = []
                for _ in range(3):
                    async with session.get(url) as response:
                        if response.status == 200:
                            content = await response.text()
                            contents.append(content)
                        await asyncio.sleep(0.1)
                
                response_time = time.time() - start_time
                
                if len(contents) < 2:
                    return ValidationResult(
                        method=ValidationMethod.CONTENT_CHECK,
                        success=False,
                        response_time=response_time,
                        error_message="Insufficient responses for content check"
                    )
                
                # Check content consistency
                content_hashes = [hashlib.md5(c.encode()).hexdigest() for c in contents]
                unique_hashes = set(content_hashes)
                consistency_rate = 1.0 - (len(unique_hashes) - 1) / len(contents)
                
                # Check for expected content patterns
                expected_patterns = ['<!DOCTYPE', '<html', '<head', '<body']
                has_expected_content = any(
                    any(pattern in content for pattern in expected_patterns)
                    for content in contents
                )
                
                success = (consistency_rate >= self.false_positive_thresholds['content_similarity'] 
                          and has_expected_content)
                
                return ValidationResult(
                    method=ValidationMethod.CONTENT_CHECK,
                    success=success,
                    response_time=response_time,
                    metadata={
                        'consistency_rate': consistency_rate,
                        'unique_content_hashes': len(unique_hashes),
                        'has_expected_content': has_expected_content,
                        'content_lengths': [len(c) for c in contents]
                    }
                )
                
        except Exception as e:
            response_time = time.time() - start_time
            return ValidationResult(
                method=ValidationMethod.CONTENT_CHECK,
                success=False,
                response_time=response_time,
                error_message=str(e)
            )
    
    async def _validate_timing_analysis(self, domain: str, port: int, start_time: float) -> ValidationResult:
        """Validate response timing patterns."""
        url = f"{'https' if port == 443 else 'http'}://{domain}"
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Measure multiple request timings
                timings = []
                for _ in range(5):
                    request_start = time.time()
                    async with session.get(url) as response:
                        await response.text()
                        request_time = time.time() - request_start
                        timings.append(request_time)
                    await asyncio.sleep(0.1)
                
                response_time = time.time() - start_time
                
                # Analyze timing patterns
                avg_timing = statistics.mean(timings)
                timing_variance = statistics.stdev(timings) if len(timings) > 1 else 0.0
                
                # Check for suspicious timing patterns
                suspicious_patterns = [
                    avg_timing > self.performance_baselines['max_response_time'],  # Too slow
                    timing_variance > avg_timing * 0.5,  # High variance
                    any(t > self.timeout * 0.8 for t in timings)  # Near-timeout responses
                ]
                
                success = not any(suspicious_patterns) and avg_timing < self.performance_baselines['max_response_time']
                
                return ValidationResult(
                    method=ValidationMethod.TIMING_ANALYSIS,
                    success=success,
                    response_time=response_time,
                    metadata={
                        'average_timing': avg_timing,
                        'timing_variance': timing_variance,
                        'individual_timings': timings,
                        'suspicious_patterns': suspicious_patterns
                    }
                )
                
        except Exception as e:
            response_time = time.time() - start_time
            return ValidationResult(
                method=ValidationMethod.TIMING_ANALYSIS,
                success=False,
                response_time=response_time,
                error_message=str(e)
            )
    
    async def _validate_multi_request(self, domain: str, port: int, start_time: float) -> ValidationResult:
        """Validate multiple concurrent requests."""
        url = f"{'https' if port == 443 else 'http'}://{domain}"
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Make concurrent requests
                tasks = []
                for i in range(3):
                    task = asyncio.create_task(session.get(url))
                    tasks.append(task)
                
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                response_time = time.time() - start_time
                
                # Analyze responses
                successful_responses = []
                for response in responses:
                    if not isinstance(response, Exception):
                        if response.status == 200:
                            successful_responses.append(response)
                        response.close()
                
                success_rate = len(successful_responses) / len(responses)
                success = success_rate >= self.performance_baselines['min_success_rate']
                
                return ValidationResult(
                    method=ValidationMethod.MULTI_REQUEST,
                    success=success,
                    response_time=response_time,
                    metadata={
                        'success_rate': success_rate,
                        'successful_responses': len(successful_responses),
                        'total_requests': len(responses)
                    }
                )
                
        except Exception as e:
            response_time = time.time() - start_time
            return ValidationResult(
                method=ValidationMethod.MULTI_REQUEST,
                success=False,
                response_time=response_time,
                error_message=str(e)
            )
    
    async def _validate_dns_resolution(self, domain: str, start_time: float) -> ValidationResult:
        """Validate DNS resolution consistency."""
        try:
            # Check cache first
            if domain in self._dns_cache:
                cached_ip = self._dns_cache[domain]
                response_time = time.time() - start_time
                
                return ValidationResult(
                    method=ValidationMethod.DNS_RESOLUTION,
                    success=True,
                    response_time=response_time,
                    metadata={
                        'resolved_ip': cached_ip,
                        'from_cache': True
                    }
                )
            
            # Resolve DNS
            loop = asyncio.get_event_loop()
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            
            # Run DNS resolution in thread pool
            result = await loop.run_in_executor(
                self._thread_pool,
                lambda: resolver.resolve(domain, 'A')
            )
            
            response_time = time.time() - start_time
            
            if result:
                ip_addresses = [str(rdata) for rdata in result]
                primary_ip = ip_addresses[0]
                
                # Cache the result
                self._dns_cache[domain] = primary_ip
                
                return ValidationResult(
                    method=ValidationMethod.DNS_RESOLUTION,
                    success=True,
                    response_time=response_time,
                    metadata={
                        'resolved_ips': ip_addresses,
                        'primary_ip': primary_ip,
                        'from_cache': False
                    }
                )
            else:
                return ValidationResult(
                    method=ValidationMethod.DNS_RESOLUTION,
                    success=False,
                    response_time=response_time,
                    error_message="No DNS records found"
                )
                
        except Exception as e:
            response_time = time.time() - start_time
            return ValidationResult(
                method=ValidationMethod.DNS_RESOLUTION,
                success=False,
                response_time=response_time,
                error_message=str(e)
            )
    
    async def _validate_ssl_handshake(self, domain: str, port: int, start_time: float) -> ValidationResult:
        """Validate SSL handshake for HTTPS connections."""
        if port != 443:
            # Skip SSL validation for non-HTTPS ports
            return ValidationResult(
                method=ValidationMethod.SSL_HANDSHAKE,
                success=True,
                response_time=0.0,
                metadata={'skipped': 'non_https_port'}
            )
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Perform SSL handshake
            loop = asyncio.get_event_loop()
            
            def ssl_handshake():
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                try:
                    sock.connect((domain, port))
                    ssl_sock = context.wrap_socket(sock, server_hostname=domain)
                    cert = ssl_sock.getpeercert()
                    ssl_sock.close()
                    return cert
                finally:
                    sock.close()
            
            cert = await loop.run_in_executor(self._thread_pool, ssl_handshake)
            response_time = time.time() - start_time
            
            success = cert is not None
            
            return ValidationResult(
                method=ValidationMethod.SSL_HANDSHAKE,
                success=success,
                response_time=response_time,
                metadata={
                    'certificate_present': success,
                    'certificate_subject': cert.get('subject', []) if cert else None
                }
            )
            
        except Exception as e:
            response_time = time.time() - start_time
            return ValidationResult(
                method=ValidationMethod.SSL_HANDSHAKE,
                success=False,
                response_time=response_time,
                error_message=str(e)
            )
    
    async def _validate_header_analysis(self, domain: str, port: int, start_time: float) -> ValidationResult:
        """Validate HTTP headers for authenticity."""
        url = f"{'https' if port == 443 else 'http'}://{domain}"
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.head(url) as response:
                    response_time = time.time() - start_time
                    
                    headers = dict(response.headers)
                    
                    # Check for expected headers
                    expected_headers = ['server', 'content-type', 'date']
                    present_headers = [h.lower() for h in headers.keys()]
                    expected_present = sum(1 for h in expected_headers if h in present_headers)
                    
                    # Check for blocking indicators in headers
                    blocking_headers = ['x-blocked', 'x-filtered', 'x-censored']
                    blocking_detected = any(h in present_headers for h in blocking_headers)
                    
                    success = (response.status == 200 and 
                              expected_present >= 2 and 
                              not blocking_detected)
                    
                    return ValidationResult(
                        method=ValidationMethod.HEADER_ANALYSIS,
                        success=success,
                        response_time=response_time,
                        status_code=response.status,
                        metadata={
                            'headers': headers,
                            'expected_headers_present': expected_present,
                            'blocking_detected': blocking_detected
                        }
                    )
                    
        except Exception as e:
            response_time = time.time() - start_time
            return ValidationResult(
                method=ValidationMethod.HEADER_ANALYSIS,
                success=False,
                response_time=response_time,
                error_message=str(e)
            )
    
    async def _validate_payload_verification(self, domain: str, port: int, start_time: float) -> ValidationResult:
        """Validate payload integrity and authenticity."""
        url = f"{'https' if port == 443 else 'http'}://{domain}"
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as response:
                    content = await response.read()
                    response_time = time.time() - start_time
                    
                    # Basic payload validation
                    content_length = len(content)
                    
                    # Check for minimum content length (avoid empty responses)
                    min_content_length = 100
                    
                    # Check for binary vs text content
                    try:
                        text_content = content.decode('utf-8')
                        is_text = True
                    except UnicodeDecodeError:
                        is_text = False
                        text_content = ""
                    
                    # Check for HTML structure if text content
                    has_html_structure = False
                    if is_text:
                        html_tags = ['<html', '<head', '<body', '<!doctype']
                        has_html_structure = any(tag in text_content.lower() for tag in html_tags)
                    
                    success = (response.status == 200 and 
                              content_length >= min_content_length and
                              (has_html_structure or not is_text))
                    
                    return ValidationResult(
                        method=ValidationMethod.PAYLOAD_VERIFICATION,
                        success=success,
                        response_time=response_time,
                        status_code=response.status,
                        content_length=content_length,
                        metadata={
                            'is_text_content': is_text,
                            'has_html_structure': has_html_structure,
                            'content_hash': hashlib.md5(content).hexdigest()[:16]
                        }
                    )
                    
        except Exception as e:
            response_time = time.time() - start_time
            return ValidationResult(
                method=ValidationMethod.PAYLOAD_VERIFICATION,
                success=False,
                response_time=response_time,
                error_message=str(e)
            )    

    async def _collect_baseline_measurements(self, domain: str, port: int) -> Dict[str, Any]:
        """Collect baseline measurements without bypass for comparison."""
        cache_key = f"{domain}:{port}"
        
        if cache_key in self._baseline_cache:
            return self._baseline_cache[cache_key]
        
        self.logger.debug(f"Collecting baseline measurements for {domain}:{port}")
        
        # Run basic accessibility check without bypass
        baseline_result = await self.multi_level_accessibility_check(domain, port)
        
        baseline_data = {
            'accessibility_status': baseline_result.status.value,
            'reliability_score': baseline_result.reliability_score,
            'average_response_time': baseline_result.average_response_time,
            'successful_tests': baseline_result.successful_tests,
            'total_tests': baseline_result.total_tests,
            'timestamp': time.time()
        }
        
        # Cache the baseline
        self._baseline_cache[cache_key] = baseline_data
        
        return baseline_data
    
    def _calculate_reliability_score(self, validation_results: List[ValidationResult]) -> float:
        """Calculate overall reliability score from validation results."""
        if not validation_results:
            return 0.0
        
        # Weight different validation methods
        method_weights = {
            ValidationMethod.HTTP_RESPONSE: 0.25,
            ValidationMethod.CONTENT_CHECK: 0.20,
            ValidationMethod.TIMING_ANALYSIS: 0.15,
            ValidationMethod.MULTI_REQUEST: 0.15,
            ValidationMethod.DNS_RESOLUTION: 0.10,
            ValidationMethod.SSL_HANDSHAKE: 0.05,
            ValidationMethod.HEADER_ANALYSIS: 0.05,
            ValidationMethod.PAYLOAD_VERIFICATION: 0.05
        }
        
        weighted_score = 0.0
        total_weight = 0.0
        
        for result in validation_results:
            weight = method_weights.get(result.method, 0.1)
            score = 1.0 if result.success else 0.0
            
            # Adjust score based on response time
            if result.success and result.response_time > 0:
                time_penalty = min(result.response_time / self.performance_baselines['max_response_time'], 1.0)
                score *= (1.0 - time_penalty * 0.2)  # Up to 20% penalty for slow responses
            
            weighted_score += score * weight
            total_weight += weight
        
        return weighted_score / total_weight if total_weight > 0 else 0.0
    
    def _detect_false_positive_in_results(self, validation_results: List[ValidationResult]) -> bool:
        """Detect false positives in validation results."""
        if len(validation_results) < 2:
            return False
        
        # Check for inconsistent results
        success_rates = [1.0 if r.success else 0.0 for r in validation_results]
        success_rate = statistics.mean(success_rates)
        
        # Check response time consistency
        response_times = [r.response_time for r in validation_results if r.success and r.response_time > 0]
        if len(response_times) > 1:
            time_variance = statistics.stdev(response_times)
            avg_time = statistics.mean(response_times)
            
            # High variance in response times might indicate false positives
            if time_variance > avg_time * 0.5:
                return True
        
        # Check status code consistency
        status_codes = [r.status_code for r in validation_results if r.status_code is not None]
        if len(status_codes) > 1:
            unique_codes = set(status_codes)
            consistency_rate = 1.0 - (len(unique_codes) - 1) / len(status_codes)
            
            if consistency_rate < self.false_positive_thresholds['status_code_consistency']:
                return True
        
        # Check for mixed success/failure patterns that might indicate instability
        if 0.3 < success_rate < 0.7:  # Mixed results
            return True
        
        return False
    
    def _determine_accessibility_status(self, validation_results: List[ValidationResult], 
                                      reliability_score: float) -> AccessibilityStatus:
        """Determine overall accessibility status from validation results."""
        if not validation_results:
            return AccessibilityStatus.UNKNOWN
        
        successful_tests = sum(1 for r in validation_results if r.success)
        total_tests = len(validation_results)
        success_rate = successful_tests / total_tests
        
        # Check for specific error patterns
        dns_errors = sum(1 for r in validation_results 
                        if r.method == ValidationMethod.DNS_RESOLUTION and not r.success)
        ssl_errors = sum(1 for r in validation_results 
                        if r.method == ValidationMethod.SSL_HANDSHAKE and not r.success)
        timeout_errors = sum(1 for r in validation_results 
                           if 'timeout' in (r.error_message or '').lower())
        
        # Determine status based on patterns
        if dns_errors > 0 and success_rate < 0.3:
            return AccessibilityStatus.DNS_ERROR
        elif ssl_errors > 0 and success_rate < 0.3:
            return AccessibilityStatus.SSL_ERROR
        elif timeout_errors > total_tests * 0.5:
            return AccessibilityStatus.TIMEOUT
        elif success_rate >= 0.8 and reliability_score >= 0.7:
            return AccessibilityStatus.ACCESSIBLE
        elif success_rate >= 0.3:
            return AccessibilityStatus.PARTIALLY_BLOCKED
        elif success_rate < 0.3:
            return AccessibilityStatus.BLOCKED
        else:
            return AccessibilityStatus.UNKNOWN
    
    def _calculate_effectiveness_score(self, accessibility_results: List[AccessibilityResult],
                                     baseline_result: Dict[str, Any]) -> float:
        """Calculate strategy effectiveness score."""
        if not accessibility_results:
            return 0.0
        
        # Calculate average bypass effectiveness
        bypass_scores = [r.bypass_effectiveness for r in accessibility_results]
        avg_bypass_effectiveness = statistics.mean(bypass_scores)
        
        # Compare with baseline
        baseline_success_rate = (baseline_result.get('successful_tests', 0) / 
                               max(baseline_result.get('total_tests', 1), 1))
        
        # Calculate improvement over baseline
        improvement_factor = avg_bypass_effectiveness / max(baseline_success_rate, 0.1)
        
        # Normalize improvement factor to 0-1 scale
        normalized_improvement = min(improvement_factor / 2.0, 1.0)  # Cap at 2x improvement
        
        # Weight by consistency
        reliability_scores = [r.reliability_score for r in accessibility_results]
        avg_reliability = statistics.mean(reliability_scores)
        
        # Final effectiveness score
        effectiveness_score = (avg_bypass_effectiveness * 0.6 + 
                             normalized_improvement * 0.2 + 
                             avg_reliability * 0.2)
        
        return min(effectiveness_score, 1.0)
    
    def _detect_false_positives(self, accessibility_results: List[AccessibilityResult],
                              baseline_result: Dict[str, Any]) -> float:
        """Detect and calculate false positive rate."""
        if not accessibility_results:
            return 1.0
        
        false_positive_indicators = 0
        total_indicators = 0
        
        for result in accessibility_results:
            # Check for false positive indicators
            total_indicators += 1
            
            # High variance in response times
            if len(result.validation_results) > 1:
                response_times = [r.response_time for r in result.validation_results 
                                if r.success and r.response_time > 0]
                if len(response_times) > 1:
                    time_variance = statistics.stdev(response_times)
                    avg_time = statistics.mean(response_times)
                    
                    if time_variance > avg_time * self.false_positive_thresholds['response_time_variance']:
                        false_positive_indicators += 1
            
            # Inconsistent results across validation methods
            if result.false_positive_detected:
                false_positive_indicators += 1
            
            # Suspiciously high success rate compared to baseline
            baseline_success_rate = (baseline_result.get('successful_tests', 0) / 
                                   max(baseline_result.get('total_tests', 1), 1))
            
            if (result.bypass_effectiveness > baseline_success_rate + 0.5 and 
                baseline_success_rate < 0.3):  # Dramatic improvement from very low baseline
                false_positive_indicators += 0.5  # Partial indicator
        
        return false_positive_indicators / max(total_indicators, 1)
    
    def _calculate_consistency_score(self, accessibility_results: List[AccessibilityResult]) -> float:
        """Calculate consistency score across multiple test iterations."""
        if len(accessibility_results) < 2:
            return 1.0  # Single result is perfectly consistent
        
        # Check consistency of bypass effectiveness
        bypass_scores = [r.bypass_effectiveness for r in accessibility_results]
        bypass_variance = statistics.stdev(bypass_scores) if len(bypass_scores) > 1 else 0.0
        bypass_consistency = 1.0 - min(bypass_variance, 1.0)
        
        # Check consistency of reliability scores
        reliability_scores = [r.reliability_score for r in accessibility_results]
        reliability_variance = statistics.stdev(reliability_scores) if len(reliability_scores) > 1 else 0.0
        reliability_consistency = 1.0 - min(reliability_variance, 1.0)
        
        # Check consistency of accessibility status
        status_values = [r.status.value for r in accessibility_results]
        unique_statuses = set(status_values)
        status_consistency = 1.0 - (len(unique_statuses) - 1) / len(status_values)
        
        # Weighted average
        consistency_score = (bypass_consistency * 0.4 + 
                           reliability_consistency * 0.3 + 
                           status_consistency * 0.3)
        
        return consistency_score
    
    def _calculate_performance_score(self, accessibility_results: List[AccessibilityResult]) -> float:
        """Calculate performance score based on response times and efficiency."""
        if not accessibility_results:
            return 0.0
        
        # Collect all response times
        all_response_times = []
        for result in accessibility_results:
            if result.average_response_time > 0:
                all_response_times.append(result.average_response_time)
        
        if not all_response_times:
            return 0.0
        
        avg_response_time = statistics.mean(all_response_times)
        
        # Calculate performance score (inverse of response time, normalized)
        max_acceptable_time = self.performance_baselines['max_response_time']
        
        if avg_response_time <= 1.0:  # Excellent performance
            performance_score = 1.0
        elif avg_response_time <= max_acceptable_time:  # Acceptable performance
            performance_score = 1.0 - (avg_response_time - 1.0) / (max_acceptable_time - 1.0) * 0.5
        else:  # Poor performance
            performance_score = 0.5 * (max_acceptable_time / avg_response_time)
        
        return min(performance_score, 1.0)
    
    def _determine_reliability_level(self, effectiveness_score: float, 
                                   consistency_score: float, 
                                   false_positive_rate: float) -> ReliabilityLevel:
        """Determine overall reliability level."""
        # Calculate composite reliability score
        composite_score = (effectiveness_score * 0.5 + 
                          consistency_score * 0.3 + 
                          (1.0 - false_positive_rate) * 0.2)
        
        if composite_score >= 0.95:
            return ReliabilityLevel.EXCELLENT
        elif composite_score >= 0.85:
            return ReliabilityLevel.VERY_GOOD
        elif composite_score >= 0.70:
            return ReliabilityLevel.GOOD
        elif composite_score >= 0.50:
            return ReliabilityLevel.MODERATE
        elif composite_score >= 0.30:
            return ReliabilityLevel.POOR
        else:
            return ReliabilityLevel.UNRELIABLE
    
    def _generate_strategy_recommendation(self, effectiveness_score: float,
                                        reliability_level: ReliabilityLevel,
                                        false_positive_rate: float,
                                        consistency_score: float,
                                        performance_score: float) -> str:
        """Generate recommendation for strategy usage."""
        if reliability_level in [ReliabilityLevel.EXCELLENT, ReliabilityLevel.VERY_GOOD]:
            if performance_score >= 0.8:
                return "Highly recommended - excellent reliability and performance"
            else:
                return "Recommended - excellent reliability but consider performance optimization"
        
        elif reliability_level == ReliabilityLevel.GOOD:
            if false_positive_rate < 0.1:
                return "Recommended with monitoring - good reliability, low false positive rate"
            else:
                return "Use with caution - good reliability but elevated false positive rate"
        
        elif reliability_level == ReliabilityLevel.MODERATE:
            if consistency_score >= 0.7:
                return "Limited use recommended - moderate reliability but consistent results"
            else:
                return "Use with extensive testing - moderate and inconsistent reliability"
        
        elif reliability_level == ReliabilityLevel.POOR:
            return "Not recommended - poor reliability, consider alternative strategies"
        
        else:  # UNRELIABLE
            return "Avoid - unreliable results, strategy may be ineffective or harmful"
    
    async def batch_validate_strategies(self, 
                                      strategy_domain_pairs: List[Tuple[str, str, int]],
                                      test_iterations: int = 3) -> List[StrategyEffectivenessResult]:
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
                self.logger.error(f"Validation failed for {strategy_id} on {domain}:{port}: {result}")
            else:
                valid_results.append(result)
        
        return valid_results
    
    def generate_reliability_report(self, results: List[StrategyEffectivenessResult]) -> Dict[str, Any]:
        """Generate comprehensive reliability report."""
        if not results:
            return {'error': 'No results to analyze'}
        
        # Overall statistics
        effectiveness_scores = [r.effectiveness_score for r in results]
        consistency_scores = [r.consistency_score for r in results]
        performance_scores = [r.performance_score for r in results]
        false_positive_rates = [r.false_positive_rate for r in results]
        
        # Reliability level distribution
        reliability_distribution = {}
        for level in ReliabilityLevel:
            reliability_distribution[level.value] = sum(
                1 for r in results if r.reliability_level == level
            )
        
        # Strategy performance ranking
        strategy_ranking = sorted(results, key=lambda r: r.effectiveness_score, reverse=True)
        
        # Domain analysis
        domain_analysis = {}
        for result in results:
            if result.domain not in domain_analysis:
                domain_analysis[result.domain] = {
                    'strategies_tested': 0,
                    'avg_effectiveness': 0.0,
                    'best_strategy': None,
                    'reliability_levels': []
                }
            
            domain_data = domain_analysis[result.domain]
            domain_data['strategies_tested'] += 1
            domain_data['reliability_levels'].append(result.reliability_level.value)
            
            if (domain_data['best_strategy'] is None or 
                result.effectiveness_score > domain_data['avg_effectiveness']):
                domain_data['best_strategy'] = result.strategy_id
                domain_data['avg_effectiveness'] = result.effectiveness_score
        
        # Generate recommendations
        recommendations = []
        
        # Overall performance recommendations
        avg_effectiveness = statistics.mean(effectiveness_scores)
        if avg_effectiveness < 0.5:
            recommendations.append("Overall strategy effectiveness is low - consider strategy optimization")
        
        # False positive recommendations
        avg_false_positive_rate = statistics.mean(false_positive_rates)
        if avg_false_positive_rate > 0.2:
            recommendations.append("High false positive rate detected - implement additional validation")
        
        # Consistency recommendations
        avg_consistency = statistics.mean(consistency_scores)
        if avg_consistency < 0.7:
            recommendations.append("Low consistency detected - strategies may be unstable")
        
        # Performance recommendations
        avg_performance = statistics.mean(performance_scores)
        if avg_performance < 0.6:
            recommendations.append("Performance optimization needed - response times are high")
        
        return {
            'summary': {
                'total_strategies_tested': len(results),
                'avg_effectiveness_score': avg_effectiveness,
                'avg_consistency_score': avg_consistency,
                'avg_performance_score': avg_performance,
                'avg_false_positive_rate': avg_false_positive_rate
            },
            'reliability_distribution': reliability_distribution,
            'strategy_ranking': [
                {
                    'strategy_id': r.strategy_id,
                    'domain': r.domain,
                    'effectiveness_score': r.effectiveness_score,
                    'reliability_level': r.reliability_level.value,
                    'recommendation': r.recommendation
                }
                for r in strategy_ranking[:10]  # Top 10
            ],
            'domain_analysis': domain_analysis,
            'recommendations': recommendations,
            'detailed_results': results,
            'report_timestamp': time.time()
        }
    
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


async def validate_strategy_reliability(strategy_id: str, domain: str, 
                                      port: int = 443, 
                                      iterations: int = 5) -> StrategyEffectivenessResult:
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
    return await validator.validate_strategy_effectiveness(
        strategy_id, domain, port, iterations
    )