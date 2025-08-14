# recon/core/fingerprint/http_analyzer.py
"""
HTTP Behavior Analyzer - Task 5 Implementation
Implements HTTP-specific DPI behavior analysis including header filtering detection,
content inspection depth analysis, user agent filtering, host header manipulation,
redirect injection detection, and response modification analysis.

Requirements: 2.2, 4.1, 4.2
"""

import asyncio
import aiohttp
import time
import random
import logging
import ssl
import json
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum
from urllib.parse import urlparse, urljoin

from .advanced_models import FingerprintingError, NetworkAnalysisError

LOG = logging.getLogger(__name__)


class HTTPBlockingMethod(Enum):
    """Enumeration for HTTP blocking methods"""
    NONE = "none"
    CONNECTION_RESET = "connection_reset"
    TIMEOUT = "timeout"
    REDIRECT = "redirect"
    CONTENT_MODIFICATION = "content_modification"
    HEADER_FILTERING = "header_filtering"
    STATUS_CODE_INJECTION = "status_code_injection"


@dataclass
class HTTPRequest:
    """Data structure for tracking HTTP requests"""
    timestamp: float
    url: str
    method: str
    headers: Dict[str, str] = field(default_factory=dict)
    user_agent: str = ""
    host_header: str = ""
    content_type: str = ""
    body: Optional[str] = None
    success: bool = False
    status_code: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: Optional[str] = None
    response_time_ms: float = 0.0
    blocking_method: HTTPBlockingMethod = HTTPBlockingMethod.NONE
    error_message: Optional[str] = None
    redirect_url: Optional[str] = None
    content_modified: bool = False


@dataclass
class HTTPAnalysisResult:
    """Result container for HTTP behavior analysis"""
    target: str
    timestamp: float = field(default_factory=time.time)
    
    # Header filtering analysis
    http_header_filtering: bool = False
    filtered_headers: List[str] = field(default_factory=list)
    header_case_sensitivity: bool = False
    custom_header_blocking: bool = False
    
    # Content inspection analysis
    content_inspection_depth: int = 0
    content_based_blocking: bool = False
    keyword_filtering: List[str] = field(default_factory=list)
    content_modification_detected: bool = False
    
    # User agent analysis
    user_agent_filtering: bool = False
    blocked_user_agents: List[str] = field(default_factory=list)
    user_agent_whitelist_detected: bool = False
    
    # Host header analysis
    host_header_manipulation: bool = False
    host_header_validation: bool = False
    sni_host_mismatch_blocking: bool = False
    
    # HTTP method restrictions
    http_method_restrictions: List[str] = field(default_factory=list)
    allowed_methods: List[str] = field(default_factory=list)
    method_based_blocking: bool = False
    
    # Content type filtering
    content_type_filtering: bool = False
    blocked_content_types: List[str] = field(default_factory=list)
    content_type_validation: bool = False
    
    # Redirect injection
    redirect_injection: bool = False
    redirect_patterns: List[str] = field(default_factory=list)
    redirect_status_codes: List[int] = field(default_factory=list)
    
    # Response modification
    http_response_modification: bool = False
    response_modification_patterns: List[str] = field(default_factory=list)
    injected_content: List[str] = field(default_factory=list)
    
    # Connection behavior
    keep_alive_manipulation: bool = False
    connection_header_filtering: bool = False
    persistent_connection_blocking: bool = False
    
    # Encoding handling
    chunked_encoding_handling: str = "unknown"  # 'supported', 'blocked', 'modified'
    compression_handling: str = "unknown"  # 'supported', 'blocked', 'modified'
    transfer_encoding_filtering: bool = False
    
    # Analysis metadata
    http_requests: List[HTTPRequest] = field(default_factory=list)
    analysis_errors: List[str] = field(default_factory=list)
    reliability_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert analysis result to dictionary"""
        return {
            'target': self.target,
            'timestamp': self.timestamp,
            'http_header_filtering': self.http_header_filtering,
            'filtered_headers': self.filtered_headers,
            'header_case_sensitivity': self.header_case_sensitivity,
            'custom_header_blocking': self.custom_header_blocking,
            'content_inspection_depth': self.content_inspection_depth,
            'content_based_blocking': self.content_based_blocking,
            'keyword_filtering': self.keyword_filtering,
            'content_modification_detected': self.content_modification_detected,
            'user_agent_filtering': self.user_agent_filtering,
            'blocked_user_agents': self.blocked_user_agents,
            'user_agent_whitelist_detected': self.user_agent_whitelist_detected,
            'host_header_manipulation': self.host_header_manipulation,
            'host_header_validation': self.host_header_validation,
            'sni_host_mismatch_blocking': self.sni_host_mismatch_blocking,
            'http_method_restrictions': self.http_method_restrictions,
            'allowed_methods': self.allowed_methods,
            'method_based_blocking': self.method_based_blocking,
            'content_type_filtering': self.content_type_filtering,
            'blocked_content_types': self.blocked_content_types,
            'content_type_validation': self.content_type_validation,
            'redirect_injection': self.redirect_injection,
            'redirect_patterns': self.redirect_patterns,
            'redirect_status_codes': self.redirect_status_codes,
            'http_response_modification': self.http_response_modification,
            'response_modification_patterns': self.response_modification_patterns,
            'injected_content': self.injected_content,
            'keep_alive_manipulation': self.keep_alive_manipulation,
            'connection_header_filtering': self.connection_header_filtering,
            'persistent_connection_blocking': self.persistent_connection_blocking,
            'chunked_encoding_handling': self.chunked_encoding_handling,
            'compression_handling': self.compression_handling,
            'transfer_encoding_filtering': self.transfer_encoding_filtering,
            'reliability_score': self.reliability_score,
            'analysis_errors': self.analysis_errors
        }


class HTTPAnalyzer:
    """
    HTTP-specific DPI behavior analyzer.
    Analyzes HTTP-level DPI behavior including header filtering, content inspection,
    user agent filtering, host header manipulation, redirect injection, and response modification.
    """
    
    def __init__(self, timeout: float = 10.0, max_attempts: int = 10):
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.logger = logging.getLogger(__name__)
        
        # Test data for analysis
        self.test_user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "curl/7.68.0",
            "python-requests/2.25.1",
            "Wget/1.20.3",
            "HTTPie/2.4.0",
            "PostmanRuntime/7.28.0",
            "Custom-Bot/1.0",
            "Suspicious-Agent/1.0"
        ]
        
        self.test_headers = [
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Real-IP", "192.168.1.1"),
            ("X-Custom-Header", "test-value"),
            ("Authorization", "Bearer test-token"),
            ("Cookie", "session=test123"),
            ("Referer", "https://blocked-site.com"),
            ("Origin", "https://suspicious-domain.com"),
            ("X-Requested-With", "XMLHttpRequest")
        ]
        
        self.test_content_keywords = [
            "vpn", "proxy", "tor", "censorship", "freedom",
            "blocked", "restricted", "forbidden", "政治", "民主"
        ]
        
        self.test_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE"]
        
        self.test_content_types = [
            "text/html",
            "application/json",
            "application/xml",
            "text/plain",
            "application/octet-stream",
            "multipart/form-data",
            "application/x-www-form-urlencoded"
        ]
    
    async def analyze_http_behavior(self, target: str, port: int = 443) -> Dict[str, Any]:
        """
        Main method to analyze HTTP-specific DPI behavior.
        
        Args:
            target: Target hostname or domain
            port: Target port number (80 for HTTP, 443 for HTTPS)
            
        Returns:
            Dictionary containing HTTP analysis results
        """
        self.logger.info(f"Starting HTTP behavior analysis for {target}:{port}")
        
        result = HTTPAnalysisResult(target=target)
        
        try:
            # Determine protocol
            protocol = "https" if port == 443 else "http"
            base_url = f"{protocol}://{target}:{port}" if port not in [80, 443] else f"{protocol}://{target}"
            
            # Phase 1: Basic connectivity test
            await self._test_basic_connectivity(result, base_url)
            
            # Phase 2: Header filtering analysis
            await self._analyze_header_filtering(result, base_url)
            
            # Phase 3: User agent filtering analysis
            await self._analyze_user_agent_filtering(result, base_url)
            
            # Phase 4: Host header manipulation analysis
            await self._analyze_host_header_manipulation(result, base_url, target)
            
            # Phase 5: HTTP method restrictions analysis
            await self._analyze_http_method_restrictions(result, base_url)
            
            # Phase 6: Content type filtering analysis
            await self._analyze_content_type_filtering(result, base_url)
            
            # Phase 7: Content inspection depth analysis
            await self._analyze_content_inspection(result, base_url)
            
            # Phase 8: Redirect injection analysis
            await self._analyze_redirect_injection(result, base_url)
            
            # Phase 9: Response modification analysis
            await self._analyze_response_modification(result, base_url)
            
            # Phase 10: Connection behavior analysis
            await self._analyze_connection_behavior(result, base_url)
            
            # Phase 11: Encoding handling analysis
            await self._analyze_encoding_handling(result, base_url)
            
            # Calculate overall reliability score
            result.reliability_score = self._calculate_reliability_score(result)
            
            self.logger.info(f"HTTP analysis complete for {target}:{port} (reliability: {result.reliability_score:.2f})")
            
        except Exception as e:
            error_msg = f"HTTP analysis failed for {target}:{port}: {e}"
            self.logger.error(error_msg)
            result.analysis_errors.append(error_msg)
            raise NetworkAnalysisError(error_msg) from e
        
        return result.to_dict()
    
    async def _test_basic_connectivity(self, result: HTTPAnalysisResult, base_url: str):
        """Test basic HTTP connectivity"""
        self.logger.debug("Testing basic HTTP connectivity")
        
        request = HTTPRequest(
            timestamp=time.time(),
            url=base_url,
            method="GET",
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        )
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                start_time = time.perf_counter()
                
                async with session.get(base_url, headers=request.headers) as response:
                    request.response_time_ms = (time.perf_counter() - start_time) * 1000
                    request.status_code = response.status
                    request.response_headers = dict(response.headers)
                    request.response_body = await response.text()
                    request.success = True
                    
        except asyncio.TimeoutError:
            request.blocking_method = HTTPBlockingMethod.TIMEOUT
            request.error_message = "Request timeout"
            
        except aiohttp.ClientConnectorError as e:
            if "Connection reset" in str(e):
                request.blocking_method = HTTPBlockingMethod.CONNECTION_RESET
            request.error_message = str(e)
            
        except Exception as e:
            request.error_message = str(e)
        
        result.http_requests.append(request)
    
    async def _analyze_header_filtering(self, result: HTTPAnalysisResult, base_url: str):
        """Analyze HTTP header filtering behavior"""
        self.logger.debug("Analyzing HTTP header filtering")
        
        # Test standard headers first
        baseline_request = await self._make_request(base_url, "GET", {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        
        if not baseline_request.success:
            self.logger.warning("Baseline request failed, skipping header filtering analysis")
            return
        
        # Test each suspicious header
        for header_name, header_value in self.test_headers:
            test_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                header_name: header_value
            }
            
            request = await self._make_request(base_url, "GET", test_headers)
            result.http_requests.append(request)
            
            # Compare with baseline
            if baseline_request.success and not request.success:
                result.http_header_filtering = True
                result.filtered_headers.append(header_name)
                self.logger.info(f"Header filtering detected for: {header_name}")
            
            # Check for different response when header is present
            elif (baseline_request.success and request.success and 
                  request.status_code != baseline_request.status_code):
                result.http_header_filtering = True
                result.filtered_headers.append(header_name)
                self.logger.info(f"Header-based response modification detected for: {header_name}")
            
            await asyncio.sleep(0.1)  # Rate limiting
        
        # Test header case sensitivity
        await self._test_header_case_sensitivity(result, base_url)
        
        # Test custom headers
        await self._test_custom_header_blocking(result, base_url)
    
    async def _test_header_case_sensitivity(self, result: HTTPAnalysisResult, base_url: str):
        """Test if DPI is case-sensitive with headers"""
        test_cases = [
            ("user-agent", "test-agent"),
            ("USER-AGENT", "test-agent"),
            ("User-Agent", "test-agent"),
            ("uSeR-aGeNt", "test-agent")
        ]
        
        responses = []
        for header_name, header_value in test_cases:
            request = await self._make_request(base_url, "GET", {header_name: header_value})
            responses.append(request.success)
            result.http_requests.append(request)
            await asyncio.sleep(0.1)
        
        # If responses differ, case sensitivity is detected
        if len(set(responses)) > 1:
            result.header_case_sensitivity = True
            self.logger.info("Header case sensitivity detected")
    
    async def _test_custom_header_blocking(self, result: HTTPAnalysisResult, base_url: str):
        """Test blocking of custom/unusual headers"""
        custom_headers = [
            ("X-Bypass-DPI", "true"),
            ("X-Tunnel-Protocol", "http"),
            ("X-Proxy-Connection", "keep-alive"),
            ("X-Censorship-Bypass", "enabled")
        ]
        
        baseline_request = await self._make_request(base_url, "GET", {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        
        blocked_count = 0
        for header_name, header_value in custom_headers:
            test_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                header_name: header_value
            }
            
            request = await self._make_request(base_url, "GET", test_headers)
            result.http_requests.append(request)
            
            if baseline_request.success and not request.success:
                blocked_count += 1
                result.filtered_headers.append(header_name)
            
            await asyncio.sleep(0.1)
        
        if blocked_count > 0:
            result.custom_header_blocking = True
            self.logger.info(f"Custom header blocking detected ({blocked_count} headers blocked)")
    
    async def _analyze_user_agent_filtering(self, result: HTTPAnalysisResult, base_url: str):
        """Analyze user agent filtering behavior"""
        self.logger.debug("Analyzing user agent filtering")
        
        successful_agents = []
        blocked_agents = []
        
        for user_agent in self.test_user_agents:
            request = await self._make_request(base_url, "GET", {"User-Agent": user_agent})
            result.http_requests.append(request)
            
            if request.success:
                successful_agents.append(user_agent)
            else:
                blocked_agents.append(user_agent)
                self.logger.info(f"User agent blocked: {user_agent}")
            
            await asyncio.sleep(0.1)
        
        # Analyze results
        if blocked_agents:
            result.user_agent_filtering = True
            result.blocked_user_agents = blocked_agents
            
            # Check if it's a whitelist (more blocked than allowed)
            if len(blocked_agents) > len(successful_agents):
                result.user_agent_whitelist_detected = True
                self.logger.info("User agent whitelist detected")
        
        # Test empty user agent
        empty_ua_request = await self._make_request(base_url, "GET", {})
        result.http_requests.append(empty_ua_request)
        
        if not empty_ua_request.success:
            result.user_agent_filtering = True
            self.logger.info("Empty user agent blocked")
    
    async def _analyze_host_header_manipulation(self, result: HTTPAnalysisResult, base_url: str, target: str):
        """Analyze host header manipulation and validation"""
        self.logger.debug("Analyzing host header manipulation")
        
        # Test with correct host header
        correct_request = await self._make_request(base_url, "GET", {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Host": target
        })
        result.http_requests.append(correct_request)
        
        # Test with different host headers
        test_hosts = [
            "blocked-site.com",
            "suspicious-domain.org",
            "127.0.0.1",
            "localhost",
            "example.com",
            ""  # Empty host
        ]
        
        for test_host in test_hosts:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            
            if test_host:  # Don't add empty host header
                headers["Host"] = test_host
            
            request = await self._make_request(base_url, "GET", headers)
            result.http_requests.append(request)
            
            # Compare with correct host request
            if correct_request.success and not request.success:
                result.host_header_manipulation = True
                result.host_header_validation = True
                self.logger.info(f"Host header validation detected for: {test_host}")
            
            await asyncio.sleep(0.1)
        
        # Test SNI-Host mismatch (for HTTPS)
        if base_url.startswith("https://"):
            await self._test_sni_host_mismatch(result, base_url, target)
    
    async def _test_sni_host_mismatch(self, result: HTTPAnalysisResult, base_url: str, target: str):
        """Test SNI-Host header mismatch detection"""
        try:
            # This is a simplified test - full SNI testing would require lower-level SSL control
            # We test by using a different host header with HTTPS
            mismatch_request = await self._make_request(base_url, "GET", {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Host": "different-domain.com"
            })
            result.http_requests.append(mismatch_request)
            
            if not mismatch_request.success:
                result.sni_host_mismatch_blocking = True
                self.logger.info("SNI-Host mismatch blocking detected")
                
        except Exception as e:
            self.logger.debug(f"SNI-Host mismatch test failed: {e}")
    
    async def _analyze_http_method_restrictions(self, result: HTTPAnalysisResult, base_url: str):
        """Analyze HTTP method restrictions"""
        self.logger.debug("Analyzing HTTP method restrictions")
        
        method_results = {}
        
        for method in self.test_methods:
            request = await self._make_request(base_url, method, {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            })
            result.http_requests.append(request)
            
            method_results[method] = request.success
            
            if not request.success:
                result.http_method_restrictions.append(method)
                self.logger.info(f"HTTP method blocked: {method}")
            else:
                result.allowed_methods.append(method)
            
            await asyncio.sleep(0.1)
        
        # Analyze patterns
        blocked_methods = [m for m, success in method_results.items() if not success]
        if blocked_methods:
            result.method_based_blocking = True
            
            # Check for common patterns
            if "TRACE" in blocked_methods:
                self.logger.info("TRACE method blocked (common security practice)")
            if "DELETE" in blocked_methods and "PUT" in blocked_methods:
                self.logger.info("Destructive methods blocked")
    
    async def _analyze_content_type_filtering(self, result: HTTPAnalysisResult, base_url: str):
        """Analyze content type filtering"""
        self.logger.debug("Analyzing content type filtering")
        
        for content_type in self.test_content_types:
            # Test with POST request and specific content type
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Content-Type": content_type
            }
            
            request = await self._make_request(base_url, "POST", headers, data="test data")
            result.http_requests.append(request)
            
            if not request.success:
                result.content_type_filtering = True
                result.blocked_content_types.append(content_type)
                self.logger.info(f"Content type blocked: {content_type}")
            
            await asyncio.sleep(0.1)
        
        # Test content type validation
        await self._test_content_type_validation(result, base_url)
    
    async def _test_content_type_validation(self, result: HTTPAnalysisResult, base_url: str):
        """Test content type validation"""
        # Send JSON data with wrong content type
        mismatch_request = await self._make_request(
            base_url, "POST",
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Content-Type": "text/plain"
            },
            data='{"key": "value"}'  # JSON data with text/plain content type
        )
        result.http_requests.append(mismatch_request)
        
        # Send correct content type
        correct_request = await self._make_request(
            base_url, "POST",
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Content-Type": "application/json"
            },
            data='{"key": "value"}'
        )
        result.http_requests.append(correct_request)
        
        # If mismatch fails but correct succeeds, validation is detected
        if not mismatch_request.success and correct_request.success:
            result.content_type_validation = True
            self.logger.info("Content type validation detected")
    
    async def _analyze_content_inspection(self, result: HTTPAnalysisResult, base_url: str):
        """Analyze content inspection depth and keyword filtering"""
        self.logger.debug("Analyzing content inspection depth")
        
        # Test different content lengths to determine inspection depth
        content_lengths = [100, 500, 1000, 2000, 5000, 10000]
        inspection_depth = 0
        
        for length in content_lengths:
            # Create content with keyword at the end
            content = "A" * (length - 10) + "forbidden"
            
            request = await self._make_request(
                base_url, "POST",
                {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Content-Type": "text/plain"
                },
                data=content
            )
            result.http_requests.append(request)
            
            if not request.success:
                inspection_depth = length
                result.content_based_blocking = True
                self.logger.info(f"Content inspection detected at depth: {length}")
                break
            
            await asyncio.sleep(0.1)
        
        result.content_inspection_depth = inspection_depth
        
        # Test keyword filtering
        await self._test_keyword_filtering(result, base_url)
    
    async def _test_keyword_filtering(self, result: HTTPAnalysisResult, base_url: str):
        """Test keyword-based content filtering"""
        blocked_keywords = []
        
        for keyword in self.test_content_keywords:
            # Test keyword in different positions
            test_contents = [
                keyword,  # Just the keyword
                f"This content contains {keyword} word",  # Keyword in middle
                f"{keyword} at the beginning",  # Keyword at start
                f"At the end {keyword}"  # Keyword at end
            ]
            
            for content in test_contents:
                request = await self._make_request(
                    base_url, "POST",
                    {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        "Content-Type": "text/plain"
                    },
                    data=content
                )
                result.http_requests.append(request)
                
                if not request.success:
                    if keyword not in blocked_keywords:
                        blocked_keywords.append(keyword)
                    result.content_based_blocking = True
                    self.logger.info(f"Keyword filtering detected: {keyword}")
                    break  # No need to test other positions for this keyword
                
                await asyncio.sleep(0.05)
        
        result.keyword_filtering = blocked_keywords
    
    async def _analyze_redirect_injection(self, result: HTTPAnalysisResult, base_url: str):
        """Analyze redirect injection patterns"""
        self.logger.debug("Analyzing redirect injection")
        
        # Test requests that might trigger redirects
        test_paths = [
            "/",
            "/blocked",
            "/forbidden",
            "/admin",
            "/proxy",
            "/vpn"
        ]
        
        for path in test_paths:
            test_url = urljoin(base_url, path)
            
            request = await self._make_request(test_url, "GET", {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }, allow_redirects=False)
            result.http_requests.append(request)
            
            # Check for redirect responses
            if request.status_code in [301, 302, 303, 307, 308]:
                result.redirect_injection = True
                result.redirect_status_codes.append(request.status_code)
                
                # Get redirect location
                if 'location' in request.response_headers:
                    redirect_url = request.response_headers['location']
                    result.redirect_patterns.append(redirect_url)
                    request.redirect_url = redirect_url
                    
                    # Check for suspicious redirect patterns
                    suspicious_patterns = [
                        'block', 'forbidden', 'restricted', 'warning',
                        'government', 'censorship', 'unavailable'
                    ]
                    
                    if any(pattern in redirect_url.lower() for pattern in suspicious_patterns):
                        self.logger.info(f"Suspicious redirect detected: {redirect_url}")
            
            await asyncio.sleep(0.1)
    
    async def _analyze_response_modification(self, result: HTTPAnalysisResult, base_url: str):
        """Analyze response modification and content injection"""
        self.logger.debug("Analyzing response modification")
        
        # Make multiple requests to detect response modifications
        baseline_responses = []
        
        for i in range(3):
            request = await self._make_request(base_url, "GET", {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            })
            
            if request.success and request.response_body:
                baseline_responses.append(request.response_body)
            
            result.http_requests.append(request)
            await asyncio.sleep(0.2)
        
        # Check for response consistency
        if len(set(baseline_responses)) > 1:
            result.http_response_modification = True
            self.logger.info("Response modification detected (inconsistent responses)")
        
        # Check for common injection patterns
        if baseline_responses:
            response_text = baseline_responses[0].lower()
            
            injection_patterns = [
                'blocked', 'forbidden', 'restricted', 'access denied',
                'this site is blocked', 'content filtered',
                'government warning', 'censorship notice'
            ]
            
            for pattern in injection_patterns:
                if pattern in response_text:
                    result.http_response_modification = True
                    result.injected_content.append(pattern)
                    result.response_modification_patterns.append(pattern)
                    self.logger.info(f"Content injection detected: {pattern}")
        
        # Test for header injection
        await self._test_header_injection(result, base_url)
    
    async def _test_header_injection(self, result: HTTPAnalysisResult, base_url: str):
        """Test for response header injection"""
        request = await self._make_request(base_url, "GET", {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        result.http_requests.append(request)
        
        if request.success and request.response_headers:
            # Check for suspicious headers that might indicate injection
            suspicious_headers = [
                'x-blocked-by', 'x-filtered-by', 'x-censorship',
                'x-government-warning', 'x-content-filter'
            ]
            
            for header in suspicious_headers:
                if header in [h.lower() for h in request.response_headers.keys()]:
                    result.http_response_modification = True
                    result.response_modification_patterns.append(f"header:{header}")
                    self.logger.info(f"Response header injection detected: {header}")
    
    async def _analyze_connection_behavior(self, result: HTTPAnalysisResult, base_url: str):
        """Analyze connection behavior and keep-alive handling"""
        self.logger.debug("Analyzing connection behavior")
        
        # Test keep-alive connections
        keep_alive_request = await self._make_request(base_url, "GET", {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Connection": "keep-alive"
        })
        result.http_requests.append(keep_alive_request)
        
        # Test connection close
        close_request = await self._make_request(base_url, "GET", {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Connection": "close"
        })
        result.http_requests.append(close_request)
        
        # Compare results
        if keep_alive_request.success != close_request.success:
            result.keep_alive_manipulation = True
            result.connection_header_filtering = True
            self.logger.info("Connection header manipulation detected")
        
        # Test persistent connections
        await self._test_persistent_connections(result, base_url)
    
    async def _test_persistent_connections(self, result: HTTPAnalysisResult, base_url: str):
        """Test persistent connection handling"""
        try:
            # Make multiple requests with the same session
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                connector=aiohttp.TCPConnector(limit=1, limit_per_host=1)
            ) as session:
                
                success_count = 0
                for i in range(3):
                    try:
                        async with session.get(base_url, headers={
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                        }) as response:
                            if response.status == 200:
                                success_count += 1
                    except Exception:
                        pass
                    
                    await asyncio.sleep(0.1)
                
                # If not all requests succeed, persistent connections might be blocked
                if success_count < 3:
                    result.persistent_connection_blocking = True
                    self.logger.info("Persistent connection blocking detected")
                    
        except Exception as e:
            self.logger.debug(f"Persistent connection test failed: {e}")
    
    async def _analyze_encoding_handling(self, result: HTTPAnalysisResult, base_url: str):
        """Analyze encoding and transfer handling"""
        self.logger.debug("Analyzing encoding handling")
        
        # Test chunked encoding
        await self._test_chunked_encoding(result, base_url)
        
        # Test compression handling
        await self._test_compression_handling(result, base_url)
        
        # Test transfer encoding
        await self._test_transfer_encoding(result, base_url)
    
    async def _test_chunked_encoding(self, result: HTTPAnalysisResult, base_url: str):
        """Test chunked transfer encoding handling"""
        # Test with chunked encoding request
        chunked_request = await self._make_request(base_url, "POST", {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Transfer-Encoding": "chunked",
            "Content-Type": "text/plain"
        }, data="test data")
        result.http_requests.append(chunked_request)
        
        # Test without chunked encoding
        normal_request = await self._make_request(base_url, "POST", {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Content-Type": "text/plain"
        }, data="test data")
        result.http_requests.append(normal_request)
        
        # Compare results
        if normal_request.success and not chunked_request.success:
            result.chunked_encoding_handling = "blocked"
            result.transfer_encoding_filtering = True
            self.logger.info("Chunked encoding blocked")
        elif chunked_request.success:
            result.chunked_encoding_handling = "supported"
        else:
            result.chunked_encoding_handling = "unknown"
    
    async def _test_compression_handling(self, result: HTTPAnalysisResult, base_url: str):
        """Test compression handling"""
        # Test with compression
        compressed_request = await self._make_request(base_url, "GET", {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept-Encoding": "gzip, deflate, br"
        })
        result.http_requests.append(compressed_request)
        
        # Test without compression
        uncompressed_request = await self._make_request(base_url, "GET", {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept-Encoding": "identity"
        })
        result.http_requests.append(uncompressed_request)
        
        # Analyze compression support
        if compressed_request.success and uncompressed_request.success:
            # Check if response was actually compressed
            if ('content-encoding' in compressed_request.response_headers and
                'content-encoding' not in uncompressed_request.response_headers):
                result.compression_handling = "supported"
            else:
                result.compression_handling = "modified"  # Compression headers stripped
        elif uncompressed_request.success and not compressed_request.success:
            result.compression_handling = "blocked"
            self.logger.info("Compression blocked")
        else:
            result.compression_handling = "unknown"
    
    async def _test_transfer_encoding(self, result: HTTPAnalysisResult, base_url: str):
        """Test transfer encoding filtering"""
        # Test various transfer encodings
        encodings = ["chunked", "compress", "deflate", "gzip"]
        
        for encoding in encodings:
            request = await self._make_request(base_url, "POST", {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Transfer-Encoding": encoding,
                "Content-Type": "text/plain"
            }, data="test data")
            result.http_requests.append(request)
            
            if not request.success:
                result.transfer_encoding_filtering = True
                self.logger.info(f"Transfer encoding blocked: {encoding}")
            
            await asyncio.sleep(0.1)
    
    async def _make_request(self, url: str, method: str, headers: Dict[str, str], 
                          data: Optional[str] = None, allow_redirects: bool = True) -> HTTPRequest:
        """Make HTTP request and return HTTPRequest object"""
        request = HTTPRequest(
            timestamp=time.time(),
            url=url,
            method=method,
            headers=headers.copy(),
            user_agent=headers.get("User-Agent", ""),
            host_header=headers.get("Host", ""),
            content_type=headers.get("Content-Type", ""),
            body=data
        )
        
        try:
            # Create SSL context that doesn't verify certificates for testing
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            connector = aiohttp.TCPConnector(ssl=ssl_context)
            
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                connector=connector
            ) as session:
                
                start_time = time.perf_counter()
                
                # Choose appropriate method and make request
                response = None
                if method.upper() == "GET":
                    response = await session.get(url, headers=headers, allow_redirects=allow_redirects)
                elif method.upper() == "POST":
                    response = await session.post(url, headers=headers, data=data, allow_redirects=allow_redirects)
                elif method.upper() == "PUT":
                    response = await session.put(url, headers=headers, data=data, allow_redirects=allow_redirects)
                elif method.upper() == "DELETE":
                    response = await session.delete(url, headers=headers, allow_redirects=allow_redirects)
                elif method.upper() == "HEAD":
                    response = await session.head(url, headers=headers, allow_redirects=allow_redirects)
                elif method.upper() == "OPTIONS":
                    response = await session.options(url, headers=headers, allow_redirects=allow_redirects)
                elif method.upper() == "PATCH":
                    response = await session.patch(url, headers=headers, data=data, allow_redirects=allow_redirects)
                else:
                    # For unsupported methods like TRACE, use a generic request
                    response = await session.request(method, url, headers=headers, data=data, allow_redirects=allow_redirects)
                
                # Process response using context manager
                async with response:
                    await self._process_response(request, response, start_time)
                        
        except asyncio.TimeoutError:
            request.blocking_method = HTTPBlockingMethod.TIMEOUT
            request.error_message = "Request timeout"
            
        except aiohttp.ClientConnectorError as e:
            error_str = str(e)
            if ("Connection reset" in error_str or "Connection refused" in error_str or 
                "reset by peer" in error_str or "refused" in error_str):
                request.blocking_method = HTTPBlockingMethod.CONNECTION_RESET
            request.error_message = error_str
            
        except aiohttp.ClientResponseError as e:
            request.status_code = e.status
            request.error_message = str(e)
            
        except Exception as e:
            error_str = str(e)
            # Check for connection reset patterns in generic exceptions too
            if ("Connection reset" in error_str or "reset by peer" in error_str):
                request.blocking_method = HTTPBlockingMethod.CONNECTION_RESET
            request.error_message = error_str
        
        return request
    
    async def _process_response(self, request: HTTPRequest, response, start_time: float):
        """Process HTTP response and update request object"""
        request.response_time_ms = (time.perf_counter() - start_time) * 1000
        request.status_code = response.status
        request.response_headers = dict(response.headers)
        
        try:
            request.response_body = await response.text()
            request.success = True
        except Exception as e:
            request.error_message = f"Failed to read response body: {e}"
        
        # Check for redirect
        if response.status in [301, 302, 303, 307, 308]:
            request.redirect_url = response.headers.get('location')
        
        # Check for content modification indicators
        if request.response_body:
            modification_indicators = [
                'blocked', 'forbidden', 'restricted', 'access denied',
                'this site is blocked', 'content filtered'
            ]
            
            response_lower = request.response_body.lower()
            for indicator in modification_indicators:
                if indicator in response_lower:
                    request.content_modified = True
                    break
    
    def _calculate_reliability_score(self, result: HTTPAnalysisResult) -> float:
        """Calculate reliability score based on analysis completeness"""
        total_tests = 0
        successful_tests = 0
        
        # Count successful requests
        for request in result.http_requests:
            total_tests += 1
            if request.success or request.status_code is not None:
                successful_tests += 1
        
        if total_tests == 0:
            return 0.0
        
        base_score = successful_tests / total_tests
        
        # Adjust score based on analysis completeness
        analysis_factors = [
            result.http_header_filtering or len(result.filtered_headers) > 0,
            result.user_agent_filtering or len(result.blocked_user_agents) > 0,
            result.host_header_manipulation,
            result.method_based_blocking or len(result.http_method_restrictions) > 0,
            result.content_type_filtering or len(result.blocked_content_types) > 0,
            result.content_based_blocking or len(result.keyword_filtering) > 0,
            result.redirect_injection,
            result.http_response_modification,
            result.keep_alive_manipulation,
            result.chunked_encoding_handling != "unknown"
        ]
        
        completeness_score = sum(analysis_factors) / len(analysis_factors)
        
        # Penalize for errors
        error_penalty = min(0.3, len(result.analysis_errors) * 0.1)
        
        final_score = (base_score * 0.6 + completeness_score * 0.4) - error_penalty
        return max(0.0, min(1.0, final_score))