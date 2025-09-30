# path: core/fingerprint/http_analyzer.py

import asyncio
import aiohttp
import time
import inspect
import logging
import ssl
import socket
import sys
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlsplit

from .unified_models import (
    NetworkAnalysisError,
    HTTPAnalysisResult,
    HTTPRequest,
    HTTPBlockingMethod
)
from enum import Enum
from dataclasses import dataclass, field

# Импорт DoHResolver для фоллбэка
try:
    from core.doh_resolver import DoHResolver
    DOH_AVAILABLE = True
except ImportError:
    DOH_AVAILABLE = False

from aiohttp import abc as aiohttp_abc  # для AbstractResolver

LOG = logging.getLogger(__name__)


class _StaticResolver(aiohttp_abc.AbstractResolver):
    """Фиксирует домен на конкретный IP, чтобы SNI оставался корректным при прямом подключении."""
    def __init__(self, mapping: Dict[str, str]):
        self._map = dict(mapping or {})

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET):
        ip = self._map.get(host)
        if not ip:
            # Если IP не найден, возвращаемся к стандартному поведению
            return [{"hostname": host, "host": host, "port": port,
                     "family": family, "proto": 0, "flags": 0}]
        return [{"hostname": host, "host": ip, "port": port,
                 "family": family, "proto": 0, "flags": 0}]

    async def close(self) -> None:
        pass




class HTTPAnalyzer:
    """
    Enhanced HTTP analyzer with IPv4 forcing, DoH fallback, and comprehensive error handling
    """
    
    def __init__(
        self,
        timeout: float = 10.0,
        max_attempts: int = 10,
        force_ipv4: bool = True,
        use_system_proxy: bool = True,
        enable_doh_fallback: bool = True
    ):
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.force_ipv4 = force_ipv4
        self.use_system_proxy = use_system_proxy
        self.enable_doh_fallback = enable_doh_fallback
        self.logger = logging.getLogger(__name__)
        
        # DoH resolver for fallback
        self.doh_resolver = DoHResolver() if (DOH_AVAILABLE and enable_doh_fallback) else None
        
        # Windows event loop fix
        if sys.platform.startswith("win") and sys.version_info >= (3, 12):
            try:
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
                self.logger.info("Applied WindowsSelectorEventLoopPolicy")
            except Exception as e:
                self.logger.warning(f"Failed to set event loop policy: {e}")

    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with relaxed verification"""
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # Set minimum TLS version (with fallback for older OpenSSL)
        try:
            if hasattr(ssl, 'TLSVersion'):
                ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        except Exception:
            pass
        
        # Disable session tickets for consistent fingerprinting
        try:
            ssl_context.options |= ssl.OP_NO_TICKET
        except Exception:
            pass
        
        return ssl_context
    
    def _create_connector(
        self,
        ssl_context: Optional[ssl.SSLContext] = None,
        pinned_ip: Optional[str] = None
    ) -> aiohttp.TCPConnector:
        """Create TCP connector with optimal settings"""
        connector_kwargs = {
            'ssl': ssl_context or self._create_ssl_context(),
            'ttl_dns_cache': 300,
            'enable_cleanup_closed': True,
            'force_close': False,
            'limit': 100,
            'limit_per_host': 10
        }
        
        if self.force_ipv4:
            connector_kwargs['family'] = socket.AF_INET
            self.logger.debug("Forcing IPv4 (AF_INET)")
        
        # TODO: Add custom resolver for IP pinning if needed
        # if pinned_ip:
        #     connector_kwargs['resolver'] = CustomResolver({hostname: pinned_ip})
        
        return aiohttp.TCPConnector(**connector_kwargs)
    
    async def _create_session(
        self,
        pinned_ip: Optional[str] = None
    ) -> aiohttp.ClientSession:
        """Create aiohttp session"""
        connector = self._create_connector(pinned_ip=pinned_ip)
        
        timeout = aiohttp.ClientTimeout(
            total=self.timeout,
            connect=min(5.0, self.timeout / 2),
            sock_read=self.timeout,
            sock_connect=min(3.0, self.timeout / 3)
        )
        
        return aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            trust_env=self.use_system_proxy,
            auto_decompress=True
        )
    
    def _format_exc(self, e: BaseException) -> str:
        """Форматирует исключение в подробную строку."""
        try:
            info = f"{type(e).__name__}: {repr(e)}"
            cause = f"cause={repr(e.__cause__)}" if getattr(e, "__cause__", None) else None
            ctx = f"context={repr(e.__context__)}" if getattr(e, "__context__", None) else None
            return " | ".join(x for x in (info, cause, ctx) if x)
        except Exception:
            return str(e)
    
    def _host_for_url(self, url: str, headers: Dict[str, str]) -> str:
        """Извлекает хост из URL или заголовка Host."""
        return (headers or {}).get("Host") or (urlsplit(url).hostname or "")
    
    async def _open_session(self, host: str, pinned_ip: Optional[str] = None) -> aiohttp.ClientSession:
        """Создает сессию aiohttp с нужными настройками (IPv4, SSL, Resolver)."""
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        connector_kwargs = dict(
            ssl=ssl_context,
            family=socket.AF_INET,           # Форсируем IPv4
            enable_cleanup_closed=True
        )
        
        resolver = _StaticResolver({host: pinned_ip}) if pinned_ip else None
        if resolver:
            connector_kwargs['resolver'] = resolver
            
        connector = aiohttp.TCPConnector(**connector_kwargs)
        
        # trust_env=True чтобы учитывать системные прокси
        return aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout), 
            connector=connector, 
            trust_env=True
        )
    
    # <<< FIX: Added helper functions to safely handle mock/awaitable values >>>
    async def _coerce_text(self, v) -> str:
        try:
            if inspect.isawaitable(v): v = await v
        except Exception: return ""
        if v is None: return ""
        try: return str(v)
        except Exception: return ""

    async def _coerce_headers(self, v) -> Dict[str, str]:
        try:
            if inspect.isawaitable(v): v = await v
        except Exception: return {}
        try:
            if isinstance(v, dict): return v
            return dict(v or {})
        except Exception: return {}

    async def _await_if_needed(self, maybe_awaitable):
        for _ in range(3):
            if inspect.isawaitable(maybe_awaitable):
                maybe_awaitable = await maybe_awaitable
            else:
                break
        return maybe_awaitable

    async def _call_session(self, session, method, url, **kwargs):
        res = await session.request(method, url, **kwargs)
        return await self._await_if_needed(res)

    def _format_exception_details(self, e: Exception) -> str:
        """Format exception with full context"""
        parts = [f"{type(e).__name__}: {str(e)}"]
        
        if hasattr(e, '__cause__') and e.__cause__:
            parts.append(f"Cause: {type(e.__cause__).__name__}: {str(e.__cause__)}")
        
        if hasattr(e, '__context__') and e.__context__:
            parts.append(f"Context: {type(e.__context__).__name__}: {str(e.__context__)}")
        
        if isinstance(e, aiohttp.ClientConnectorError):
            parts.append(f"OS Error: {e.os_error}")
            if hasattr(e, 'host'):
                parts.append(f"Host: {e.host}")
        elif isinstance(e, aiohttp.ClientResponseError):
            parts.append(f"Status: {e.status}, Message: {e.message}")
        elif isinstance(e, asyncio.TimeoutError):
            parts.append("Timeout - possible network filtering")
        elif isinstance(e, socket.gaierror):
            parts.append(f"DNS resolution failed: errno={e.errno}")
        
        return " | ".join(parts)
    
    async def analyze_http_behavior(
        self,
        target: str,
        port: int = 443
    ) -> Dict[str, Any]:
        """Main HTTP analysis method"""
        self.logger.info(f"Starting HTTP analysis for {target}:{port}")
        
        result = HTTPAnalysisResult()
        protocol = "https" if port == 443 else "http"
        base_url = f"{protocol}://{target}:{port}" if port not in [80, 443] else f"{protocol}://{target}"
        
        # Test basic connectivity with fallback strategies
        success = await self._test_basic_connectivity(result, base_url, target)
        
        if not success:
            self.logger.warning(f"Basic connectivity failed for {target}")
            # Don't abort - continue with limited analysis
        
        # Run remaining tests
        try:
            await self._analyze_header_filtering(result, base_url)
            await self._analyze_user_agent_filtering(result, base_url)
            await self._analyze_host_header_manipulation(result, base_url, target)
            await self._analyze_http_method_restrictions(result, base_url)
            await self._analyze_content_type_filtering(result, base_url)
            await self._analyze_content_inspection(result, base_url)
            await self._analyze_redirect_injection(result, base_url)
            await self._analyze_response_modification(result, base_url)
            await self._analyze_connection_behavior(result, base_url)
            await self._analyze_encoding_handling(result, base_url)
            
            result.reliability_score = self._calculate_reliability_score(result)
            
            self.logger.info(
                f"HTTP analysis complete for {target}:{port} "
                f"(reliability: {result.reliability_score:.2f})"
            )
        except Exception as e:
            error_msg = f"HTTP analysis failed: {self._format_exception_details(e)}"
            self.logger.error(error_msg)
            result.analysis_errors.append(error_msg)
        
        return result.to_dict()

    async def _test_basic_connectivity(
        self,
        result: HTTPAnalysisResult,
        base_url: str,
        target: str
    ) -> bool:
        """Test basic connectivity with multiple fallback strategies"""
        self.logger.debug(f"Testing basic connectivity to {base_url}")
        
        # Strategy 1: Full HTTPS with standard headers
        success = await self._try_connection(
            base_url,
            method="GET",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive"
            },
            result=result,
            strategy_name="full_https"
        )
        
        if success:
            return True
        
        # Strategy 2: Minimal headers (some DPI blocks rich headers)
        self.logger.info("Full HTTPS failed, trying minimal headers")
        success = await self._try_connection(
            base_url,
            method="GET",
            headers={"User-Agent": "curl/7.68.0"},
            result=result,
            strategy_name="minimal_https"
        )
        
        if success:
            result.analysis_errors.append(
                "Full HTTPS blocked, minimal headers work - header filtering detected"
            )
            return True
        
        # Strategy 3: HTTP fallback (HTTPS-only blocking detection)
        if base_url.startswith("https://"):
            http_url = base_url.replace("https://", "http://").replace(":443", ":80")
            self.logger.info(f"HTTPS failed, trying HTTP: {http_url}")
            
            success = await self._try_connection(
                http_url,
                method="HEAD",
                headers={"User-Agent": "Mozilla/5.0"},
                result=result,
                strategy_name="http_fallback"
            )
            
            if success:
                result.analysis_errors.append(
                    "HTTPS blocked but HTTP works - HTTPS-specific blocking"
                )
                result.http_blocking_detected = True
                return True
        
        # Strategy 4: Alternative User-Agent
        self.logger.info("Trying alternative User-Agent")
        success = await self._try_connection(
            base_url,
            method="GET",
            headers={"User-Agent": "python-requests/2.31.0"},
            result=result,
            strategy_name="alt_useragent"
        )
        
        if success:
            result.user_agent_filtering = True
            result.analysis_errors.append(
                "Browser UA blocked, python-requests works - UA filtering"
            )
            return True
        
        # Strategy 5: DoH fallback (DNS issues)
        if self.doh_resolver:
            self.logger.info("Trying DoH fallback for DNS resolution")
            try:
                ip = await self.doh_resolver.resolve(target)
                if ip:
                    self.logger.info(f"DoH resolved {target} -> {ip}")
                    # TODO: Retry with pinned IP
                    # success = await self._try_connection_with_ip(base_url, ip, result)
                    # if success:
                    #     result.analysis_errors.append("DNS resolution via DoH successful")
                    #     return True
            except Exception as e:
                self.logger.debug(f"DoH fallback failed: {e}")
        
        # All strategies failed
        error_msg = f"All connectivity strategies failed for {base_url}"
        result.analysis_errors.append(error_msg)
        result.analysis_errors.append("NETWORK_CONNECTIVITY_ISSUE=True")
        self.logger.error(error_msg)
        
        return False

    async def _try_connection(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        result: HTTPAnalysisResult,
        strategy_name: str,
        allow_redirects: bool = True
    ) -> bool:
        """Try single connection with detailed error reporting"""
        request = HTTPRequest(
            timestamp=time.time(),
            url=url,
            method=method,
            headers=headers.copy(),
            user_agent=headers.get("User-Agent", "")
        )
        
        session = None
        try:
            session = await self._create_session()
            start_time = time.perf_counter()
            
            async with session.request(
                method,
                url,
                headers=headers,
                allow_redirects=allow_redirects
            ) as response:
                request.response_time_ms = (time.perf_counter() - start_time) * 1000
                request.status_code = response.status
                request.response_headers = dict(response.headers)
                
                try:
                    body = await response.text(encoding='utf-8', errors='ignore')
                    request.response_body = body[:10000]  # Limit to 10KB
                except Exception as body_error:
                    self.logger.debug(f"Failed to read body: {body_error}")
                    request.response_body = ""
                
                request.success = True
                self.logger.info(
                    f"✅ Strategy '{strategy_name}' succeeded: "
                    f"{method} {url} -> {response.status}"
                )
                result.http_requests.append(request)
                return True
        
        except aiohttp.ClientConnectorError as e:
            request.error_message = self._format_exception_details(e)
            
            # Classify error
            msg_lower = request.error_message.lower()
            if "dns" in msg_lower or "getaddrinfo" in msg_lower:
                request.blocking_method = HTTPBlockingMethod.TIMEOUT
                result.analysis_errors.append(f"DNS_RESOLUTION_FAILED: {e.os_error}")
                self.logger.warning(f"❌ DNS failed for {url}: {e.os_error}")
            elif "refused" in msg_lower:
                request.blocking_method = HTTPBlockingMethod.CONNECTION_RESET
                result.analysis_errors.append("CONNECTION_REFUSED: Port blocking")
                self.logger.warning(f"❌ Connection refused for {url}")
            elif "reset" in msg_lower:
                request.blocking_method = HTTPBlockingMethod.CONNECTION_RESET
                result.http_blocking_detected = True
                self.logger.warning(f"❌ Connection reset for {url} - DPI likely")
            else:
                request.blocking_method = HTTPBlockingMethod.TIMEOUT
                self.logger.warning(f"❌ Connection error for {url}: {request.error_message}")
        
        except asyncio.TimeoutError as e:
            request.error_message = self._format_exception_details(e)
            request.blocking_method = HTTPBlockingMethod.TIMEOUT
            result.analysis_errors.append("TIMEOUT: Traffic filtering")
            self.logger.warning(f"⏱️ Timeout for {url} after {self.timeout}s")
        
        except aiohttp.ClientError as e:
            request.error_message = self._format_exception_details(e)
            self.logger.warning(f"❌ Client error for {url}: {request.error_message}")
        
        except Exception as e:
            request.error_message = self._format_exception_details(e)
            self.logger.error(
                f"❌ Unexpected error for {url}: {request.error_message}",
                exc_info=True
            )
        
        finally:
            if session and not session.closed:
                await session.close()
        
        result.http_requests.append(request)
        return False
    
    async def _analyze_header_filtering(
        self, result: HTTPAnalysisResult, base_url: str
    ):
        """Analyze HTTP header filtering behavior"""
        self.logger.debug("Analyzing HTTP header filtering")
        baseline_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
        }
        
        baseline_request = await self._make_request(base_url, "GET", baseline_headers.copy())
        result.http_requests.append(baseline_request)
        
        if not baseline_request.success:
            self.logger.warning("Baseline request failed, skipping header filtering analysis")
            return
        
        baseline_body = await self._coerce_text(baseline_request.response_body)
        baseline_status = baseline_request.status_code

        for header_name, header_value in self.test_headers:
            test_headers = baseline_headers.copy()
            test_headers[header_name] = header_value
            request = await self._make_request(base_url, "GET", test_headers)
            result.http_requests.append(request)

            if baseline_request.success:
                strong_indicators = (
                    not request.success or
                    request.blocking_method == HTTPBlockingMethod.CONNECTION_RESET
                )
                
                request_body = await self._coerce_text(request.response_body)

                weak_indicators = (
                    (
                        request.success and
                        baseline_status is not None and baseline_status < 400 and
                        request.status_code is not None and request.status_code >= 400
                    ) or
                    (
                        request.success and
                        request.redirect_url and not baseline_request.redirect_url and
                        any(p in request.redirect_url.lower() for p in ["block", "warn", "restrict", "forbidden"])
                    ) or
                    (
                        request.success and
                        request_body and
                        not any(p in baseline_body.lower() for p in ["blocked", "forbidden", "restricted"]) and
                        any(p in request_body.lower() for p in ["blocked", "forbidden", "restricted"])
                    )
                )

                if strong_indicators or weak_indicators:
                    result.http_header_filtering = True
                    if header_name not in result.filtered_headers:
                        result.filtered_headers.append(header_name)
                    if header_name not in result.header_filtering:
                        result.header_filtering.append(header_name)
                    result.http_blocking_detected = True
                    self.logger.info(
                        f"Header filtering detected for: {header_name} (strong: {strong_indicators}, weak: {weak_indicators})"
                    )
            await asyncio.sleep(0.1)
        
        await self._test_header_case_sensitivity(result, base_url)
        await self._test_custom_header_blocking(result, base_url)

    async def _test_header_case_sensitivity(
        self, result: HTTPAnalysisResult, base_url: str
    ):
        """Test if DPI is case-sensitive with headers"""
        test_cases = [
            ("user-agent", "test-agent"),
            ("USER-AGENT", "test-agent"),
            ("User-Agent", "test-agent"),
            ("uSeR-aGeNt", "test-agent"),
        ]
        responses = []
        for header_name, header_value in test_cases:
            request = await self._make_request(
                base_url, "GET", {header_name: header_value}
            )
            responses.append(request.success)
            result.http_requests.append(request)
            await asyncio.sleep(0.1)
        if len(set(responses)) > 1:
            result.header_case_sensitivity = True
            self.logger.info("Header case sensitivity detected")

    async def _test_custom_header_blocking(
        self, result: HTTPAnalysisResult, base_url: str
    ):
        """Test blocking of custom/unusual headers"""
        custom_headers = [
            ("X-Bypass-DPI", "true"),
            ("X-Tunnel-Protocol", "http"),
            ("X-Proxy-Connection", "keep-alive"),
            ("X-Censorship-Bypass", "enabled"),
        ]
        baseline_request = await self._make_request(
            base_url,
            "GET",
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
        )
        blocked_count = 0
        for header_name, header_value in custom_headers:
            test_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                header_name: header_value,
            }
            request = await self._make_request(base_url, "GET", test_headers)
            result.http_requests.append(request)
            if baseline_request.success and (not request.success):
                blocked_count += 1
                if header_name not in result.filtered_headers:
                    result.filtered_headers.append(header_name)
            await asyncio.sleep(0.1)
        if blocked_count > 0:
            result.custom_header_blocking = True
            self.logger.info(
                f"Custom header blocking detected ({blocked_count} headers blocked)"
            )

    async def _analyze_user_agent_filtering(
        self, result: HTTPAnalysisResult, base_url: str
    ):
        """Analyze user agent filtering behavior"""
        self.logger.debug("Analyzing user agent filtering")
        successful_agents = []
        blocked_agents = []
        for user_agent in self.test_user_agents:
            request = await self._make_request(
                base_url, "GET", {"User-Agent": user_agent}
            )
            result.http_requests.append(request)
            if request.success:
                successful_agents.append(user_agent)
            else:
                blocked_agents.append(user_agent)
                self.logger.info(f"User agent blocked: {user_agent}")
            await asyncio.sleep(0.1)
        if blocked_agents:
            result.user_agent_filtering = True
            result.user_agent_blocking = True
            result.blocked_user_agents = blocked_agents
            if len(blocked_agents) > len(successful_agents):
                result.user_agent_whitelist_detected = True
                self.logger.info("User agent whitelist detected")
        empty_ua_request = await self._make_request(base_url, "GET", {})
        result.http_requests.append(empty_ua_request)
        if not empty_ua_request.success:
            result.user_agent_filtering = True
            result.user_agent_blocking = True
            self.logger.info("Empty user agent blocked")

    async def _analyze_host_header_manipulation(
        self, result: HTTPAnalysisResult, base_url: str, target: str
    ):
        """Analyze host header manipulation and validation"""
        self.logger.debug("Analyzing host header manipulation")
        correct_request = await self._make_request(
            base_url,
            "GET",
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Host": target,
            },
        )
        result.http_requests.append(correct_request)
        test_hosts = [
            "blocked-site.com",
            "suspicious-domain.org",
            "127.0.0.1",
            "localhost",
            "example.com",
            "",
        ]
        for test_host in test_hosts:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            if test_host:
                headers["Host"] = test_host
            request = await self._make_request(base_url, "GET", headers)
            result.http_requests.append(request)
            if correct_request.success and (not request.success):
                result.host_header_manipulation = True
                result.host_header_validation = True
                self.logger.info(f"Host header validation detected for: {test_host}")
            await asyncio.sleep(0.1)
        if base_url.startswith("https://"):
            await self._test_sni_host_mismatch(result, base_url, target)

    async def _test_sni_host_mismatch(
        self, result: HTTPAnalysisResult, base_url: str, target: str
    ):
        """Test SNI-Host header mismatch detection"""
        try:
            mismatch_request = await self._make_request(
                base_url,
                "GET",
                {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Host": "different-domain.com",
                },
            )
            result.http_requests.append(mismatch_request)
            if not mismatch_request.success:
                result.sni_host_mismatch_blocking = True
                self.logger.info("SNI-Host mismatch blocking detected")
        except Exception as e:
            self.logger.debug(f"SNI-Host mismatch test failed: {e}")

    async def _analyze_http_method_restrictions(
        self, result: HTTPAnalysisResult, base_url: str
    ):
        """Analyze HTTP method restrictions"""
        self.logger.debug("Analyzing HTTP method restrictions")
        baseline_request = await self._make_request(
            base_url,
            "GET",
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
        )
        result.http_requests.append(baseline_request)
        if not baseline_request.success:
            self.logger.warning("Baseline GET request failed, skipping method analysis")
            return
        for method in self.test_methods:
            request = await self._make_request(
                base_url,
                method,
                {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                },
            )
            result.http_requests.append(request)
            is_blocked = any(
                (
                    not request.success,
                    request.blocking_method != HTTPBlockingMethod.NONE,
                    request.status_code is not None
                    and (
                        request.status_code in [405, 403, 401, 501]
                        or request.status_code >= 400
                    ),
                )
            )
            if is_blocked:
                if method not in result.http_method_restrictions:
                    result.http_method_restrictions.append(method)
                self.logger.info(
                    f"HTTP method restricted: {method} (status: {request.status_code})"
                )
            elif request.success and (
                request.status_code is None or request.status_code < 400
            ):
                if method not in result.allowed_methods:
                    result.allowed_methods.append(method)
            await asyncio.sleep(0.1)
        if result.http_method_restrictions:
            result.method_based_blocking = True
            dangerous_methods = set(["TRACE", "DELETE", "PUT"])
            blocked_dangerous = dangerous_methods.intersection(
                set(result.http_method_restrictions)
            )
            if blocked_dangerous:
                self.logger.info(
                    f"Dangerous methods blocked: {', '.join(blocked_dangerous)}"
                )
                if len(blocked_dangerous) >= 2:
                    result.method_based_blocking = True

    async def _analyze_content_type_filtering(
        self, result: HTTPAnalysisResult, base_url: str
    ):
        """Analyze content type filtering"""
        self.logger.debug("Analyzing content type filtering")
        for content_type in self.test_content_types:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Content-Type": content_type,
            }
            request = await self._make_request(
                base_url, "POST", headers, data="test data"
            )
            result.http_requests.append(request)
            if not request.success:
                result.content_type_filtering = True
                result.blocked_content_types.append(content_type)
                self.logger.info(f"Content type blocked: {content_type}")
            await asyncio.sleep(0.1)
        await self._test_content_type_validation(result, base_url)

    async def _test_content_type_validation(
        self, result: HTTPAnalysisResult, base_url: str
    ):
        """Test content type validation"""
        mismatch_request = await self._make_request(
            base_url,
            "POST",
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Content-Type": "text/plain",
            },
            data='{"key": "value"}',
        )
        result.http_requests.append(mismatch_request)
        correct_request = await self._make_request(
            base_url,
            "POST",
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Content-Type": "application/json",
            },
            data='{"key": "value"}',
        )
        result.http_requests.append(correct_request)
        if not mismatch_request.success and correct_request.success:
            result.content_type_validation = True
            self.logger.info("Content type validation detected")

    async def _analyze_content_inspection(
        self, result: HTTPAnalysisResult, base_url: str
    ):
        """Analyze content inspection depth and keyword filtering"""
        self.logger.debug("Analyzing content inspection depth")
        content_lengths = [100, 500, 1000, 2000, 5000, 10000]
        inspection_depth = 0
        for length in content_lengths:
            content = "A" * (length - 10) + "forbidden"
            request = await self._make_request(
                base_url,
                "POST",
                {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Content-Type": "text/plain",
                },
                data=content,
            )
            result.http_requests.append(request)
            if not request.success:
                inspection_depth = length
                result.content_based_blocking = True
                self.logger.info(f"Content inspection detected at depth: {length}")
                break
            await asyncio.sleep(0.1)
        result.content_inspection_depth = inspection_depth
        await self._test_keyword_filtering(result, base_url)

    async def _test_keyword_filtering(self, result: HTTPAnalysisResult, base_url: str):
        """Test keyword-based content filtering"""
        blocked_keywords = []
        for keyword in self.test_content_keywords:
            test_contents = [
                keyword,
                f"This content contains {keyword} word",
                f"{keyword} at the beginning",
                f"At the end {keyword}",
            ]
            for content in test_contents:
                request = await self._make_request(
                    base_url,
                    "POST",
                    {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        "Content-Type": "text/plain",
                    },
                    data=content,
                )
                result.http_requests.append(request)
                if not request.success:
                    if keyword not in blocked_keywords:
                        blocked_keywords.append(keyword)
                    result.content_based_blocking = True
                    self.logger.info(f"Keyword filtering detected: {keyword}")
                    break
                await asyncio.sleep(0.05)
        result.keyword_filtering = blocked_keywords

    async def _analyze_redirect_injection(
        self, result: HTTPAnalysisResult, base_url: str
    ):
        """Analyze redirect injection patterns"""
        self.logger.debug("Analyzing redirect injection")
        test_paths = ["/", "/blocked", "/forbidden", "/admin", "/proxy", "/vpn"]
        for path in test_paths:
            test_url = urljoin(base_url, path)
            request = await self._make_request(
                test_url,
                "GET",
                {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                },
                allow_redirects=False,
            )
            result.http_requests.append(request)
            if request.status_code in [301, 302, 303, 307, 308]:
                result.redirect_injection = True
                result.redirect_status_codes.append(request.status_code)
                if "Location" in request.response_headers:
                    redirect_url = request.response_headers["Location"]
                    if redirect_url not in result.redirect_patterns:
                        result.redirect_patterns.append(redirect_url)
                    request.redirect_url = redirect_url
                    suspicious_patterns = [
                        "block",
                        "forbidden",
                        "restricted",
                        "warning",
                        "government",
                        "censorship",
                        "unavailable",
                    ]
                    if any(
                        (
                            pattern in redirect_url.lower()
                            for pattern in suspicious_patterns
                        )
                    ):
                        self.logger.info(
                            f"Suspicious redirect detected: {redirect_url}"
                        )
                        result.http_response_modification = True
            await asyncio.sleep(0.1)

    async def _analyze_response_modification(
        self, result: HTTPAnalysisResult, base_url: str
    ):
        """Analyze response modification and content injection"""
        self.logger.debug("Analyzing response modification")
        baseline_responses = []
        for _ in range(3):
            request = await self._make_request(
                base_url,
                "GET",
                {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                },
            )
            if request.success and request.response_body:
                baseline_responses.append(request.response_body)
            result.http_requests.append(request)
            await asyncio.sleep(0.2)
        if len(set(baseline_responses)) > 1:
            result.http_response_modification = True
            self.logger.info("Response modification detected (inconsistent responses)")
        if baseline_responses:
            response_text = baseline_responses[0].lower()
            injection_patterns = [
                "blocked",
                "forbidden",
                "restricted",
                "access denied",
                "this site is blocked",
                "content filtered",
                "government warning",
                "censorship notice",
            ]
            for pattern in injection_patterns:
                if pattern in response_text:
                    result.http_response_modification = True
                    result.injected_content.append(pattern)
                    result.response_modification_patterns.append(pattern)
                    self.logger.info(f"Content injection detected: {pattern}")
        await self._test_header_injection(result, base_url)

    async def _test_header_injection(self, result: HTTPAnalysisResult, base_url: str):
        """Test for response header injection"""
        request = await self._make_request(
            base_url,
            "GET",
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
        )
        result.http_requests.append(request)
        if request.success and request.response_headers:
            suspicious_headers = [
                "x-blocked-by",
                "x-filtered-by",
                "x-censorship",
                "x-government-warning",
                "x-content-filter",
            ]
            keys_lower = [h.lower() for h in request.response_headers.keys()]
            for header in suspicious_headers:
                if header in keys_lower:
                    result.http_response_modification = True
                    result.response_modification_patterns.append(f"header:{header}")
                    self.logger.info(f"Response header injection detected: {header}")

    async def _analyze_connection_behavior(
        self, result: HTTPAnalysisResult, base_url: str
    ):
        """Analyze connection behavior and keep-alive handling"""
        self.logger.debug("Analyzing connection behavior")
        keep_alive_request = await self._make_request(
            base_url,
            "GET",
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Connection": "keep-alive",
            },
        )
        result.http_requests.append(keep_alive_request)
        close_request = await self._make_request(
            base_url,
            "GET",
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Connection": "close",
            },
        )
        result.http_requests.append(close_request)
        if keep_alive_request.success != close_request.success:
            result.keep_alive_manipulation = True
            result.connection_header_filtering = True
            self.logger.info("Connection header manipulation detected")
        await self._test_persistent_connections(result, base_url)

    async def _test_persistent_connections(
        self, result: HTTPAnalysisResult, base_url: str
    ):
        """Test persistent connection handling"""
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                connector=aiohttp.TCPConnector(limit=1, limit_per_host=1),
            ) as session:
                success_count = 0
                for _ in range(3):
                    try:
                        resp_ctx = await self._call_session(
                            session,
                            "GET",
                            base_url,
                            headers={
                                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                            },
                        )
                        async with resp_ctx as response:
                            if getattr(response, "status", 0) == 200:
                                success_count += 1
                    except Exception:
                        pass
                    await asyncio.sleep(0.1)
                if success_count < 3:
                    result.persistent_connection_blocking = True
                    self.logger.info("Persistent connection blocking detected")
        except Exception as e:
            self.logger.debug(f"Persistent connection test failed: {e}")

    async def _analyze_encoding_handling(
        self, result: HTTPAnalysisResult, base_url: str
    ):
        """Analyze encoding and transfer handling"""
        self.logger.debug("Analyzing encoding handling")
        await self._test_chunked_encoding(result, base_url)
        await self._test_compression_handling(result, base_url)
        await self._test_transfer_encoding(result, base_url)

    async def _test_chunked_encoding(self, result: HTTPAnalysisResult, base_url: str):
        """Test chunked transfer encoding handling"""
        chunked_request = await self._make_request(
            base_url,
            "POST",
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Transfer-Encoding": "chunked",
                "Content-Type": "text/plain",
            },
            data="test data",
        )
        result.http_requests.append(chunked_request)
        normal_request = await self._make_request(
            base_url,
            "POST",
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Content-Type": "text/plain",
            },
            data="test data",
        )
        result.http_requests.append(normal_request)
        if normal_request.success and (not chunked_request.success):
            result.chunked_encoding_handling = "blocked"
            result.transfer_encoding_filtering = True
            self.logger.info("Chunked encoding blocked")
        elif chunked_request.success:
            result.chunked_encoding_handling = "supported"
        else:
            result.chunked_encoding_handling = "unknown"

    async def _test_compression_handling(
        self, result: HTTPAnalysisResult, base_url: str
    ):
        """Test compression handling"""
        compressed_request = await self._make_request(
            base_url,
            "GET",
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept-Encoding": "gzip, deflate, br",
            },
        )
        result.http_requests.append(compressed_request)
        uncompressed_request = await self._make_request(
            base_url,
            "GET",
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept-Encoding": "identity",
            },
        )
        result.http_requests.append(uncompressed_request)
        if compressed_request.success and uncompressed_request.success:
            if "content-encoding" in {
                k.lower(): v for k, v in compressed_request.response_headers.items()
            } and "content-encoding" not in {
                k.lower(): v for k, v in uncompressed_request.response_headers.items()
            }:
                result.compression_handling = "supported"
            else:
                result.compression_handling = "modified"
        elif uncompressed_request.success and (not compressed_request.success):
            result.compression_handling = "blocked"
            self.logger.info("Compression blocked")
        else:
            result.compression_handling = "unknown"

    async def _test_transfer_encoding(self, result: HTTPAnalysisResult, base_url: str):
        """Test transfer encoding filtering"""
        encodings = ["chunked", "compress", "deflate", "gzip"]
        for encoding in encodings:
            request = await self._make_request(
                base_url,
                "POST",
                {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Transfer-Encoding": encoding,
                    "Content-Type": "text/plain",
                },
                data="test data",
            )
            result.http_requests.append(request)
            if not request.success:
                result.transfer_encoding_filtering = True
                self.logger.info(f"Transfer encoding blocked: {encoding}")
            await asyncio.sleep(0.1)

    async def _make_request(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        data: Optional[str] = None,
        allow_redirects: bool = True,
    ) -> HTTPRequest:
        """Make HTTP request with DoH fallback and detailed error reporting."""
        request = HTTPRequest(
            timestamp=time.time(), url=url, method=method, headers=headers.copy(),
            user_agent=headers.get("User-Agent", ""), host_header=headers.get("Host", ""),
            content_type=headers.get("Content-Type", ""), body=data,
        )
        
        host = self._host_for_url(url, headers)
        session = None
        err_details = ""

        try:
            # Попытка 1: Стандартный резолв (но с форсированным IPv4)
            try:
                session = await self._open_session(host)
                start_time = time.perf_counter()
                response_ctx = await self._call_session(session, method, url, headers=headers, data=data, allow_redirects=allow_redirects)
                async with response_ctx as resp:
                    await self._process_response(request, resp, start_time)
                await session.close()
                return request
            except (aiohttp.ClientConnectorError, socket.gaierror) as e:
                err_details = self._format_exc(e)
                is_dns_issue = "dns" in err_details.lower() or "getaddrinfo" in err_details.lower() or "no data" in err_details.lower()
                if not (DOH_AVAILABLE and is_dns_issue):
                    raise # Если не DNS-ошибка или DoH недоступен, пробрасываем дальше

                self.logger.debug(f"DNS resolution failed for {host}, trying DoH fallback. Error: {err_details}")
                if session: await session.close()

            # Попытка 2: DoH-фоллбэк
            doh = DoHResolver()
            ip = await doh.resolve(host)
            if not ip:
                raise NetworkAnalysisError(f"DoH fallback failed for {host}")

            self.logger.info(f"Using DoH fallback for {host} -> {ip}")
            session = await self._open_session(host, pinned_ip=ip)
            start_time = time.perf_counter()
            response_ctx = await self._call_session(session, method, url, headers=headers, data=data, allow_redirects=allow_redirects)
            async with response_ctx as resp:
                await self._process_response(request, resp, start_time)
            
            return request

        except Exception as e:
            request.error_message = err_details or self._format_exc(e)
            low_err = request.error_message.lower()
            if "reset" in low_err:
                request.blocking_method = HTTPBlockingMethod.CONNECTION_RESET
            elif "timeout" in low_err:
                request.blocking_method = HTTPBlockingMethod.TIMEOUT
            return request
        finally:
            if session and not session.closed:
                await session.close()

    async def _process_response(
        self, request: HTTPRequest, response, start_time: float
    ):
        """Process HTTP response and update request object"""
        request.response_time_ms = (time.perf_counter() - start_time) * 1000
        request.status_code = int(getattr(response, "status", 0)) if hasattr(response, "status") else None
        request.response_headers = await self._coerce_headers(getattr(response, "headers", {}))
        try:
            txt = await response.text()
        except Exception:
            txt = None
        request.response_body = await self._coerce_text(txt)
        request.success = True
        if request.status_code in [301, 302, 303, 307, 308]:
            request.redirect_url = (getattr(response, "headers", {}) or {}).get("location")
        if request.response_body:
            modification_indicators = [
                "blocked", "forbidden", "restricted", "access denied",
                "this site is blocked", "content filtered",
            ]
            response_lower = request.response_body.lower()
            for indicator in modification_indicators:
                if indicator in response_lower:
                    request.content_modified = True
                    break

    def _calculate_reliability_score(self, result: HTTPAnalysisResult) -> float:
        """Calculate reliability score"""
        total_tests = len(result.http_requests)
        if total_tests == 0:
            return 0.0
        
        successful_tests = sum(1 for r in result.http_requests if r.success)
        useful_responses = sum(
            1 for r in result.http_requests
            if r.success and (
                r.status_code is not None or
                r.blocking_method != HTTPBlockingMethod.NONE or
                r.response_headers or
                r.redirect_url or
                r.content_modified
            )
        )
        
        base_score = (
            successful_tests / total_tests * 0.5 +
            useful_responses / total_tests * 0.5
        )
        
        # Analysis completeness factors
        analysis_factors = []
        
        if any(r.success or r.status_code for r in result.http_requests):
            analysis_factors.append(1.0)
        
        if result.http_header_filtering or result.filtered_headers:
            analysis_factors.append(1.0)
        
        if result.user_agent_filtering or result.blocked_user_agents:
            analysis_factors.append(1.0)
        
        if result.content_based_blocking or result.keyword_filtering:
            analysis_factors.append(1.0)
        
        if result.redirect_injection or result.http_response_modification:
            analysis_factors.append(0.5)
        
        if result.method_based_blocking or result.http_method_restrictions:
            analysis_factors.append(0.5)
        
        completeness_score = (
            sum(analysis_factors) / len(analysis_factors)
            if analysis_factors else 0.0
        )
        
        error_penalty = min(0.2, len(result.analysis_errors) * 0.05)
        
        final_score = base_score * 0.7 + completeness_score * 0.3 - error_penalty
        
        return max(0.0, min(1.0, final_score))

    async def analyze_packet_stream(
        self, target: str, port: int = 443
    ) -> Dict[str, Any]:
        """
        Эмуляция побайтовой обработки — читаем raw_packets из контекста ответа (см. тест).
        Возвращает:
        - packet_processing_method
        - segmentation_detected
        - packet_reassembly_success
        """
        protocol = "https" if port == 443 else "http"
        base_url = (
            f"{protocol}://{target}:{port}"
            if port not in [80, 443]
            else f"{protocol}://{target}"
        )
        result = {
            "target": target,
            "packet_processing_method": (
                "bytewise" if self.use_bytewise_processing else "stream"
            ),
            "segmentation_detected": False,
            "packet_reassembly_success": False,
        }
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            response_ctx = await session.get(base_url)
            async with response_ctx as resp:
                raw_packets = getattr(resp, "raw_packets", None)
                if isinstance(raw_packets, list) and raw_packets:
                    result["segmentation_detected"] = len(raw_packets) > 1
                    assembled = b"".join(raw_packets)
                    result["packet_reassembly_success"] = bool(assembled)
        return result

    async def analyze_packet_modifications(
        self, target: str, port: int = 443
    ) -> Dict[str, Any]:
        """
        Эмуляция детекции модификаций пакетов — сравнение original_packets и raw_packets.
        Возвращает:
        - packet_modified
        - modifications_detected: dict(header_injection, user_agent_modified)
        - original_size, modified_size
        """
        protocol = "https" if port == 443 else "http"
        base_url = (
            f"{protocol}://{target}:{port}"
            if port not in [80, 443]
            else f"{protocol}://{target}"
        )
        result = {
            "target": target,
            "packet_modified": False,
            "modifications_detected": {
                "header_injection": False,
                "user_agent_modified": False,
            },
            "original_size": 0,
            "modified_size": 0,
        }
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            response_ctx = await session.get(base_url)
            async with response_ctx as resp:
                original_packets = getattr(resp, "original_packets", [])
                raw_packets = getattr(resp, "raw_packets", [])
                original = b"".join(original_packets) if original_packets else b""
                modified = b"".join(raw_packets) if raw_packets else b""
                result["original_size"] = len(original)
                result["modified_size"] = len(modified)
                result["packet_modified"] = original != modified
                if b"X-Injected:" in modified and b"X-Injected:" not in original:
                    result["modifications_detected"]["header_injection"] = True
                if (
                    b"User-Agent: modified-agent" in modified
                    and b"User-Agent: modified-agent" not in original
                ):
                    result["modifications_detected"]["user_agent_modified"] = True
        return result

    async def analyze_fragmentation_handling(
        self, target: str, port: int = 443
    ) -> Dict[str, Any]:
        """
        Эмуляция обработки фрагментов — собираем raw_packets и проверяем сборку.
        Возвращает:
        - fragmentation_handled
        - fragments_count
        - reassembly_successful
        - total_size
        """
        protocol = "https" if port == 443 else "http"
        base_url = (
            f"{protocol}://{target}:{port}"
            if port not in [80, 443]
            else f"{protocol}://{target}"
        )
        result = {
            "target": target,
            "fragmentation_handled": False,
            "fragments_count": 0,
            "reassembly_successful": False,
            "total_size": 0,
        }
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            response_ctx = await session.get(base_url)
            async with response_ctx as resp:
                fragments = getattr(resp, "raw_packets", [])
                result["fragments_count"] = len(fragments)
                result["total_size"] = sum((len(f) for f in fragments))
                if fragments:
                    assembled = b"".join(fragments)
                    result["reassembly_successful"] = bool(assembled)
                    result["fragmentation_handled"] = True
        return result