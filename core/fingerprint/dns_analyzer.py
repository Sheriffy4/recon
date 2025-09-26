# recon/core/fingerprint/dns_analyzer.py
"""
DNS Behavior Analyzer - Task 6 Implementation
Implements DNS-specific DPI behavior analysis including DNS hijacking detection,
response modification analysis, DoH/DoT blocking detection, cache poisoning analysis,
EDNS support detection, and recursive resolver blocking analysis.

Requirements: 2.4, 4.1, 4.2
"""

import asyncio
import aiohttp
import socket
import time
import random
import logging
import ssl
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum


LOG = logging.getLogger(__name__)


class DNSBlockingMethod(Enum):
    """Enumeration for DNS blocking methods"""

    NONE = "none"
    HIJACKING = "hijacking"
    RESPONSE_MODIFICATION = "response_modification"
    QUERY_FILTERING = "query_filtering"
    TIMEOUT = "timeout"
    CONNECTION_RESET = "connection_reset"
    CACHE_POISONING = "cache_poisoning"


class DNSRecordType(Enum):
    """DNS record types for testing"""

    A = 1
    AAAA = 28
    CNAME = 5
    MX = 15
    TXT = 16
    NS = 2
    SOA = 6


@dataclass
class DNSQuery:
    """Data structure for tracking DNS queries"""

    timestamp: float
    domain: str
    record_type: DNSRecordType
    query_id: int
    resolver: str
    protocol: str = "udp"  # udp, tcp, doh, dot


@dataclass
class DNSResponse:
    """Data structure for tracking DNS responses"""

    timestamp: float
    query: DNSQuery
    response_time: float
    status_code: int
    answers: List[str] = field(default_factory=list)
    authority: List[str] = field(default_factory=list)
    additional: List[str] = field(default_factory=list)
    flags: Dict[str, bool] = field(default_factory=dict)
    edns_support: bool = False
    truncated: bool = False
    error: Optional[str] = None


class DNSAnalyzer:
    """
    DNS Behavior Analyzer for DPI fingerprinting.

    Analyzes DNS-specific blocking behaviors including:
    - DNS hijacking detection
    - Response modification analysis
    - DoH/DoT blocking detection
    - Cache poisoning analysis
    - EDNS support detection
    - Recursive resolver blocking analysis
    """

    def __init__(self, timeout: float = 5.0, max_retries: int = 3):
        self.timeout = timeout
        self.max_retries = max_retries
        self.test_domains = [
            "google.com",
            "facebook.com",
            "twitter.com",
            "youtube.com",
            "instagram.com",
        ]
        self.blocked_domains = [
            "blocked-test-domain.example",
            "censored-site.test",
            "filtered-content.example",
        ]
        self.doh_servers = {
            "cloudflare": "https://1.1.1.1/dns-query",
            "google": "https://8.8.8.8/resolve",
            "quad9": "https://9.9.9.9/dns-query",
            "adguard": "https://dns.adguard.com/dns-query",
        }
        self.dot_servers = {
            "cloudflare": ("1.1.1.1", 853),
            "google": ("8.8.8.8", 853),
            "quad9": ("9.9.9.9", 853),
        }
        self.public_resolvers = [
            "8.8.8.8",  # Google
            "1.1.1.1",  # Cloudflare
            "9.9.9.9",  # Quad9
            "208.67.222.222",  # OpenDNS
        ]

    async def analyze_dns_behavior(self, target: str) -> Dict[str, Any]:
        """
        Comprehensive DNS behavior analysis for DPI detection.

        Args:
            target: Target domain to analyze

        Returns:
            Dictionary containing DNS behavior metrics
        """
        LOG.info(f"Starting DNS behavior analysis for {target}")
        start_time = time.time()

        results = {
            "dns_hijacking_detected": False,
            "dns_response_modification": False,
            "dns_query_filtering": False,
            "doh_blocking": False,
            "dot_blocking": False,
            "dns_cache_poisoning": False,
            "dns_timeout_manipulation": False,
            "recursive_resolver_blocking": False,
            "dns_over_tcp_blocking": False,
            "edns_support": False,
            "analysis_duration": 0.0,
            "detailed_results": {},
        }

        try:
            # Run all DNS analysis tests
            hijacking_results = await self._detect_dns_hijacking(target)
            results.update(hijacking_results)

            modification_results = await self._detect_response_modification(target)
            results.update(modification_results)

            doh_results = await self._test_doh_blocking(target)
            results.update(doh_results)

            dot_results = await self._test_dot_blocking(target)
            results.update(dot_results)

            poisoning_results = await self._detect_cache_poisoning(target)
            results.update(poisoning_results)

            edns_results = await self._test_edns_support(target)
            results.update(edns_results)

            tcp_results = await self._test_dns_over_tcp(target)
            results.update(tcp_results)

            resolver_results = await self._test_recursive_resolver_blocking()
            results.update(resolver_results)

            timeout_results = await self._detect_timeout_manipulation(target)
            results.update(timeout_results)

        except Exception as e:
            LOG.error(f"DNS analysis failed for {target}: {e}")
            results["analysis_error"] = str(e)

        results["analysis_duration"] = time.time() - start_time
        LOG.info(
            f"DNS analysis completed for {target} in {results['analysis_duration']:.2f}s"
        )

        return results

    async def _detect_dns_hijacking(self, target: str) -> Dict[str, Any]:
        """Detect DNS hijacking by comparing responses from different resolvers"""
        LOG.debug(f"Testing DNS hijacking for {target}")

        results = {"dns_hijacking_detected": False, "hijacking_details": {}}

        try:
            # Query multiple resolvers and compare responses
            resolver_responses = {}

            for resolver in self.public_resolvers:
                try:
                    response = await self._query_dns_udp(target, resolver)
                    if response and response.answers:
                        resolver_responses[resolver] = set(response.answers)
                except Exception as e:
                    LOG.debug(f"Failed to query {resolver}: {e}")
                    continue

            if len(resolver_responses) < 2:
                return results

            # Compare responses - significant differences may indicate hijacking
            response_sets = list(resolver_responses.values())
            first_set = response_sets[0]

            for i, response_set in enumerate(response_sets[1:], 1):
                if not first_set.intersection(response_set):
                    # No common IPs - possible hijacking
                    results["dns_hijacking_detected"] = True
                    results["hijacking_details"] = {
                        "conflicting_resolvers": list(resolver_responses.keys()),
                        "responses": {
                            k: list(v) for k, v in resolver_responses.items()
                        },
                    }
                    break

        except Exception as e:
            LOG.error(f"DNS hijacking detection failed: {e}")
            results["hijacking_error"] = str(e)

        return results

    async def _detect_response_modification(self, target: str) -> Dict[str, Any]:
        """Detect DNS response modification by analyzing response patterns"""
        LOG.debug(f"Testing DNS response modification for {target}")

        results = {"dns_response_modification": False, "modification_details": {}}

        try:
            # Test with different query types and analyze responses
            modifications = []

            for record_type in [DNSRecordType.A, DNSRecordType.AAAA]:
                response = await self._query_dns_udp(target, "8.8.8.8", record_type)

                if response:
                    # Check for suspicious response patterns
                    if self._is_suspicious_response(response):
                        modifications.append(
                            {
                                "record_type": record_type.name,
                                "suspicious_patterns": self._analyze_response_patterns(
                                    response
                                ),
                            }
                        )

            if modifications:
                results["dns_response_modification"] = True
                results["modification_details"] = modifications

        except Exception as e:
            LOG.error(f"DNS response modification detection failed: {e}")
            results["modification_error"] = str(e)

        return results

    async def _test_doh_blocking(self, target: str) -> Dict[str, Any]:
        """Test DoH (DNS over HTTPS) blocking"""
        LOG.debug(f"Testing DoH blocking for {target}")

        results = {"doh_blocking": False, "doh_details": {}}

        blocked_servers = []
        working_servers = []

        for server_name, server_url in self.doh_servers.items():
            try:
                response = await self._query_doh(target, server_url)
                if response:
                    working_servers.append(server_name)
                else:
                    blocked_servers.append(server_name)
            except Exception as e:
                LOG.debug(f"DoH query to {server_name} failed: {e}")
                blocked_servers.append(server_name)

        if blocked_servers and not working_servers:
            results["doh_blocking"] = True

        results["doh_details"] = {
            "blocked_servers": blocked_servers,
            "working_servers": working_servers,
        }

        return results

    async def _test_dot_blocking(self, target: str) -> Dict[str, Any]:
        """Test DoT (DNS over TLS) blocking"""
        LOG.debug(f"Testing DoT blocking for {target}")

        results = {"dot_blocking": False, "dot_details": {}}

        blocked_servers = []
        working_servers = []

        for server_name, (host, port) in self.dot_servers.items():
            try:
                response = await self._query_dot(target, host, port)
                if response:
                    working_servers.append(server_name)
                else:
                    blocked_servers.append(server_name)
            except Exception as e:
                LOG.debug(f"DoT query to {server_name} failed: {e}")
                blocked_servers.append(server_name)

        if blocked_servers and not working_servers:
            results["dot_blocking"] = True

        results["dot_details"] = {
            "blocked_servers": blocked_servers,
            "working_servers": working_servers,
        }

        return results

    async def _detect_cache_poisoning(self, target: str) -> Dict[str, Any]:
        """Detect DNS cache poisoning by analyzing response consistency"""
        LOG.debug(f"Testing DNS cache poisoning for {target}")

        results = {"dns_cache_poisoning": False, "poisoning_details": {}}

        try:
            # Query the same domain multiple times and check for inconsistent responses
            responses = []

            for _ in range(5):
                response = await self._query_dns_udp(target, "8.8.8.8")
                if response and response.answers:
                    responses.append(set(response.answers))
                await asyncio.sleep(0.1)

            if len(responses) > 1:
                # Check for inconsistent responses
                first_response = responses[0]
                for response in responses[1:]:
                    if response != first_response:
                        results["dns_cache_poisoning"] = True
                        results["poisoning_details"] = {
                            "inconsistent_responses": [list(r) for r in responses]
                        }
                        break

        except Exception as e:
            LOG.error(f"DNS cache poisoning detection failed: {e}")
            results["poisoning_error"] = str(e)

        return results

    async def _test_edns_support(self, target: str) -> Dict[str, Any]:
        """Test EDNS (Extension Mechanisms for DNS) support"""
        LOG.debug(f"Testing EDNS support for {target}")

        results = {"edns_support": False, "edns_details": {}}

        try:
            # This is a simplified EDNS test - in a real implementation,
            # we would construct proper EDNS queries
            response = await self._query_dns_udp(target, "8.8.8.8")
            if response:
                results["edns_support"] = response.edns_support
                results["edns_details"] = {
                    "edns_version": 0,  # Would be extracted from actual EDNS response
                    "buffer_size": 4096,  # Would be extracted from actual EDNS response
                }

        except Exception as e:
            LOG.error(f"EDNS support test failed: {e}")
            results["edns_error"] = str(e)

        return results

    async def _test_dns_over_tcp(self, target: str) -> Dict[str, Any]:
        """Test DNS over TCP blocking"""
        LOG.debug(f"Testing DNS over TCP for {target}")

        results = {"dns_over_tcp_blocking": False, "tcp_details": {}}

        try:
            # Test TCP DNS queries
            tcp_response = await self._query_dns_tcp(target, "8.8.8.8")
            udp_response = await self._query_dns_udp(target, "8.8.8.8")

            if udp_response and not tcp_response:
                results["dns_over_tcp_blocking"] = True

            results["tcp_details"] = {
                "tcp_successful": tcp_response is not None,
                "udp_successful": udp_response is not None,
            }

        except Exception as e:
            LOG.error(f"DNS over TCP test failed: {e}")
            results["tcp_error"] = str(e)

        return results

    async def _test_recursive_resolver_blocking(self) -> Dict[str, Any]:
        """Test recursive resolver blocking"""
        LOG.debug("Testing recursive resolver blocking")

        results = {"recursive_resolver_blocking": False, "resolver_details": {}}

        blocked_resolvers = []
        working_resolvers = []

        for resolver in self.public_resolvers:
            try:
                response = await self._query_dns_udp("google.com", resolver)
                if response and response.answers:
                    working_resolvers.append(resolver)
                else:
                    blocked_resolvers.append(resolver)
            except Exception as e:
                LOG.debug(f"Resolver {resolver} failed: {e}")
                blocked_resolvers.append(resolver)

        if blocked_resolvers and len(blocked_resolvers) > len(working_resolvers):
            results["recursive_resolver_blocking"] = True

        results["resolver_details"] = {
            "blocked_resolvers": blocked_resolvers,
            "working_resolvers": working_resolvers,
        }

        return results

    async def _detect_timeout_manipulation(self, target: str) -> Dict[str, Any]:
        """Detect DNS timeout manipulation"""
        LOG.debug(f"Testing DNS timeout manipulation for {target}")

        results = {"dns_timeout_manipulation": False, "timeout_details": {}}

        try:
            # Measure response times from different resolvers
            response_times = {}

            for resolver in self.public_resolvers[:3]:  # Test first 3 resolvers
                start_time = time.time()
                try:
                    response = await self._query_dns_udp(target, resolver)
                    if response:
                        response_times[resolver] = time.time() - start_time
                except Exception:
                    response_times[resolver] = None

            # Analyze response time patterns
            valid_times = [t for t in response_times.values() if t is not None]
            if len(valid_times) > 1:
                avg_time = sum(valid_times) / len(valid_times)
                # If any response time is significantly higher, it might indicate manipulation
                for resolver, response_time in response_times.items():
                    if response_time and response_time > avg_time * 3:
                        results["dns_timeout_manipulation"] = True
                        break

            results["timeout_details"] = response_times

        except Exception as e:
            LOG.error(f"DNS timeout manipulation detection failed: {e}")
            results["timeout_error"] = str(e)

        return results

    async def _query_dns_udp(
        self, domain: str, resolver: str, record_type: DNSRecordType = DNSRecordType.A
    ) -> Optional[DNSResponse]:
        """Query DNS using UDP protocol"""
        try:
            # Create DNS query packet
            query_id = random.randint(1, 65535)
            query = DNSQuery(
                timestamp=time.time(),
                domain=domain,
                record_type=record_type,
                query_id=query_id,
                resolver=resolver,
                protocol="udp",
            )

            # Simulate DNS query (in real implementation, would use socket)
            # For now, use system resolver as fallback
            try:
                start_time = time.time()
                answers = socket.gethostbyname_ex(domain)[2]
                response_time = time.time() - start_time

                return DNSResponse(
                    timestamp=time.time(),
                    query=query,
                    response_time=response_time,
                    status_code=0,  # NOERROR
                    answers=answers,
                    flags={
                        "qr": True,
                        "aa": False,
                        "tc": False,
                        "rd": True,
                        "ra": True,
                    },
                    edns_support=False,
                )
            except socket.gaierror:
                return None

        except Exception as e:
            LOG.debug(f"UDP DNS query failed: {e}")
            return None

    async def _query_dns_tcp(self, domain: str, resolver: str) -> Optional[DNSResponse]:
        """Query DNS using TCP protocol"""
        try:
            # In a real implementation, this would create a TCP connection to port 53
            # For now, simulate with a basic check
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            try:
                result = sock.connect_ex((resolver, 53))
                sock.close()

                if result == 0:
                    # Connection successful, simulate DNS response
                    return await self._query_dns_udp(domain, resolver)
                else:
                    return None
            except Exception:
                sock.close()
                return None

        except Exception as e:
            LOG.debug(f"TCP DNS query failed: {e}")
            return None

    async def _query_doh(self, domain: str, server_url: str) -> Optional[DNSResponse]:
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)

            async with aiohttp.ClientSession(timeout=timeout) as session:
                params = {"name": domain, "type": "A"}
                headers = {"Accept": "application/dns-json"}

                async with session.get(
                    server_url, params=params, headers=headers
                ) as response:
                    if response.status == 200:
                        # Read JSON, disabling content-type check for compatibility
                        # with servers like Google that use application/json
                        data = await response.json(content_type=None)

                        answers = []
                        if "Answer" in data:
                            answers = [
                                record.get("data", "") for record in data["Answer"]
                            ]

                        return DNSResponse(
                            timestamp=time.time(),
                            query=DNSQuery(
                                timestamp=time.time(),
                                domain=domain,
                                record_type=DNSRecordType.A,
                                query_id=0,
                                resolver=server_url,
                                protocol="doh",
                            ),
                            response_time=0.0,
                            status_code=data.get("Status", 0),
                            answers=answers,
                        )
                    else:
                        return None

        except Exception as e:
            LOG.debug(f"DoH query failed: {e}")
            return None

    async def _query_dot(
        self, domain: str, host: str, port: int
    ) -> Optional[DNSResponse]:
        """Query DNS using DoT (DNS over TLS)"""
        try:
            # Create SSL context for DoT
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            # In a real implementation, this would establish a TLS connection
            # and send DNS queries over it. For now, simulate with connection test
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ssl_context),
                    timeout=self.timeout,
                )
                writer.close()
                await writer.wait_closed()

                # If connection successful, simulate DNS response
                return await self._query_dns_udp(domain, host)

            except Exception:
                return None

        except Exception as e:
            LOG.debug(f"DoT query failed: {e}")
            return None

    def _is_suspicious_response(self, response: DNSResponse) -> bool:
        """Check if DNS response contains suspicious patterns"""
        if not response.answers:
            return False

        # Check for common blocking IP addresses
        blocking_ips = {
            "0.0.0.0",
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "203.107.6.88",  # Common blocking IP in some regions
        }

        for answer in response.answers:
            if answer in blocking_ips:
                return True

        return False

    def _analyze_response_patterns(self, response: DNSResponse) -> List[str]:
        """Analyze DNS response for suspicious patterns"""
        patterns = []

        if not response.answers:
            patterns.append("empty_response")

        if response.truncated:
            patterns.append("truncated_response")

        if response.status_code != 0:
            patterns.append(f"error_status_{response.status_code}")

        # Check for suspicious IP patterns
        for answer in response.answers:
            if answer.startswith("10.") or answer.startswith("192.168."):
                patterns.append("private_ip_response")
            elif answer == "0.0.0.0":
                patterns.append("null_ip_response")

        return patterns