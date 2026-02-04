#!/usr/bin/env python3
"""
Validation method implementations for reliability checking.

This module contains individual validation methods that can be used
to check domain accessibility and bypass effectiveness.
"""

import asyncio
import hashlib
import socket
import ssl
import time
from typing import Dict, Any

import aiohttp
import dns.resolver

from .types import ValidationMethod, ValidationResult


async def validate_http_response(domain: str, port: int, timeout: float) -> ValidationResult:
    """Validate HTTP response accessibility."""
    start_time = time.monotonic()
    url = f"{'https' if port == 443 else 'http'}://{domain}"

    try:
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=client_timeout) as session:
            async with session.get(url) as response:
                content = await response.text(errors="ignore")
                response_time = time.monotonic() - start_time

                # Check for blocking indicators
                blocking_indicators = [
                    "blocked",
                    "forbidden",
                    "access denied",
                    "not available",
                    "restricted",
                    "censored",
                    "filtered",
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
                        "headers": dict(response.headers),
                        "content_hash": hashlib.md5(content.encode()).hexdigest()[:16],
                        "blocking_detected": is_blocked,
                    },
                )

    except asyncio.TimeoutError:
        response_time = time.monotonic() - start_time
        return ValidationResult(
            method=ValidationMethod.HTTP_RESPONSE,
            success=False,
            response_time=response_time,
            error_message="Request timeout",
        )
    except aiohttp.ClientError as e:
        response_time = time.monotonic() - start_time
        return ValidationResult(
            method=ValidationMethod.HTTP_RESPONSE,
            success=False,
            response_time=response_time,
            error_message=f"Client error: {str(e)}",
        )
    except Exception as e:
        response_time = time.monotonic() - start_time
        return ValidationResult(
            method=ValidationMethod.HTTP_RESPONSE,
            success=False,
            response_time=response_time,
            error_message=str(e),
        )


async def validate_content_check(
    domain: str, port: int, timeout: float, content_similarity_threshold: float = 0.8
) -> ValidationResult:
    """Validate content consistency and authenticity."""
    start_time = time.monotonic()
    url = f"{'https' if port == 443 else 'http'}://{domain}"

    try:
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=client_timeout) as session:
            # Make multiple requests to check consistency
            contents = []
            for _ in range(3):
                async with session.get(url) as response:
                    if response.status == 200:
                        content = await response.text(errors="ignore")
                        contents.append(content)
                    await asyncio.sleep(0.1)

            response_time = time.monotonic() - start_time

            if len(contents) < 2:
                return ValidationResult(
                    method=ValidationMethod.CONTENT_CHECK,
                    success=False,
                    response_time=response_time,
                    error_message="Insufficient responses for content check",
                )

            # Check content consistency
            content_hashes = [hashlib.md5(c.encode()).hexdigest() for c in contents]
            unique_hashes = set(content_hashes)
            consistency_rate = 1.0 - (len(unique_hashes) - 1) / len(contents)

            # Check for expected content patterns
            expected_patterns = ["<!DOCTYPE", "<html", "<head", "<body"]
            has_expected_content = any(
                any(pattern in content for pattern in expected_patterns) for content in contents
            )

            success = consistency_rate >= content_similarity_threshold and has_expected_content

            return ValidationResult(
                method=ValidationMethod.CONTENT_CHECK,
                success=success,
                response_time=response_time,
                metadata={
                    "consistency_rate": consistency_rate,
                    "unique_content_hashes": len(unique_hashes),
                    "has_expected_content": has_expected_content,
                    "content_lengths": [len(c) for c in contents],
                },
            )

    except aiohttp.ClientError as e:
        response_time = time.monotonic() - start_time
        return ValidationResult(
            method=ValidationMethod.CONTENT_CHECK,
            success=False,
            response_time=response_time,
            error_message=f"Client error: {str(e)}",
        )
    except Exception as e:
        response_time = time.monotonic() - start_time
        return ValidationResult(
            method=ValidationMethod.CONTENT_CHECK,
            success=False,
            response_time=response_time,
            error_message=str(e),
        )


async def validate_timing_analysis(
    domain: str, port: int, timeout: float, max_response_time: float = 10.0
) -> ValidationResult:
    """Validate response timing patterns."""
    start_time = time.monotonic()
    url = f"{'https' if port == 443 else 'http'}://{domain}"

    try:
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=client_timeout) as session:
            # Measure multiple request timings
            timings = []
            for _ in range(5):
                request_start = time.monotonic()
                async with session.get(url) as response:
                    await response.read()
                    request_time = time.monotonic() - request_start
                    timings.append(request_time)
                await asyncio.sleep(0.1)

            response_time = time.monotonic() - start_time

            # Analyze timing patterns
            import statistics

            avg_timing = statistics.mean(timings)
            timing_variance = statistics.stdev(timings) if len(timings) > 1 else 0.0

            # Check for suspicious timing patterns
            suspicious_patterns = [
                avg_timing > max_response_time,  # Too slow
                timing_variance > avg_timing * 0.5,  # High variance
                any(t > timeout * 0.8 for t in timings),  # Near-timeout responses
            ]

            success = not any(suspicious_patterns) and avg_timing < max_response_time

            return ValidationResult(
                method=ValidationMethod.TIMING_ANALYSIS,
                success=success,
                response_time=response_time,
                metadata={
                    "average_timing": avg_timing,
                    "timing_variance": timing_variance,
                    "individual_timings": timings,
                    "suspicious_patterns": suspicious_patterns,
                },
            )

    except aiohttp.ClientError as e:
        response_time = time.monotonic() - start_time
        return ValidationResult(
            method=ValidationMethod.TIMING_ANALYSIS,
            success=False,
            response_time=response_time,
            error_message=f"Client error: {str(e)}",
        )
    except Exception as e:
        response_time = time.monotonic() - start_time
        return ValidationResult(
            method=ValidationMethod.TIMING_ANALYSIS,
            success=False,
            response_time=response_time,
            error_message=str(e),
        )


async def validate_multi_request(
    domain: str, port: int, timeout: float, min_success_rate: float = 0.7
) -> ValidationResult:
    """Validate multiple concurrent requests."""
    start_time = time.monotonic()
    url = f"{'https' if port == 443 else 'http'}://{domain}"

    try:
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=client_timeout) as session:

            async def _one_request() -> Any:
                try:
                    async with session.get(url) as resp:
                        await resp.read()  # ensure connection is released back to pool
                        return resp.status
                except Exception as e:
                    return e

            responses = await asyncio.gather(
                *(_one_request() for _ in range(3)), return_exceptions=False
            )
            response_time = time.monotonic() - start_time

            successful = 0
            for r in responses:
                if isinstance(r, Exception):
                    continue
                if r == 200:
                    successful += 1

            success_rate = successful / max(len(responses), 1)
            success = success_rate >= min_success_rate

            return ValidationResult(
                method=ValidationMethod.MULTI_REQUEST,
                success=success,
                response_time=response_time,
                metadata={
                    "success_rate": success_rate,
                    "successful_responses": successful,
                    "total_requests": len(responses),
                },
            )

    except aiohttp.ClientError as e:
        response_time = time.monotonic() - start_time
        return ValidationResult(
            method=ValidationMethod.MULTI_REQUEST,
            success=False,
            response_time=response_time,
            error_message=f"Client error: {str(e)}",
        )
    except Exception as e:
        response_time = time.monotonic() - start_time
        return ValidationResult(
            method=ValidationMethod.MULTI_REQUEST,
            success=False,
            response_time=response_time,
            error_message=str(e),
        )


async def validate_dns_resolution(
    domain: str, timeout: float, dns_cache: Dict[str, str], thread_pool, cache_lock=None
) -> ValidationResult:
    """Validate DNS resolution consistency with thread-safe cache access."""
    start_time = time.monotonic()

    try:
        # Check cache first (thread-safe)
        cached_ip = None
        if cache_lock:
            with cache_lock:
                cached_ip = dns_cache.get(domain)
        else:
            cached_ip = dns_cache.get(domain)

        if cached_ip:
            response_time = time.monotonic() - start_time
            return ValidationResult(
                method=ValidationMethod.DNS_RESOLUTION,
                success=True,
                response_time=response_time,
                metadata={"resolved_ip": cached_ip, "from_cache": True},
            )

        # Resolve DNS
        loop = asyncio.get_running_loop()
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        # Run DNS resolution in thread pool
        result = await loop.run_in_executor(thread_pool, lambda: resolver.resolve(domain, "A"))

        response_time = time.monotonic() - start_time

        if result:
            ip_addresses = [str(rdata) for rdata in result]
            primary_ip = ip_addresses[0]

            # Cache the result (thread-safe)
            if cache_lock:
                with cache_lock:
                    dns_cache[domain] = primary_ip
            else:
                dns_cache[domain] = primary_ip

            return ValidationResult(
                method=ValidationMethod.DNS_RESOLUTION,
                success=True,
                response_time=response_time,
                metadata={
                    "resolved_ips": ip_addresses,
                    "primary_ip": primary_ip,
                    "from_cache": False,
                },
            )
        else:
            return ValidationResult(
                method=ValidationMethod.DNS_RESOLUTION,
                success=False,
                response_time=response_time,
                error_message="No DNS records found",
            )

    except dns.resolver.NXDOMAIN:
        response_time = time.monotonic() - start_time
        return ValidationResult(
            method=ValidationMethod.DNS_RESOLUTION,
            success=False,
            response_time=response_time,
            error_message="Domain does not exist (NXDOMAIN)",
        )
    except dns.resolver.Timeout:
        response_time = time.monotonic() - start_time
        return ValidationResult(
            method=ValidationMethod.DNS_RESOLUTION,
            success=False,
            response_time=response_time,
            error_message="DNS resolution timeout",
        )
    except Exception as e:
        response_time = time.monotonic() - start_time
        return ValidationResult(
            method=ValidationMethod.DNS_RESOLUTION,
            success=False,
            response_time=response_time,
            error_message=str(e),
        )


async def validate_ssl_handshake(
    domain: str, port: int, timeout: float, thread_pool
) -> ValidationResult:
    """Validate SSL handshake for HTTPS connections."""
    start_time = time.monotonic()

    if port != 443:
        # Skip SSL validation for non-HTTPS ports
        return ValidationResult(
            method=ValidationMethod.SSL_HANDSHAKE,
            success=True,
            response_time=0.0,
            metadata={"skipped": "non_https_port"},
        )

    try:
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Perform SSL handshake
        loop = asyncio.get_running_loop()

        def ssl_handshake():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                sock.connect((domain, port))
                ssl_sock = context.wrap_socket(sock, server_hostname=domain)
                cert = ssl_sock.getpeercert()
                ssl_sock.close()
                return cert
            finally:
                sock.close()

        cert = await loop.run_in_executor(thread_pool, ssl_handshake)
        response_time = time.monotonic() - start_time

        success = cert is not None

        return ValidationResult(
            method=ValidationMethod.SSL_HANDSHAKE,
            success=success,
            response_time=response_time,
            metadata={
                "certificate_present": success,
                "certificate_subject": cert.get("subject", []) if cert else None,
            },
        )

    except ssl.SSLError as e:
        response_time = time.monotonic() - start_time
        return ValidationResult(
            method=ValidationMethod.SSL_HANDSHAKE,
            success=False,
            response_time=response_time,
            error_message=f"SSL error: {str(e)}",
        )
    except socket.timeout:
        response_time = time.monotonic() - start_time
        return ValidationResult(
            method=ValidationMethod.SSL_HANDSHAKE,
            success=False,
            response_time=response_time,
            error_message="SSL handshake timeout",
        )
    except Exception as e:
        response_time = time.monotonic() - start_time
        return ValidationResult(
            method=ValidationMethod.SSL_HANDSHAKE,
            success=False,
            response_time=response_time,
            error_message=str(e),
        )


async def validate_header_analysis(domain: str, port: int, timeout: float) -> ValidationResult:
    """Validate HTTP headers for authenticity."""
    start_time = time.monotonic()
    url = f"{'https' if port == 443 else 'http'}://{domain}"

    try:
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=client_timeout) as session:
            async with session.head(url) as response:
                response_time = time.monotonic() - start_time

                headers = dict(response.headers)

                # Check for expected headers
                expected_headers = ["server", "content-type", "date"]
                present_headers = [h.lower() for h in headers.keys()]
                expected_present = sum(1 for h in expected_headers if h in present_headers)

                # Check for blocking indicators in headers
                blocking_headers = ["x-blocked", "x-filtered", "x-censored"]
                blocking_detected = any(h in present_headers for h in blocking_headers)

                success = response.status == 200 and expected_present >= 2 and not blocking_detected

                return ValidationResult(
                    method=ValidationMethod.HEADER_ANALYSIS,
                    success=success,
                    response_time=response_time,
                    status_code=response.status,
                    metadata={
                        "headers": headers,
                        "expected_headers_present": expected_present,
                        "blocking_detected": blocking_detected,
                    },
                )

    except aiohttp.ClientError as e:
        response_time = time.monotonic() - start_time
        return ValidationResult(
            method=ValidationMethod.HEADER_ANALYSIS,
            success=False,
            response_time=response_time,
            error_message=f"Client error: {str(e)}",
        )
    except Exception as e:
        response_time = time.monotonic() - start_time
        return ValidationResult(
            method=ValidationMethod.HEADER_ANALYSIS,
            success=False,
            response_time=response_time,
            error_message=str(e),
        )


async def validate_payload_verification(domain: str, port: int, timeout: float) -> ValidationResult:
    """Validate payload integrity and authenticity."""
    start_time = time.monotonic()
    url = f"{'https' if port == 443 else 'http'}://{domain}"

    try:
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=client_timeout) as session:
            async with session.get(url) as response:
                content = await response.read()
                response_time = time.monotonic() - start_time

                # Basic payload validation
                content_length = len(content)

                # Check for minimum content length (avoid empty responses)
                min_content_length = 100

                # Check for binary vs text content
                try:
                    text_content = content.decode("utf-8")
                    is_text = True
                except UnicodeDecodeError:
                    is_text = False
                    text_content = ""

                # Check for HTML structure if text content
                has_html_structure = False
                if is_text:
                    html_tags = ["<html", "<head", "<body", "<!doctype"]
                    has_html_structure = any(tag in text_content.lower() for tag in html_tags)

                success = (
                    response.status == 200
                    and content_length >= min_content_length
                    and (has_html_structure or not is_text)
                )

                return ValidationResult(
                    method=ValidationMethod.PAYLOAD_VERIFICATION,
                    success=success,
                    response_time=response_time,
                    status_code=response.status,
                    content_length=content_length,
                    metadata={
                        "is_text_content": is_text,
                        "has_html_structure": has_html_structure,
                        "content_hash": hashlib.md5(content).hexdigest()[:16],
                    },
                )

    except aiohttp.ClientError as e:
        response_time = time.monotonic() - start_time
        return ValidationResult(
            method=ValidationMethod.PAYLOAD_VERIFICATION,
            success=False,
            response_time=response_time,
            error_message=f"Client error: {str(e)}",
        )
    except Exception as e:
        response_time = time.monotonic() - start_time
        return ValidationResult(
            method=ValidationMethod.PAYLOAD_VERIFICATION,
            success=False,
            response_time=response_time,
            error_message=str(e),
        )
