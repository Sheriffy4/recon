# core/dns/robust_dns_handler.py
import socket
import logging
import time
from typing import Optional, List, Set, Dict, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from ..doh_resolver import DoHResolver

LOG = logging.getLogger("RobustDNSHandler")


@dataclass
class DNSResolutionResult:
    """Result of DNS resolution attempt."""

    domain: str
    ip: Optional[str]
    method: str
    success: bool
    error: Optional[str] = None
    latency_ms: Optional[float] = None


class RobustDNSHandler:
    """
    Robust DNS resolution handler with multiple fallback methods.
    Handles DNS resolution failures gracefully without stopping service.
    """

    def __init__(self, timeout: float = 5.0, max_retries: int = 3):
        self.timeout = timeout
        self.max_retries = max_retries
        self.cache: Dict[str, str] = {}
        self.cache_lock = threading.Lock()

        # Initialize DoH resolvers with different providers
        self.doh_resolvers = {
            "cloudflare": DoHResolver("cloudflare"),
            "google": DoHResolver("google"),
            "quad9": DoHResolver("quad9"),
        }

        # Resolution method priority order
        self.resolution_methods = [
            self._resolve_via_doh_cloudflare,
            self._resolve_via_doh_google,
            self._resolve_via_doh_quad9,
            self._resolve_via_system_dns,
            self._resolve_via_getaddrinfo,
        ]

    def resolve_with_fallback(self, domain: str) -> Optional[str]:
        """
        Resolve domain with multiple fallback methods.
        Returns IP address or None if all methods fail.
        """
        # Check cache first
        with self.cache_lock:
            if domain in self.cache:
                LOG.debug(f"DNS cache hit for {domain}: {self.cache[domain]}")
                return self.cache[domain]

        LOG.info(f"Resolving domain: {domain}")

        # Try each resolution method
        for method in self.resolution_methods:
            try:
                result = method(domain)
                if result.success and result.ip:
                    # Cache successful result
                    with self.cache_lock:
                        self.cache[domain] = result.ip

                    LOG.info(
                        f"Successfully resolved {domain} -> {result.ip} via {result.method} "
                        f"(latency: {result.latency_ms:.1f}ms)"
                    )
                    return result.ip
                else:
                    LOG.debug(
                        f"Failed to resolve {domain} via {result.method}: {result.error}"
                    )

            except Exception as e:
                LOG.warning(
                    f"DNS resolution method {method.__name__} failed for {domain}: {e}"
                )
                continue

        LOG.error(f"All DNS resolution methods failed for domain: {domain}")
        return None

    def resolve_multiple_domains(
        self, domains: List[str], max_workers: int = 10
    ) -> Dict[str, Optional[str]]:
        """
        Resolve multiple domains concurrently.
        Returns dict mapping domain to IP (or None if failed).
        """
        results = {}

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all resolution tasks
            future_to_domain = {
                executor.submit(self.resolve_with_fallback, domain): domain
                for domain in domains
            }

            # Collect results as they complete
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    ip = future.result()
                    results[domain] = ip
                except Exception as e:
                    LOG.error(
                        f"Exception during concurrent resolution of {domain}: {e}"
                    )
                    results[domain] = None

        return results

    def validate_ip_resolution(self, domain: str, ip: str) -> bool:
        """
        Validate that IP resolution result is valid with correct private range checks.
        """
        if not ip:
            return False

        try:
            # Use ipaddress module for robust IP validation
            import ipaddress

            addr = ipaddress.ip_address(ip)
        except (ValueError, ImportError):
            # Fallback to socket if ipaddress is not available or IP is invalid
            try:
                socket.inet_aton(ip)
            except socket.error:
                LOG.warning(f"Invalid IP format for {domain}: {ip}")
                return False
            # Cannot perform private check without ipaddress module
            return True

        # Check if IP is private, loopback, or reserved, unless it's for a local domain
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_multicast
            or addr.is_unspecified
        ):
            if not domain.endswith((".local", ".lan", ".internal", ".test")):
                LOG.warning(
                    f"Suspicious private/loopback IP {ip} for public domain {domain}"
                )
                return False

        return True

    def _resolve_via_doh_cloudflare(self, domain: str) -> DNSResolutionResult:
        """Resolve via Cloudflare DoH."""
        return self._resolve_via_doh(domain, "cloudflare")

    def _resolve_via_doh_google(self, domain: str) -> DNSResolutionResult:
        """Resolve via Google DoH."""
        return self._resolve_via_doh(domain, "google")

    def _resolve_via_doh_quad9(self, domain: str) -> DNSResolutionResult:
        """Resolve via Quad9 DoH."""
        return self._resolve_via_doh(domain, "quad9")

    def _resolve_via_doh(self, domain: str, provider: str) -> DNSResolutionResult:
        """Generic DoH resolution method."""
        start_time = time.time()

        try:
            resolver = self.doh_resolvers[provider]
            ip = resolver.resolve(domain)
            latency_ms = (time.time() - start_time) * 1000

            if ip and self.validate_ip_resolution(domain, ip):
                return DNSResolutionResult(
                    domain=domain,
                    ip=ip,
                    method=f"DoH-{provider}",
                    success=True,
                    latency_ms=latency_ms,
                )
            else:
                return DNSResolutionResult(
                    domain=domain,
                    ip=None,
                    method=f"DoH-{provider}",
                    success=False,
                    error="Invalid or empty IP result",
                    latency_ms=latency_ms,
                )

        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            return DNSResolutionResult(
                domain=domain,
                ip=None,
                method=f"DoH-{provider}",
                success=False,
                error=str(e),
                latency_ms=latency_ms,
            )

    def _resolve_via_system_dns(self, domain: str) -> DNSResolutionResult:
        """Resolve via system DNS (gethostbyname)."""
        start_time = time.time()

        try:
            ip = socket.gethostbyname(domain)
            latency_ms = (time.time() - start_time) * 1000

            if self.validate_ip_resolution(domain, ip):
                return DNSResolutionResult(
                    domain=domain,
                    ip=ip,
                    method="system-dns",
                    success=True,
                    latency_ms=latency_ms,
                )
            else:
                return DNSResolutionResult(
                    domain=domain,
                    ip=None,
                    method="system-dns",
                    success=False,
                    error="Invalid IP result",
                    latency_ms=latency_ms,
                )

        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            return DNSResolutionResult(
                domain=domain,
                ip=None,
                method="system-dns",
                success=False,
                error=str(e),
                latency_ms=latency_ms,
            )

    def _resolve_via_getaddrinfo(self, domain: str) -> DNSResolutionResult:
        """Resolve via getaddrinfo (most comprehensive)."""
        start_time = time.time()

        try:
            addr_info = socket.getaddrinfo(
                domain, 443, socket.AF_INET, socket.SOCK_STREAM
            )
            if addr_info:
                # Get the first IP address
                ip = addr_info[0][4][0]
                latency_ms = (time.time() - start_time) * 1000

                if self.validate_ip_resolution(domain, ip):
                    return DNSResolutionResult(
                        domain=domain,
                        ip=ip,
                        method="getaddrinfo",
                        success=True,
                        latency_ms=latency_ms,
                    )
                else:
                    return DNSResolutionResult(
                        domain=domain,
                        ip=None,
                        method="getaddrinfo",
                        success=False,
                        error="Invalid IP result",
                        latency_ms=latency_ms,
                    )
            else:
                latency_ms = (time.time() - start_time) * 1000
                return DNSResolutionResult(
                    domain=domain,
                    ip=None,
                    method="getaddrinfo",
                    success=False,
                    error="No address info returned",
                    latency_ms=latency_ms,
                )

        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            return DNSResolutionResult(
                domain=domain,
                ip=None,
                method="getaddrinfo",
                success=False,
                error=str(e),
                latency_ms=latency_ms,
            )

    def clear_cache(self):
        """Clear DNS resolution cache."""
        with self.cache_lock:
            self.cache.clear()
        LOG.info("DNS cache cleared")

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get DNS cache statistics."""
        with self.cache_lock:
            return {
                "cache_size": len(self.cache),
                "cached_domains": list(self.cache.keys()),
            }
