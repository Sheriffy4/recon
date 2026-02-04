#!/usr/bin/env python3
"""
Runtime IP Resolver

This module implements runtime IP-to-domain resolution with caching to support
dynamic CDN IP addresses that are not pre-resolved during service initialization.
"""

import socket
import time
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass
from threading import Lock, Thread
from collections import OrderedDict, deque

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Cache entry for IP-to-domain mapping."""

    domain: str
    timestamp: float  # Unix timestamp when cached
    ttl: int  # Time-to-live in seconds

    @property
    def expires_at(self) -> float:
        """Calculate expiration timestamp."""
        return self.timestamp + self.ttl

    def is_expired(self) -> bool:
        """Check if cache entry has expired."""
        return time.time() > self.expires_at


class RuntimeIPResolver:
    """
    Resolve IP addresses to domain names at runtime with caching.

    This resolver performs reverse DNS lookups for unknown IP addresses
    and maintains a cache with TTL-based expiration to minimize DNS queries.
    Implements LRU eviction when cache exceeds maximum size.
    """

    def __init__(
        self,
        cache_ttl: int = 300,
        max_cache_size: int = 1000,
        enable_periodic_logging: bool = True,
        log_interval: int = 60,
        dns_timeout: float = 2.0,
        max_lookups_per_second: int = 10,
    ):
        """
        Initialize the runtime IP resolver.

        Args:
            cache_ttl: Time-to-live for cache entries in seconds (default: 300)
            max_cache_size: Maximum number of entries in cache before LRU eviction (default: 1000)
            enable_periodic_logging: Enable periodic statistics logging (default: True)
            log_interval: Interval in seconds for periodic logging (default: 60)
            dns_timeout: Timeout for DNS lookups in seconds (default: 2.0)
            max_lookups_per_second: Maximum DNS lookups per second for rate limiting (default: 10)
        """
        self.cache_ttl = cache_ttl
        self.max_cache_size = max_cache_size
        self.enable_periodic_logging = enable_periodic_logging
        self.log_interval = log_interval
        self.dns_timeout = dns_timeout
        self.max_lookups_per_second = max_lookups_per_second

        # Use OrderedDict for LRU cache implementation
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = Lock()

        # Reverse DNS uses global socket default timeout; serialize and restore safely.
        self._dns_lock = Lock()

        # Rate limiting: track DNS lookup timestamps
        self._lookup_timestamps: deque = deque(maxlen=max_lookups_per_second)
        self._rate_limit_lock = Lock()

        # Statistics
        self._cache_hits = 0
        self._cache_misses = 0
        self._lookup_failures = 0
        self._evictions = 0
        self._rate_limited_requests = 0
        self._cache_corruption_errors = 0
        self._timeout_errors = 0

        # Periodic logging thread
        self._logging_thread = None
        self._stop_logging = False

        logger.info(
            "RuntimeIPResolver initialized: ttl=%ss max=%s dns_timeout=%ss rate=%s/s",
            cache_ttl, max_cache_size, dns_timeout, max_lookups_per_second
        )

        # Start periodic logging if enabled
        if self.enable_periodic_logging:
            self._start_periodic_logging()

    def _check_rate_limit(self) -> bool:
        """
        Check if DNS lookup is allowed based on rate limiting.

        Returns:
            True if lookup is allowed, False if rate limited
        """
        with self._rate_limit_lock:
            current_time = time.time()

            # Remove timestamps older than 1 second
            while self._lookup_timestamps and current_time - self._lookup_timestamps[0] > 1.0:
                self._lookup_timestamps.popleft()

            # Check if we've exceeded the rate limit
            if len(self._lookup_timestamps) >= self.max_lookups_per_second:
                with self._lock:
                    self._rate_limited_requests += 1
                logger.warning(
                    "⚠️ DNS lookup rate limit exceeded (%s/s), skipping lookup",
                    self.max_lookups_per_second,
                )
                return False

            # Add current timestamp
            self._lookup_timestamps.append(current_time)
            return True

    def resolve_ip_to_domain(self, ip_address: str) -> Optional[str]:
        """
        Resolve an IP address to a domain name.

        First checks cache, then performs reverse DNS lookup if not cached.
        Implements rate limiting and comprehensive error handling to ensure
        DNS operations don't block packet processing.

        Args:
            ip_address: IP address to resolve

        Returns:
            Domain name if resolved, None if resolution fails
        """
        # Validate IP address format
        if not ip_address or not isinstance(ip_address, str):
            logger.warning("⚠️ Invalid IP address format: %r", ip_address)
            return None

        # Check cache first
        try:
            cached_domain = self.get_cached_domain(ip_address)
            if cached_domain is not None:
                logger.debug(f"✅ Cache hit: {ip_address} → {cached_domain}")
                return cached_domain
        except Exception as e:
            # Handle cache corruption gracefully
            with self._lock:
                self._cache_corruption_errors += 1
            logger.error("❌ Cache corruption error for %s: %s, clearing entry", ip_address, e)
            # Try to remove corrupted entry
            try:
                with self._lock:
                    if ip_address in self._cache:
                        del self._cache[ip_address]
            except Exception:
                pass  # Ignore errors during cleanup

        # Cache miss - perform reverse DNS lookup
        with self._lock:
            self._cache_misses += 1

        # Check rate limit before performing DNS lookup
        if not self._check_rate_limit():
            logger.debug("⚠️ Rate limited: skipping DNS lookup for %s", ip_address)
            return None

        logger.debug("🔍 Cache miss: performing reverse DNS lookup for %s", ip_address)

        try:
            # Reverse DNS uses global timeout; guard with lock and restore previous value.
            with self._dns_lock:
                prev_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(self.dns_timeout)
                try:
                    hostname, _, _ = socket.gethostbyaddr(ip_address)
                finally:
                    socket.setdefaulttimeout(prev_timeout)

            # Validate hostname
            if not hostname or not isinstance(hostname, str):
                logger.warning(f"⚠️ Invalid hostname returned for {ip_address}: {hostname}")
                with self._lock:
                    self._lookup_failures += 1
                return None

            # Cache the result
            try:
                self._add_to_cache(ip_address, hostname)
            except Exception as e:
                # Log cache error but still return the resolved hostname
                logger.error("❌ Failed to cache result for %s: %s", ip_address, e)

            logger.info("✅ Resolved %s → %s", ip_address, hostname)
            return hostname

        except socket.herror as e:
            # DNS lookup failed (host not found)
            with self._lock:
                self._lookup_failures += 1
            logger.warning("❌ Reverse DNS lookup failed for %s: %s", ip_address, e)
            return None

        except socket.gaierror as e:
            # Address-related error
            with self._lock:
                self._lookup_failures += 1
            logger.warning("❌ Address resolution failed for %s: %s", ip_address, e)
            return None

        except socket.timeout:
            # Lookup timed out - don't block packet processing
            with self._lock:
                self._lookup_failures += 1
                self._timeout_errors += 1
            logger.warning(
                "❌ Reverse DNS lookup timed out for %s (timeout: %ss)",
                ip_address, self.dns_timeout,
            )
            return None

        except OSError as e:
            # Network or system error
            with self._lock:
                self._lookup_failures += 1
            logger.warning("❌ Network error resolving %s: %s", ip_address, e)
            return None

        except Exception as e:
            # Unexpected error - log and continue
            with self._lock:
                self._lookup_failures += 1
            logger.error(
                "❌ Unexpected error resolving %s: %s: %s",
                ip_address, type(e).__name__, e,
            )
            return None

    def get_cached_domain(self, ip_address: str) -> Optional[str]:
        """
        Get domain from cache without performing lookup.
        Handles cache corruption and invalid entries gracefully.

        Args:
            ip_address: IP address to look up

        Returns:
            Cached domain name if exists and not expired, None otherwise
        """
        with self._lock:
            try:
                entry = self._cache.get(ip_address)

                if entry is None:
                    return None

                # Validate cache entry structure
                if not isinstance(entry, CacheEntry):
                    logger.warning(f"⚠️ Invalid cache entry type for {ip_address}, removing")
                    del self._cache[ip_address]
                    self._cache_corruption_errors += 1
                    return None

                # Validate entry fields
                if (
                    not hasattr(entry, "domain")
                    or not hasattr(entry, "timestamp")
                    or not hasattr(entry, "ttl")
                ):
                    logger.warning(f"⚠️ Corrupted cache entry for {ip_address}, removing")
                    del self._cache[ip_address]
                    self._cache_corruption_errors += 1
                    return None

                # Validate domain value
                if not entry.domain or not isinstance(entry.domain, str):
                    logger.warning(f"⚠️ Invalid domain in cache entry for {ip_address}, removing")
                    del self._cache[ip_address]
                    self._cache_corruption_errors += 1
                    return None

                # Check if entry has expired
                try:
                    if entry.is_expired():
                        logger.debug(f"⏰ Cache entry expired for {ip_address}")
                        del self._cache[ip_address]
                        return None
                except Exception as e:
                    logger.warning(f"⚠️ Error checking expiration for {ip_address}: {e}, removing")
                    del self._cache[ip_address]
                    self._cache_corruption_errors += 1
                    return None

                # Move to end for LRU (most recently used)
                self._cache.move_to_end(ip_address)

                # Increment cache hits counter
                self._cache_hits += 1

                return entry.domain

            except Exception as e:
                # Handle any unexpected errors in cache access
                logger.error(f"❌ Unexpected error accessing cache for {ip_address}: {e}")
                self._cache_corruption_errors += 1
                # Try to remove corrupted entry
                try:
                    if ip_address in self._cache:
                        del self._cache[ip_address]
                except Exception:
                    pass  # Ignore errors during cleanup
                return None

    def _add_to_cache(self, ip_address: str, domain: str):
        """
        Add an IP-to-domain mapping to the cache.
        Implements LRU eviction when cache exceeds max_cache_size.
        Handles errors gracefully to prevent cache corruption.

        Args:
            ip_address: IP address
            domain: Resolved domain name
        """
        # Validate inputs
        if not ip_address or not isinstance(ip_address, str):
            logger.warning(f"⚠️ Invalid IP address for caching: {ip_address}")
            return

        if not domain or not isinstance(domain, str):
            logger.warning(f"⚠️ Invalid domain for caching: {domain}")
            return

        with self._lock:
            try:
                entry = CacheEntry(domain=domain, timestamp=time.time(), ttl=self.cache_ttl)

                # If IP already exists, update it (move to end)
                if ip_address in self._cache:
                    del self._cache[ip_address]

                self._cache[ip_address] = entry

                # Implement LRU eviction if cache exceeds max size
                while len(self._cache) > self.max_cache_size:
                    try:
                        # Remove oldest entry (first item in OrderedDict)
                        evicted_ip, evicted_entry = self._cache.popitem(last=False)
                        self._evictions += 1
                        logger.debug(f"🗑️ LRU eviction: {evicted_ip} → {evicted_entry.domain}")
                    except Exception as e:
                        logger.error(f"❌ Error during LRU eviction: {e}")
                        break  # Stop eviction to prevent infinite loop

                logger.debug(
                    f"💾 Cached IP-to-domain mapping: {ip_address} → {domain} (TTL: {self.cache_ttl}s)"
                )

            except Exception as e:
                logger.error(f"❌ Failed to add cache entry for {ip_address}: {e}")
                self._cache_corruption_errors += 1

    def clear_cache(self):
        """
        Clear all cached IP-to-domain mappings.
        Useful for troubleshooting and forcing fresh DNS lookups.
        Handles errors gracefully to ensure cache can be cleared even if corrupted.
        """
        with self._lock:
            try:
                cache_size = len(self._cache)
                self._cache.clear()
                logger.info(f"🗑️ Manually cleared cache ({cache_size} entries)")
            except Exception as e:
                logger.error(f"❌ Error clearing cache: {e}, recreating cache")
                # Recreate cache if clearing fails
                try:
                    self._cache = OrderedDict()
                    logger.info("✅ Cache recreated successfully")
                except Exception as e2:
                    logger.critical(f"❌ Failed to recreate cache: {e2}")

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get resolver statistics.
        Handles errors gracefully to ensure statistics can always be retrieved.

        Returns:
            Dictionary with cache_size, cache_hits, cache_misses, lookup_failures,
            hit_rate, miss_rate, evictions, rate_limited_requests, cache_corruption_errors,
            timeout_errors
        """
        with self._lock:
            try:
                # Clean up expired entries before reporting statistics
                expired_keys = []
                for ip, entry in list(self._cache.items()):
                    try:
                        if entry.is_expired():
                            expired_keys.append(ip)
                    except Exception as e:
                        logger.warning(
                            f"⚠️ Error checking expiration for {ip}: {e}, marking for removal"
                        )
                        expired_keys.append(ip)

                for ip in expired_keys:
                    try:
                        del self._cache[ip]
                    except Exception:
                        pass  # Ignore errors during cleanup

                cache_size = len(self._cache)
                cache_hits = self._cache_hits
                cache_misses = self._cache_misses
                lookup_failures = self._lookup_failures
                evictions = self._evictions
                rate_limited = self._rate_limited_requests
                corruption_errors = self._cache_corruption_errors
                timeout_errors = self._timeout_errors

                # Calculate hit rate and miss rate
                total_lookups = cache_hits + cache_misses
                hit_rate = cache_hits / total_lookups if total_lookups > 0 else 0.0
                miss_rate = cache_misses / total_lookups if total_lookups > 0 else 0.0

                return {
                    "cache_size": cache_size,
                    "cache_hits": cache_hits,
                    "cache_misses": cache_misses,
                    "lookup_failures": lookup_failures,
                    "hit_rate": hit_rate,
                    "miss_rate": miss_rate,
                    "evictions": evictions,
                    "rate_limited_requests": rate_limited,
                    "cache_corruption_errors": corruption_errors,
                    "timeout_errors": timeout_errors,
                    "cache_ttl": self.cache_ttl,
                    "max_cache_size": self.max_cache_size,
                    "dns_timeout": self.dns_timeout,
                    "max_lookups_per_second": self.max_lookups_per_second,
                }
            except Exception as e:
                logger.error(f"❌ Error getting statistics: {e}")
                # Return minimal statistics on error
                return {
                    "error": str(e),
                    "cache_size": 0,
                    "cache_hits": self._cache_hits,
                    "cache_misses": self._cache_misses,
                    "lookup_failures": self._lookup_failures,
                }

    def _start_periodic_logging(self):
        """Start background thread for periodic statistics logging."""
        self._stop_logging = False
        self._logging_thread = Thread(target=self._periodic_logging_loop, daemon=True)
        self._logging_thread.start()
        logger.info("📊 Started periodic cache statistics logging (interval: %ss)", self.log_interval)

    def _periodic_logging_loop(self):
        """Background loop that logs cache statistics periodically."""
        while not self._stop_logging:
            time.sleep(self.log_interval)
            if not self._stop_logging:
                self._log_statistics()

    def _log_statistics(self):
        """Log current cache statistics with comprehensive error metrics."""
        try:
            stats = self.get_statistics()

            # Check if statistics retrieval failed
            if "error" in stats:
                logger.error(f"❌ Failed to retrieve statistics: {stats['error']}")
                return

            logger.info(
                f"📊 Cache Statistics: "
                f"size={stats['cache_size']}/{stats['max_cache_size']}, "
                f"hits={stats['cache_hits']}, "
                f"misses={stats['cache_misses']}, "
                f"failures={stats['lookup_failures']}, "
                f"evictions={stats['evictions']}, "
                f"rate_limited={stats['rate_limited_requests']}, "
                f"corruption_errors={stats['cache_corruption_errors']}, "
                f"timeout_errors={stats['timeout_errors']}, "
                f"hit_rate={stats['hit_rate']:.2%}, "
                f"miss_rate={stats['miss_rate']:.2%}"
            )
        except Exception as e:
            logger.error(f"❌ Error logging statistics: {e}")

    def stop_periodic_logging(self):
        """Stop the periodic logging thread."""
        if self._logging_thread and self._logging_thread.is_alive():
            self._stop_logging = True
            self._logging_thread.join(timeout=2.0)
            logger.info("📊 Stopped periodic cache statistics logging")

    def close(self) -> None:
        """Explicit lifecycle hook (preferred over __del__)."""
        try:
            self.stop_periodic_logging()
        except Exception:
            pass

    def __del__(self):
        """Cleanup when resolver is destroyed."""
        self.close()
