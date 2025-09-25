# recon/core/doh_resolver_fixed.py
import aiohttp
import asyncio
import socket
import random
import time
from typing import Optional, Set, Dict, Any, List
import logging
import json

LOG = logging.getLogger("doh_resolver")


class DoHResolver:
    """Enhanced DoH resolver with failover, load balancing, and caching."""

    DOH_SERVERS = {
        "cloudflare": [
            "https://1.1.1.1/dns-query",
            "https://1.0.0.1/dns-query",
        ],
        "google": [
            "https://8.8.8.8/resolve",
            "https://8.8.4.4/resolve",
        ],
        "quad9": [
            "https://9.9.9.9/dns-query",
        ],
    }

    def __init__(self, preferred_providers=None, cache_ttl=300):
        """
        Args:
            preferred_providers: List of preferred providers ('cloudflare', 'google', etc.)
            cache_ttl: Time to live for cached records in seconds
        """
        self.preferred_providers = preferred_providers or [
            "cloudflare",
            "google",
            "quad9",
        ]
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.cache_ttl = cache_ttl
        self.session = None
        self.provider_health = {provider: 1.0 for provider in self.DOH_SERVERS.keys()}

    async def _ensure_session(self):
        """Ensures aiohttp session exists."""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession()

    async def _cleanup(self):
        """Cleanup resources."""
        if self.session:
            await self.session.close()
            self.session = None

    def _get_next_servers(self) -> List[str]:
        """Gets next servers to try based on health and preferences."""
        servers = []
        # Sort providers by health score
        providers = sorted(
            [(p, self.provider_health[p]) for p in self.preferred_providers],
            key=lambda x: x[1],
            reverse=True,
        )

        for provider, _ in providers:
            # Add servers from each provider, shuffled for load balancing
            provider_servers = self.DOH_SERVERS[provider].copy()
            random.shuffle(provider_servers)
            servers.extend(provider_servers)

        return servers

    def _update_provider_health(self, provider: str, success: bool):
        """Updates provider health score."""
        current = self.provider_health[provider]
        if success:
            # Slowly improve score on success
            self.provider_health[provider] = min(1.0, current + 0.1)
        else:
            # Quickly degrade score on failure
            self.provider_health[provider] = max(0.1, current * 0.5)

    async def _query_doh(self, server: str, hostname: str) -> Optional[str]:
        """Queries a single DoH server."""
        try:
            await self._ensure_session()

            params = {"name": hostname, "type": "A"}
            headers = {"accept": "application/dns-json"}

            async with self.session.get(
                server, params=params, headers=headers, timeout=5
            ) as response:
                if response.status == 200:
                    # Get text response and parse as JSON manually to avoid content-type issues
                    text = await response.text()
                    try:
                        data = json.loads(text)
                    except json.JSONDecodeError:
                        LOG.warning(f"Failed to parse DoH response from {server}")
                        return None
                    
                    if data.get("Answer"):
                        # Use random answer if multiple are returned
                        answer = random.choice(data["Answer"])
                        if answer.get("data"):
                            return answer["data"]

        except asyncio.TimeoutError:
            LOG.warning(f"DoH timeout for {hostname} using {server}")
        except Exception as e:
            LOG.debug(f"DoH error for {hostname} using {server}: {e}")

        return None

    async def resolve_all(self, hostname: str) -> Set[str]:
        """Resolves all IPs for a hostname using DoH."""
        # Check cache first
        cache_entry = self.cache.get(hostname)
        if cache_entry and time.time() < cache_entry["expires"]:
            return cache_entry["ips"].copy()

        ips = set()
        errors = 0
        servers = self._get_next_servers()

        for server in servers:
            provider = next(
                (
                    p
                    for p in self.DOH_SERVERS.keys()
                    if any(s in server for s in self.DOH_SERVERS[p])
                ),
                None,
            )

            try:
                ip = await self._query_doh(server, hostname)
                if ip:
                    ips.add(ip)
                    self._update_provider_health(provider, True)
                    if len(ips) >= 2:  # Stop after getting 2+ IPs
                        break
                else:
                    errors += 1
                    self._update_provider_health(provider, False)

            except Exception as e:
                errors += 1
                self._update_provider_health(provider, False)
                LOG.debug(f"DoH query failed for {hostname} via {server}: {e}")

        # Fallback to system DNS if DoH fails
        if not ips:
            LOG.warning(f"Used system DNS fallback for {hostname}")
            try:
                system_ips = socket.gethostbyname_ex(hostname)[2]
                ips.update(system_ips)
            except socket.gaierror:
                LOG.error(f"System DNS also failed for {hostname}")

        # Cache results
        if ips:
            self.cache[hostname] = {
                "ips": ips.copy(),
                "expires": time.time() + self.cache_ttl,
            }
            LOG.info(f"Resolved {hostname} -> {ips} via DoH")

        return ips

    async def resolve_one(self, hostname: str) -> Optional[str]:
        """Resolves one IP for a hostname using DoH."""
        ips = await self.resolve_all(hostname)
        return random.choice(list(ips)) if ips else None
    
    async def resolve(self, hostname: str) -> Optional[str]:
        """Resolves one IP for a hostname using DoH (compatibility method)."""
        return await self.resolve_one(hostname)

    def get_cache_stats(self) -> Dict[str, Any]:
        """Returns cache statistics."""
        now = time.time()
        valid_entries = sum(
            1 for entry in self.cache.values() if entry["expires"] > now
        )
        return {
            "total_entries": len(self.cache),
            "valid_entries": valid_entries,
            "expired_entries": len(self.cache) - valid_entries,
            "provider_health": self.provider_health.copy(),
        }

    def clear_cache(self):
        """Clears the DNS cache."""
        self.cache.clear()
        LOG.info("DoH cache cleared")

    async def __aenter__(self):
        """Async context manager entry."""
        await self._ensure_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self._cleanup()