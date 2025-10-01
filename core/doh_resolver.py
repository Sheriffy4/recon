# recon/core/doh_resolver_fixed.py
import aiohttp
import asyncio
import socket
import random
import time
from typing import Optional, Set, Dict, Any, List
import logging
import json
import ipaddress

LOG = logging.getLogger("doh_resolver")


class DoHResolver:
    """Enhanced DoH resolver with failover, load balancing, and caching."""

    DOH_SERVERS = {
        "cloudflare": [
            "https://1.1.1.1/dns-query",
            "https://1.0.0.1/dns-query",
            "https://[2606:4700:4700::1111]/dns-query",
            "https://cloudflare-dns.com/dns-query",
        ],
        "google": [
            "https://8.8.8.8/resolve",
            "https://8.8.4.4/resolve",
            "https://dns.google/resolve",
        ],
        "quad9": [
            "https://9.9.9.9/dns-query",
            "https://149.112.112.112/dns-query",
            "https://dns9.quad9.net/dns-query",
        ],
        "opendns": [
            "https://doh.opendns.com/dns-query",
            "https://dns.opendns.com/dns-query",
        ],
        "adguard": ["https://dns.adguard.com/dns-query"],
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
                    if provider: self._update_provider_health(provider, True)
                    if len(ips) >= 2:
                        break
                else:
                    errors += 1
                    if provider: self._update_provider_health(provider, False)
            except Exception as e:
                errors += 1
                if provider: self._update_provider_health(provider, False)
                LOG.debug(f"DoH query failed for {hostname} via {server}: {e}")

            # Early fallback after several errors
            if errors >= 3:
                try:
                    results = await asyncio.get_event_loop().getaddrinfo(
                        hostname, None, family=socket.AF_INET
                    )
                    system_ips = {result[4][0] for result in results}
                    ips.update(system_ips)
                    LOG.warning(f"Used system DNS fallback for {hostname}")
                except Exception as e:
                    LOG.error(f"System DNS fallback failed for {hostname}: {e}")
                break

        # Filter out non-IP addresses and prepare for caching
        valid_ips = set()
        for ip_str in ips:
            try:
                ipaddress.ip_address(ip_str)
                valid_ips.add(ip_str)
            except ValueError:
                pass  # Not a valid IP, ignore

        # Always cache the result, even if it's an empty set
        self.cache[hostname] = {
            "ips": valid_ips.copy(),
            "expires": time.time() + self.cache_ttl,
        }

        if valid_ips:
            LOG.info(f"Resolved {hostname} -> {valid_ips} via DoH")
        else:
            LOG.warning(f"Failed to resolve {hostname} to any valid IP addresses.")

        return valid_ips

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

    def save_cache_to_file(self, filepath: str):
        """Сохраняет кэш DNS в файл для последующего использования."""
        try:
            cache_data = {}
            current_time = time.time()
            for hostname, entry in self.cache.items():
                if current_time < entry["expires"]:
                    cache_data[hostname] = {
                        "ips": list(entry["ips"]),
                        "expires": entry["expires"],
                    }
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(cache_data, f, indent=2)
            LOG.info(f"DNS кэш сохранен в {filepath} ({len(cache_data)} записей)")
        except Exception as e:
            LOG.error(f"Ошибка сохранения DNS кэша: {e}")

    def load_cache_from_file(self, filepath: str):
        """Загружает кэш DNS из файла."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                cache_data = json.load(f)
            current_time = time.time()
            loaded_count = 0
            for hostname, entry in cache_data.items():
                if current_time < entry["expires"]:
                    self.cache[hostname] = {
                        "ips": set(entry["ips"]),
                        "expires": entry["expires"],
                    }
                    loaded_count += 1
            LOG.info(f"DNS кэш загружен из {filepath} ({loaded_count} записей)")
        except Exception as e:
            LOG.error(f"Ошибка загрузки DNS кэша: {e}")