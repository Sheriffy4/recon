"""
Automatic strategy updates from trusted sources.
"""

import asyncio
import json
import aiohttp
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging
from core.bypass.sharing.sharing_models import (
    TrustedSource,
    SharedStrategy,
    SyncResult,
    TrustLevel,
    ValidationStatus,
    ShareLevel,
)
from core.bypass.sharing.strategy_validator import StrategyValidator
from core.bypass.sharing.community_database import CommunityDatabase


class UpdateManager:
    """Manages automatic updates from trusted strategy sources."""

    def __init__(self, config_path: str = "trusted_sources.json"):
        self.config_path = Path(config_path)
        self.logger = logging.getLogger(__name__)
        self.validator = StrategyValidator()
        self.community_db = CommunityDatabase()
        self.trusted_sources: Dict[str, TrustedSource] = {}
        self.sync_lock = asyncio.Lock()
        self._load_trusted_sources()

    def _load_trusted_sources(self):
        """Load trusted sources from configuration file."""
        try:
            if self.config_path.exists():
                with open(self.config_path, "r") as f:
                    data = json.load(f)
                for source_data in data.get("sources", []):
                    source = TrustedSource(
                        id=source_data["id"],
                        name=source_data["name"],
                        url=source_data["url"],
                        public_key=source_data["public_key"],
                        trust_level=TrustLevel(source_data["trust_level"]),
                        auto_update=source_data.get("auto_update", False),
                        sync_interval=source_data.get("sync_interval", 3600),
                        enabled=source_data.get("enabled", True),
                    )
                    if source_data.get("last_sync"):
                        source.last_sync = datetime.fromisoformat(source_data["last_sync"])
                    self.trusted_sources[source.id] = source
            else:
                self._create_default_config()
        except Exception as e:
            self.logger.error(f"Failed to load trusted sources: {e}")
            self._create_default_config()

    def _create_default_config(self):
        """Create default trusted sources configuration."""
        default_sources = [
            {
                "id": "official_recon",
                "name": "Official Recon Repository",
                "url": "https://api.recon-strategies.org/v1/strategies",
                "public_key": "default_public_key_placeholder",
                "trust_level": TrustLevel.VERIFIED.value,
                "auto_update": False,
                "sync_interval": 3600,
                "enabled": False,
            },
            {
                "id": "community_verified",
                "name": "Community Verified Strategies",
                "url": "https://community.recon-strategies.org/api/verified",
                "public_key": "community_public_key_placeholder",
                "trust_level": TrustLevel.HIGH.value,
                "auto_update": False,
                "sync_interval": 7200,
                "enabled": False,
            },
        ]
        config = {"sources": default_sources}
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, "w") as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to create default config: {e}")

    def _save_trusted_sources(self):
        """Save trusted sources to configuration file."""
        try:
            sources_data = []
            for source in self.trusted_sources.values():
                source_data = {
                    "id": source.id,
                    "name": source.name,
                    "url": source.url,
                    "public_key": source.public_key,
                    "trust_level": source.trust_level.value,
                    "auto_update": source.auto_update,
                    "sync_interval": source.sync_interval,
                    "enabled": source.enabled,
                }
                if source.last_sync:
                    source_data["last_sync"] = source.last_sync.isoformat()
                sources_data.append(source_data)
            config = {"sources": sources_data}
            with open(self.config_path, "w") as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save trusted sources: {e}")

    async def add_trusted_source(self, source: TrustedSource) -> bool:
        """Add a new trusted source."""
        try:
            if not await self._validate_source_url(source.url):
                self.logger.warning(f"Source URL not accessible: {source.url}")
                return False
            self.trusted_sources[source.id] = source
            self._save_trusted_sources()
            self.logger.info(f"Added trusted source: {source.name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to add trusted source: {e}")
            return False

    async def remove_trusted_source(self, source_id: str) -> bool:
        """Remove a trusted source."""
        try:
            if source_id in self.trusted_sources:
                del self.trusted_sources[source_id]
                self._save_trusted_sources()
                self.logger.info(f"Removed trusted source: {source_id}")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to remove trusted source: {e}")
            return False

    async def sync_source(self, source_id: str) -> SyncResult:
        """Synchronize strategies from a specific trusted source."""
        if source_id not in self.trusted_sources:
            return SyncResult(source_id=source_id, success=False, errors=["Source not found"])
        source = self.trusted_sources[source_id]
        if not source.enabled:
            return SyncResult(source_id=source_id, success=False, errors=["Source is disabled"])
        async with self.sync_lock:
            return await self._perform_sync(source)

    async def _perform_sync(self, source: TrustedSource) -> SyncResult:
        """Perform actual synchronization with a trusted source."""
        result = SyncResult(source_id=source.id, success=False)
        try:
            self.logger.info(f"Starting sync with source: {source.name}")
            strategies = await self._fetch_strategies_from_source(source)
            if not strategies:
                result.errors.append("No strategies received from source")
                return result
            for strategy_data in strategies:
                try:
                    strategy = self._parse_strategy_data(strategy_data, source)
                    if not strategy:
                        continue
                    validation_result = await self.validator.validate_strategy(strategy)
                    min_trust_score = self._get_min_trust_score_for_level(source.trust_level)
                    if validation_result.trust_score < min_trust_score:
                        self.logger.warning(
                            f"Strategy {strategy.id} trust score too low: {validation_result.trust_score}"
                        )
                        continue
                    existing = await self.community_db.get_strategy(strategy.id)
                    if existing:
                        if self._is_newer_version(strategy.version, existing.version):
                            await self.community_db.add_strategy(strategy)
                            result.strategies_updated += 1
                    else:
                        await self.community_db.add_strategy(strategy)
                        result.strategies_added += 1
                except Exception as e:
                    result.errors.append(f"Failed to process strategy: {str(e)}")
            source.last_sync = datetime.now()
            self._save_trusted_sources()
            result.success = True
            self.logger.info(
                f"Sync completed: {result.strategies_added} added, {result.strategies_updated} updated"
            )
        except Exception as e:
            result.errors.append(f"Sync failed: {str(e)}")
            self.logger.error(f"Sync with {source.name} failed: {e}")
        return result

    async def _fetch_strategies_from_source(self, source: TrustedSource) -> List[Dict[str, Any]]:
        """Fetch strategies from a trusted source URL."""
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(source.url) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("strategies", [])
                    else:
                        self.logger.error(f"HTTP {response.status} from {source.url}")
                        return []
        except Exception as e:
            self.logger.error(f"Failed to fetch from {source.url}: {e}")
            return []

    def _parse_strategy_data(
        self, data: Dict[str, Any], source: TrustedSource
    ) -> Optional[SharedStrategy]:
        """Parse strategy data from source into SharedStrategy object."""
        try:
            strategy = SharedStrategy(
                id=data["id"],
                name=data["name"],
                description=data.get("description", ""),
                strategy_data=data["strategy_data"],
                author=data.get("author", source.name),
                version=data["version"],
                share_level=ShareLevel.COMMUNITY,
                validation_status=ValidationStatus.PENDING,
                trust_score=0.0,
                tags=data.get("tags", []),
                target_regions=data.get("target_regions", []),
                target_isps=data.get("target_isps", []),
                signature=data.get("signature"),
            )
            if strategy.signature and (not strategy.verify_signature(source.public_key)):
                self.logger.warning(f"Invalid signature for strategy {strategy.id}")
                return None
            return strategy
        except Exception as e:
            self.logger.error(f"Failed to parse strategy data: {e}")
            return None

    def _get_min_trust_score_for_level(self, trust_level: TrustLevel) -> float:
        """Get minimum trust score required for a trust level."""
        trust_score_map = {
            TrustLevel.UNKNOWN: 0.3,
            TrustLevel.LOW: 0.4,
            TrustLevel.MEDIUM: 0.6,
            TrustLevel.HIGH: 0.7,
            TrustLevel.VERIFIED: 0.8,
        }
        return trust_score_map.get(trust_level, 0.5)

    def _is_newer_version(self, version1: str, version2: str) -> bool:
        """Compare version strings to determine if version1 is newer than version2."""
        try:
            v1_parts = [int(x) for x in version1.split(".")]
            v2_parts = [int(x) for x in version2.split(".")]
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            return v1_parts > v2_parts
        except Exception:
            return version1 > version2

    async def _validate_source_url(self, url: str) -> bool:
        """Validate that a source URL is accessible."""
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.head(url) as response:
                    return response.status < 400
        except Exception:
            return False

    async def sync_all_sources(self) -> Dict[str, SyncResult]:
        """Synchronize all enabled trusted sources."""
        results = {}
        for source_id, source in self.trusted_sources.items():
            if source.enabled and source.auto_update and source.is_sync_due():
                result = await self.sync_source(source_id)
                results[source_id] = result
        return results

    async def start_auto_sync_scheduler(self):
        """Start automatic synchronization scheduler."""
        self.logger.info("Starting auto-sync scheduler")
        while True:
            try:
                await self.sync_all_sources()
                await asyncio.sleep(300)
            except Exception as e:
                self.logger.error(f"Auto-sync scheduler error: {e}")
                await asyncio.sleep(60)

    def get_trusted_sources(self) -> List[TrustedSource]:
        """Get list of all trusted sources."""
        return list(self.trusted_sources.values())

    def get_source_stats(self) -> Dict[str, Any]:
        """Get statistics about trusted sources."""
        total = len(self.trusted_sources)
        enabled = sum((1 for s in self.trusted_sources.values() if s.enabled))
        auto_update = sum((1 for s in self.trusted_sources.values() if s.auto_update))
        return {
            "total_sources": total,
            "enabled_sources": enabled,
            "auto_update_sources": auto_update,
            "last_sync_times": {
                s.id: s.last_sync.isoformat() if s.last_sync else None
                for s in self.trusted_sources.values()
            },
        }
