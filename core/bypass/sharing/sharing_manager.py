"""
Main strategy sharing and collaboration manager.
"""

import asyncio
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging
import uuid

from .sharing_models import (
    SharedStrategy,
    StrategyPackage,
    StrategyFeedback,
    SharingConfig,
    ShareLevel,
    ValidationStatus,
    TrustedSource,
    TrustLevel,
)
from .strategy_validator import StrategyValidator
from .community_database import CommunityDatabase
from .update_manager import UpdateManager


class SharingManager:
    """Main manager for strategy sharing and collaboration features."""

    def __init__(self, config_path: str = "sharing_config.json"):
        self.config_path = Path(config_path)
        self.logger = logging.getLogger(__name__)

        # Initialize components
        self.validator = StrategyValidator()
        self.community_db = CommunityDatabase()
        self.update_manager = UpdateManager()

        # Load configuration
        self.config = self._load_config()

        # Auto-sync task
        self._auto_sync_task: Optional[asyncio.Task] = None

    def _load_config(self) -> SharingConfig:
        """Load sharing configuration from file."""
        try:
            if self.config_path.exists():
                with open(self.config_path, "r") as f:
                    data = json.load(f)
                    return SharingConfig(
                        enable_sharing=data.get("enable_sharing", True),
                        enable_auto_updates=data.get("enable_auto_updates", False),
                        default_share_level=ShareLevel(
                            data.get("default_share_level", "private")
                        ),
                        min_trust_score=data.get("min_trust_score", 0.7),
                        max_strategies_per_source=data.get(
                            "max_strategies_per_source", 1000
                        ),
                        validation_timeout=data.get("validation_timeout", 300),
                        community_db_url=data.get("community_db_url", ""),
                        private_key=data.get("private_key", ""),
                        public_key=data.get("public_key", ""),
                    )
            else:
                # Create default configuration
                config = SharingConfig()
                self._save_config(config)
                return config

        except Exception as e:
            self.logger.error(f"Failed to load sharing config: {e}")
            return SharingConfig()

    def _save_config(self, config: SharingConfig):
        """Save sharing configuration to file."""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)

            data = {
                "enable_sharing": config.enable_sharing,
                "enable_auto_updates": config.enable_auto_updates,
                "default_share_level": config.default_share_level.value,
                "min_trust_score": config.min_trust_score,
                "max_strategies_per_source": config.max_strategies_per_source,
                "validation_timeout": config.validation_timeout,
                "community_db_url": config.community_db_url,
                "private_key": config.private_key,
                "public_key": config.public_key,
            }

            with open(self.config_path, "w") as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            self.logger.error(f"Failed to save sharing config: {e}")

    async def initialize(self):
        """Initialize the sharing manager."""
        self.logger.info("Initializing strategy sharing manager")

        if self.config.enable_auto_updates:
            await self.start_auto_sync()

    async def share_strategy(
        self,
        strategy_data: Dict[str, Any],
        name: str,
        description: str = "",
        tags: List[str] = None,
        share_level: ShareLevel = None,
    ) -> Optional[SharedStrategy]:
        """Share a strategy with the community."""
        if not self.config.enable_sharing:
            self.logger.warning("Strategy sharing is disabled")
            return None

        try:
            # Create shared strategy object
            strategy = SharedStrategy(
                id=str(uuid.uuid4()),
                name=name,
                description=description,
                strategy_data=strategy_data,
                author="local_user",  # In production, would use actual user ID
                version="1.0.0",
                share_level=share_level or self.config.default_share_level,
                validation_status=ValidationStatus.PENDING,
                trust_score=0.0,
                tags=tags or [],
            )

            # Sign strategy if keys are available
            if self.config.private_key:
                strategy.signature = strategy.calculate_signature(
                    self.config.private_key
                )

            # Validate strategy
            validation_result = await self.validator.validate_strategy(strategy)

            if not validation_result.is_valid:
                self.logger.warning(
                    f"Strategy validation failed: {validation_result.issues}"
                )
                return None

            strategy.trust_score = validation_result.trust_score
            strategy.validation_status = ValidationStatus.VALIDATED

            # Add to community database
            success = await self.community_db.add_strategy(strategy)

            if success:
                self.logger.info(f"Successfully shared strategy: {strategy.name}")
                return strategy
            else:
                self.logger.error("Failed to add strategy to community database")
                return None

        except Exception as e:
            self.logger.error(f"Failed to share strategy: {e}")
            return None

    async def download_strategy(self, strategy_id: str) -> Optional[SharedStrategy]:
        """Download a strategy from the community."""
        try:
            strategy = await self.community_db.get_strategy(strategy_id)

            if not strategy:
                self.logger.warning(f"Strategy not found: {strategy_id}")
                return None

            # Check trust score
            if strategy.trust_score < self.config.min_trust_score:
                self.logger.warning(
                    f"Strategy trust score too low: {strategy.trust_score}"
                )
                return None

            # Increment download count
            await self.community_db.increment_download_count(strategy_id)

            self.logger.info(f"Downloaded strategy: {strategy.name}")
            return strategy

        except Exception as e:
            self.logger.error(f"Failed to download strategy: {e}")
            return None

    async def search_strategies(
        self,
        query: str = "",
        tags: List[str] = None,
        author: str = "",
        min_trust_score: float = None,
        limit: int = 50,
    ) -> List[SharedStrategy]:
        """Search for strategies in the community database."""
        min_score = min_trust_score or self.config.min_trust_score

        return await self.community_db.search_strategies(
            query=query,
            tags=tags,
            author=author,
            min_trust_score=min_score,
            limit=limit,
        )

    async def get_popular_strategies(self, limit: int = 20) -> List[SharedStrategy]:
        """Get most popular strategies."""
        return await self.community_db.get_popular_strategies(limit)

    async def submit_feedback(
        self,
        strategy_id: str,
        success: bool,
        region: str = "",
        isp: str = "",
        notes: str = "",
    ) -> bool:
        """Submit feedback for a strategy."""
        try:
            feedback = StrategyFeedback(
                strategy_id=strategy_id,
                user_id="local_user",  # In production, would use actual user ID
                success=success,
                region=region,
                isp=isp,
                notes=notes,
            )

            return await self.community_db.add_feedback(feedback)

        except Exception as e:
            self.logger.error(f"Failed to submit feedback: {e}")
            return False

    async def create_strategy_package(
        self, name: str, description: str, strategy_ids: List[str]
    ) -> Optional[StrategyPackage]:
        """Create a package of related strategies."""
        try:
            # Load strategies
            strategies = []
            for sid in strategy_ids:
                strategy = await self.community_db.get_strategy(sid)
                if strategy:
                    strategies.append(strategy)

            if not strategies:
                self.logger.warning("No valid strategies found for package")
                return None

            package = StrategyPackage(
                id=str(uuid.uuid4()),
                name=name,
                description=description,
                strategies=strategies,
                author="local_user",
                version="1.0.0",
            )

            success = await self.community_db.create_package(package)

            if success:
                self.logger.info(f"Created strategy package: {package.name}")
                return package
            else:
                return None

        except Exception as e:
            self.logger.error(f"Failed to create strategy package: {e}")
            return None

    async def add_trusted_source(
        self,
        name: str,
        url: str,
        public_key: str,
        trust_level: TrustLevel = TrustLevel.MEDIUM,
        auto_update: bool = False,
    ) -> bool:
        """Add a new trusted source for strategy updates."""
        source = TrustedSource(
            id=str(uuid.uuid4()),
            name=name,
            url=url,
            public_key=public_key,
            trust_level=trust_level,
            auto_update=auto_update,
        )

        return await self.update_manager.add_trusted_source(source)

    async def sync_trusted_source(self, source_id: str):
        """Manually sync a trusted source."""
        return await self.update_manager.sync_source(source_id)

    async def start_auto_sync(self):
        """Start automatic synchronization with trusted sources."""
        if self._auto_sync_task and not self._auto_sync_task.done():
            return

        self._auto_sync_task = asyncio.create_task(
            self.update_manager.start_auto_sync_scheduler()
        )
        self.logger.info("Started auto-sync scheduler")

    async def stop_auto_sync(self):
        """Stop automatic synchronization."""
        if self._auto_sync_task and not self._auto_sync_task.done():
            self._auto_sync_task.cancel()
            try:
                await self._auto_sync_task
            except asyncio.CancelledError:
                pass
        self.logger.info("Stopped auto-sync scheduler")

    def update_config(self, **kwargs):
        """Update sharing configuration."""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)

        self._save_config(self.config)
        self.logger.info("Updated sharing configuration")

    async def get_sharing_stats(self) -> Dict[str, Any]:
        """Get comprehensive sharing statistics."""
        db_stats = await self.community_db.get_database_stats()
        source_stats = self.update_manager.get_source_stats()
        validation_stats = self.validator.get_validation_stats()

        return {
            "database": db_stats,
            "sources": source_stats,
            "validation": validation_stats,
            "config": {
                "sharing_enabled": self.config.enable_sharing,
                "auto_updates_enabled": self.config.enable_auto_updates,
                "min_trust_score": self.config.min_trust_score,
            },
        }

    async def export_strategies(self, strategy_ids: List[str]) -> Dict[str, Any]:
        """Export strategies for sharing."""
        try:
            strategies = []
            for sid in strategy_ids:
                strategy = await self.community_db.get_strategy(sid)
                if strategy:
                    strategies.append(
                        {
                            "id": strategy.id,
                            "name": strategy.name,
                            "description": strategy.description,
                            "strategy_data": strategy.strategy_data,
                            "author": strategy.author,
                            "version": strategy.version,
                            "tags": strategy.tags,
                            "signature": strategy.signature,
                        }
                    )

            return {
                "export_version": "1.0",
                "export_date": datetime.now().isoformat(),
                "strategies": strategies,
            }

        except Exception as e:
            self.logger.error(f"Failed to export strategies: {e}")
            return {}

    async def import_strategies(self, import_data: Dict[str, Any]) -> int:
        """Import strategies from export data."""
        try:
            imported_count = 0

            for strategy_data in import_data.get("strategies", []):
                strategy = SharedStrategy(
                    id=strategy_data["id"],
                    name=strategy_data["name"],
                    description=strategy_data["description"],
                    strategy_data=strategy_data["strategy_data"],
                    author=strategy_data["author"],
                    version=strategy_data["version"],
                    share_level=ShareLevel.PRIVATE,  # Imported as private by default
                    validation_status=ValidationStatus.PENDING,
                    trust_score=0.0,
                    tags=strategy_data.get("tags", []),
                    signature=strategy_data.get("signature"),
                )

                # Validate imported strategy
                validation_result = await self.validator.validate_strategy(strategy)

                if validation_result.is_valid:
                    success = await self.community_db.add_strategy(strategy)
                    if success:
                        imported_count += 1

            self.logger.info(f"Imported {imported_count} strategies")
            return imported_count

        except Exception as e:
            self.logger.error(f"Failed to import strategies: {e}")
            return 0

    async def cleanup(self):
        """Cleanup resources."""
        await self.stop_auto_sync()
        self.logger.info("Sharing manager cleanup completed")
