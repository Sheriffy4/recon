"""
Strategy database management for persistence and retrieval.

Handles loading and saving strategy data to/from best_strategy.json format.
"""

import json
import os
import time
import logging
from typing import Dict, Any, List
from .models import Strategy


class StrategyDatabaseManager:
    """Manages strategy database operations with best_strategy.json format."""

    def __init__(self, database_path: str = "best_strategy.json", debug: bool = False):
        """
        Initialize database manager.

        Args:
            database_path: Path to strategy database file
            debug: Enable debug logging
        """
        self.database_path = database_path
        self.logger = logging.getLogger("StrategyDatabaseManager")
        if debug:
            self.logger.setLevel(logging.DEBUG)

    def load_database(self) -> Dict[str, Any]:
        """
        Load strategy database from file.

        Returns:
            Dictionary with database structure or default empty structure
        """
        try:
            if os.path.exists(self.database_path):
                with open(self.database_path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading strategy database: {e}")

        # Return default structure
        return {
            "metadata": {"version": "3.1", "last_updated": time.time()},
            "strategies_by_fingerprint": {},
        }

    def save_database(self, strategy_db: Dict[str, Any]):
        """
        Save strategy database to file.

        Args:
            strategy_db: Database dictionary to save

        Raises:
            Exception: If save operation fails
        """
        try:
            with open(self.database_path, "w", encoding="utf-8") as f:
                json.dump(strategy_db, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving strategy database: {e}")
            raise

    def load_existing_strategies(self) -> Dict[str, str]:
        """
        Load existing domain-to-strategy mappings from database.

        Returns:
            Dictionary mapping domain to strategy_id
        """
        domain_strategies = {}

        try:
            strategy_db = self.load_database()
            strategies = strategy_db.get("strategies_by_fingerprint", {})

            for strategy_id, strategy_data in strategies.items():
                domains = strategy_data.get("domains", [])
                for domain in domains:
                    domain_strategies[domain] = strategy_id

            self.logger.info(f"Loaded {len(domain_strategies)} existing domain-strategy mappings")

        except Exception as e:
            self.logger.error(f"Error loading existing strategies: {e}")

        return domain_strategies

    def update_strategies(self, new_strategies: List[Strategy]) -> int:
        """
        Update strategy database with new strategies.

        Args:
            new_strategies: List of Strategy objects to add

        Returns:
            Number of strategies successfully added
        """
        try:
            self.logger.info(
                f"Updating strategy database with {len(new_strategies)} new strategies"
            )

            # Load existing database
            strategy_db = self.load_database()

            # Add new strategies
            added_count = 0
            for strategy in new_strategies:
                # Convert to best_strategy.json format
                strategy_entry = {
                    "strategy": strategy.strategy_string,
                    "result_status": ("WORKING" if strategy.success_rate > 0.5 else "TESTING"),
                    "success_rate": strategy.success_rate,
                    "avg_latency_ms": strategy.avg_latency_ms,
                    "domains": strategy.domains,
                    "fingerprint_summary": strategy.fingerprint_hash or "Auto-discovered",
                    "created_at": strategy.created_at.isoformat(),
                    "technique_type": strategy.technique_type,
                    "parameters": strategy.parameters,
                }

                strategy_db["strategies_by_fingerprint"][strategy.strategy_id] = strategy_entry
                added_count += 1

            # Update metadata
            strategy_db["metadata"]["last_updated"] = time.time()
            strategy_db["metadata"]["version"] = "3.1"

            # Save updated database
            self.save_database(strategy_db)

            self.logger.info(f"Successfully added {added_count} strategies to database")
            return added_count

        except Exception as e:
            self.logger.error(f"Error updating strategy database: {e}")
            return 0
