# recon/core/bypass/attacks/learning_memory.py
"""
Learning Memory System

Implements persistent storage and retrieval of learning results for adaptive attacks.
Uses SQLite for reliable storage and provides methods for analyzing historical data.
"""

import sqlite3
import json
import hashlib
import asyncio
import logging
import time
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path

LOG = logging.getLogger("LearningMemory")


@dataclass
class StrategyRecord:
    """Record of a strategy execution result."""

    fingerprint_hash: str
    attack_name: str
    parameters: Dict[str, Any]
    effectiveness_score: float
    success: bool
    latency_ms: float
    timestamp: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LearningHistory:
    """Historical learning data for a specific fingerprint."""

    fingerprint_hash: str
    successful_attacks: Dict[str, float]  # attack_name -> success_rate
    failed_attacks: set[str]
    optimal_parameters: Dict[str, Dict[str, Any]]  # attack_name -> params
    adaptation_patterns: List[Dict[str, Any]]
    last_updated: datetime
    total_attempts: int = 0
    best_effectiveness: float = 0.0


@dataclass
class AdaptationRecord:
    """Record of an adaptation decision and its outcome."""

    timestamp: datetime
    fingerprint_hash: str
    original_strategy: str
    adapted_strategy: str
    adaptation_reason: str
    effectiveness_before: float
    effectiveness_after: float
    parameters_before: Dict[str, Any]
    parameters_after: Dict[str, Any]


class LearningMemory:
    """
    Persistent learning memory system using SQLite storage.
    """
    def __init__(self, storage_path: str = "data/learning_memory.db", max_history_entries: int = 10000):
        self.storage_path = Path(storage_path)
        self.max_history_entries = max_history_entries # <-- ДОБАВЛЕНО
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self.logger = LOG
        self._connection = None
        self._lock = asyncio.Lock()
        self._initialized = False

    async def _initialize_database(self):
        """Initialize SQLite database with required tables."""
        if self._initialized:
            return

        async with self._lock:
            try:
                # Create connection directly to avoid recursion
                self._connection = sqlite3.connect(
                    str(self.storage_path), timeout=30.0, check_same_thread=False
                )
                self._connection.execute("PRAGMA journal_mode=WAL")
                self._connection.execute("PRAGMA synchronous=NORMAL")
                self._connection.execute("PRAGMA cache_size=10000")
                self._connection.execute("PRAGMA temp_store=MEMORY")

                cursor = self._connection.cursor()

                # Strategy records table
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS strategy_records (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        fingerprint_hash TEXT NOT NULL,
                        attack_name TEXT NOT NULL,
                        parameters TEXT NOT NULL,
                        effectiveness_score REAL NOT NULL,
                        success BOOLEAN NOT NULL,
                        latency_ms REAL NOT NULL,
                        timestamp REAL NOT NULL,
                        metadata TEXT
                    )
                """
                )

                # Create indexes for strategy_records
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_strategy_records_fingerprint ON strategy_records(fingerprint_hash)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_strategy_records_attack ON strategy_records(attack_name)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_strategy_records_timestamp ON strategy_records(timestamp)"
                )

                # Adaptation records table
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS adaptation_records (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        fingerprint_hash TEXT NOT NULL,
                        timestamp REAL NOT NULL,
                        original_strategy TEXT NOT NULL,
                        adapted_strategy TEXT NOT NULL,
                        adaptation_reason TEXT NOT NULL,
                        effectiveness_before REAL NOT NULL,
                        effectiveness_after REAL NOT NULL,
                        parameters_before TEXT NOT NULL,
                        parameters_after TEXT NOT NULL
                    )
                """
                )

                # Create indexes for adaptation_records
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_adaptation_records_fingerprint ON adaptation_records(fingerprint_hash)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_adaptation_records_timestamp ON adaptation_records(timestamp)"
                )

                # Learning statistics table
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS learning_stats (
                        fingerprint_hash TEXT PRIMARY KEY,
                        total_attempts INTEGER DEFAULT 0,
                        successful_attempts INTEGER DEFAULT 0,
                        best_effectiveness REAL DEFAULT 0.0,
                        best_attack_name TEXT,
                        best_parameters TEXT,
                        last_updated REAL NOT NULL,
                        created_at REAL NOT NULL
                    )
                """
                )

                self._connection.commit()
                self._initialized = True
                self.logger.info(
                    f"Learning memory database initialized at {self.storage_path}"
                )

            except Exception as e:
                self.logger.error(f"Failed to initialize learning memory database: {e}")
                raise

    async def _get_connection(self) -> sqlite3.Connection:
        """Get database connection with proper configuration."""
        if self._connection is None:
            self._connection = sqlite3.connect(
                str(self.storage_path), timeout=30.0, check_same_thread=False
            )
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=NORMAL")
            self._connection.execute("PRAGMA cache_size=10000")
            self._connection.execute("PRAGMA temp_store=MEMORY")

        return self._connection

    def _generate_fingerprint_hash(self, fingerprint_data: Dict[str, Any]) -> str:
        """Generate consistent hash for fingerprint data."""
        # Sort keys to ensure consistent hashing
        sorted_data = json.dumps(fingerprint_data, sort_keys=True, default=str)
        return hashlib.sha256(sorted_data.encode()).hexdigest()[:16]

    async def save_learning_result(
        self,
        fingerprint_hash: str,
        attack_name: str,
        effectiveness_score: float,
        parameters: Dict[str, Any],
        success: bool = None,
        latency_ms: float = 0.0,
        metadata: Dict[str, Any] = None,
    ) -> bool:
        """
        Save a learning result to persistent storage.

        Args:
            fingerprint_hash: Hash of the DPI fingerprint
            attack_name: Name of the attack strategy
            effectiveness_score: Effectiveness score (0.0 - 1.0)
            parameters: Attack parameters used
            success: Whether the attack was successful
            latency_ms: Attack latency in milliseconds
            metadata: Additional metadata

        Returns:
            True if saved successfully, False otherwise
        """
        if not self._initialized:
            await self._initialize_database()

        async with self._lock:
            try:
                conn = await self._get_connection()
                cursor = conn.cursor()

                # Determine success if not provided
                if success is None:
                    success = effectiveness_score > 0.5

                # Insert strategy record
                cursor.execute(
                    """
                    INSERT INTO strategy_records 
                    (fingerprint_hash, attack_name, parameters, effectiveness_score, 
                     success, latency_ms, timestamp, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        fingerprint_hash,
                        attack_name,
                        json.dumps(parameters),
                        effectiveness_score,
                        success,
                        latency_ms,
                        time.time(),
                        json.dumps(metadata or {}),
                    ),
                )

                # Update learning statistics
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO learning_stats 
                    (fingerprint_hash, total_attempts, successful_attempts, 
                     best_effectiveness, best_attack_name, best_parameters, 
                     last_updated, created_at)
                    VALUES (
                        ?,
                        COALESCE((SELECT total_attempts FROM learning_stats WHERE fingerprint_hash = ?), 0) + 1,
                        COALESCE((SELECT successful_attempts FROM learning_stats WHERE fingerprint_hash = ?), 0) + ?,
                        CASE WHEN ? > COALESCE((SELECT best_effectiveness FROM learning_stats WHERE fingerprint_hash = ?), 0)
                             THEN ? ELSE COALESCE((SELECT best_effectiveness FROM learning_stats WHERE fingerprint_hash = ?), 0) END,
                        CASE WHEN ? > COALESCE((SELECT best_effectiveness FROM learning_stats WHERE fingerprint_hash = ?), 0)
                             THEN ? ELSE COALESCE((SELECT best_attack_name FROM learning_stats WHERE fingerprint_hash = ?), '') END,
                        CASE WHEN ? > COALESCE((SELECT best_effectiveness FROM learning_stats WHERE fingerprint_hash = ?), 0)
                             THEN ? ELSE COALESCE((SELECT best_parameters FROM learning_stats WHERE fingerprint_hash = ?), '{}') END,
                        ?,
                        COALESCE((SELECT created_at FROM learning_stats WHERE fingerprint_hash = ?), ?)
                    )
                """,
                    (
                        fingerprint_hash,
                        fingerprint_hash,
                        fingerprint_hash,
                        1 if success else 0,
                        effectiveness_score,
                        fingerprint_hash,
                        effectiveness_score,
                        fingerprint_hash,
                        effectiveness_score,
                        fingerprint_hash,
                        attack_name,
                        fingerprint_hash,
                        effectiveness_score,
                        fingerprint_hash,
                        json.dumps(parameters),
                        fingerprint_hash,
                        time.time(),
                        fingerprint_hash,
                        time.time(),
                    ),
                )

                conn.commit()

                self.logger.debug(
                    f"Saved learning result: {fingerprint_hash[:8]}... -> {attack_name} "
                    f"(effectiveness: {effectiveness_score:.2f}, success: {success})"
                )

                return True

            except Exception as e:
                self.logger.error(f"Failed to save learning result: {e}")
                return False

    async def load_learning_history(
        self, fingerprint_hash: str
    ) -> Optional[LearningHistory]:
        """
        Load learning history for a specific fingerprint.

        Args:
            fingerprint_hash: Hash of the DPI fingerprint

        Returns:
            LearningHistory object or None if not found
        """
        if not self._initialized:
            await self._initialize_database()

        async with self._lock:
            try:
                conn = await self._get_connection()
                cursor = conn.cursor()

                # Get learning statistics
                cursor.execute(
                    """
                    SELECT total_attempts, successful_attempts, best_effectiveness, 
                           best_attack_name, best_parameters, last_updated, created_at
                    FROM learning_stats 
                    WHERE fingerprint_hash = ?
                """,
                    (fingerprint_hash,),
                )

                stats_row = cursor.fetchone()
                if not stats_row:
                    return None

                (
                    total_attempts,
                    successful_attempts,
                    best_effectiveness,
                    best_attack_name,
                    best_parameters,
                    last_updated,
                    created_at,
                ) = stats_row

                # Get successful attacks with success rates
                cursor.execute(
                    """
                    SELECT attack_name, 
                           AVG(effectiveness_score) as avg_effectiveness,
                           COUNT(*) as total_count,
                           SUM(CASE WHEN success THEN 1 ELSE 0 END) as success_count
                    FROM (
                        SELECT * FROM strategy_records
                        WHERE fingerprint_hash = ?
                        ORDER BY timestamp DESC
                        LIMIT ?  -- <-- ДОБАВЛЕНО
                    )
                    GROUP BY attack_name
                    HAVING success_count > 0
                """,
                    (fingerprint_hash, self.max_history_entries), # <-- ДОБАВЛЕНО
                )

                successful_attacks = {}
                for row in cursor.fetchall():
                    attack_name, avg_effectiveness, total_count, success_count = row
                    success_rate = success_count / total_count
                    successful_attacks[attack_name] = success_rate

                # Get failed attacks
                cursor.execute(
                    """
                    SELECT DISTINCT attack_name
                    FROM (
                        SELECT * FROM strategy_records
                        WHERE fingerprint_hash = ?
                        ORDER BY timestamp DESC
                        LIMIT ?  -- <-- ДОБАВЛЕНО
                    )
                    WHERE success = 0
                    AND attack_name NOT IN (
                        SELECT DISTINCT attack_name 
                        FROM strategy_records 
                        WHERE fingerprint_hash = ? AND success = 1
                    )
                """,
                    (fingerprint_hash, self.max_history_entries, fingerprint_hash), # <-- ДОБАВЛЕНО
                )

                failed_attacks = {row[0] for row in cursor.fetchall()}

                # Get optimal parameters for each successful attack
                optimal_parameters = {}
                for attack_name in successful_attacks.keys():
                    cursor.execute(
                        """
                        SELECT parameters
                        FROM strategy_records 
                        WHERE fingerprint_hash = ? AND attack_name = ? AND success = 1
                        ORDER BY effectiveness_score DESC
                        LIMIT 1
                    """,
                        (fingerprint_hash, attack_name),
                    )

                    params_row = cursor.fetchone()
                    if params_row:
                        optimal_parameters[attack_name] = json.loads(params_row[0])

                # Get recent adaptation patterns
                cursor.execute(
                    """
                    SELECT timestamp, original_strategy, adapted_strategy, adaptation_reason,
                           effectiveness_before, effectiveness_after, parameters_before, parameters_after
                    FROM adaptation_records 
                    WHERE fingerprint_hash = ?
                    ORDER BY timestamp DESC
                    LIMIT 50
                """,
                    (fingerprint_hash,),
                )

                adaptation_patterns = []
                for row in cursor.fetchall():
                    (
                        timestamp,
                        orig_strategy,
                        adapted_strategy,
                        reason,
                        eff_before,
                        eff_after,
                        params_before,
                        params_after,
                    ) = row
                    adaptation_patterns.append(
                        {
                            "timestamp": datetime.fromtimestamp(timestamp),
                            "original_strategy": orig_strategy,
                            "adapted_strategy": adapted_strategy,
                            "adaptation_reason": reason,
                            "effectiveness_before": eff_before,
                            "effectiveness_after": eff_after,
                            "parameters_before": json.loads(params_before),
                            "parameters_after": json.loads(params_after),
                        }
                    )

                history = LearningHistory(
                    fingerprint_hash=fingerprint_hash,
                    successful_attacks=successful_attacks,
                    failed_attacks=failed_attacks,
                    optimal_parameters=optimal_parameters,
                    adaptation_patterns=adaptation_patterns,
                    last_updated=datetime.fromtimestamp(last_updated),
                    total_attempts=total_attempts,
                    best_effectiveness=best_effectiveness,
                )

                self.logger.debug(
                    f"Loaded learning history for {fingerprint_hash[:8]}...: "
                    f"{len(successful_attacks)} successful attacks, "
                    f"{len(failed_attacks)} failed attacks"
                )

                return history

            except Exception as e:
                self.logger.error(f"Failed to load learning history: {e}")
                return None

    async def get_best_strategies(
        self, fingerprint_hash: str, limit: int = 5, min_effectiveness: float = 0.3
    ) -> List[StrategyRecord]:
        """
        Get the best strategies for a specific fingerprint.

        Args:
            fingerprint_hash: Hash of the DPI fingerprint
            limit: Maximum number of strategies to return
            min_effectiveness: Minimum effectiveness threshold

        Returns:
            List of StrategyRecord objects sorted by effectiveness
        """
        async with self._lock:
            try:
                conn = await self._get_connection()
                cursor = conn.cursor()

                cursor.execute(
                    """
                    SELECT fingerprint_hash, attack_name, parameters, effectiveness_score,
                           success, latency_ms, timestamp, metadata
                    FROM strategy_records 
                    WHERE fingerprint_hash = ? 
                      AND effectiveness_score >= ?
                      AND success = 1
                    ORDER BY effectiveness_score DESC, timestamp DESC
                    LIMIT ?
                """,
                    (fingerprint_hash, min_effectiveness, limit),
                )

                strategies = []
                for row in cursor.fetchall():
                    (
                        fh,
                        attack_name,
                        params,
                        eff_score,
                        success,
                        latency,
                        timestamp,
                        metadata,
                    ) = row

                    strategy = StrategyRecord(
                        fingerprint_hash=fh,
                        attack_name=attack_name,
                        parameters=json.loads(params),
                        effectiveness_score=eff_score,
                        success=bool(success),
                        latency_ms=latency,
                        timestamp=timestamp,
                        metadata=json.loads(metadata or "{}"),
                    )
                    strategies.append(strategy)

                self.logger.debug(
                    f"Retrieved {len(strategies)} best strategies for {fingerprint_hash[:8]}..."
                )
                return strategies

            except Exception as e:
                self.logger.error(f"Failed to get best strategies: {e}")
                return []

    async def save_adaptation_record(self, record: AdaptationRecord) -> bool:
        """
        Save an adaptation record to track learning decisions.

        Args:
            record: AdaptationRecord to save

        Returns:
            True if saved successfully, False otherwise
        """
        if not self._initialized:
            await self._initialize_database()
            
        async with self._lock:
            try:
                conn = await self._get_connection()
                cursor = conn.cursor()

                cursor.execute(
                    """
                    INSERT INTO adaptation_records 
                    (fingerprint_hash, timestamp, original_strategy, adapted_strategy,
                     adaptation_reason, effectiveness_before, effectiveness_after,
                     parameters_before, parameters_after)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        record.fingerprint_hash,
                        record.timestamp.timestamp(),
                        record.original_strategy,
                        record.adapted_strategy,
                        record.adaptation_reason,
                        record.effectiveness_before,
                        record.effectiveness_after,
                        json.dumps(record.parameters_before),
                        json.dumps(record.parameters_after),
                    ),
                )

                conn.commit()

                self.logger.debug(
                    f"Saved adaptation record: {record.original_strategy} -> {record.adapted_strategy}"
                )
                return True

            except Exception as e:
                self.logger.error(f"Failed to save adaptation record: {e}")
                return False

    async def analyze_learning_trends(
        self, fingerprint_hash: str, days_back: int = 30
    ) -> Dict[str, Any]:
        """
        Analyze learning trends for a fingerprint over time.

        Args:
            fingerprint_hash: Hash of the DPI fingerprint
            days_back: Number of days to analyze

        Returns:
            Dictionary with trend analysis
        """
        if not self._initialized:
            await self._initialize_database()
            
        async with self._lock:
            try:
                conn = await self._get_connection()
                cursor = conn.cursor()

                cutoff_time = time.time() - (days_back * 24 * 3600)

                # Get effectiveness trends
                cursor.execute(
                    """
                    SELECT DATE(timestamp, 'unixepoch') as date,
                           AVG(effectiveness_score) as avg_effectiveness,
                           COUNT(*) as attempts,
                           SUM(CASE WHEN success THEN 1 ELSE 0 END) as successes
                    FROM strategy_records 
                    WHERE fingerprint_hash = ? AND timestamp >= ?
                    GROUP BY DATE(timestamp, 'unixepoch')
                    ORDER BY date
                """,
                    (fingerprint_hash, cutoff_time),
                )

                daily_trends = []
                for row in cursor.fetchall():
                    date, avg_eff, attempts, successes = row
                    daily_trends.append(
                        {
                            "date": date,
                            "avg_effectiveness": avg_eff,
                            "attempts": attempts,
                            "success_rate": successes / attempts if attempts > 0 else 0,
                        }
                    )

                # Get attack type trends
                cursor.execute(
                    """
                    SELECT attack_name,
                           AVG(effectiveness_score) as avg_effectiveness,
                           COUNT(*) as attempts,
                           SUM(CASE WHEN success THEN 1 ELSE 0 END) as successes
                    FROM strategy_records 
                    WHERE fingerprint_hash = ? AND timestamp >= ?
                    GROUP BY attack_name
                    ORDER BY avg_effectiveness DESC
                """,
                    (fingerprint_hash, cutoff_time),
                )

                attack_trends = []
                for row in cursor.fetchall():
                    attack_name, avg_eff, attempts, successes = row
                    attack_trends.append(
                        {
                            "attack_name": attack_name,
                            "avg_effectiveness": avg_eff,
                            "attempts": attempts,
                            "success_rate": successes / attempts if attempts > 0 else 0,
                        }
                    )

                return {
                    "daily_trends": daily_trends,
                    "attack_trends": attack_trends,
                    "analysis_period_days": days_back,
                    "total_attempts": sum(t["attempts"] for t in daily_trends),
                    "overall_success_rate": (
                        sum(t["successes"] for t in attack_trends)
                        / sum(t["attempts"] for t in attack_trends)
                        if attack_trends
                        else 0
                    ),
                }

            except Exception as e:
                self.logger.error(f"Failed to analyze learning trends: {e}")
                return {}

    async def cleanup_old_records(self, days_to_keep: int = 90) -> int:
        """
        Clean up old learning records to prevent database bloat.

        Args:
            days_to_keep: Number of days of records to keep

        Returns:
            Number of records deleted
        """
        async with self._lock:
            try:
                conn = await self._get_connection()
                cursor = conn.cursor()

                cutoff_time = time.time() - (days_to_keep * 24 * 3600)

                # Delete old strategy records
                cursor.execute(
                    """
                    DELETE FROM strategy_records 
                    WHERE timestamp < ?
                """,
                    (cutoff_time,),
                )

                strategy_deleted = cursor.rowcount

                # Delete old adaptation records
                cursor.execute(
                    """
                    DELETE FROM adaptation_records 
                    WHERE timestamp < ?
                """,
                    (cutoff_time,),
                )

                adaptation_deleted = cursor.rowcount

                conn.commit()

                total_deleted = strategy_deleted + adaptation_deleted
                self.logger.info(
                    f"Cleaned up {total_deleted} old learning records "
                    f"({strategy_deleted} strategy, {adaptation_deleted} adaptation)"
                )

                return total_deleted

            except Exception as e:
                self.logger.error(f"Failed to cleanup old records: {e}")
                return 0

    async def close(self):
        """Close database connection."""
        if self._connection:
            self._connection.close()
            self._connection = None
            self.logger.debug("Learning memory database connection closed")
