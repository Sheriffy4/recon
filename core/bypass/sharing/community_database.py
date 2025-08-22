"""
Community-driven strategy database implementation.
"""
import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging
from recon.core.bypass.sharing.sharing_models import SharedStrategy, StrategyPackage, StrategyFeedback, ShareLevel, ValidationStatus
from recon.core.bypass.sharing.strategy_validator import StrategyValidator

class CommunityDatabase:
    """Manages community-driven strategy database."""

    def __init__(self, db_path: str='community_strategies.db'):
        self.db_path = Path(db_path)
        self.logger = logging.getLogger(__name__)
        self.validator = StrategyValidator()
        self._init_database()

    def _init_database(self):
        """Initialize SQLite database for community strategies."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript('\n                CREATE TABLE IF NOT EXISTS strategies (\n                    id TEXT PRIMARY KEY,\n                    name TEXT NOT NULL,\n                    description TEXT,\n                    strategy_data TEXT NOT NULL,\n                    author TEXT NOT NULL,\n                    version TEXT NOT NULL,\n                    share_level TEXT NOT NULL,\n                    validation_status TEXT NOT NULL,\n                    trust_score REAL DEFAULT 0.0,\n                    download_count INTEGER DEFAULT 0,\n                    success_reports INTEGER DEFAULT 0,\n                    failure_reports INTEGER DEFAULT 0,\n                    tags TEXT,\n                    target_regions TEXT,\n                    target_isps TEXT,\n                    created_at TEXT NOT NULL,\n                    updated_at TEXT NOT NULL,\n                    signature TEXT\n                );\n                \n                CREATE TABLE IF NOT EXISTS packages (\n                    id TEXT PRIMARY KEY,\n                    name TEXT NOT NULL,\n                    description TEXT,\n                    author TEXT NOT NULL,\n                    version TEXT NOT NULL,\n                    strategy_ids TEXT NOT NULL,\n                    dependencies TEXT,\n                    created_at TEXT NOT NULL,\n                    updated_at TEXT NOT NULL\n                );\n                \n                CREATE TABLE IF NOT EXISTS feedback (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    strategy_id TEXT NOT NULL,\n                    user_id TEXT NOT NULL,\n                    success INTEGER NOT NULL,\n                    region TEXT,\n                    isp TEXT,\n                    notes TEXT,\n                    timestamp TEXT NOT NULL,\n                    FOREIGN KEY (strategy_id) REFERENCES strategies (id)\n                );\n                \n                CREATE INDEX IF NOT EXISTS idx_strategies_author ON strategies (author);\n                CREATE INDEX IF NOT EXISTS idx_strategies_tags ON strategies (tags);\n                CREATE INDEX IF NOT EXISTS idx_strategies_trust_score ON strategies (trust_score);\n                CREATE INDEX IF NOT EXISTS idx_feedback_strategy ON feedback (strategy_id);\n            ')

    async def add_strategy(self, strategy: SharedStrategy) -> bool:
        """Add a new strategy to the community database."""
        try:
            validation_result = await self.validator.validate_strategy(strategy)
            if not validation_result.is_valid:
                self.logger.warning(f'Strategy {strategy.id} failed validation')
                return False
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('\n                    INSERT OR REPLACE INTO strategies \n                    (id, name, description, strategy_data, author, version, \n                     share_level, validation_status, trust_score, download_count,\n                     success_reports, failure_reports, tags, target_regions, \n                     target_isps, created_at, updated_at, signature)\n                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n                ', (strategy.id, strategy.name, strategy.description, json.dumps(strategy.strategy_data), strategy.author, strategy.version, strategy.share_level.value, strategy.validation_status.value, strategy.trust_score, strategy.download_count, strategy.success_reports, strategy.failure_reports, json.dumps(strategy.tags), json.dumps(strategy.target_regions), json.dumps(strategy.target_isps), strategy.created_at.isoformat(), strategy.updated_at.isoformat(), strategy.signature))
            self.logger.info(f'Added strategy {strategy.id} to community database')
            return True
        except Exception as e:
            self.logger.error(f'Failed to add strategy {strategy.id}: {e}')
            return False

    async def get_strategy(self, strategy_id: str) -> Optional[SharedStrategy]:
        """Get a strategy by ID."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('SELECT * FROM strategies WHERE id = ?', (strategy_id,))
                row = cursor.fetchone()
                if not row:
                    return None
                return self._row_to_strategy(row)
        except Exception as e:
            self.logger.error(f'Failed to get strategy {strategy_id}: {e}')
            return None

    async def search_strategies(self, query: str='', tags: List[str]=None, author: str='', min_trust_score: float=0.0, share_level: ShareLevel=None, limit: int=50) -> List[SharedStrategy]:
        """Search strategies with various filters."""
        try:
            conditions = ['trust_score >= ?']
            params = [min_trust_score]
            if query:
                conditions.append('(name LIKE ? OR description LIKE ?)')
                params.extend([f'%{query}%', f'%{query}%'])
            if author:
                conditions.append('author = ?')
                params.append(author)
            if share_level:
                conditions.append('share_level = ?')
                params.append(share_level.value)
            if tags:
                for tag in tags:
                    conditions.append('tags LIKE ?')
                    params.append(f'%{tag}%')
            where_clause = ' AND '.join(conditions)
            query_sql = f'\n                SELECT * FROM strategies \n                WHERE {where_clause}\n                ORDER BY trust_score DESC, download_count DESC\n                LIMIT ?\n            '
            params.append(limit)
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(query_sql, params)
                rows = cursor.fetchall()
                return [self._row_to_strategy(row) for row in rows]
        except Exception as e:
            self.logger.error(f'Failed to search strategies: {e}')
            return []

    async def get_popular_strategies(self, limit: int=20) -> List[SharedStrategy]:
        """Get most popular strategies by download count."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("\n                    SELECT * FROM strategies \n                    WHERE validation_status = 'validated' AND trust_score >= 0.7\n                    ORDER BY download_count DESC, trust_score DESC\n                    LIMIT ?\n                ", (limit,))
                rows = cursor.fetchall()
                return [self._row_to_strategy(row) for row in rows]
        except Exception as e:
            self.logger.error(f'Failed to get popular strategies: {e}')
            return []

    async def add_feedback(self, feedback: StrategyFeedback) -> bool:
        """Add user feedback for a strategy."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('\n                    INSERT INTO feedback \n                    (strategy_id, user_id, success, region, isp, notes, timestamp)\n                    VALUES (?, ?, ?, ?, ?, ?, ?)\n                ', (feedback.strategy_id, feedback.user_id, int(feedback.success), feedback.region, feedback.isp, feedback.notes, feedback.timestamp.isoformat()))
                if feedback.success:
                    conn.execute('\n                        UPDATE strategies \n                        SET success_reports = success_reports + 1\n                        WHERE id = ?\n                    ', (feedback.strategy_id,))
                else:
                    conn.execute('\n                        UPDATE strategies \n                        SET failure_reports = failure_reports + 1\n                        WHERE id = ?\n                    ', (feedback.strategy_id,))
            self.logger.info(f'Added feedback for strategy {feedback.strategy_id}')
            return True
        except Exception as e:
            self.logger.error(f'Failed to add feedback: {e}')
            return False

    async def increment_download_count(self, strategy_id: str) -> bool:
        """Increment download count for a strategy."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('\n                    UPDATE strategies \n                    SET download_count = download_count + 1\n                    WHERE id = ?\n                ', (strategy_id,))
            return True
        except Exception as e:
            self.logger.error(f'Failed to increment download count: {e}')
            return False

    async def create_package(self, package: StrategyPackage) -> bool:
        """Create a strategy package."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('\n                    INSERT OR REPLACE INTO packages\n                    (id, name, description, author, version, strategy_ids, \n                     dependencies, created_at, updated_at)\n                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)\n                ', (package.id, package.name, package.description, package.author, package.version, json.dumps([s.id for s in package.strategies]), json.dumps(package.dependencies), package.created_at.isoformat(), package.updated_at.isoformat()))
            self.logger.info(f'Created package {package.id}')
            return True
        except Exception as e:
            self.logger.error(f'Failed to create package: {e}')
            return False

    async def get_package(self, package_id: str) -> Optional[StrategyPackage]:
        """Get a strategy package by ID."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('SELECT * FROM packages WHERE id = ?', (package_id,))
                row = cursor.fetchone()
                if not row:
                    return None
                strategy_ids = json.loads(row['strategy_ids'])
                strategies = []
                for sid in strategy_ids:
                    strategy = await self.get_strategy(sid)
                    if strategy:
                        strategies.append(strategy)
                return StrategyPackage(id=row['id'], name=row['name'], description=row['description'], strategies=strategies, author=row['author'], version=row['version'], dependencies=json.loads(row['dependencies']), created_at=datetime.fromisoformat(row['created_at']), updated_at=datetime.fromisoformat(row['updated_at']))
        except Exception as e:
            self.logger.error(f'Failed to get package {package_id}: {e}')
            return None

    def _row_to_strategy(self, row: sqlite3.Row) -> SharedStrategy:
        """Convert database row to SharedStrategy object."""
        return SharedStrategy(id=row['id'], name=row['name'], description=row['description'], strategy_data=json.loads(row['strategy_data']), author=row['author'], version=row['version'], share_level=ShareLevel(row['share_level']), validation_status=ValidationStatus(row['validation_status']), trust_score=row['trust_score'], download_count=row['download_count'], success_reports=row['success_reports'], failure_reports=row['failure_reports'], tags=json.loads(row['tags']) if row['tags'] else [], target_regions=json.loads(row['target_regions']) if row['target_regions'] else [], target_isps=json.loads(row['target_isps']) if row['target_isps'] else [], created_at=datetime.fromisoformat(row['created_at']), updated_at=datetime.fromisoformat(row['updated_at']), signature=row['signature'])

    async def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("\n                    SELECT \n                        COUNT(*) as total_strategies,\n                        COUNT(CASE WHEN validation_status = 'validated' THEN 1 END) as validated,\n                        COUNT(CASE WHEN trust_score >= 0.8 THEN 1 END) as high_trust,\n                        AVG(trust_score) as avg_trust_score,\n                        SUM(download_count) as total_downloads\n                    FROM strategies\n                ")
                row = cursor.fetchone()
                return {'total_strategies': row[0], 'validated_strategies': row[1], 'high_trust_strategies': row[2], 'average_trust_score': row[3] or 0.0, 'total_downloads': row[4] or 0}
        except Exception as e:
            self.logger.error(f'Failed to get database stats: {e}')
            return {}

    async def cleanup_old_strategies(self, days: int=90) -> int:
        """Remove old, unused strategies."""
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('\n                    DELETE FROM strategies \n                    WHERE updated_at < ? AND download_count = 0 AND trust_score < 0.5\n                ', (cutoff_date.isoformat(),))
                deleted_count = cursor.rowcount
                self.logger.info(f'Cleaned up {deleted_count} old strategies')
                return deleted_count
        except Exception as e:
            self.logger.error(f'Failed to cleanup old strategies: {e}')
            return 0