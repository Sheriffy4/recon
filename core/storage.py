# recon/core/storage.py
import sqlite3
import json
import time
import pathlib
import logging
from typing import List, Dict

DB_PATH = pathlib.Path(__file__).parent.parent / "recon_history.db"
LOG = logging.getLogger("storage")


class Storage:
    """Менеджер для работы с SQLite базой данных истории тестов."""

    def __init__(self, db_path: pathlib.Path = DB_PATH):
        self.db_path = db_path
        self.conn = None

    def __enter__(self):
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_db()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            self.conn.commit()
            self.conn.close()

    def _init_db(self):
        self.conn.execute(
            """
        CREATE TABLE IF NOT EXISTS tests (
            timestamp REAL,
            target_host TEXT,
            fingerprint TEXT,
            tech_type TEXT,
            tech_params TEXT,
            result TEXT,
            rtt REAL
        )"""
        )

    def save(
        self,
        target_host: str,
        fp: Dict,
        tech_type: str,
        tech_params: Dict,
        result: str,
        rtt: float,
    ):
        self.conn.execute(
            "INSERT INTO tests VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                time.time(),
                target_host,
                json.dumps(fp),
                tech_type,
                json.dumps(tech_params),
                result,
                rtt,
            ),
        )
        LOG.debug(f"Saved result for {tech_type}: {result}")

    def get_success_rate(self, tech_type: str) -> float:
        """Возвращает долю успешных запусков для техники."""
        cur = self.conn.execute(
            "SELECT SUM(CASE WHEN result = 'SUCCESS' THEN 1 ELSE 0 END), COUNT(*) FROM tests WHERE tech_type = ?",
            (tech_type,),
        )
        row = cur.fetchone()
        if not row or row[1] == 0:
            return 0.0
        return (row[0] or 0) / row[1]

    def get_recent_successful(self, limit: int = 3) -> List[Dict]:
        """Возвращает последние успешные тесты."""
        cur = self.conn.execute(
            """
            SELECT tech_type, tech_params, rtt FROM tests 
            WHERE result = 'SUCCESS' ORDER BY timestamp DESC LIMIT ?
        """,
            (limit,),
        )
        return [dict(row) for row in cur.fetchall()]

    def export_for_ml(self, limit: int = 1000) -> List[Dict]:
        """
        Экспортирует историю тестов для использования в ML-моделях.
        """
        cur = self.conn.execute("SELECT * FROM tests ORDER BY timestamp DESC LIMIT ?", (limit,))
        return [dict(row) for row in cur.fetchall()]
