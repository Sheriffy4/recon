import logging
import threading
from typing import Dict, Optional, Any, TYPE_CHECKING

from .signature_persistence import (
    load_signatures_from_file,
    save_signatures_to_file,
)
from .signature_sync import sync_from_remote_source
from .signature_scheduler import SyncScheduler
from .signature_queries import find_matching_signature
from .signature_updates import create_signature_entry, update_strategy_in_place
from .signature_io import export_signatures, import_signatures
from .signature_analytics import compute_signature_statistics, generate_text_report

if TYPE_CHECKING:
    from recon.core.fingerprint import Fingerprint

LOG = logging.getLogger("SignatureManager")
SIGNATURE_DB_PATH = "dpi_signatures.json"
REMOTE_DB_URL = "https://raw.githubusercontent.com/ValdikSS/Recon/main/dpi_signatures_export.json"
SIGNATURE_SCHEMA = {
    "type": "object",
    "properties": {
        "fingerprint_details": {"type": "object"},
        "working_strategy": {
            "type": "object",
            "properties": {
                "strategy": {"type": "string"},
                "success_rate": {"type": "number", "minimum": 0, "maximum": 1},
            },
            "required": ["strategy"],
        },
        "metadata": {"type": "object"},
    },
    "required": ["working_strategy"],
}


class SignatureManager:
    """
    Facade for DPI signature management operations.

    Coordinates persistence, synchronization, queries, updates, I/O, and analytics.
    Thread-safe for concurrent access.
    """

    def __init__(self, db_path: str = SIGNATURE_DB_PATH):
        self.db_path = db_path
        self._lock = threading.RLock()  # Reentrant lock for thread safety
        self.signatures = self._load_signatures()
        self._scheduler = SyncScheduler()

    def _load_signatures(self) -> Dict[str, Any]:
        """Load signatures from file (delegates to persistence layer)."""
        return load_signatures_from_file(self.db_path)

    def _save_signatures(self):
        """Save signatures to file (delegates to persistence layer)."""
        save_signatures_to_file(self.db_path, self.signatures)

    def sync_from_remote(self):
        """Synchronize with remote signature database (thread-safe)."""
        # Perform network I/O and merge without holding lock
        updated_signatures, new_count = sync_from_remote_source(
            self.signatures.copy(),  # Work on snapshot to avoid long lock
            REMOTE_DB_URL,
            SIGNATURE_SCHEMA,
            timeout=10,
        )

        # Only lock for final update
        if new_count > 0:
            with self._lock:
                self.signatures = updated_signatures
                self._save_signatures()

    def start_auto_sync(self, interval_hours: int = 24):
        """Start automatic periodic synchronization."""
        self._scheduler.start(self.sync_from_remote, interval_hours)

    def stop_auto_sync(self):
        """Stop automatic synchronization."""
        self._scheduler.stop()

    def find_strategy_for_fingerprint(self, fp: "Fingerprint") -> Optional[Dict[str, Any]]:
        """Find matching strategy for a fingerprint (thread-safe)."""
        with self._lock:
            return find_matching_signature(self.signatures, fp)

    def update_signature(self, fp: "Fingerprint", best_strategy_result: Dict[str, Any]):
        """Update signature with new strategy result (thread-safe)."""
        with self._lock:
            fp_hash = fp.short_hash()
            existing_entry = self.signatures.get(fp_hash, {})

            entry = create_signature_entry(fp, best_strategy_result, existing_entry)
            self.signatures[fp_hash] = entry

            LOG.info(f"💾 База данных сигнатур обновлена для фингерпринта {fp_hash}.")
            self._save_signatures()

    def update_strategy_for_fingerprint(
        self, fp_hash: str, new_strategy: str, new_success_rate: float
    ):
        """Update strategy for existing fingerprint (thread-safe)."""
        with self._lock:
            if fp_hash not in self.signatures:
                LOG.warning(
                    f"Попытка обновить стратегию для несуществующего фингерпринта: {fp_hash}"
                )
                return

            entry = self.signatures[fp_hash]
            update_strategy_in_place(entry, new_strategy, new_success_rate)

            LOG.info(f"💾 [Монитор] Стратегия для {fp_hash} обновлена на: {new_strategy}")
            self._save_signatures()

    def export_for_sharing(self, export_path: str = "dpi_signatures_export.json"):
        """Export signatures for community sharing (thread-safe)."""
        with self._lock:
            export_signatures(self.signatures, export_path)

    def import_from_community(self, import_path: str):
        """Import signatures from community file (thread-safe)."""
        with self._lock:
            imported, imported_count, skipped_count = import_signatures(
                import_path, SIGNATURE_SCHEMA
            )

            # Merge only new signatures and count actually added
            actually_added = 0
            for fp_hash, entry in imported.items():
                if fp_hash not in self.signatures:
                    self.signatures[fp_hash] = entry
                    actually_added += 1

            if actually_added > 0:
                self._save_signatures()
                LOG.info(f"📥 Импортировано {actually_added} новых сигнатур из '{import_path}'.")

            if skipped_count == 0 and actually_added == 0:
                LOG.info("Новых сигнатур для импорта не найдено.")

    def generate_report(self, output_file: str = "dpi_report.txt"):
        """Generate comprehensive signature report (thread-safe)."""
        with self._lock:
            stats = self.get_statistics()
            generate_text_report(stats, output_file)

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics about signatures (thread-safe)."""
        with self._lock:
            return compute_signature_statistics(self.signatures)
