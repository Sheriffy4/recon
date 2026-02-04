#!/usr/bin/env python3
"""
Backward Compatibility Layer for Advanced DPI Fingerprinting - Task 15 Implementation
Provides compatibility wrappers, data migration, and graceful handling of legacy formats.
"""

import json
import pickle
import logging
import shutil
from typing import Dict, Any, Optional, List
from pathlib import Path
import time

try:
    from core.fingerprint.advanced_models import (
        DPIFingerprint,
        DPIType,
        ConfidenceLevel,
    )
except ImportError:
    from core.fingerprint.advanced_models import (
        DPIFingerprint,
        DPIType,
    )


logger = logging.getLogger(__name__)


class CompatibilityError(Exception):
    """Base exception for compatibility layer operations"""

    pass


class MigrationError(CompatibilityError):
    """Exception raised during data migration"""

    pass


class LegacyFormatError(CompatibilityError):
    """Exception raised when legacy format cannot be processed"""

    pass


class BackwardCompatibilityLayer:
    """
    Backward compatibility layer for advanced DPI fingerprinting system.
    Handles migration from old formats, provides compatibility wrappers,
    and ensures graceful degradation when advanced features are unavailable.
    """

    def __init__(self, cache_dir: str = "cache", backup_dir: str = "backup"):
        """
        Initialize backward compatibility layer.

        Args:
            cache_dir: Directory for cache files
            backup_dir: Directory for backup files during migration
        """
        self.cache_dir = Path(cache_dir)
        self.backup_dir = Path(backup_dir)
        self.migration_log = []

        # Ensure directories exist
        self.cache_dir.mkdir(exist_ok=True)
        self.backup_dir.mkdir(exist_ok=True)

        # Legacy format mappings
        self.legacy_dpi_type_mapping = {
            "LIKELY_WINDOWS_BASED": DPIType.FIREWALL_BASED,
            "LIKELY_LINUX_BASED": DPIType.FIREWALL_BASED,
            "ROSKOMNADZOR": DPIType.ROSKOMNADZOR_TSPU,
            "ROSKOMNADZOR_ADVANCED": DPIType.ROSKOMNADZOR_DPI,
            "COMMERCIAL": DPIType.COMMERCIAL_DPI,
            "GOVERNMENT": DPIType.GOVERNMENT_CENSORSHIP,
            "PROXY": DPIType.ISP_TRANSPARENT_PROXY,
            "CLOUDFLARE": DPIType.CLOUDFLARE_PROTECTION,
            "UNKNOWN": DPIType.UNKNOWN,
        }

    def migrate_legacy_cache(self, legacy_cache_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Migrate legacy cache files to new format.

        Args:
            legacy_cache_path: Path to legacy cache file (auto-detect if None)

        Returns:
            Migration report with statistics and errors
        """
        migration_report = {
            "started_at": time.time(),
            "files_processed": 0,
            "entries_migrated": 0,
            "entries_failed": 0,
            "errors": [],
            "warnings": [],
        }

        try:
            # Auto-detect legacy cache files if not specified
            if legacy_cache_path is None:
                legacy_files = self._find_legacy_cache_files()
            else:
                legacy_files = [Path(legacy_cache_path)]

            if not legacy_files:
                migration_report["warnings"].append("No legacy cache files found")
                return migration_report

            # Create backup before migration
            backup_timestamp = int(time.time())
            backup_path = self.backup_dir / f"migration_backup_{backup_timestamp}"
            backup_path.mkdir(exist_ok=True)

            for legacy_file in legacy_files:
                try:
                    migration_report["files_processed"] += 1

                    # Backup original file
                    backup_file = backup_path / legacy_file.name
                    shutil.copy2(legacy_file, backup_file)

                    # Migrate file contents
                    migrated_entries = self._migrate_cache_file(legacy_file)
                    migration_report["entries_migrated"] += len(migrated_entries)

                    logger.info(f"Migrated {len(migrated_entries)} entries from {legacy_file}")

                except Exception as e:
                    error_msg = f"Failed to migrate {legacy_file}: {str(e)}"
                    migration_report["errors"].append(error_msg)
                    migration_report["entries_failed"] += 1
                    logger.error(error_msg)

            migration_report["completed_at"] = time.time()
            migration_report["duration"] = (
                migration_report["completed_at"] - migration_report["started_at"]
            )

            # Save migration report
            report_path = self.backup_dir / f"migration_report_{backup_timestamp}.json"
            with open(report_path, "w") as f:
                json.dump(migration_report, f, indent=2)

            logger.info(
                f"Migration completed: {migration_report['entries_migrated']} entries migrated"
            )

        except Exception as e:
            migration_report["errors"].append(f"Migration failed: {str(e)}")
            logger.error(f"Migration failed: {str(e)}")

        return migration_report

    def _find_legacy_cache_files(self) -> List[Path]:
        """Find legacy cache files in common locations."""
        legacy_patterns = [
            "fingerprint_cache.pkl",
            "dpi_cache.pkl",
            "simple_fingerprints.json",
            "*.fingerprint",
            "cache/*.pkl",
        ]

        legacy_files = []

        # Search in current directory and cache directory
        search_dirs = [Path("."), self.cache_dir, Path("cache"), Path("data")]

        for search_dir in search_dirs:
            if not search_dir.exists():
                continue

            for pattern in legacy_patterns:
                try:
                    matches = list(search_dir.glob(pattern))
                    legacy_files.extend(matches)
                except Exception as e:
                    logger.warning(f"Error searching for pattern {pattern} in {search_dir}: {e}")

        # Remove duplicates and non-existent files
        unique_files = []
        seen = set()
        for file_path in legacy_files:
            if file_path.exists() and file_path.resolve() not in seen:
                unique_files.append(file_path)
                seen.add(file_path.resolve())

        return unique_files

    def _migrate_cache_file(self, legacy_file: Path) -> List[DPIFingerprint]:
        """Migrate a single legacy cache file."""
        migrated_entries = []

        try:
            # Try different legacy formats
            if legacy_file.suffix == ".pkl":
                data = self._load_pickle_cache(legacy_file)
            elif legacy_file.suffix == ".json":
                data = self._load_json_cache(legacy_file)
            else:
                # Try to detect format by content
                data = self._auto_detect_and_load(legacy_file)

            # Convert legacy entries to new format
            for key, value in data.items():
                try:
                    fingerprint = self._convert_legacy_entry(key, value)
                    if fingerprint:
                        migrated_entries.append(fingerprint)

                        # Save to new cache format
                        self._save_migrated_fingerprint(fingerprint)

                except Exception as e:
                    logger.warning(f"Failed to convert legacy entry {key}: {e}")
                    continue

        except Exception as e:
            raise MigrationError(f"Failed to migrate cache file {legacy_file}: {e}")

        return migrated_entries

    def _load_pickle_cache(self, file_path: Path) -> Dict[str, Any]:
        """Load legacy pickle cache file."""
        try:
            with open(file_path, "rb") as f:
                return pickle.load(f)
        except Exception as e:
            raise LegacyFormatError(f"Failed to load pickle cache {file_path}: {e}")

    def _load_json_cache(self, file_path: Path) -> Dict[str, Any]:
        """Load legacy JSON cache file."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            raise LegacyFormatError(f"Failed to load JSON cache {file_path}: {e}")

    def _auto_detect_and_load(self, file_path: Path) -> Dict[str, Any]:
        """Auto-detect legacy file format and load it."""
        # Try pickle first
        try:
            return self._load_pickle_cache(file_path)
        except (
            pickle.UnpicklingError,
            ValueError,
            EOFError,
            AttributeError,
            LegacyFormatError,
        ):
            pass

        # Try JSON
        try:
            return self._load_json_cache(file_path)
        except (json.JSONDecodeError, UnicodeDecodeError, LegacyFormatError):
            pass

        # Try plain text format
        try:
            data = self._load_text_cache(file_path)
            if not data and file_path.stat().st_size > 0:
                # Heuristic: if file has content but we parsed nothing, it's probably not a text file.
                is_effectively_empty = True
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if line.strip() and not line.strip().startswith("#"):
                            is_effectively_empty = False
                            break
                if not is_effectively_empty:
                    raise LegacyFormatError("File has non-comment content but produced no data.")
            return data
        except LegacyFormatError:
            pass

        raise LegacyFormatError(f"Unable to detect format of {file_path}")

    def _load_text_cache(self, file_path: Path) -> Dict[str, Any]:
        """Load legacy text-based cache file."""
        data = {}

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    try:
                        # Try to parse as key=value or key:value
                        if "=" in line:
                            key, value = line.split("=", 1)
                        elif ":" in line:
                            key, value = line.split(":", 1)
                        else:
                            continue

                        key = key.strip()
                        value = value.strip()

                        # Try to parse value as JSON
                        try:
                            value = json.loads(value)
                        except:
                            pass

                        data[key] = value

                    except Exception as e:
                        logger.warning(f"Failed to parse line {line_num} in {file_path}: {e}")
                        continue

        except Exception as e:
            raise LegacyFormatError(f"Failed to load text cache {file_path}: {e}")

        return data

    def _convert_legacy_entry(self, key: str, value: Any) -> Optional[DPIFingerprint]:
        """Convert a legacy cache entry to new DPIFingerprint format."""
        if not isinstance(key, str) or value is None:
            return None

        try:
            # Handle different legacy value formats
            if isinstance(value, dict):
                return self._convert_dict_entry(key, value)
            elif isinstance(value, str):
                return self._convert_string_entry(key, value)
            elif isinstance(value, (list, tuple)):
                return self._convert_list_entry(key, value)
            else:
                # Unsupported type, return None to signify failure
                return None

        except Exception as e:
            logger.warning(f"Failed to convert legacy entry {key}: {e}")
            return None

    def _convert_dict_entry(self, key: str, value: Dict[str, Any]) -> DPIFingerprint:
        """Convert dictionary-based legacy entry."""
        # Extract target from key (usually domain name)
        target = key.split("_")[0] if "_" in key else key

        # Map legacy DPI type
        legacy_dpi_type = str(value.get("dpi_type", value.get("type", "UNKNOWN"))).upper()
        dpi_type = self.legacy_dpi_type_mapping.get(legacy_dpi_type, DPIType.UNKNOWN)

        # Extract confidence
        confidence = float(value.get("confidence", value.get("score", 0.5)))

        # Create new fingerprint with available data
        fingerprint = DPIFingerprint(
            target=target,
            dpi_type=dpi_type,
            confidence=confidence,
            timestamp=value.get("timestamp", time.time()),
            reliability_score=confidence,  # Use confidence as reliability for legacy data
        )

        # Map legacy fields to new fields
        field_mappings = {
            "rst_detected": "rst_injection_detected",
            "header_filtering": "http_header_filtering",
            "dns_hijack": "dns_hijacking_detected",
            "content_inspection": "content_inspection_depth",
            "user_agent_block": "user_agent_filtering",
            "supports_ipv6": "supports_ipv6",
            "timeout_manipulation": "dns_timeout_manipulation",
        }

        for legacy_field, new_field in field_mappings.items():
            if legacy_field in value:
                setattr(fingerprint, new_field, value[legacy_field])

        # Handle special cases
        if "blocking_methods" in value:
            methods = value["blocking_methods"]
            if isinstance(methods, list):
                if "RST" in methods:
                    fingerprint.rst_injection_detected = True
                if "DNS" in methods:
                    fingerprint.dns_hijacking_detected = True
                if "HTTP" in methods:
                    fingerprint.http_header_filtering = True

        return fingerprint

    def _convert_string_entry(self, key: str, value: str) -> DPIFingerprint:
        """Convert string-based legacy entry."""
        target = key.split("_")[0] if "_" in key else key

        # Try to parse string as JSON
        try:
            parsed_value = json.loads(value)
            if isinstance(parsed_value, dict):
                return self._convert_dict_entry(key, parsed_value)
        except:
            pass

        # Handle simple string values
        dpi_type = self.legacy_dpi_type_mapping.get(value.upper(), DPIType.UNKNOWN)

        return DPIFingerprint(
            target=target,
            dpi_type=dpi_type,
            confidence=0.5,  # Default confidence for string entries
            reliability_score=0.4,  # Lower reliability for simple entries
        )

    def _convert_list_entry(self, key: str, value: List[Any]) -> DPIFingerprint:
        """Convert list-based legacy entry."""
        target = key.split("_")[0] if "_" in key else key

        # Assume list contains [dpi_type, confidence, ...other_data]
        dpi_type_str = str(value[0]) if len(value) > 0 else "UNKNOWN"
        confidence = (
            float(value[1]) if len(value) > 1 and isinstance(value[1], (int, float)) else 0.5
        )

        dpi_type = self.legacy_dpi_type_mapping.get(dpi_type_str.upper(), DPIType.UNKNOWN)

        fingerprint = DPIFingerprint(
            target=target,
            dpi_type=dpi_type,
            confidence=confidence,
            reliability_score=confidence * 0.8,  # Slightly lower reliability
        )

        # Try to extract additional data from list
        if len(value) > 2:
            additional_data = value[2]
            if isinstance(additional_data, dict):
                # Apply additional data similar to dict conversion
                if additional_data.get("rst_detected"):
                    fingerprint.rst_injection_detected = True
                if additional_data.get("dns_hijack"):
                    fingerprint.dns_hijacking_detected = True

        return fingerprint

    def _save_migrated_fingerprint(self, fingerprint: DPIFingerprint):
        """Save migrated fingerprint to new cache format."""
        try:
            # Import cache here to avoid circular imports
            from core.fingerprint.cache import FingerprintCache

            cache = FingerprintCache()
            cache.set(fingerprint.target, fingerprint)

        except ImportError:
            # Fallback: save to JSON file
            cache_file = self.cache_dir / f"migrated_{fingerprint.target.replace('.', '_')}.json"
            with open(cache_file, "w") as f:
                json.dump(fingerprint.to_dict(), f, indent=2)

    def create_compatibility_wrapper(self) -> "LegacyFingerprintWrapper":
        """Create a compatibility wrapper for legacy code."""
        return LegacyFingerprintWrapper(self)

    def validate_migration(
        self, original_cache_path: str, migrated_cache_path: str
    ) -> Dict[str, Any]:
        """Validate that migration was successful."""
        validation_report = {
            "original_entries": 0,
            "migrated_entries": 0,
            "validation_errors": [],
            "sample_comparisons": [],
        }

        try:
            # Load original cache
            original_data = self._auto_detect_and_load(Path(original_cache_path))
            validation_report["original_entries"] = len(original_data)

            # Count migrated entries
            migrated_files = list(self.cache_dir.glob("migrated_*.json"))
            validation_report["migrated_entries"] = len(migrated_files)

            # Sample validation
            sample_keys = list(original_data.keys())[:5]  # Validate first 5 entries

            for key in sample_keys:
                try:
                    original_value = original_data[key]
                    migrated_fingerprint = self._convert_legacy_entry(key, original_value)

                    if migrated_fingerprint:
                        validation_report["sample_comparisons"].append(
                            {
                                "key": key,
                                "original": str(original_value)[:100],  # Truncate for readability
                                "migrated_target": migrated_fingerprint.target,
                                "migrated_type": migrated_fingerprint.dpi_type.value,
                                "migrated_confidence": migrated_fingerprint.confidence,
                            }
                        )
                    else:
                        validation_report["validation_errors"].append(
                            f"Failed to migrate key: {key}"
                        )

                except Exception as e:
                    validation_report["validation_errors"].append(
                        f"Validation error for {key}: {e}"
                    )

        except Exception as e:
            validation_report["validation_errors"].append(f"Validation failed: {e}")

        return validation_report


class LegacyFingerprintWrapper:
    """
    Compatibility wrapper that provides legacy fingerprinting interface
    while using the new advanced fingerprinting system underneath.
    """

    def __init__(self, compatibility_layer: BackwardCompatibilityLayer):
        """Initialize wrapper with compatibility layer."""
        self.compatibility_layer = compatibility_layer
        self._advanced_fingerprinter = None

    def get_simple_fingerprint(self, target: str) -> Dict[str, Any]:
        """
        Get fingerprint in legacy simple format.

        Args:
            target: Target domain or IP

        Returns:
            Legacy format fingerprint dictionary
        """
        try:
            # Try to get advanced fingerprint
            advanced_fp = self._get_advanced_fingerprint(target)

            if advanced_fp:
                # Convert to legacy format
                return self._convert_to_legacy_format(advanced_fp)
            else:
                # Fallback to simple detection
                return self._simple_fallback_detection(target)

        except Exception as e:
            logger.warning(f"Failed to get fingerprint for {target}: {e}")
            return self._create_unknown_fingerprint(target)

    def _get_advanced_fingerprint(self, target: str) -> Optional[DPIFingerprint]:
        """Get fingerprint using advanced fingerprinting system."""
        try:
            if self._advanced_fingerprinter is None:
                from core.fingerprint.advanced_fingerprinter import (
                    AdvancedFingerprinter,
                )

                self._advanced_fingerprinter = AdvancedFingerprinter()

            # Use async fingerprinting (simplified for compatibility)
            import asyncio

            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            return loop.run_until_complete(self._advanced_fingerprinter.fingerprint_target(target))

        except Exception as e:
            logger.warning(f"Advanced fingerprinting failed for {target}: {e}")
            return None

    def _convert_to_legacy_format(self, fingerprint: DPIFingerprint) -> Dict[str, Any]:
        """Convert advanced fingerprint to legacy format."""
        # Map new DPI types back to legacy types
        legacy_type_mapping = {
            DPIType.ROSKOMNADZOR_TSPU: "ROSKOMNADZOR",
            DPIType.ROSKOMNADZOR_DPI: "ROSKOMNADZOR_ADVANCED",
            DPIType.COMMERCIAL_DPI: "COMMERCIAL",
            DPIType.FIREWALL_BASED: "LIKELY_WINDOWS_BASED",
            DPIType.ISP_TRANSPARENT_PROXY: "PROXY",
            DPIType.CLOUDFLARE_PROTECTION: "CLOUDFLARE",
            DPIType.GOVERNMENT_CENSORSHIP: "GOVERNMENT",
            DPIType.UNKNOWN: "UNKNOWN",
        }

        legacy_type = legacy_type_mapping.get(fingerprint.dpi_type, "UNKNOWN")

        # Create legacy format
        legacy_fingerprint = {
            "dpi_type": legacy_type,
            "confidence": fingerprint.confidence,
            "timestamp": fingerprint.timestamp,
            "blocking_methods": [],
        }

        # Add blocking methods based on detected characteristics
        if fingerprint.rst_injection_detected:
            legacy_fingerprint["blocking_methods"].append("RST")
        if fingerprint.dns_hijacking_detected:
            legacy_fingerprint["blocking_methods"].append("DNS")
        if fingerprint.http_header_filtering:
            legacy_fingerprint["blocking_methods"].append("HTTP")

        # Add additional legacy fields
        legacy_fingerprint.update(
            {
                "rst_detected": fingerprint.rst_injection_detected,
                "header_filtering": fingerprint.http_header_filtering,
                "dns_hijack": fingerprint.dns_hijacking_detected,
                "user_agent_block": fingerprint.user_agent_filtering,
                "supports_ipv6": fingerprint.supports_ipv6,
            }
        )

        return legacy_fingerprint

    def _simple_fallback_detection(self, target: str) -> Dict[str, Any]:
        """Simple fallback detection when advanced fingerprinting is unavailable."""
        # Basic detection logic (simplified)
        import socket
        import time

        try:
            # Simple connectivity test
            start_time = time.time()
            socket.create_connection((target, 80), timeout=5)
            response_time = time.time() - start_time

            # Very basic heuristics
            if response_time > 2.0:
                dpi_type = "LIKELY_WINDOWS_BASED"
                confidence = 0.3
            else:
                dpi_type = "UNKNOWN"
                confidence = 0.1

        except Exception:
            dpi_type = "UNKNOWN"
            confidence = 0.1

        return {
            "dpi_type": dpi_type,
            "confidence": confidence,
            "timestamp": time.time(),
            "blocking_methods": [],
            "fallback_used": True,
        }

    def _create_unknown_fingerprint(self, target: str) -> Dict[str, Any]:
        """Create unknown fingerprint when all detection methods fail."""
        return {
            "dpi_type": "UNKNOWN",
            "confidence": 0.0,
            "timestamp": time.time(),
            "blocking_methods": [],
            "error": True,
            "target": target,
        }

    def is_blocked(self, target: str) -> bool:
        """Legacy method to check if target is blocked."""
        fingerprint = self.get_simple_fingerprint(target)
        return fingerprint.get("dpi_type", "UNKNOWN") != "UNKNOWN"

    def get_blocking_type(self, target: str) -> str:
        """Legacy method to get blocking type."""
        fingerprint = self.get_simple_fingerprint(target)
        return fingerprint.get("dpi_type", "UNKNOWN")


def migrate_legacy_data(cache_dir: str = "cache", backup_dir: str = "backup") -> Dict[str, Any]:
    """
    Convenience function to migrate legacy data.

    Args:
        cache_dir: Directory for cache files
        backup_dir: Directory for backup files

    Returns:
        Migration report
    """
    compatibility_layer = BackwardCompatibilityLayer(cache_dir, backup_dir)
    return compatibility_layer.migrate_legacy_cache()


def create_legacy_wrapper() -> LegacyFingerprintWrapper:
    """
    Convenience function to create legacy compatibility wrapper.

    Returns:
        Legacy fingerprint wrapper
    """
    compatibility_layer = BackwardCompatibilityLayer()
    return compatibility_layer.create_compatibility_wrapper()


if __name__ == "__main__":
    # CLI interface for migration
    import argparse

    parser = argparse.ArgumentParser(description="Migrate legacy DPI fingerprint data")
    parser.add_argument("--cache-dir", default="cache", help="Cache directory")
    parser.add_argument("--backup-dir", default="backup", help="Backup directory")
    parser.add_argument("--legacy-file", help="Specific legacy file to migrate")
    parser.add_argument("--validate", help="Validate migration against original file")

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    compatibility_layer = BackwardCompatibilityLayer(args.cache_dir, args.backup_dir)

    if args.validate:
        print("Validating migration...")
        report = compatibility_layer.validate_migration(args.validate, args.cache_dir)
        print(json.dumps(report, indent=2))
    else:
        print("Starting migration...")
        report = compatibility_layer.migrate_legacy_cache(args.legacy_file)
        print(json.dumps(report, indent=2))

        if report["entries_migrated"] > 0:
            print(f"\n✅ Successfully migrated {report['entries_migrated']} entries")
        if report["errors"]:
            print(f"\n❌ {len(report['errors'])} errors occurred during migration")
            for error in report["errors"]:
                print(f"   - {error}")
