"""
History Manager for Results Validation System.

Extracted from results_validation_system.py to reduce god class complexity.
Handles loading, saving, and managing validation history.
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
from dataclasses import asdict, is_dataclass
from enum import Enum

LOG = logging.getLogger("ValidationHistoryManager")


class ValidationHistoryManager:
    """Manages validation history persistence and retrieval."""

    SCHEMA_VERSION = 2

    @staticmethod
    def _jsonify(value: Any) -> Any:
        """Convert dataclasses/enums/datetimes into JSON-serializable structures."""
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, Enum):
            return value.value
        if is_dataclass(value):
            return ValidationHistoryManager._jsonify(asdict(value))
        if isinstance(value, dict):
            return {k: ValidationHistoryManager._jsonify(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [ValidationHistoryManager._jsonify(v) for v in value]
        return value

    @staticmethod
    def serialize_report(report) -> Dict[str, Any]:
        """
        Serialize ValidationReport to dictionary for JSON storage.

        Args:
            report: ValidationReport instance

        Returns:
            Dictionary representation of the report
        """
        # v2 stores both summary and detailed sections to allow future extensions.
        # Backward compatibility: keep top-level summary keys stable.
        base = {
            "schema_version": ValidationHistoryManager.SCHEMA_VERSION,
            "report_id": report.report_id,
            "generated_at": report.generated_at.isoformat(),
            "test_period": [report.test_period[0].isoformat(), report.test_period[1].isoformat()],
            "total_tests": report.total_tests,
            "passed_tests": report.passed_tests,
            "failed_tests": report.failed_tests,
            "overall_score": report.overall_score,
        }
        # Store full report details (can be used for metrics/trends later)
        # and to avoid losing signal when loading from history.
        try:
            base["details"] = ValidationHistoryManager._jsonify(report)
        except Exception as e:
            # Do not break persistence if some nested field becomes non-serializable.
            LOG.warning(f"Failed to serialize full report details; storing summary only: {e}")
            base["details"] = None
        return base

    @staticmethod
    def deserialize_report(report_data: Dict[str, Any], validation_report_class):
        """
        Deserialize dictionary to ValidationReport instance.

        Args:
            report_data: Dictionary with report data
            validation_report_class: ValidationReport class for instantiation

        Returns:
            ValidationReport instance
        """
        schema_version = int(report_data.get("schema_version", 1))

        # v1: legacy summary-only format
        if schema_version <= 1 or not report_data.get("details"):
            return validation_report_class(
                report_id=report_data["report_id"],
                generated_at=datetime.fromisoformat(report_data["generated_at"]),
                test_period=(
                    datetime.fromisoformat(report_data["test_period"][0]),
                    datetime.fromisoformat(report_data["test_period"][1]),
                ),
                total_tests=report_data.get("total_tests", 0),
                passed_tests=report_data.get("passed_tests", 0),
                failed_tests=report_data.get("failed_tests", 0),
                overall_score=report_data.get("overall_score", 0.0),
            )

        # v2: full details format (still keeps summary keys at top-level)
        details = report_data.get("details") or {}

        # Lazy import to avoid circular imports at module import time
        try:
            from .results_validation_system import (
                StrategyValidationResult,
                FingerprintValidationResult,
                ABTestResult,
                QualityMetrics,
            )
        except Exception as e:
            LOG.warning(f"Failed to import result classes for history deserialization: {e}")
            # Fallback to summary-only construction
            return validation_report_class(
                report_id=report_data["report_id"],
                generated_at=datetime.fromisoformat(report_data["generated_at"]),
                test_period=(
                    datetime.fromisoformat(report_data["test_period"][0]),
                    datetime.fromisoformat(report_data["test_period"][1]),
                ),
                total_tests=report_data.get("total_tests", 0),
                passed_tests=report_data.get("passed_tests", 0),
                failed_tests=report_data.get("failed_tests", 0),
                overall_score=report_data.get("overall_score", 0.0),
            )

        def _dt(x: Any) -> datetime:
            return x if isinstance(x, datetime) else datetime.fromisoformat(str(x))

        def _build_list(items: Any, cls):
            if not items:
                return []
            out = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                try:
                    out.append(cls(**item))
                except Exception:
                    # If format evolves, ignore bad entry rather than failing entire history load.
                    continue
            return out

        # Parse required fields
        generated_at = _dt(details.get("generated_at", report_data["generated_at"]))
        tp = details.get("test_period") or report_data.get("test_period")
        test_period = (_dt(tp[0]), _dt(tp[1]))

        # Parse optional sections
        strategy_validations = _build_list(
            details.get("strategy_validations"), StrategyValidationResult
        )
        fingerprint_validations = _build_list(
            details.get("fingerprint_validations"), FingerprintValidationResult
        )

        ab_test_results_raw = details.get("ab_test_results") or []
        ab_test_results = []
        for item in ab_test_results_raw:
            if not isinstance(item, dict):
                continue
            try:
                ci = item.get("confidence_interval")
                if isinstance(ci, list):
                    item["confidence_interval"] = tuple(ci)
                ab_test_results.append(ABTestResult(**item))
            except Exception:
                continue

        qm = None
        qm_raw = details.get("quality_metrics")
        if isinstance(qm_raw, dict):
            try:
                qm_raw = dict(qm_raw)
                if "timestamp" in qm_raw:
                    qm_raw["timestamp"] = _dt(qm_raw["timestamp"])
                qm = QualityMetrics(**qm_raw)
            except Exception:
                qm = None

        return validation_report_class(
            report_id=str(details.get("report_id", report_data["report_id"])),
            generated_at=generated_at,
            test_period=test_period,
            strategy_validations=strategy_validations,
            fingerprint_validations=fingerprint_validations,
            ab_test_results=ab_test_results,
            quality_metrics=qm,
            total_tests=int(details.get("total_tests", report_data.get("total_tests", 0))),
            passed_tests=int(details.get("passed_tests", report_data.get("passed_tests", 0))),
            failed_tests=int(details.get("failed_tests", report_data.get("failed_tests", 0))),
            overall_score=float(
                details.get("overall_score", report_data.get("overall_score", 0.0))
            ),
            recommendations=list(details.get("recommendations") or []),
            action_items=list(details.get("action_items") or []),
        )

    def load_history(self, results_dir: Path, validation_report_class) -> List:
        """
        Load validation history from JSON file.

        Args:
            results_dir: Directory containing validation results
            validation_report_class: ValidationReport class for deserialization

        Returns:
            List of ValidationReport instances
        """
        history_file = results_dir / "validation_history.json"

        if not history_file.exists():
            LOG.info("No validation history file found, starting fresh")
            return []

        try:
            with open(history_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                history = []

                for report_data in data:
                    report = self.deserialize_report(report_data, validation_report_class)
                    history.append(report)

                LOG.info(f"Loaded {len(history)} validation reports from history")
                return history

        except json.JSONDecodeError as e:
            LOG.warning(f"Invalid JSON in history file: {e}. Starting with empty history.")
            return []

        except (IOError, OSError) as e:
            LOG.warning(f"Failed to read history file: {e}. Starting with empty history.")
            return []

        except (KeyError, ValueError) as e:
            LOG.warning(f"Invalid data format in history file: {e}. Starting with empty history.")
            return []

    def save_history(self, results_dir: Path, validation_history: List) -> bool:
        """
        Save validation history to JSON file.

        Args:
            results_dir: Directory for validation results
            validation_history: List of ValidationReport instances

        Returns:
            True if saved successfully, False otherwise
        """
        # Defensive handling: some callers may accidentally pass args in reverse order.
        # Keep method signature intact to avoid breaking external code.
        if isinstance(results_dir, list) and isinstance(validation_history, Path):
            LOG.warning(
                "save_history called with swapped arguments; auto-correcting (results_dir <-> validation_history)"
            )
            results_dir, validation_history = validation_history, results_dir

        # Ensure directory exists
        try:
            results_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            LOG.error(f"Failed to ensure results_dir exists ({results_dir}): {e}")
            return False

        history_file = results_dir / "validation_history.json"

        try:
            # Serialize reports to dictionaries
            history_data = []
            for report in validation_history:
                history_data.append(self.serialize_report(report))

            # Write to file
            with open(history_file, "w", encoding="utf-8") as f:
                json.dump(history_data, f, indent=2, ensure_ascii=False)

            LOG.info(f"Saved {len(history_data)} validation reports to history")
            return True

        except (IOError, OSError) as e:
            LOG.error(f"Failed to save validation history: {e}")
            return False

        except Exception as e:
            LOG.error(f"Unexpected error saving validation history: {e}")
            return False
