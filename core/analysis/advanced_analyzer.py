"""
Advanced root cause analysis components.

This module provides specialized analyzers for extracting causes from
strategy and packet differences, correlating findings, and generating
fix recommendations.
"""

from typing import List, Dict, Any, Optional


class CauseExtractor:
    """Extracts root causes from strategy and packet differences."""

    @staticmethod
    def create_cause_from_strategy_difference(
        diff: Any,
    ) -> Optional[Dict[str, Any]]:
        """
        Create root cause from strategy difference.

        Args:
            diff: StrategyDifference object

        Returns:
            Dictionary with cause information or None
        """
        # Map parameter differences to root causes
        if diff.parameter == "desync_method":
            if diff.discovery_value == "multidisorder" and diff.service_value != "multidisorder":
                return {
                    "type": "strategy_interpreter_mapping_error",
                    "description": f"Strategy interpreter incorrectly maps multidisorder to {diff.service_value}",
                    "parameter": diff.parameter,
                    "expected_value": diff.discovery_value,
                    "actual_value": diff.service_value,
                    "severity": "critical" if diff.is_critical else "medium",
                    "confidence": 0.9,
                    "component": "strategy_interpreter",
                    "evidence": {
                        "discovery_strategy_parsed_correctly": True,
                        "service_strategy_mapped_incorrectly": True,
                        "likely_cause": "desync_method check happens after fooling parameter check",
                    },
                }

        elif diff.parameter == "ttl":
            if diff.discovery_value is None and diff.service_value is not None:
                return {
                    "type": "autottl_not_implemented",
                    "description": "AutoTTL parameter not implemented in service mode",
                    "parameter": diff.parameter,
                    "expected_value": "calculated_dynamically",
                    "actual_value": diff.service_value,
                    "severity": "critical" if diff.is_critical else "medium",
                    "confidence": 0.85,
                    "component": "bypass_engine",
                    "evidence": {
                        "discovery_uses_autottl": True,
                        "service_uses_fixed_ttl": True,
                    },
                }

        elif diff.parameter in ["split_pos", "overlap_size", "repeats"]:
            return {
                "type": "parameter_parsing_error",
                "description": f"Parameter {diff.parameter} parsed differently in service mode",
                "parameter": diff.parameter,
                "expected_value": diff.discovery_value,
                "actual_value": diff.service_value,
                "severity": "medium",
                "confidence": 0.75,
                "component": "strategy_parser",
                "evidence": {
                    "parameter_exists_in_discovery": True,
                    "parameter_differs_in_service": True,
                },
            }

        elif diff.parameter == "fooling":
            return {
                "type": "fooling_parameter_parsing_error",
                "description": f"Fooling parameter parsed differently: {diff.discovery_value} vs {diff.service_value}",
                "parameter": diff.parameter,
                "expected_value": diff.discovery_value,
                "actual_value": diff.service_value,
                "severity": "medium",
                "confidence": 0.8,
                "component": "strategy_parser",
                "evidence": {
                    "multiple_fooling_methods_possible": True,
                    "parsing_order_matters": True,
                },
            }

        return None

    @staticmethod
    def create_cause_from_packet_difference(
        diff: Any,
    ) -> Optional[Dict[str, Any]]:
        """
        Create root cause from packet difference.

        Args:
            diff: PacketDifference object

        Returns:
            Dictionary with cause information or None
        """
        if diff.field == "ttl":
            return {
                "type": "ttl_calculation_error",
                "description": f"TTL value differs in packet {diff.packet_index}",
                "field": diff.field,
                "expected_value": diff.discovery_value,
                "actual_value": diff.service_value,
                "severity": "high" if diff.is_critical else "medium",
                "confidence": 0.85,
                "component": "packet_builder",
                "evidence": {
                    "packet_index": diff.packet_index,
                    "ttl_not_matching": True,
                },
            }

        elif diff.field == "flags":
            return {
                "type": "tcp_flags_error",
                "description": f"TCP flags differ in packet {diff.packet_index}",
                "field": diff.field,
                "expected_value": diff.discovery_value,
                "actual_value": diff.service_value,
                "severity": "high" if diff.is_critical else "medium",
                "confidence": 0.8,
                "component": "packet_builder",
                "evidence": {
                    "packet_index": diff.packet_index,
                    "flags_not_matching": True,
                },
            }

        elif diff.field == "payload_len":
            return {
                "type": "payload_segmentation_error",
                "description": f"Payload length differs in packet {diff.packet_index}",
                "field": diff.field,
                "expected_value": diff.discovery_value,
                "actual_value": diff.service_value,
                "severity": "medium",
                "confidence": 0.75,
                "component": "attack_implementation",
                "evidence": {
                    "packet_index": diff.packet_index,
                    "segmentation_differs": True,
                },
            }

        return None


class DifferenceCorrelator:
    """Correlates strategy and packet differences to find common root causes."""

    @staticmethod
    def correlate_differences(
        strategy_diffs: List[Any], packet_diffs: List[Any]
    ) -> List[Dict[str, Any]]:
        """
        Correlate strategy and packet differences.

        Args:
            strategy_diffs: List of StrategyDifference objects
            packet_diffs: List of PacketDifference objects

        Returns:
            List of correlated cause dictionaries
        """
        correlated = []

        # Check for TTL correlation
        ttl_strategy_diff = next((d for d in strategy_diffs if d.parameter == "ttl"), None)
        ttl_packet_diffs = [d for d in packet_diffs if d.field == "ttl"]

        if ttl_strategy_diff and ttl_packet_diffs:
            correlated.append(
                {
                    "type": "correlated_ttl_issue",
                    "description": f"TTL strategy difference causes {len(ttl_packet_diffs)} packet differences",
                    "severity": "critical",
                    "confidence": 0.95,
                    "component": "bypass_engine",
                    "evidence": {
                        "strategy_ttl_differs": True,
                        "packet_ttl_differs": True,
                        "correlation_strength": "strong",
                    },
                }
            )

        # Check for fooling correlation
        fooling_strategy_diff = next((d for d in strategy_diffs if d.parameter == "fooling"), None)
        flag_packet_diffs = [d for d in packet_diffs if d.field == "flags"]

        if fooling_strategy_diff and flag_packet_diffs:
            correlated.append(
                {
                    "type": "correlated_fooling_issue",
                    "description": f"Fooling strategy difference causes {len(flag_packet_diffs)} flag differences",
                    "severity": "high",
                    "confidence": 0.85,
                    "component": "attack_implementation",
                    "evidence": {
                        "strategy_fooling_differs": True,
                        "packet_flags_differ": True,
                        "correlation_strength": "medium",
                    },
                }
            )

        return correlated


class CauseDeduplicator:
    """Deduplicates and prioritizes root causes."""

    @staticmethod
    def deduplicate_causes(causes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Deduplicate causes by type and merge evidence.

        Args:
            causes: List of cause dictionaries

        Returns:
            Deduplicated list of causes
        """
        seen_types = {}

        for cause in causes:
            cause_type = cause.get("type")
            if cause_type not in seen_types:
                seen_types[cause_type] = cause
            else:
                # Merge evidence if same type
                existing = seen_types[cause_type]
                if "evidence" in cause and "evidence" in existing:
                    existing["evidence"].update(cause["evidence"])
                # Keep higher confidence
                if cause.get("confidence", 0) > existing.get("confidence", 0):
                    existing["confidence"] = cause["confidence"]

        return list(seen_types.values())


class FixRecommender:
    """Generates fix recommendations from identified causes."""

    @staticmethod
    def generate_fix_recommendations(causes: List[Dict[str, Any]]) -> List[str]:
        """
        Generate fix recommendations from causes.

        Args:
            causes: List of cause dictionaries

        Returns:
            List of fix recommendation strings
        """
        recommendations = []

        for cause in causes:
            cause_type = cause.get("type")

            if cause_type == "strategy_interpreter_mapping_error":
                recommendations.append(
                    "Fix strategy interpreter: Check desync_method BEFORE fooling parameter "
                    "(recon/core/strategy_interpreter.py)"
                )

            elif cause_type == "autottl_not_implemented":
                recommendations.append(
                    "Implement AutoTTL in bypass engine: Add calculate_autottl() support "
                    "(recon/core/bypass/engine/base_engine.py)"
                )

            elif cause_type == "parameter_parsing_error":
                param = cause.get("parameter", "unknown")
                recommendations.append(
                    f"Fix {param} parsing in strategy parser " "(recon/core/strategy_parser_v2.py)"
                )

            elif cause_type == "fooling_parameter_parsing_error":
                recommendations.append(
                    "Fix fooling parameter parsing: Ensure multiple fooling methods are parsed correctly "
                    "(recon/core/strategy_parser_v2.py)"
                )

            elif cause_type == "ttl_calculation_error":
                recommendations.append(
                    "Fix TTL calculation in packet builder " "(recon/core/bypass/packet/builder.py)"
                )

            elif cause_type == "tcp_flags_error":
                recommendations.append(
                    "Fix TCP flags setting in packet builder "
                    "(recon/core/bypass/packet/builder.py)"
                )

            elif cause_type == "payload_segmentation_error":
                recommendations.append(
                    "Fix payload segmentation in attack implementation "
                    "(recon/core/bypass/attacks/)"
                )

            elif cause_type == "correlated_ttl_issue":
                recommendations.append(
                    "Fix TTL handling: Address both strategy parsing and packet building "
                    "(strategy_parser_v2.py + bypass/engine/base_engine.py)"
                )

            elif cause_type == "correlated_fooling_issue":
                recommendations.append(
                    "Fix fooling implementation: Address both strategy parsing and attack execution "
                    "(strategy_parser_v2.py + bypass/attacks/)"
                )

        return recommendations
