"""
Parameter difference handlers for root cause analysis.

This module provides a registry-based system for handling different types
of parameter differences in strategy comparisons.
"""

from typing import Any, Callable, Dict


class ParameterDifferenceHandler:
    """Registry-based handler for parameter differences in strategy analysis."""

    def __init__(self):
        """Initialize handler registry with all parameter handlers."""
        self._handlers: Dict[str, Callable] = {
            "desync_method": self._handle_desync_method,
            "attack_type": self._handle_desync_method,  # Same handler
            "ttl": self._handle_ttl,
            "autottl": self._handle_autottl,
            "split_pos": self._handle_split_pos,
            "overlap_size": self._handle_overlap_size,
            "split_seqovl": self._handle_overlap_size,  # Same handler
            "repeats": self._handle_repeats,
            "fooling": self._handle_fooling,
        }

    def handle_difference(self, diff: Any, analysis: Any) -> None:
        """
        Handle a parameter difference by dispatching to appropriate handler.

        Args:
            diff: StrategyDifference object with parameter, discovery_value, service_value
            analysis: RootCauseAnalysis object to populate with findings

        Note:
            If no handler exists for the parameter, this method does nothing.
        """
        handler = self._handlers.get(diff.parameter)
        if handler:
            handler(diff, analysis)

    def _handle_desync_method(self, diff: Any, analysis: Any) -> None:
        """Handle desync_method or attack_type difference."""
        # Keep method name for backward compatibility; adjust message semantics.
        label = "Desync method" if diff.parameter == "desync_method" else "Attack type"
        analysis.root_causes.append(
            f"{label} mismatch: discovery uses '{diff.discovery_value}' "
            f"but service uses '{diff.service_value}'"
        )
        analysis.code_locations.append(
            "recon/core/strategy_interpreter.py: _config_to_strategy_task()"
        )
        analysis.fix_recommendations.append(
            "Check strategy interpreter mapping logic. Ensure desync_method "
            "is checked BEFORE fooling parameter (Fix #1 from ПОЛНОЕ_РЕШЕНИЕ_ПРОБЛЕМЫ.txt)"
        )

    def _handle_ttl(self, diff: Any, analysis: Any) -> None:
        """Handle TTL difference."""
        analysis.root_causes.append(
            f"TTL mismatch: discovery uses {diff.discovery_value} "
            f"but service uses {diff.service_value}"
        )
        analysis.code_locations.append(
            "recon/core/bypass/engine/base_engine.py: calculate_autottl() or packet building"
        )
        analysis.fix_recommendations.append(
            "Verify autottl calculation is working correctly. "
            "Check if autottl parameter is being passed to bypass engine."
        )

    def _handle_autottl(self, diff: Any, analysis: Any) -> None:
        """Handle AutoTTL difference."""
        analysis.root_causes.append(
            f"AutoTTL mismatch: discovery uses {diff.discovery_value} "
            f"but service uses {diff.service_value}"
        )
        analysis.code_locations.append("recon/core/strategy_parser_v2.py: parse() method")
        analysis.fix_recommendations.append(
            "Ensure --dpi-desync-autottl parameter is being parsed correctly. "
            "Verify it's not being overridden by fixed TTL value."
        )

    def _handle_split_pos(self, diff: Any, analysis: Any) -> None:
        """Handle split_pos difference."""
        analysis.root_causes.append(
            f"Split position mismatch: discovery uses {diff.discovery_value} "
            f"but service uses {diff.service_value}"
        )
        analysis.code_locations.append("recon/core/strategy_parser_v2.py: parse() method")
        analysis.fix_recommendations.append(
            "Check --dpi-desync-split-pos parsing. "
            "Verify default value is not overriding configured value."
        )

    def _handle_overlap_size(self, diff: Any, analysis: Any) -> None:
        """Handle overlap_size or split_seqovl difference."""
        analysis.root_causes.append(
            f"Sequence overlap mismatch: discovery uses {diff.discovery_value} "
            f"but service uses {diff.service_value}"
        )
        analysis.code_locations.append("recon/core/strategy_parser_v2.py: parse() method")
        analysis.fix_recommendations.append(
            "Ensure --dpi-desync-split-seqovl parameter is being parsed "
            "and mapped to overlap_size correctly."
        )

    def _handle_repeats(self, diff: Any, analysis: Any) -> None:
        """Handle repeats difference."""
        analysis.root_causes.append(
            f"Repeats mismatch: discovery uses {diff.discovery_value} "
            f"but service uses {diff.service_value}"
        )
        analysis.code_locations.append("recon/core/strategy_parser_v2.py: parse() method")
        analysis.fix_recommendations.append(
            "Check --dpi-desync-repeats parsing. "
            "Verify repeats parameter is being applied in attack execution."
        )

    def _handle_fooling(self, diff: Any, analysis: Any) -> None:
        """Handle fooling difference."""
        analysis.root_causes.append(
            f"Fooling method mismatch: discovery uses {diff.discovery_value} "
            f"but service uses {diff.service_value}"
        )
        analysis.code_locations.append("recon/core/strategy_parser_v2.py: parse() method")
        analysis.fix_recommendations.append(
            "Verify --dpi-desync-fooling parameter parsing. "
            "Check if multiple fooling methods are being parsed correctly."
        )
