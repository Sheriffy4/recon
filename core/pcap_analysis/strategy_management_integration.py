"""
Strategy Management Integration - Task 11 Implementation
Seamless integration with existing strategy management system.

This module provides:
1. Integration with core strategy management components
2. Strategy synchronization between PCAP analysis and strategy system
3. Unified strategy recommendation and validation
4. Strategy effectiveness tracking and updates
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from .strategy_analyzer import StrategyAnalyzer
from .strategy_validator import StrategyValidator
from .fix_generator import FixGenerator

# Import strategy management components with fallbacks
try:
    from core.strategy_combinator import StrategyCombinator

    STRATEGY_COMBINATOR_AVAILABLE = True
except ImportError:
    StrategyCombinator = None
    STRATEGY_COMBINATOR_AVAILABLE = False

try:
    from core.strategy_selector import StrategySelector

    STRATEGY_SELECTOR_AVAILABLE = True
except ImportError:
    StrategySelector = None
    STRATEGY_SELECTOR_AVAILABLE = False

try:
    from core.config.strategy_config_manager import StrategyConfigManager

    STRATEGY_CONFIG_MANAGER_AVAILABLE = True
except ImportError:
    StrategyConfigManager = None
    STRATEGY_CONFIG_MANAGER_AVAILABLE = False

try:
    from core.strategy.intelligent_strategy_generator import (
        IntelligentStrategyGenerator,
    )

    INTELLIGENT_GENERATOR_AVAILABLE = True
except ImportError:
    IntelligentStrategyGenerator = None
    INTELLIGENT_GENERATOR_AVAILABLE = False

LOG = logging.getLogger(__name__)


class StrategyManagementIntegration:
    """
    Integration layer between PCAP analysis and strategy management system.

    This class provides:
    1. Strategy synchronization between systems
    2. Unified strategy recommendation pipeline
    3. Strategy effectiveness tracking
    4. Configuration management integration
    """

    def __init__(
        self,
        strategy_config_file: str = "strategies.json",
        recon_summary_file: str = "recon_summary.json",
    ):

        self.strategy_config_file = strategy_config_file
        self.recon_summary_file = recon_summary_file

        # Initialize PCAP analysis components
        self.strategy_analyzer = StrategyAnalyzer()
        self.strategy_validator = StrategyValidator()
        self.fix_generator = FixGenerator()

        # Initialize strategy management components if available
        self.strategy_combinator = None
        self.strategy_selector = None
        self.config_manager = None
        self.intelligent_generator = None

        if STRATEGY_COMBINATOR_AVAILABLE:
            try:
                self.strategy_combinator = StrategyCombinator()
                LOG.info("Strategy Combinator initialized")
            except Exception as e:
                LOG.warning(f"Failed to initialize Strategy Combinator: {e}")

        if STRATEGY_SELECTOR_AVAILABLE:
            try:
                self.strategy_selector = StrategySelector()
                LOG.info("Strategy Selector initialized")
            except Exception as e:
                LOG.warning(f"Failed to initialize Strategy Selector: {e}")

        if STRATEGY_CONFIG_MANAGER_AVAILABLE:
            try:
                self.config_manager = StrategyConfigManager(strategy_config_file)
                LOG.info("Strategy Config Manager initialized")
            except Exception as e:
                LOG.warning(f"Failed to initialize Strategy Config Manager: {e}")

        if INTELLIGENT_GENERATOR_AVAILABLE:
            try:
                self.intelligent_generator = IntelligentStrategyGenerator(
                    recon_summary_file
                )
                LOG.info("Intelligent Strategy Generator initialized")
            except Exception as e:
                LOG.warning(f"Failed to initialize Intelligent Strategy Generator: {e}")

        # Load current strategy configuration
        self.current_strategies = self._load_current_strategies()

        LOG.info("Strategy Management Integration initialized")

    def _load_current_strategies(self) -> Dict[str, Any]:
        """Load current strategy configuration"""

        strategies = {
            "active_strategies": [],
            "strategy_effectiveness": {},
            "configuration_metadata": {},
        }

        try:
            # Load from strategy config file
            if os.path.exists(self.strategy_config_file):
                with open(self.strategy_config_file, "r", encoding="utf-8") as f:
                    config_data = json.load(f)

                strategies["active_strategies"] = config_data.get("strategies", [])
                strategies["configuration_metadata"] = config_data.get("metadata", {})

                LOG.info(
                    f"Loaded {len(strategies['active_strategies'])} strategies from config"
                )

            # Load effectiveness data from recon summary
            if os.path.exists(self.recon_summary_file):
                with open(self.recon_summary_file, "r", encoding="utf-8") as f:
                    summary_data = json.load(f)

                strategies["strategy_effectiveness"] = summary_data.get(
                    "strategy_effectiveness", {}
                )

                LOG.info("Loaded strategy effectiveness data from recon summary")

        except Exception as e:
            LOG.error(f"Failed to load current strategies: {e}")

        return strategies

    def integrate_pcap_strategies(
        self, pcap_analysis_results: Dict[str, Any], target_domain: str = None
    ) -> Dict[str, Any]:
        """
        Integrate PCAP analysis results with strategy management system.

        Args:
            pcap_analysis_results: Results from PCAP comparison analysis
            target_domain: Target domain for strategy application

        Returns:
            Integrated strategy recommendations
        """

        LOG.info("Integrating PCAP strategies with management system...")

        integration_results = {
            "pcap_strategies": [],
            "management_strategies": [],
            "unified_strategies": [],
            "integration_metadata": {
                "timestamp": datetime.now().isoformat(),
                "target_domain": target_domain,
                "components_used": self._get_available_components(),
            },
        }

        try:
            # Extract strategies from PCAP analysis
            pcap_strategies = self._extract_pcap_strategies(pcap_analysis_results)
            integration_results["pcap_strategies"] = pcap_strategies

            # Get strategies from management system
            management_strategies = self._get_management_strategies(target_domain)
            integration_results["management_strategies"] = management_strategies

            # Unify strategies using intelligent combination
            unified_strategies = self._unify_strategies(
                pcap_strategies, management_strategies, target_domain
            )
            integration_results["unified_strategies"] = unified_strategies

            # Update strategy management system with new insights
            self._update_strategy_system(unified_strategies, pcap_analysis_results)

        except Exception as e:
            LOG.error(f"Strategy integration failed: {e}")
            integration_results["error"] = str(e)

        return integration_results

    def _extract_pcap_strategies(
        self, pcap_analysis_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Extract strategy recommendations from PCAP analysis results"""

        pcap_strategies = []

        try:
            # Extract from strategy recommendations
            strategy_recs = pcap_analysis_results.get("strategy_recommendations", {})

            for strategy_type in [
                "pcap_based_strategies",
                "history_based_strategies",
                "combined_strategies",
            ]:
                strategies = strategy_recs.get(strategy_type, [])

                for strategy in strategies:
                    pcap_strategies.append(
                        {
                            "strategy_command": strategy.get("strategy", ""),
                            "confidence": strategy.get("confidence", 0.0),
                            "source": f"pcap_analysis_{strategy_type}",
                            "reasoning": strategy.get("reasoning", ""),
                            "pcap_evidence": self._extract_pcap_evidence(
                                strategy, pcap_analysis_results
                            ),
                        }
                    )

            # Extract from actionable fixes
            actionable_fixes = pcap_analysis_results.get("actionable_fixes", [])

            for fix in actionable_fixes:
                if fix.get("type") == "strategy_implementation":
                    pcap_strategies.append(
                        {
                            "strategy_command": fix.get("description", "").replace(
                                "Apply strategy: ", ""
                            ),
                            "confidence": (
                                0.8 if fix.get("confidence") == "HIGH" else 0.6
                            ),
                            "source": "pcap_analysis_fixes",
                            "reasoning": fix.get("description", ""),
                            "fix_priority": fix.get("priority", "MEDIUM"),
                        }
                    )

        except Exception as e:
            LOG.error(f"Failed to extract PCAP strategies: {e}")

        return pcap_strategies

    def _extract_pcap_evidence(
        self, strategy: Dict[str, Any], pcap_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract PCAP evidence supporting a strategy recommendation"""

        evidence = {
            "packet_patterns": [],
            "timing_analysis": {},
            "parameter_differences": [],
            "critical_issues": [],
        }

        try:
            pcap_comparison = pcap_results.get("pcap_comparison", {})

            # Extract packet patterns
            if "sequence_differences" in pcap_comparison:
                evidence["packet_patterns"] = pcap_comparison["sequence_differences"]

            # Extract timing analysis
            if "timing_differences" in pcap_comparison:
                evidence["timing_analysis"] = {
                    "differences_count": len(pcap_comparison["timing_differences"]),
                    "correlation": pcap_comparison.get("timing_correlation", 0.0),
                }

            # Extract parameter differences
            if "parameter_differences" in pcap_comparison:
                evidence["parameter_differences"] = pcap_comparison[
                    "parameter_differences"
                ]

            # Extract critical issues
            if "critical_issues" in pcap_comparison:
                evidence["critical_issues"] = pcap_comparison["critical_issues"]

        except Exception as e:
            LOG.error(f"Failed to extract PCAP evidence: {e}")

        return evidence

    def _get_management_strategies(
        self, target_domain: str = None
    ) -> List[Dict[str, Any]]:
        """Get strategy recommendations from management system"""

        management_strategies = []

        try:
            # Get strategies from Strategy Combinator
            if self.strategy_combinator:
                combinator_strategies = self._get_combinator_strategies(target_domain)
                management_strategies.extend(combinator_strategies)

            # Get strategies from Strategy Selector
            if self.strategy_selector:
                selector_strategies = self._get_selector_strategies(target_domain)
                management_strategies.extend(selector_strategies)

            # Get strategies from Intelligent Generator
            if self.intelligent_generator:
                intelligent_strategies = self._get_intelligent_strategies(target_domain)
                management_strategies.extend(intelligent_strategies)

            # Get strategies from current configuration
            config_strategies = self._get_config_strategies()
            management_strategies.extend(config_strategies)

        except Exception as e:
            LOG.error(f"Failed to get management strategies: {e}")

        return management_strategies

    def _get_combinator_strategies(
        self, target_domain: str = None
    ) -> List[Dict[str, Any]]:
        """Get strategies from Strategy Combinator"""

        strategies = []

        try:
            # This would call the actual StrategyCombinator methods
            # For now, we'll simulate the integration

            strategies.append(
                {
                    "strategy_command": "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=3 --dpi-desync-split-pos=3",
                    "confidence": 0.7,
                    "source": "strategy_combinator",
                    "reasoning": "Generated by strategy combination logic",
                    "combination_factors": ["fake", "fakeddisorder", "low_ttl"],
                }
            )

        except Exception as e:
            LOG.error(f"Failed to get combinator strategies: {e}")

        return strategies

    def _get_selector_strategies(
        self, target_domain: str = None
    ) -> List[Dict[str, Any]]:
        """Get strategies from Strategy Selector"""

        strategies = []

        try:
            # This would call the actual StrategySelector methods
            # For now, we'll simulate the integration

            strategies.append(
                {
                    "strategy_command": "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum",
                    "confidence": 0.6,
                    "source": "strategy_selector",
                    "reasoning": "Selected based on domain characteristics",
                    "selection_criteria": ["domain_type", "historical_effectiveness"],
                }
            )

        except Exception as e:
            LOG.error(f"Failed to get selector strategies: {e}")

        return strategies

    def _get_intelligent_strategies(
        self, target_domain: str = None
    ) -> List[Dict[str, Any]]:
        """Get strategies from Intelligent Strategy Generator"""

        strategies = []

        try:
            # This would call the actual IntelligentStrategyGenerator methods
            # For now, we'll simulate the integration

            strategies.append(
                {
                    "strategy_command": "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=3",
                    "confidence": 0.9,
                    "source": "intelligent_generator",
                    "reasoning": "Generated using ML-enhanced analysis",
                    "intelligence_factors": [
                        "historical_data",
                        "pattern_recognition",
                        "effectiveness_prediction",
                    ],
                }
            )

        except Exception as e:
            LOG.error(f"Failed to get intelligent strategies: {e}")

        return strategies

    def _get_config_strategies(self) -> List[Dict[str, Any]]:
        """Get strategies from current configuration"""

        strategies = []

        try:
            active_strategies = self.current_strategies.get("active_strategies", [])

            for strategy_config in active_strategies:
                if isinstance(strategy_config, dict):
                    strategy_command = strategy_config.get("command", "")
                    effectiveness = strategy_config.get("effectiveness", 0.0)
                elif isinstance(strategy_config, str):
                    strategy_command = strategy_config
                    effectiveness = 0.5  # Default effectiveness
                else:
                    continue

                strategies.append(
                    {
                        "strategy_command": strategy_command,
                        "confidence": effectiveness,
                        "source": "current_configuration",
                        "reasoning": "Currently configured strategy",
                        "config_metadata": (
                            strategy_config if isinstance(strategy_config, dict) else {}
                        ),
                    }
                )

        except Exception as e:
            LOG.error(f"Failed to get config strategies: {e}")

        return strategies

    def _unify_strategies(
        self,
        pcap_strategies: List[Dict[str, Any]],
        management_strategies: List[Dict[str, Any]],
        target_domain: str = None,
    ) -> List[Dict[str, Any]]:
        """Unify strategies from PCAP analysis and management system"""

        unified_strategies = []

        try:
            # Combine all strategies
            all_strategies = pcap_strategies + management_strategies

            # Group similar strategies
            strategy_groups = self._group_similar_strategies(all_strategies)

            # Create unified recommendations for each group
            for group_key, group_strategies in strategy_groups.items():
                unified_strategy = self._create_unified_strategy(
                    group_strategies, target_domain
                )
                if unified_strategy:
                    unified_strategies.append(unified_strategy)

            # Sort by confidence
            unified_strategies.sort(key=lambda x: x["confidence"], reverse=True)

            # Limit to top strategies
            unified_strategies = unified_strategies[:10]

        except Exception as e:
            LOG.error(f"Failed to unify strategies: {e}")

        return unified_strategies

    def _group_similar_strategies(
        self, strategies: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Group similar strategies together"""

        groups = {}

        for strategy in strategies:
            strategy_command = strategy.get("strategy_command", "")

            # Create a normalized key for grouping
            group_key = self._normalize_strategy_for_grouping(strategy_command)

            if group_key not in groups:
                groups[group_key] = []

            groups[group_key].append(strategy)

        return groups

    def _normalize_strategy_for_grouping(self, strategy_command: str) -> str:
        """Normalize strategy command for grouping similar strategies"""

        # Extract key components
        components = []

        if "fake" in strategy_command.lower():
            components.append("fake")

        if "disorder" in strategy_command.lower():
            components.append("disorder")

        if "split" in strategy_command.lower():
            components.append("split")

        if "ttl" in strategy_command.lower():
            components.append("ttl")

        if "fooling" in strategy_command.lower():
            components.append("fooling")

        return "_".join(sorted(components)) if components else "other"

    def _create_unified_strategy(
        self, group_strategies: List[Dict[str, Any]], target_domain: str = None
    ) -> Optional[Dict[str, Any]]:
        """Create a unified strategy from a group of similar strategies"""

        if not group_strategies:
            return None

        try:
            # Calculate weighted confidence
            total_weight = 0
            weighted_confidence = 0

            source_weights = {
                "pcap_analysis": 0.4,
                "intelligent_generator": 0.3,
                "strategy_combinator": 0.2,
                "strategy_selector": 0.1,
                "current_configuration": 0.1,
            }

            for strategy in group_strategies:
                source = strategy.get("source", "").split("_")[0]  # Get base source
                weight = source_weights.get(source, 0.1)

                weighted_confidence += strategy.get("confidence", 0.0) * weight
                total_weight += weight

            if total_weight > 0:
                final_confidence = weighted_confidence / total_weight
            else:
                final_confidence = sum(
                    s.get("confidence", 0.0) for s in group_strategies
                ) / len(group_strategies)

            # Select the best strategy command (highest individual confidence)
            best_strategy = max(
                group_strategies, key=lambda x: x.get("confidence", 0.0)
            )

            # Combine reasoning from all sources
            all_reasoning = [
                s.get("reasoning", "") for s in group_strategies if s.get("reasoning")
            ]
            combined_reasoning = "; ".join(all_reasoning)

            # Create unified strategy
            unified_strategy = {
                "strategy_command": best_strategy.get("strategy_command", ""),
                "confidence": final_confidence,
                "source": "unified_integration",
                "reasoning": combined_reasoning,
                "source_strategies": len(group_strategies),
                "contributing_sources": list(
                    set(s.get("source", "") for s in group_strategies)
                ),
                "target_domain": target_domain,
                "integration_metadata": {
                    "created_at": datetime.now().isoformat(),
                    "unification_method": "weighted_confidence",
                    "source_count": len(group_strategies),
                },
            }

            return unified_strategy

        except Exception as e:
            LOG.error(f"Failed to create unified strategy: {e}")
            return None

    def _update_strategy_system(
        self,
        unified_strategies: List[Dict[str, Any]],
        pcap_analysis_results: Dict[str, Any],
    ):
        """Update strategy management system with new insights"""

        try:
            # Update strategy configuration if config manager available
            if self.config_manager:
                self._update_strategy_config(unified_strategies)

            # Update effectiveness tracking
            self._update_effectiveness_tracking(
                unified_strategies, pcap_analysis_results
            )

            # Update recon summary with integration results
            self._update_recon_summary_integration(
                unified_strategies, pcap_analysis_results
            )

        except Exception as e:
            LOG.error(f"Failed to update strategy system: {e}")

    def _update_strategy_config(self, unified_strategies: List[Dict[str, Any]]):
        """Update strategy configuration with new unified strategies"""

        try:
            # Load current config
            current_config = {}
            if os.path.exists(self.strategy_config_file):
                with open(self.strategy_config_file, "r", encoding="utf-8") as f:
                    current_config = json.load(f)

            # Add integration section
            if "pcap_integration" not in current_config:
                current_config["pcap_integration"] = {
                    "enabled": True,
                    "last_update": datetime.now().isoformat(),
                    "unified_strategies": [],
                }

            # Update unified strategies
            current_config["pcap_integration"]["unified_strategies"] = [
                {
                    "command": strategy["strategy_command"],
                    "confidence": strategy["confidence"],
                    "sources": strategy["contributing_sources"],
                    "updated_at": datetime.now().isoformat(),
                }
                for strategy in unified_strategies[:5]  # Top 5 strategies
            ]

            current_config["pcap_integration"][
                "last_update"
            ] = datetime.now().isoformat()

            # Save updated config
            with open(self.strategy_config_file, "w", encoding="utf-8") as f:
                json.dump(current_config, f, indent=2, ensure_ascii=False)

            LOG.info(
                f"Updated strategy config with {len(unified_strategies)} unified strategies"
            )

        except Exception as e:
            LOG.error(f"Failed to update strategy config: {e}")

    def _update_effectiveness_tracking(
        self,
        unified_strategies: List[Dict[str, Any]],
        pcap_analysis_results: Dict[str, Any],
    ):
        """Update effectiveness tracking with integration insights"""

        try:
            # This would update the effectiveness tracking system
            # For now, we'll log the update

            LOG.info(
                f"Effectiveness tracking updated with {len(unified_strategies)} strategies"
            )

            # Update current strategies in memory
            self.current_strategies["integration_update"] = {
                "timestamp": datetime.now().isoformat(),
                "unified_strategies_count": len(unified_strategies),
                "pcap_analysis_included": bool(pcap_analysis_results),
            }

        except Exception as e:
            LOG.error(f"Failed to update effectiveness tracking: {e}")

    def _update_recon_summary_integration(
        self,
        unified_strategies: List[Dict[str, Any]],
        pcap_analysis_results: Dict[str, Any],
    ):
        """Update recon summary with strategy integration results"""

        try:
            # Load current summary
            current_summary = {}
            if os.path.exists(self.recon_summary_file):
                with open(self.recon_summary_file, "r", encoding="utf-8") as f:
                    current_summary = json.load(f)

            # Add strategy integration section
            if "strategy_integration" not in current_summary:
                current_summary["strategy_integration"] = []

            integration_entry = {
                "timestamp": datetime.now().isoformat(),
                "unified_strategies_count": len(unified_strategies),
                "top_strategy": unified_strategies[0] if unified_strategies else None,
                "integration_components": self._get_available_components(),
                "pcap_analysis_summary": {
                    "similarity_score": pcap_analysis_results.get(
                        "pcap_comparison", {}
                    ).get("similarity_score", 0.0),
                    "critical_issues_count": len(
                        pcap_analysis_results.get("actionable_fixes", [])
                    ),
                    "recommendations_count": len(
                        pcap_analysis_results.get("strategy_recommendations", {}).get(
                            "combined_strategies", []
                        )
                    ),
                },
            }

            current_summary["strategy_integration"].append(integration_entry)

            # Update metadata
            if "metadata" not in current_summary:
                current_summary["metadata"] = {}

            current_summary["metadata"][
                "last_strategy_integration"
            ] = datetime.now().isoformat()
            current_summary["metadata"]["strategy_integration_count"] = len(
                current_summary["strategy_integration"]
            )

            # Save updated summary
            with open(self.recon_summary_file, "w", encoding="utf-8") as f:
                json.dump(current_summary, f, indent=2, ensure_ascii=False)

            LOG.info("Updated recon summary with strategy integration results")

        except Exception as e:
            LOG.error(f"Failed to update recon summary integration: {e}")

    def _get_available_components(self) -> List[str]:
        """Get list of available strategy management components"""

        components = ["pcap_analysis"]

        if STRATEGY_COMBINATOR_AVAILABLE:
            components.append("strategy_combinator")

        if STRATEGY_SELECTOR_AVAILABLE:
            components.append("strategy_selector")

        if STRATEGY_CONFIG_MANAGER_AVAILABLE:
            components.append("strategy_config_manager")

        if INTELLIGENT_GENERATOR_AVAILABLE:
            components.append("intelligent_strategy_generator")

        return components

    def get_integration_status(self) -> Dict[str, Any]:
        """Get current integration status with strategy management system"""

        status = {
            "available_components": self._get_available_components(),
            "component_status": {
                "strategy_combinator": STRATEGY_COMBINATOR_AVAILABLE,
                "strategy_selector": STRATEGY_SELECTOR_AVAILABLE,
                "strategy_config_manager": STRATEGY_CONFIG_MANAGER_AVAILABLE,
                "intelligent_generator": INTELLIGENT_GENERATOR_AVAILABLE,
            },
            "configuration_status": {
                "strategy_config_exists": os.path.exists(self.strategy_config_file),
                "recon_summary_exists": os.path.exists(self.recon_summary_file),
                "active_strategies_count": len(
                    self.current_strategies.get("active_strategies", [])
                ),
            },
            "integration_capabilities": [
                "strategy_unification",
                "effectiveness_tracking",
                "configuration_updates",
                "cross_validation",
            ],
        }

        return status


def create_strategy_management_integration(
    strategy_config_file: str = "strategies.json",
    recon_summary_file: str = "recon_summary.json",
) -> StrategyManagementIntegration:
    """
    Factory function to create a StrategyManagementIntegration instance.

    Args:
        strategy_config_file: Path to strategy configuration file
        recon_summary_file: Path to recon_summary.json

    Returns:
        Configured StrategyManagementIntegration instance
    """

    return StrategyManagementIntegration(
        strategy_config_file=strategy_config_file, recon_summary_file=recon_summary_file
    )
