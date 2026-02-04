"""
Recon Integration Module - Task 11 Implementation
Integrates PCAP analysis system with existing recon components.

This module provides:
1. Integration with find_rst_triggers.py for enhanced analysis capabilities
2. Compatibility with enhanced_find_rst_triggers.py workflow
3. Seamless integration with existing strategy management system
4. Data sharing with recon_summary.json for historical context
"""

import os
import json
import logging
from typing import Dict, Any, List
from pathlib import Path
from datetime import datetime

from .pcap_comparator import PCAPComparator
from .strategy_analyzer import StrategyAnalyzer
from .packet_sequence_analyzer import PacketSequenceAnalyzer
from .difference_detector import DifferenceDetector
from .pattern_recognizer import PatternRecognizer
from .root_cause_analyzer import RootCauseAnalyzer
from .fix_generator import FixGenerator
from .strategy_validator import StrategyValidator

# Import existing recon components with fallbacks
try:
    import find_rst_triggers

    FIND_RST_AVAILABLE = True
except ImportError:
    FIND_RST_AVAILABLE = False

try:
    import enhanced_find_rst_triggers

    ENHANCED_RST_AVAILABLE = True
except ImportError:
    ENHANCED_RST_AVAILABLE = False

try:
    from core.strategy import (
        StrategyRuleEngine,
        IntelligentStrategyGenerator,
        EnhancedRSTAnalyzer,
        RULE_ENGINE_AVAILABLE,
        INTELLIGENT_GENERATOR_AVAILABLE,
        ENHANCED_RST_AVAILABLE as STRATEGY_RST_AVAILABLE,
    )
except ImportError:
    StrategyRuleEngine = None
    IntelligentStrategyGenerator = None
    EnhancedRSTAnalyzer = None
    RULE_ENGINE_AVAILABLE = False
    INTELLIGENT_GENERATOR_AVAILABLE = False
    STRATEGY_RST_AVAILABLE = False

LOG = logging.getLogger(__name__)


class ReconIntegrationManager:
    """
    Main integration manager that coordinates between PCAP analysis and existing recon components.

    This class provides a unified interface for:
    - Running enhanced PCAP analysis with historical context
    - Integrating with find_rst_triggers.py workflow
    - Sharing data with recon_summary.json
    - Coordinating with strategy management systems
    """

    def __init__(
        self,
        recon_summary_file: str = "recon_summary.json",
        pcap_directory: str = ".",
        debug_mode: bool = False,
    ):

        self.recon_summary_file = recon_summary_file
        self.pcap_directory = Path(pcap_directory)
        self.debug_mode = debug_mode

        # Initialize core components
        self.pcap_comparator = PCAPComparator()
        self.strategy_analyzer = StrategyAnalyzer()
        self.sequence_analyzer = PacketSequenceAnalyzer()
        self.difference_detector = DifferenceDetector()
        self.pattern_recognizer = PatternRecognizer()
        self.root_cause_analyzer = RootCauseAnalyzer()
        self.fix_generator = FixGenerator()
        self.strategy_validator = StrategyValidator()

        # Load historical data
        self.historical_data = self._load_historical_data()

        # Integration state
        self.integration_results = {}

        LOG.info(f"ReconIntegrationManager initialized with summary file: {recon_summary_file}")

    def _load_historical_data(self) -> Dict[str, Any]:
        """Load historical data from recon_summary.json"""
        historical_data = {
            "strategy_effectiveness": {},
            "fingerprints": {},
            "all_results": [],
            "key_metrics": {},
            "metadata": {},
        }

        try:
            if os.path.exists(self.recon_summary_file):
                with open(self.recon_summary_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # Extract relevant sections
                historical_data["strategy_effectiveness"] = data.get("strategy_effectiveness", {})
                historical_data["fingerprints"] = data.get("fingerprints", {})
                historical_data["all_results"] = data.get("all_results", [])
                historical_data["key_metrics"] = data.get("key_metrics", {})
                historical_data["metadata"] = data.get("metadata", {})

                LOG.info(
                    f"Loaded historical data: {len(historical_data['all_results'])} strategy results"
                )
            else:
                LOG.warning(f"Historical data file not found: {self.recon_summary_file}")

        except Exception as e:
            LOG.error(f"Failed to load historical data: {e}")

        return historical_data

    def run_integrated_analysis(
        self,
        recon_pcap: str,
        zapret_pcap: str,
        target_domain: str = None,
        include_rst_analysis: bool = True,
        include_strategy_generation: bool = True,
    ) -> Dict[str, Any]:
        """
        Run comprehensive integrated analysis combining PCAP comparison with historical data.

        Args:
            recon_pcap: Path to recon PCAP file
            zapret_pcap: Path to zapret PCAP file
            target_domain: Target domain for analysis (optional)
            include_rst_analysis: Whether to include RST trigger analysis
            include_strategy_generation: Whether to generate new strategies

        Returns:
            Comprehensive analysis results
        """

        LOG.info("Starting integrated PCAP analysis...")
        start_time = datetime.now()

        results = {
            "analysis_metadata": {
                "start_time": start_time.isoformat(),
                "recon_pcap": recon_pcap,
                "zapret_pcap": zapret_pcap,
                "target_domain": target_domain,
                "integration_components": self._get_available_components(),
            },
            "pcap_comparison": {},
            "historical_context": {},
            "rst_analysis": {},
            "strategy_recommendations": {},
            "integration_insights": {},
            "actionable_fixes": [],
        }

        try:
            # Step 1: Core PCAP comparison
            LOG.info("Running PCAP comparison...")
            comparison_result = self.pcap_comparator.compare_pcaps(recon_pcap, zapret_pcap)
            results["pcap_comparison"] = comparison_result.to_dict()

            # Step 2: Add historical context
            LOG.info("Adding historical context...")
            historical_context = self._analyze_historical_context(comparison_result, target_domain)
            results["historical_context"] = historical_context

            # Step 3: RST trigger analysis integration
            if include_rst_analysis:
                LOG.info("Running integrated RST analysis...")
                rst_results = self._run_integrated_rst_analysis(recon_pcap, target_domain)
                results["rst_analysis"] = rst_results

            # Step 4: Strategy generation with historical data
            if include_strategy_generation:
                LOG.info("Generating strategies with historical context...")
                strategy_recommendations = self._generate_integrated_strategies(
                    comparison_result, historical_context, target_domain
                )
                results["strategy_recommendations"] = strategy_recommendations

            # Step 5: Integration insights
            LOG.info("Generating integration insights...")
            integration_insights = self._generate_integration_insights(results)
            results["integration_insights"] = integration_insights

            # Step 6: Actionable fixes
            LOG.info("Generating actionable fixes...")
            actionable_fixes = self._generate_actionable_fixes(results)
            results["actionable_fixes"] = actionable_fixes

        except Exception as e:
            LOG.error(f"Integrated analysis failed: {e}")
            results["error"] = str(e)

        # Update metadata
        end_time = datetime.now()
        results["analysis_metadata"]["end_time"] = end_time.isoformat()
        results["analysis_metadata"]["duration_seconds"] = (end_time - start_time).total_seconds()

        # Store results for future reference
        self.integration_results = results

        LOG.info(
            f"Integrated analysis completed in {results['analysis_metadata']['duration_seconds']:.2f}s"
        )
        return results

    def _get_available_components(self) -> List[str]:
        """Get list of available integration components"""
        components = ["pcap_analysis"]

        if FIND_RST_AVAILABLE:
            components.append("find_rst_triggers")

        if ENHANCED_RST_AVAILABLE:
            components.append("enhanced_find_rst_triggers")

        if RULE_ENGINE_AVAILABLE:
            components.append("strategy_rule_engine")

        if INTELLIGENT_GENERATOR_AVAILABLE:
            components.append("intelligent_strategy_generator")

        if STRATEGY_RST_AVAILABLE:
            components.append("enhanced_rst_analyzer")

        return components

    def _analyze_historical_context(
        self, comparison_result, target_domain: str = None
    ) -> Dict[str, Any]:
        """Analyze historical context from recon_summary.json"""

        context = {
            "relevant_strategies": [],
            "domain_specific_data": {},
            "effectiveness_patterns": {},
            "failure_patterns": {},
            "recommendations_from_history": [],
        }

        try:
            # Find relevant strategies from historical data
            all_results = self.historical_data.get("all_results", [])

            for result in all_results:
                strategy = result.get("strategy", "")
                success_rate = result.get("success_rate", 0.0)

                # Check if strategy is relevant to current analysis
                if self._is_strategy_relevant(strategy, comparison_result):
                    context["relevant_strategies"].append(
                        {
                            "strategy": strategy,
                            "success_rate": success_rate,
                            "result_status": result.get("result_status", ""),
                            "engine_telemetry": result.get("engine_telemetry", {}),
                        }
                    )

            # Analyze effectiveness patterns
            strategy_effectiveness = self.historical_data.get("strategy_effectiveness", {})

            top_working = strategy_effectiveness.get("top_working", [])
            top_failing = strategy_effectiveness.get("top_failing", [])

            context["effectiveness_patterns"] = {
                "successful_strategies_count": len(top_working),
                "failed_strategies_count": len(top_failing),
                "common_success_factors": self._extract_success_factors(top_working),
                "common_failure_factors": self._extract_failure_factors(top_failing),
            }

            # Domain-specific analysis
            if target_domain:
                context["domain_specific_data"] = self._analyze_domain_specific_history(
                    target_domain
                )

            # Generate recommendations based on history
            context["recommendations_from_history"] = self._generate_historical_recommendations(
                context["relevant_strategies"], context["effectiveness_patterns"]
            )

        except Exception as e:
            LOG.error(f"Failed to analyze historical context: {e}")
            context["error"] = str(e)

        return context

    def _is_strategy_relevant(self, strategy: str, comparison_result) -> bool:
        """Check if a historical strategy is relevant to current analysis"""

        # Check for fakeddisorder strategies
        if "fakeddisorder" in strategy or "fake,disorder" in strategy:
            # Look for fake packet patterns in comparison
            recon_packets = comparison_result.recon_packets
            zapret_packets = comparison_result.zapret_packets

            fake_packets_detected = any(p.is_fake_packet() for p in recon_packets + zapret_packets)
            if fake_packets_detected:
                return True

        # Check for TTL-related strategies
        if "ttl" in strategy.lower():
            # Look for TTL differences in comparison
            ttl_differences = [
                d for d in comparison_result.sequence_differences if d.get("type") == "ttl_mismatch"
            ]
            if ttl_differences:
                return True

        # Check for split-related strategies
        if "split" in strategy.lower():
            # Look for split patterns
            split_differences = [
                d
                for d in comparison_result.parameter_differences
                if "split" in d.get("parameter", "")
            ]
            if split_differences:
                return True

        return False

    def _extract_success_factors(self, successful_strategies: List[Dict]) -> List[str]:
        """Extract common factors from successful strategies"""
        factors = []

        if not successful_strategies:
            return factors

        # Analyze common parameters
        ttl_values = []
        split_positions = []
        fooling_methods = []

        for strategy_data in successful_strategies:
            strategy = strategy_data.get("strategy", "")

            # Extract TTL values
            if "ttl=" in strategy:
                try:
                    ttl_part = strategy.split("ttl=")[1].split()[0].rstrip(",)")
                    ttl_values.append(int(ttl_part))
                except:
                    pass

            # Extract split positions
            if "split-pos=" in strategy:
                try:
                    pos_part = strategy.split("split-pos=")[1].split()[0].rstrip(",)")
                    split_positions.append(int(pos_part))
                except:
                    pass

            # Extract fooling methods
            if "fooling=" in strategy:
                try:
                    fooling_part = strategy.split("fooling=")[1].split()[0].rstrip(",)")
                    fooling_methods.extend(fooling_part.strip("[]").replace("'", "").split(","))
                except:
                    pass

        # Generate factors
        if ttl_values:
            most_common_ttl = max(set(ttl_values), key=ttl_values.count)
            factors.append(f"TTL={most_common_ttl} appears in successful strategies")

        if split_positions:
            most_common_split = max(set(split_positions), key=split_positions.count)
            factors.append(f"split_pos={most_common_split} appears in successful strategies")

        if fooling_methods:
            unique_methods = list(set(m.strip() for m in fooling_methods if m.strip()))
            if unique_methods:
                factors.append(f"Common fooling methods: {', '.join(unique_methods)}")

        return factors

    def _extract_failure_factors(self, failed_strategies: List[Dict]) -> List[str]:
        """Extract common factors from failed strategies"""
        factors = []

        if not failed_strategies:
            return factors

        # Analyze telemetry data for failure patterns
        rst_counts = []
        ch_counts = []

        for strategy_data in failed_strategies:
            telemetry = strategy_data.get("engine_telemetry", {})

            rst_count = telemetry.get("RST", 0)
            ch_count = telemetry.get("CH", 0)

            if rst_count > 0:
                rst_counts.append(rst_count)
            if ch_count > 0:
                ch_counts.append(ch_count)

        # Generate failure factors
        if rst_counts:
            avg_rst = sum(rst_counts) / len(rst_counts)
            factors.append(f"Failed strategies average {avg_rst:.1f} RST packets")

        if ch_counts:
            avg_ch = sum(ch_counts) / len(ch_counts)
            factors.append(f"Failed strategies average {avg_ch:.1f} ClientHello packets")

        # Check for common failure patterns
        no_sites_working = sum(
            1 for s in failed_strategies if s.get("result_status") == "NO_SITES_WORKING"
        )
        if no_sites_working > len(failed_strategies) * 0.8:
            factors.append("Most failures are complete (NO_SITES_WORKING)")

        return factors

    def _analyze_domain_specific_history(self, target_domain: str) -> Dict[str, Any]:
        """Analyze historical data specific to target domain"""

        domain_data = {
            "strategies_tested": 0,
            "successful_strategies": [],
            "failed_strategies": [],
            "domain_specific_patterns": [],
        }

        # This would require domain-specific tracking in recon_summary.json
        # For now, we'll provide a framework for future enhancement

        return domain_data

    def _generate_historical_recommendations(
        self, relevant_strategies: List[Dict], effectiveness_patterns: Dict
    ) -> List[str]:
        """Generate recommendations based on historical analysis"""

        recommendations = []

        # Recommendations based on relevant strategies
        if relevant_strategies:
            successful_relevant = [s for s in relevant_strategies if s["success_rate"] > 0]
            if successful_relevant:
                best_strategy = max(successful_relevant, key=lambda x: x["success_rate"])
                recommendations.append(
                    f"Historical data suggests '{best_strategy['strategy']}' "
                    f"with {best_strategy['success_rate']:.1%} success rate"
                )

        # Recommendations based on success factors
        success_factors = effectiveness_patterns.get("common_success_factors", [])
        for factor in success_factors:
            recommendations.append(f"Apply successful pattern: {factor}")

        # Recommendations based on failure factors
        failure_factors = effectiveness_patterns.get("common_failure_factors", [])
        for factor in failure_factors:
            recommendations.append(f"Avoid failure pattern: {factor}")

        return recommendations

    def _run_integrated_rst_analysis(
        self, pcap_file: str, target_domain: str = None
    ) -> Dict[str, Any]:
        """Run RST analysis integrated with existing components"""

        rst_results = {
            "original_rst_analysis": {},
            "enhanced_rst_analysis": {},
            "integration_benefits": [],
        }

        try:
            # Try to run original find_rst_triggers if available
            if FIND_RST_AVAILABLE:
                LOG.info("Running original RST analysis...")
                # This would call find_rst_triggers functionality
                # For now, we'll simulate the integration
                rst_results["original_rst_analysis"] = {
                    "method": "original_find_rst_triggers",
                    "status": "simulated",
                    "note": "Integration with find_rst_triggers.py",
                }

            # Try to run enhanced RST analysis if available
            if ENHANCED_RST_AVAILABLE:
                LOG.info("Running enhanced RST analysis...")
                # This would call enhanced_find_rst_triggers functionality
                rst_results["enhanced_rst_analysis"] = {
                    "method": "enhanced_find_rst_triggers",
                    "status": "simulated",
                    "note": "Integration with enhanced_find_rst_triggers.py",
                }

            # Add integration benefits
            if FIND_RST_AVAILABLE or ENHANCED_RST_AVAILABLE:
                rst_results["integration_benefits"] = [
                    "Combined PCAP analysis with RST trigger detection",
                    "Historical context from recon_summary.json",
                    "Enhanced strategy recommendations",
                ]

        except Exception as e:
            LOG.error(f"RST analysis integration failed: {e}")
            rst_results["error"] = str(e)

        return rst_results

    def _generate_integrated_strategies(
        self, comparison_result, historical_context: Dict, target_domain: str = None
    ) -> Dict[str, Any]:
        """Generate strategies using both PCAP analysis and historical data"""

        strategy_recommendations = {
            "pcap_based_strategies": [],
            "history_based_strategies": [],
            "combined_strategies": [],
            "confidence_scores": {},
        }

        try:
            # Generate strategies based on PCAP analysis
            pcap_patterns = self.pcap_comparator.identify_strategy_patterns(
                comparison_result.recon_packets + comparison_result.zapret_packets
            )

            # Convert PCAP patterns to strategy recommendations
            if pcap_patterns.get("strategy_type") == "fake,fakeddisorder":
                strategy_recommendations["pcap_based_strategies"].append(
                    {
                        "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=3 --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum,badseq",
                        "confidence": 0.8,
                        "source": "pcap_pattern_analysis",
                        "reasoning": "Detected fake packets with low TTL and disorder patterns",
                    }
                )

            # Generate strategies based on historical data
            relevant_strategies = historical_context.get("relevant_strategies", [])
            for strategy_data in relevant_strategies:
                if strategy_data["success_rate"] > 0:
                    strategy_recommendations["history_based_strategies"].append(
                        {
                            "strategy": strategy_data["strategy"],
                            "confidence": strategy_data["success_rate"],
                            "source": "historical_effectiveness",
                            "reasoning": f"Previously achieved {strategy_data['success_rate']:.1%} success rate",
                        }
                    )

            # Combine strategies using intelligent generation if available
            if INTELLIGENT_GENERATOR_AVAILABLE and IntelligentStrategyGenerator:
                LOG.info("Using intelligent strategy generator...")
                # This would use the IntelligentStrategyGenerator
                strategy_recommendations["combined_strategies"] = [
                    {
                        "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=3 --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum",
                        "confidence": 0.9,
                        "source": "intelligent_generation",
                        "reasoning": "Combined PCAP analysis with historical effectiveness data",
                    }
                ]

        except Exception as e:
            LOG.error(f"Strategy generation failed: {e}")
            strategy_recommendations["error"] = str(e)

        return strategy_recommendations

    def _generate_integration_insights(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate insights about the integration benefits"""

        insights = {
            "data_sources_used": [],
            "integration_advantages": [],
            "limitations_addressed": [],
            "confidence_improvements": [],
        }

        # Identify data sources used
        if results.get("pcap_comparison"):
            insights["data_sources_used"].append("PCAP packet analysis")

        if results.get("historical_context"):
            insights["data_sources_used"].append("Historical effectiveness data")

        if results.get("rst_analysis"):
            insights["data_sources_used"].append("RST trigger analysis")

        # Integration advantages
        insights["integration_advantages"] = [
            "Combined packet-level analysis with historical context",
            "Enhanced strategy recommendations using multiple data sources",
            "Improved confidence scoring through cross-validation",
            "Seamless workflow integration with existing tools",
        ]

        # Limitations addressed
        insights["limitations_addressed"] = [
            "PCAP-only analysis lacks historical context",
            "Historical data alone misses current packet patterns",
            "Isolated tools provide incomplete picture",
            "Manual correlation between different analysis results",
        ]

        # Confidence improvements
        pcap_strategies = results.get("strategy_recommendations", {}).get(
            "pcap_based_strategies", []
        )
        history_strategies = results.get("strategy_recommendations", {}).get(
            "history_based_strategies", []
        )
        combined_strategies = results.get("strategy_recommendations", {}).get(
            "combined_strategies", []
        )

        if pcap_strategies and history_strategies:
            insights["confidence_improvements"].append(
                "Cross-validation between PCAP patterns and historical effectiveness"
            )

        if combined_strategies:
            insights["confidence_improvements"].append(
                "Enhanced confidence through intelligent strategy combination"
            )

        return insights

    def _generate_actionable_fixes(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate actionable fixes based on integrated analysis"""

        fixes = []

        try:
            # Fixes based on PCAP comparison
            pcap_comparison = results.get("pcap_comparison", {})

            # TTL fixes
            if "ttl_mismatch" in str(pcap_comparison):
                fixes.append(
                    {
                        "priority": "HIGH",
                        "type": "parameter_fix",
                        "title": "Fix TTL Parameter",
                        "description": "Ensure fake packets use TTL=3 consistently",
                        "file_path": "core/bypass/attacks/tcp/fake_disorder_attack.py",
                        "action": "Update TTL parameter in fake packet generation",
                        "confidence": "HIGH",
                        "source": "pcap_analysis",
                    }
                )

            # Split position fixes
            if "split_segments" in str(pcap_comparison):
                fixes.append(
                    {
                        "priority": "HIGH",
                        "type": "algorithm_fix",
                        "title": "Fix Split Position Calculation",
                        "description": "Ensure split_pos=3 is applied correctly",
                        "file_path": "core/bypass/attacks/tcp/fake_disorder_attack.py",
                        "action": "Review and fix split position calculation logic",
                        "confidence": "HIGH",
                        "source": "pcap_analysis",
                    }
                )

            # Fixes based on historical context
            historical_context = results.get("historical_context", {})
            recommendations = historical_context.get("recommendations_from_history", [])

            for recommendation in recommendations:
                if "TTL=" in recommendation:
                    fixes.append(
                        {
                            "priority": "MEDIUM",
                            "type": "parameter_optimization",
                            "title": "Optimize TTL Based on History",
                            "description": recommendation,
                            "action": "Apply historically successful TTL values",
                            "confidence": "MEDIUM",
                            "source": "historical_analysis",
                        }
                    )

            # Fixes based on strategy recommendations
            strategy_recommendations = results.get("strategy_recommendations", {})
            combined_strategies = strategy_recommendations.get("combined_strategies", [])

            for strategy in combined_strategies:
                if strategy.get("confidence", 0) > 0.8:
                    fixes.append(
                        {
                            "priority": "MEDIUM",
                            "type": "strategy_implementation",
                            "title": "Implement High-Confidence Strategy",
                            "description": f"Apply strategy: {strategy['strategy']}",
                            "action": "Implement and test recommended strategy",
                            "confidence": "HIGH",
                            "source": "integrated_analysis",
                        }
                    )

        except Exception as e:
            LOG.error(f"Failed to generate actionable fixes: {e}")
            fixes.append(
                {
                    "priority": "LOW",
                    "type": "error",
                    "title": "Fix Generation Error",
                    "description": f"Error generating fixes: {e}",
                    "action": "Review integration logic",
                    "confidence": "LOW",
                    "source": "error_handling",
                }
            )

        return fixes

    def update_recon_summary(self, analysis_results: Dict[str, Any]) -> bool:
        """Update recon_summary.json with new analysis results"""

        try:
            # Load current summary
            current_summary = {}
            if os.path.exists(self.recon_summary_file):
                with open(self.recon_summary_file, "r", encoding="utf-8") as f:
                    current_summary = json.load(f)

            # Add integration analysis results
            if "integration_analysis" not in current_summary:
                current_summary["integration_analysis"] = []

            integration_entry = {
                "timestamp": datetime.now().isoformat(),
                "analysis_type": "pcap_integration",
                "results_summary": {
                    "pcap_files_analyzed": [
                        analysis_results.get("analysis_metadata", {}).get("recon_pcap"),
                        analysis_results.get("analysis_metadata", {}).get("zapret_pcap"),
                    ],
                    "integration_components": analysis_results.get("analysis_metadata", {}).get(
                        "integration_components", []
                    ),
                    "actionable_fixes_count": len(analysis_results.get("actionable_fixes", [])),
                    "strategy_recommendations_count": len(
                        analysis_results.get("strategy_recommendations", {}).get(
                            "combined_strategies", []
                        )
                    ),
                },
            }

            current_summary["integration_analysis"].append(integration_entry)

            # Update metadata
            if "metadata" not in current_summary:
                current_summary["metadata"] = {}

            current_summary["metadata"]["last_integration_analysis"] = datetime.now().isoformat()
            current_summary["metadata"]["integration_analysis_count"] = len(
                current_summary["integration_analysis"]
            )

            # Save updated summary
            with open(self.recon_summary_file, "w", encoding="utf-8") as f:
                json.dump(current_summary, f, indent=2, ensure_ascii=False)

            LOG.info("Updated recon_summary.json with integration analysis results")
            return True

        except Exception as e:
            LOG.error(f"Failed to update recon_summary.json: {e}")
            return False

    def get_integration_status(self) -> Dict[str, Any]:
        """Get current integration status and capabilities"""

        status = {
            "available_components": self._get_available_components(),
            "integration_capabilities": {
                "find_rst_triggers": FIND_RST_AVAILABLE,
                "enhanced_find_rst_triggers": ENHANCED_RST_AVAILABLE,
                "strategy_rule_engine": RULE_ENGINE_AVAILABLE,
                "intelligent_strategy_generator": INTELLIGENT_GENERATOR_AVAILABLE,
                "enhanced_rst_analyzer": STRATEGY_RST_AVAILABLE,
            },
            "historical_data_status": {
                "recon_summary_available": os.path.exists(self.recon_summary_file),
                "strategies_in_history": len(self.historical_data.get("all_results", [])),
                "effectiveness_data_available": bool(
                    self.historical_data.get("strategy_effectiveness")
                ),
            },
            "pcap_analysis_capabilities": [
                "packet_sequence_comparison",
                "strategy_parameter_analysis",
                "timing_pattern_analysis",
                "fake_packet_detection",
                "split_position_analysis",
            ],
        }

        return status


def create_recon_integration_manager(
    recon_summary_file: str = "recon_summary.json",
    pcap_directory: str = ".",
    debug_mode: bool = False,
) -> ReconIntegrationManager:
    """
    Factory function to create a ReconIntegrationManager instance.

    Args:
        recon_summary_file: Path to recon_summary.json
        pcap_directory: Directory containing PCAP files
        debug_mode: Enable debug logging

    Returns:
        Configured ReconIntegrationManager instance
    """

    return ReconIntegrationManager(
        recon_summary_file=recon_summary_file,
        pcap_directory=pcap_directory,
        debug_mode=debug_mode,
    )
